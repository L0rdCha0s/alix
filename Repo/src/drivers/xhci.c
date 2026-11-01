/* xHCI 1.x, boot-attached USB devices. Events are polled, so enumeration and
 * storage do not depend on firmware PCI INTx routing. All DMA objects live on
 * the identity-mapped kernel heap (<4 GiB), including on 32-bit-only controllers.
 * A controller gate serializes ring producers. Its bounded owner disables
 * preemption (not interrupts) so cancellation cannot abandon a live DMA request.
 * Interrupt endpoints keep a pending TD and its buffer across empty polls.
 * Specification: Intel xHCI, sections 4-7.
 */
#include "xhci.h"
#include "pci.h"
#include "ioremap.h"
#include "libc.h"
#include "serial.h"
#include "process.h"
#include "timer.h"

#define XHCI_CONTROLLERS 4
#define XHCI_SLOTS 32
#define RING_SIZE 256
#define DMA_BYTES 16384u
#define TRB_TYPE(t) ((uint32_t)(t) << 10)
#define TRB_IOC (1u << 5)
#define TRB_CHAIN (1u << 4)
#define PORT_CHANGE (0x7fu << 17)

typedef struct { uint64_t parameter; uint32_t status, control; } xhci_trb_t;
typedef struct { xhci_trb_t *trbs; uint16_t next; uint8_t cycle; } xhci_ring_t;
typedef struct
{
    xhci_ring_t ring;
    uint8_t *buffer;
    uint64_t token;
    uint32_t requested, remaining, code;
    bool pending, complete, short_packet;
} xhci_endpoint_t;
typedef struct
{
    usb_device_t usb;
    uint8_t slot, root_port, speed_id, parent_slot, parent_port;
    uint32_t route;
    void *input, *output;
    xhci_endpoint_t endpoints[32];
} xhci_device_t;
typedef struct
{
    volatile uint8_t *base, *op, *runtime, *doorbells;
    xhci_ring_t command;
    xhci_trb_t *events;
    uint64_t *dcbaa, *erst;
    uint16_t event_next;
    uint8_t event_cycle, context_size, max_ports, max_slots;
    volatile uint32_t busy;
    uint64_t command_token;
    uint32_t command_code;
    uint8_t command_slot;
    bool command_done, running;
    xhci_device_t *slots[XHCI_SLOTS + 1];
} xhci_controller_t;

static xhci_controller_t *g_controllers[XHCI_CONTROLLERS];
static size_t g_controller_count;
static usb_device_t *g_devices[XHCI_CONTROLLERS * XHCI_SLOTS];
static size_t g_device_count;

static uint32_t read32(volatile uint8_t *base, size_t offset)
{ return *(volatile uint32_t *)(base + offset); }
static void write32(volatile uint8_t *base, size_t offset, uint32_t value)
{ *(volatile uint32_t *)(base + offset) = value; }
static void write64(volatile uint8_t *base, size_t offset, uint64_t value)
{
    write32(base, offset, (uint32_t)value);
    write32(base, offset + 4, (uint32_t)(value >> 32));
}

/* DMA allocations remain controller-owned for its entire lifetime, including
 * after a failed halt. Never free memory that a controller might still access. */
static void *dma_alloc(size_t size, size_t alignment)
{
    void *raw = malloc(size + alignment - 1);
    if (!raw) return NULL;
    uintptr_t address = ((uintptr_t)raw + alignment - 1) & ~(alignment - 1);
    if (address >= 0x100000000ULL || size > 0x100000000ULL - address) return NULL;
    memset((void *)address, 0, size);
    return (void *)address;
}

static bool wait_register(volatile uint8_t *base, size_t off, uint32_t mask,
                          uint32_t value, uint32_t milliseconds)
{
    uint64_t start = timer_monotonic_millis();
    for (uint32_t spins = 0; spins < 100000000u; ++spins)
    {
        if ((read32(base, off) & mask) == value) return true;
        if (timer_monotonic_millis() - start >= milliseconds) break;
        __asm__ volatile ("pause");
    }
    return false;
}

static void delay_ms(uint32_t milliseconds)
{
    uint64_t start = timer_monotonic_millis();
    for (uint32_t spins = 0; spins < 100000000u; ++spins)
    {
        if (timer_monotonic_millis() - start >= milliseconds) break;
        __asm__ volatile ("pause");
    }
}

static void acquire(xhci_controller_t *hc)
{
    for (;;)
    {
        spinlock_preempt_disable();
        if (!__atomic_exchange_n(&hc->busy, 1, __ATOMIC_ACQUIRE)) return;
        spinlock_preempt_enable();
        process_yield();
    }
}
static void release(xhci_controller_t *hc)
{
    __atomic_store_n(&hc->busy, 0, __ATOMIC_RELEASE);
    spinlock_preempt_enable();
}

static bool ring_init(xhci_ring_t *ring)
{
    ring->trbs = dma_alloc(4096, 4096);
    ring->cycle = 1;
    return ring->trbs != NULL;
}

static uint64_t enqueue(xhci_ring_t *ring, uint64_t pointer, uint32_t status, uint32_t control)
{
    xhci_trb_t *trb = &ring->trbs[ring->next];
    trb->parameter = pointer;
    trb->status = status;
    __atomic_store_n(&trb->control, control | ring->cycle, __ATOMIC_RELEASE);
    uint64_t token = (uintptr_t)trb;
    if (++ring->next == RING_SIZE - 1)
    {
        trb = &ring->trbs[ring->next];
        trb->parameter = (uintptr_t)ring->trbs;
        trb->status = 0;
        __atomic_store_n(&trb->control, TRB_TYPE(6) | 2u | ring->cycle | (control & TRB_CHAIN), __ATOMIC_RELEASE);
        ring->next = 0;
        ring->cycle ^= 1;
    }
    return token;
}

static void events_poll(xhci_controller_t *hc)
{
    for (unsigned budget = 0; budget < RING_SIZE; ++budget)
    {
        xhci_trb_t *entry = &hc->events[hc->event_next];
        uint32_t control = __atomic_load_n(&entry->control, __ATOMIC_ACQUIRE);
        if ((control & 1) != hc->event_cycle) break;
        uint32_t status = entry->status;
        uint64_t parameter = entry->parameter;
        unsigned type = (control >> 10) & 63;
        unsigned slot = control >> 24;
        if (type == 33 && (parameter & ~15ULL) == hc->command_token)
        {
            hc->command_code = status >> 24;
            hc->command_slot = slot;
            hc->command_done = true;
        }
        else if (type == 32 && slot && slot <= XHCI_SLOTS && hc->slots[slot])
        {
            unsigned id = (control >> 16) & 31;
            xhci_endpoint_t *ep = &hc->slots[slot]->endpoints[id];
            if (id == 1 && ep->pending && (status >> 24) == 13)
            {
                ep->short_packet = true;
                ep->remaining = status & 0xffffff;
            }
            /* One TD per endpoint. A short data stage may signal before the
             * control status stage; only its final IOC completes EP0. */
            if (ep->pending && (id != 1 || parameter == ep->token || (status >> 24) != 13))
            {
                ep->code = status >> 24;
                if (!ep->short_packet) ep->remaining = status & 0xffffff;
                ep->complete = true;
            }
        }
        if (++hc->event_next == RING_SIZE)
        {
            hc->event_next = 0;
            hc->event_cycle ^= 1;
        }
        write64(hc->runtime, 0x38, (uintptr_t)&hc->events[hc->event_next] | 8u);
    }
    /* W1C interrupt pending and event interrupt; interrupts themselves stay off. */
    write32(hc->runtime, 0x20, 1);
    write32(hc->op, 4, 8);
}

static void fail_controller(xhci_controller_t *hc)
{
    hc->running = false;
    write32(hc->op, 0, read32(hc->op, 0) & ~1u);
    (void)wait_register(hc->op, 4, 1, 1, 100);
    serial_printf("[xhci] controller stopped after unrecoverable timeout; DMA memory retained");
}

static bool command(xhci_controller_t *hc, uint64_t pointer, uint32_t control)
{
    if (!hc->running) return false;
    hc->command_done = false;
    hc->command_token = enqueue(&hc->command, pointer, 0, control);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    write32(hc->doorbells, 0, 0);
    uint64_t start = timer_monotonic_millis();
    for (unsigned spins = 0; spins < 100000000u; ++spins)
    {
        events_poll(hc);
        if (hc->command_done) return hc->command_code == 1;
        if (timer_monotonic_millis() - start >= 1000) break;
        __asm__ volatile ("pause");
    }
    fail_controller(hc);
    return false;
}

static uint32_t *input_context(xhci_controller_t *hc, xhci_device_t *dev, unsigned index)
{ return (uint32_t *)((uint8_t *)dev->input + index * hc->context_size); }
static uint32_t *output_context(xhci_controller_t *hc, xhci_device_t *dev, unsigned index)
{ return (uint32_t *)((uint8_t *)dev->output + index * hc->context_size); }

static bool endpoint_init(xhci_endpoint_t *ep)
{
    if (!ring_init(&ep->ring)) return false;
    ep->buffer = dma_alloc(DMA_BYTES, 65536);
    return ep->buffer != NULL;
}

static void ep_context(uint32_t *ctx, xhci_endpoint_t *ep, uint16_t packet,
                        unsigned type, uint8_t interval, uint8_t burst)
{
    ctx[0] = (uint32_t)interval << 16;
    ctx[1] = (3u << 1) | (type << 3) | ((uint32_t)burst << 8) | ((uint32_t)packet << 16);
    uint64_t dequeue = (uintptr_t)ep->ring.trbs | 1;
    ctx[2] = dequeue;
    ctx[3] = dequeue >> 32;
    ctx[4] = packet | ((type == 7 ? (uint32_t)packet * (burst + 1) : 0) << 16);
}

/* Stop before reusing DMA after a timeout. Failed recovery disables the whole
 * controller. A stalled endpoint must be reset before moving its dequeue. */
static bool endpoint_recover(xhci_controller_t *hc, xhci_device_t *dev, unsigned id)
{
    xhci_endpoint_t *ep = &dev->endpoints[id];
    bool halted = ep->complete && ep->code != 1 && ep->code != 13;
    uint32_t target = ((uint32_t)dev->slot << 24) | (id << 16);
    if (!command(hc, 0, TRB_TYPE(halted ? 14 : 15) | target))
    { fail_controller(hc); return false; }
    events_poll(hc);
    uint64_t dequeue = (uintptr_t)&ep->ring.trbs[ep->ring.next] | ep->ring.cycle;
    if (!command(hc, dequeue, TRB_TYPE(16) | target))
    { fail_controller(hc); return false; }
    ep->pending = false;
    ep->complete = false;
    return true;
}

static bool endpoint_wait(xhci_controller_t *hc, xhci_endpoint_t *ep, uint32_t milliseconds)
{
    uint64_t start = timer_monotonic_millis();
    for (unsigned spins = 0; spins < 100000000u; ++spins)
    {
        events_poll(hc);
        if (ep->complete) return true;
        if (timer_monotonic_millis() - start >= milliseconds) return false;
        __asm__ volatile ("pause");
    }
    return false;
}

/* Called with the controller gate held. Setup is embedded in a TRB, and the
 * data stage uses a permanent heap buffer, never the caller's stack or CR3. */
static bool control_locked(xhci_controller_t *hc, xhci_device_t *dev,
                           const usb_setup_packet_t *setup, void *buffer, uint16_t length)
{
    xhci_endpoint_t *ep = &dev->endpoints[1];
    if (!hc->running || length > DMA_BYTES || length != setup->wLength || (length && !buffer)) return false;
    bool input = (setup->bmRequestType & 0x80) != 0;
    if (length && !input) memcpy(ep->buffer, buffer, length);
    uint64_t packet = 0;
    memcpy(&packet, setup, 8);
    ep->requested = length;
    ep->remaining = 0;
    ep->short_packet = false;
    ep->complete = false;
    ep->pending = true;
    enqueue(&ep->ring, packet, 8, TRB_TYPE(2) | (1u << 6) |
            ((length ? (input ? 3u : 2u) : 0u) << 16));
    if (length) enqueue(&ep->ring, (uintptr_t)ep->buffer, length,
                         TRB_TYPE(3) | TRB_CHAIN | (input ? (1u << 16) | 4u : 0));
    ep->token = enqueue(&ep->ring, 0, 0,
                        TRB_TYPE(4) | TRB_IOC | ((!length || !input) ? 1u << 16 : 0));
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    write32(hc->doorbells, dev->slot * 4, 1);
    if (!endpoint_wait(hc, ep, 1000) || (ep->code != 1 && ep->code != 13))
    { endpoint_recover(hc, dev, 1); return false; }
    ep->pending = false;
    if (ep->remaining > length) return false;
    if (length && input) memcpy(buffer, ep->buffer, length - ep->remaining);
    return ep->remaining == 0;
}

bool xhci_control_transfer(usb_device_t *usb, const usb_setup_packet_t *setup,
                           void *buffer, uint16_t length)
{
    if (!usb || !setup) return false;
    xhci_controller_t *hc = usb->host;
    xhci_device_t *dev = usb->host_data;
    acquire(hc);
    bool ok = control_locked(hc, dev, setup, buffer, length);
    release(hc);
    return ok;
}

bool xhci_transfer(usb_device_t *usb, usb_endpoint_t *endpoint, bool input,
                   bool interrupt, void *buffer, uint32_t length, uint32_t *transferred)
{
    if (transferred) *transferred = 0;
    if (!usb || !endpoint || !endpoint->endpoint || !buffer || !length || length > DMA_BYTES) return false;
    xhci_controller_t *hc = usb->host;
    xhci_device_t *dev = usb->host_data;
    unsigned id = endpoint->endpoint * 2 + (input ? 1 : 0);
    if (id >= 32) return false;
    acquire(hc);
    xhci_endpoint_t *ep = &dev->endpoints[id];
    if (!hc->running || !ep->buffer) { release(hc); return false; }
    if (!ep->pending)
    {
        if (!input) memcpy(ep->buffer, buffer, length);
        ep->requested = length;
        ep->remaining = 0;
        ep->short_packet = false;
        ep->pending = true;
        ep->complete = false;
        ep->token = enqueue(&ep->ring, (uintptr_t)ep->buffer, length, TRB_TYPE(1) | TRB_IOC | 4u);
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        write32(hc->doorbells, dev->slot * 4, id);
    }
    /* HID has persistent DMA ownership and needs no busy wait. In particular,
     * waiting for every PIT tick with preemption disabled on a one-CPU machine
     * would perpetually defer the scheduler's sleeping-thread wakeups. */
    bool done;
    if (interrupt) { events_poll(hc); done = ep->complete; }
    else done = endpoint_wait(hc, ep, 3000);
    if (!done && interrupt) { release(hc); return true; } /* NAK: keep TD live. */
    if (!done || (ep->code != 1 && ep->code != 13))
    { endpoint_recover(hc, dev, id); release(hc); return false; }
    uint32_t count = ep->remaining <= ep->requested ? ep->requested - ep->remaining : 0;
    bool ok = count <= length;
    if (ok && input) memcpy(buffer, ep->buffer, count);
    if (ok && transferred) *transferred = count;
    ep->pending = false;
    release(hc);
    return ok;
}

static uint8_t endpoint_interval(usb_device_t *usb, usb_endpoint_t *ep)
{
    unsigned interval = ep->interval ? ep->interval : 1;
    if (usb->speed == USB_SPEED_HIGH || usb->speed == USB_SPEED_SUPER)
        return interval > 16 ? 15 : interval - 1;
    unsigned exponent = 3;
    while (interval > 1 && exponent < 10) { interval >>= 1; ++exponent; }
    return exponent;
}

static bool configure_endpoints(xhci_controller_t *hc, xhci_device_t *dev)
{
    memset(dev->input, 0, hc->context_size * 33);
    memcpy(input_context(hc, dev, 1), output_context(hc, dev, 0), hc->context_size);
    uint32_t mask = 1;
    unsigned max_id = 1;
    usb_endpoint_t *endpoints[] = { &dev->usb.intr_ep, &dev->usb.bulk_in, &dev->usb.bulk_out };
    for (unsigned i = 0; i < 3; ++i)
    {
        usb_endpoint_t *desc = endpoints[i];
        if (!desc->endpoint) continue;
        unsigned id = desc->endpoint * 2 + (i != 2);
        if (!endpoint_init(&dev->endpoints[id])) return false;
        ep_context(input_context(hc, dev, id + 1), &dev->endpoints[id], desc->max_packet,
                   i == 0 ? 7 : (i == 1 ? 6 : 2),
                   i == 0 ? endpoint_interval(&dev->usb, desc) : 0, desc->max_burst);
        mask |= 1u << id;
        if (id > max_id) max_id = id;
    }
    if (mask == 1) return true;
    uint32_t *slot = input_context(hc, dev, 1);
    slot[0] = (slot[0] & ~(31u << 27)) | (max_id << 27);
    input_context(hc, dev, 0)[1] = mask;
    return command(hc, (uintptr_t)dev->input, TRB_TYPE(12) | ((uint32_t)dev->slot << 24));
}

static bool get_descriptor(xhci_controller_t *hc, xhci_device_t *dev, uint8_t type,
                           void *buffer, uint16_t length, bool class_request)
{
    usb_setup_packet_t setup = { .bmRequestType = class_request ? 0xa0 : 0x80,
        .bRequest = USB_REQ_GET_DESCRIPTOR, .wValue = (uint16_t)type << 8, .wLength = length };
    return control_locked(hc, dev, &setup, buffer, length);
}

static bool enumerate_device(xhci_controller_t *, unsigned, unsigned, uint32_t, xhci_device_t *, unsigned);

static bool hub_request(xhci_controller_t *hc, xhci_device_t *dev, uint8_t request,
                        unsigned port, unsigned feature, void *buffer, unsigned length)
{
    usb_setup_packet_t setup = { .bmRequestType = length ? 0xa3 : 0x23,
        .bRequest = request, .wValue = feature, .wIndex = port, .wLength = length };
    return control_locked(hc, dev, &setup, buffer, length);
}

static void enumerate_hub(xhci_controller_t *hc, xhci_device_t *dev, unsigned depth)
{
    /* USB route strings have five four-bit tiers. Refuse an unrepresentable path. */
    if (depth >= 5) return;
    uint8_t *descriptor = dev->endpoints[0].buffer;
    if (!descriptor)
    {
        descriptor = dma_alloc(64, 64);
        dev->endpoints[0].buffer = descriptor;
    }
    if (!descriptor || !get_descriptor(hc, dev, dev->usb.speed == USB_SPEED_SUPER ? 0x2a : USB_DESC_HUB,
                                        descriptor, dev->usb.speed == USB_SPEED_SUPER ? 12 : 9, true)) return;
    unsigned ports = descriptor[2];
    if (!ports || ports > 15) return;
    dev->usb.hub_port_count = ports;
    memset(dev->input, 0, hc->context_size * 33);
    input_context(hc, dev, 0)[1] = 1;
    uint32_t *slot = input_context(hc, dev, 1);
    memcpy(slot, output_context(hc, dev, 0), hc->context_size);
    slot[0] |= 1u << 26; /* Hub */
    if (dev->usb.device_protocol == 2) slot[0] |= 1u << 25; /* Multi-TT */
    slot[1] |= ports << 24;
    if (dev->usb.speed == USB_SPEED_HIGH) slot[2] |= ((descriptor[3] >> 5) & 3u) << 16;
    if (!command(hc, (uintptr_t)dev->input, TRB_TYPE(13) | ((uint32_t)dev->slot << 24))) return;
    if (dev->usb.speed == USB_SPEED_SUPER)
    {
        usb_setup_packet_t setup = { .bmRequestType = 0x20, .bRequest = 12, .wValue = depth };
        if (!control_locked(hc, dev, &setup, NULL, 0)) return;
    }
    for (unsigned port = 1; port <= ports; ++port)
        hub_request(hc, dev, USB_REQ_SET_FEATURE, port, 8, NULL, 0);
    delay_ms((unsigned)descriptor[5] * 2 + 100);
    uint32_t *status = dma_alloc(4, 4);
    if (!status) return;
    for (unsigned port = 1; port <= ports; ++port)
    {
        if (!hub_request(hc, dev, USB_REQ_GET_STATUS, port, 0, status, 4) || !(*status & 1)) continue;
        if (!hub_request(hc, dev, USB_REQ_SET_FEATURE, port, 4, NULL, 0)) continue;
        bool enabled = false;
        for (unsigned attempt = 0; attempt < 20; ++attempt)
        {
            delay_ms(10);
            if (!hub_request(hc, dev, USB_REQ_GET_STATUS, port, 0, status, 4)) break;
            if ((*status & 2) && !(*status & 16)) { enabled = true; break; }
        }
        if (!enabled) continue;
        hub_request(hc, dev, USB_REQ_CLEAR_FEATURE, port, 20, NULL, 0);
        unsigned speed = dev->usb.speed == USB_SPEED_SUPER ? 4 :
                         ((*status & (1u << 9)) ? 2 : ((*status & (1u << 10)) ? 3 : 1));
        enumerate_device(hc, dev->root_port, speed, dev->route | (port << (depth * 4)), dev, port);
    }
}

static bool enumerate_device(xhci_controller_t *hc, unsigned port, unsigned speed,
                              uint32_t route, xhci_device_t *parent, unsigned parent_port)
{
    if (g_device_count >= sizeof(g_devices) / sizeof(g_devices[0]) || !hc->running) return false;
    if (!command(hc, 0, TRB_TYPE(9))) return false;
    unsigned slot_id = hc->command_slot;
    if (!slot_id || slot_id > XHCI_SLOTS) return false;
    xhci_device_t *dev = calloc(1, sizeof(*dev));
    if (!dev) return false;
    hc->slots[slot_id] = dev;
    dev->slot = slot_id;
    dev->root_port = port;
    dev->speed_id = speed;
    dev->route = route;
    dev->usb.host = hc;
    dev->usb.host_data = dev;
    dev->usb.xhci = true;
    dev->usb.port = port;
    dev->usb.speed = speed >= 4 ? USB_SPEED_SUPER : speed == 3 ? USB_SPEED_HIGH :
                       speed == 2 ? USB_SPEED_LOW : USB_SPEED_FULL;
    dev->usb.max_packet0 = speed >= 4 ? 512 : speed == 3 ? 64 : 8;
    dev->input = dma_alloc(hc->context_size * 33, 64);
    dev->output = dma_alloc(hc->context_size * 32, 64);
    if (!dev->input || !dev->output || !endpoint_init(&dev->endpoints[1])) goto failed;
    hc->dcbaa[slot_id] = (uintptr_t)dev->output;
    input_context(hc, dev, 0)[1] = 3;
    uint32_t *slot = input_context(hc, dev, 1);
    slot[0] = route | (speed << 20) | (1u << 27);
    slot[1] = port << 16;
    if (parent && (speed == 1 || speed == 2))
    {
        if (parent->usb.speed == USB_SPEED_HIGH)
            slot[2] = parent->slot | (parent_port << 8);
        else slot[2] = output_context(hc, parent, 0)[2] & 0x3ffff;
    }
    ep_context(input_context(hc, dev, 2), &dev->endpoints[1], dev->usb.max_packet0, 4, 0, 0);
    if (!command(hc, (uintptr_t)dev->input, TRB_TYPE(11) | (slot_id << 24))) goto failed;
    dev->usb.address = output_context(hc, dev, 0)[3] & 255;
    uint8_t *descriptor = dma_alloc(4096, 64);
    if (!descriptor) goto failed;
    /* Start with 8 bytes for full-speed EP0; use the descriptor to evaluate MPS. */
    if (!get_descriptor(hc, dev, USB_DESC_DEVICE, descriptor, 8, false)) goto failed;
    uint16_t packet0 = speed >= 4 ? (descriptor[7] == 9 ? 512 : 0) : descriptor[7];
    if (packet0 != 8 && packet0 != 16 && packet0 != 32 && packet0 != 64 && packet0 != 512) goto failed;
    if (packet0 != dev->usb.max_packet0)
    {
        memset(dev->input, 0, hc->context_size * 33);
        input_context(hc, dev, 0)[1] = 2;
        memcpy(input_context(hc, dev, 2), output_context(hc, dev, 1), hc->context_size);
        uint32_t *ep = input_context(hc, dev, 2);
        ep[1] = (ep[1] & 0xffff) | ((uint32_t)packet0 << 16);
        if (!command(hc, (uintptr_t)dev->input, TRB_TYPE(13) | (slot_id << 24))) goto failed;
        dev->usb.max_packet0 = packet0;
    }
    if (!get_descriptor(hc, dev, USB_DESC_DEVICE, descriptor, 18, false)) goto failed;
    dev->usb.vendor_id = descriptor[8] | ((uint16_t)descriptor[9] << 8);
    dev->usb.product_id = descriptor[10] | ((uint16_t)descriptor[11] << 8);
    dev->usb.device_class = descriptor[4];
    dev->usb.device_subclass = descriptor[5];
    dev->usb.device_protocol = descriptor[6];
    dev->usb.is_hub = descriptor[4] == USB_CLASS_HUB;
    if (!get_descriptor(hc, dev, USB_DESC_CONFIGURATION, descriptor, 9, false)) goto failed;
    unsigned length = descriptor[2] | ((unsigned)descriptor[3] << 8);
    if (length < 9 || length > 4096 || !get_descriptor(hc, dev, USB_DESC_CONFIGURATION, descriptor, length, false)) goto failed;
    if (!usb_parse_configuration(&dev->usb, descriptor, length)) goto failed;
    usb_setup_packet_t setup = { .bRequest = USB_REQ_SET_CONFIGURATION, .wValue = dev->usb.configuration_value };
    if (!control_locked(hc, dev, &setup, NULL, 0) || !configure_endpoints(hc, dev)) goto failed;
    g_devices[g_device_count++] = &dev->usb;
    serial_printf("[xhci] configured slot=%u port=%u speed=%u vid=%04X pid=%04X type=%u",
                   slot_id, port, speed, dev->usb.vendor_id, dev->usb.product_id, dev->usb.type);
    if (dev->usb.is_hub)
    {
        unsigned depth = 0;
        for (uint32_t path = route; path; path >>= 4) ++depth;
        enumerate_hub(hc, dev, depth);
    }
    return true;
failed:
    serial_printf("[xhci] enumeration failed slot=%u port=%u command_code=%u", slot_id, port, hc->command_code);
    if (hc->running) command(hc, 0, TRB_TYPE(10) | (slot_id << 24));
    return false;
}

static bool probe(pci_device_t pci)
{
    uint32_t bar = pci_config_read32(pci, 0x10);
    if (bar & 1) return false;
    uint64_t physical = bar & ~15u;
    if ((bar & 6) == 4) physical |= (uint64_t)pci_config_read32(pci, 0x14) << 32;
    if (!physical) return false;
    xhci_controller_t *hc = calloc(1, sizeof(*hc));
    if (!hc) return false;
    pci_set_command_bits(pci, 6u | (1u << 10), 0); /* memory, busmaster; no INTx */
    hc->base = ioremap(physical, 65536);
    if (!hc->base) return false;
    hc->op = hc->base + *(volatile uint8_t *)hc->base;
    uint32_t hcs1 = read32(hc->base, 4), hcs2 = read32(hc->base, 8), hcc = read32(hc->base, 0x10);
    hc->max_slots = (hcs1 & 255) > XHCI_SLOTS ? XHCI_SLOTS : hcs1 & 255;
    hc->max_ports = hcs1 >> 24;
    hc->context_size = (hcc & 4) ? 64 : 32;
    unsigned db = read32(hc->base, 0x14) & ~3u, rt = read32(hc->base, 0x18) & ~31u;
    if (!hc->max_slots || !hc->max_ports || db > 65536 - 1024 || rt > 65536 - 64) return false;
    hc->doorbells = hc->base + db;
    hc->runtime = hc->base + rt;
    /* Extended capability list: claim ownership and disable legacy USB SMI. */
    unsigned offset = (hcc >> 16) * 4;
    for (unsigned steps = 0; offset && steps < 256; ++steps)
    {
        if (offset > 65536 - 8) return false;
        uint32_t cap = read32(hc->base, offset);
        if ((cap & 255) == 1)
        {
            write32(hc->base, offset, cap | (1u << 24));
            if (!wait_register(hc->base, offset, 1u << 16, 0, 1000))
            { serial_printf("[xhci] firmware ownership handoff timed out"); return false; }
            write32(hc->base, offset + 4, 0xe0000000u); /* clear events, no SMI enables */
        }
        unsigned next = (cap >> 8) & 255;
        if (!next) break;
        offset += next * 4;
    }
    if (!wait_register(hc->op, 4, 1u << 11, 0, 1000)) return false; /* CNR */
    write32(hc->op, 0, read32(hc->op, 0) & ~1u);
    if (!wait_register(hc->op, 4, 1, 1, 1000)) return false;
    write32(hc->op, 0, 2);
    if (!wait_register(hc->op, 0, 2, 0, 1000) || !wait_register(hc->op, 4, 1u << 11, 0, 1000)) return false;
    if (!(read32(hc->op, 8) & 1)) return false; /* 4 KiB pages required */
    hc->dcbaa = dma_alloc(2048, 64);
    hc->erst = dma_alloc(64, 64);
    hc->events = dma_alloc(4096, 4096);
    if (!hc->dcbaa || !hc->erst || !hc->events || !ring_init(&hc->command)) return false;
    unsigned scratchpads = ((hcs2 >> 27) & 31) | (((hcs2 >> 21) & 31) << 5);
    if (scratchpads)
    {
        uint64_t *array = dma_alloc(scratchpads * 8, 64);
        if (!array) return false;
        for (unsigned i = 0; i < scratchpads; ++i)
        {
            array[i] = (uintptr_t)dma_alloc(4096, 4096);
            if (!array[i]) return false;
        }
        hc->dcbaa[0] = (uintptr_t)array;
    }
    hc->erst[0] = (uintptr_t)hc->events;
    hc->erst[1] = RING_SIZE;
    hc->event_cycle = 1;
    write64(hc->op, 0x30, (uintptr_t)hc->dcbaa);
    write64(hc->op, 0x18, (uintptr_t)hc->command.trbs | 1u);
    write32(hc->op, 0x38, hc->max_slots);
    write32(hc->runtime, 0x28, 1);
    write64(hc->runtime, 0x38, (uintptr_t)hc->events);
    write64(hc->runtime, 0x30, (uintptr_t)hc->erst);
    write32(hc->runtime, 0x20, 0);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    write32(hc->op, 0, 1); /* Run, event polling; IMAN.IE/USBCMD.INTE stay clear. */
    if (!wait_register(hc->op, 4, 1, 0, 1000)) return false;
    hc->running = true;
    g_controllers[g_controller_count++] = hc;
    serial_printf("[xhci] controller %u:%u.%u ports=%u slots=%u context=%u polling=1",
                   pci.bus, pci.device, pci.function, hc->max_ports, hc->max_slots, hc->context_size);
    acquire(hc);
    for (unsigned port = 1; port <= hc->max_ports && hc->running; ++port)
    {
        size_t off = 0x400 + (port - 1) * 16;
        uint32_t value = read32(hc->op, off);
        if (!(value & 1)) continue;
        /* Preserve only RW port power/wake fields, never echo W1C/enable bits. */
        write32(hc->op, off, (value & ((1u << 9) | (7u << 25))) | PORT_CHANGE | (1u << 9));
        delay_ms(100); /* connect debounce */
        value = read32(hc->op, off);
        if (!(value & 1)) continue;
        if (!(value & 2))
        {
            write32(hc->op, off, (value & ((1u << 9) | (7u << 25))) | (1u << 4));
            if (!wait_register(hc->op, off, (1u << 4) | 2u, 2u, 1000))
            { serial_printf("[xhci] port %u reset failed", port); continue; }
        }
        delay_ms(20); /* reset recovery */
        value = read32(hc->op, off);
        unsigned speed = (value >> 10) & 15;
        if (speed < 1 || speed > 4)
        { serial_printf("[xhci] port %u unsupported speed id=%u", port, speed); continue; }
        enumerate_device(hc, port, speed, 0, NULL, 0);
    }
    release(hc);
    return true;
}

bool xhci_init(void)
{
    for (unsigned bus = 0; bus < 256 && g_controller_count < XHCI_CONTROLLERS; ++bus)
        for (unsigned device = 0; device < 32 && g_controller_count < XHCI_CONTROLLERS; ++device)
            for (unsigned function = 0; function < 8 && g_controller_count < XHCI_CONTROLLERS; ++function)
            {
                pci_device_t pci = { bus, device, function };
                if (pci_config_read16(pci, 0) == 0xffff)
                { if (!function) break; else continue; }
                if (pci_config_read8(pci, 0xb) == 0xc && pci_config_read8(pci, 0xa) == 3 &&
                    pci_config_read8(pci, 9) == 0x30 && !probe(pci))
                    serial_printf("[xhci] controller initialization failed at %u:%u.%u", bus, device, function);
            }
    return g_controller_count != 0;
}

size_t xhci_device_count(void) { return g_device_count; }
usb_device_t *xhci_device_at(size_t index)
{ return index < g_device_count ? g_devices[index] : NULL; }
