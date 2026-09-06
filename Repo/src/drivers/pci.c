#include "pci.h"
#include "io.h"

#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

static uint32_t pci_build_address(pci_device_t dev, uint8_t offset)
{
    return 0x80000000U
        | ((uint32_t)dev.bus << 16)
        | ((uint32_t)dev.device << 11)
        | ((uint32_t)dev.function << 8)
        | (offset & 0xFC);
}

uint32_t pci_config_read32(pci_device_t dev, uint8_t offset)
{
    uint32_t address = pci_build_address(dev, offset);
    outl(PCI_CONFIG_ADDRESS, address);
    return inl(PCI_CONFIG_DATA);
}

uint16_t pci_config_read16(pci_device_t dev, uint8_t offset)
{
    uint32_t value = pci_config_read32(dev, offset);
    uint8_t shift = (uint8_t)((offset & 0x02) * 8);
    return (uint16_t)((value >> shift) & 0xFFFF);
}

uint8_t pci_config_read8(pci_device_t dev, uint8_t offset)
{
    uint32_t value = pci_config_read32(dev, offset);
    uint8_t shift = (uint8_t)((offset & 0x03) * 8);
    return (uint8_t)((value >> shift) & 0xFF);
}

void pci_config_write32(pci_device_t dev, uint8_t offset, uint32_t value)
{
    uint32_t address = pci_build_address(dev, offset);
    outl(PCI_CONFIG_ADDRESS, address);
    outl(PCI_CONFIG_DATA, value);
}

void pci_config_write16(pci_device_t dev, uint8_t offset, uint16_t value)
{
    uint32_t full = pci_config_read32(dev, offset);
    uint8_t shift = (uint8_t)((offset & 0x02) * 8);
    full &= ~(0xFFFFU << shift);
    full |= ((uint32_t)value << shift);
    pci_config_write32(dev, offset, full);
}

void pci_config_write8(pci_device_t dev, uint8_t offset, uint8_t value)
{
    uint32_t full = pci_config_read32(dev, offset);
    uint8_t shift = (uint8_t)((offset & 0x03) * 8);
    full &= ~(0xFFU << shift);
    full |= ((uint32_t)value << shift);
    pci_config_write32(dev, offset, full);
}

bool pci_find_device(uint16_t vendor, uint16_t device_id, pci_device_t *out_dev)
{
    for (uint16_t bus = 0; bus < 256; ++bus)
    {
        for (uint8_t device = 0; device < 32; ++device)
        {
            for (uint8_t function = 0; function < 8; ++function)
            {
                pci_device_t candidate = { .bus = (uint8_t)bus, .device = device, .function = function };
                uint16_t current_vendor = pci_config_read16(candidate, 0x00);
                if (current_vendor == 0xFFFF)
                {
                    if (function == 0)
                    {
                        break;
                    }
                    continue;
                }
                uint16_t current_device = pci_config_read16(candidate, 0x02);
                if (current_vendor == vendor && current_device == device_id)
                {
                    if (out_dev)
                    {
                        *out_dev = candidate;
                    }
                    return true;
                }
            }
        }
    }
    return false;
}

void pci_set_command_bits(pci_device_t dev, uint16_t set_bits, uint16_t clear_bits)
{
    uint16_t value = pci_config_read16(dev, 0x04);
    value |= set_bits;
    value &= (uint16_t)~clear_bits;
    pci_config_write16(dev, 0x04, value);
}

static uint8_t pci_find_capability(pci_device_t dev, uint8_t cap_id)
{
    /* Capabilities list pointer at 0x34 for header type 0. */
    uint16_t status = pci_config_read16(dev, 0x06);
    const uint16_t CAP_LIST_BIT = (1u << 4);
    if ((status & CAP_LIST_BIT) == 0)
    {
        return 0;
    }

    uint8_t ptr = pci_config_read8(dev, 0x34);
    int safety = 48;
    while (ptr >= 0x40 && safety-- > 0)
    {
        uint8_t id = pci_config_read8(dev, ptr);
        if (id == cap_id)
        {
            return ptr;
        }
        ptr = pci_config_read8(dev, (uint8_t)(ptr + 1));
    }
    return 0;
}

bool pci_enable_msi(pci_device_t dev, uint8_t vector, uint8_t apic_id)
{
    const uint8_t MSI_CAP_ID = 0x05;
    uint8_t cap = pci_find_capability(dev, MSI_CAP_ID);
    if (cap == 0)
    {
        return false;
    }

    uint16_t control = pci_config_read16(dev, (uint8_t)(cap + 0x2));
    bool addr64 = (control & (1u << 7)) != 0;

    uint32_t msg_addr = 0xFEE00000U | ((uint32_t)apic_id << 12);
    pci_config_write32(dev, (uint8_t)(cap + 0x4), msg_addr);
    uint8_t data_off = (uint8_t)(cap + (addr64 ? 0xC : 0x8));
    if (addr64)
    {
        pci_config_write32(dev, (uint8_t)(cap + 0x8), 0);
    }
    uint16_t msg_data = vector;
    pci_config_write16(dev, data_off, msg_data);

    control |= 0x0001u; /* MSI Enable */
    control &= (uint16_t)~(1u << 8); /* per-vector mask disable */
    pci_config_write16(dev, (uint8_t)(cap + 0x2), control);

    /* Disable legacy INTx to avoid double-delivery. */
    pci_set_command_bits(dev, 0x0400, 0);
    return true;
}
