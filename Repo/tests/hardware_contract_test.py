#!/usr/bin/env python3
"""Execute production USB parsing, framebuffer validation and BOT error paths."""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def source(path):
    return re.sub(r"^#include[^\n]*\n", "", (ROOT / path).read_text(), flags=re.M)


def run(name, code):
    with tempfile.TemporaryDirectory(prefix="alix-hardware-contract-") as folder:
        path = Path(folder)
        (path / "test.c").write_text(code)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                        "-fsanitize=address,undefined", "-g", str(path / "test.c"), "-o", str(path / "test")], check=True)
        subprocess.run([str(path / "test")], check=True, env={**__import__('os').environ, "ASAN_OPTIONS": "detect_leaks=0"})
        print(name + ": PASS")


COMMON = '''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
typedef uint64_t paddr_t;
typedef struct { unsigned value; } spinlock_t;
'''


def descriptors_and_framebuffer():
    code = COMMON + source("include/usb.h") + source("include/bootinfo.h")
    code += source("include/framebuffer.h")
    code += '''
bootinfo_t boot_info;
static void *ioremap(paddr_t address, size_t bytes) { (void)bytes; return (void *)(uintptr_t)address; }
'''
    code += source("src/drivers/usb_descriptors.c") + source("src/drivers/framebuffer.c")
    code += '''
int main(void) {
    uint8_t config[] = {9,2,44,0,1,1,0,0x80,50,
        9,4,2,0,2,8,6,0x50,0,
        7,5,0x81,2,0,4,0, 6,0x30,3,0,0,0,
        7,5,0x02,2,0,4,0, 6,0x30,3,0,0,0};
    usb_device_t dev = {0};
    assert(usb_parse_configuration(&dev,config,sizeof(config)));
    assert(dev.type==USB_DEV_STORAGE && dev.interface_number==2);
    assert(dev.bulk_in.endpoint==1 && dev.bulk_out.endpoint==2 && dev.bulk_in.max_packet==1024 && dev.bulk_in.max_burst==3);
    for(size_t i=0;i<sizeof(config);i++) assert(!usb_parse_configuration(&dev,config,i));
    config[18]=0; assert(!usb_parse_configuration(&dev,config,sizeof(config))); config[18]=7;
    config[16]=0x62; assert(usb_parse_configuration(&dev,config,sizeof(config)) && dev.type==USB_DEV_UNKNOWN); config[16]=0x50;
    config[12]=1; assert(usb_parse_configuration(&dev,config,sizeof(config)) && dev.type==USB_DEV_UNKNOWN); config[12]=0;
    uint8_t hid[]={9,2,25,0,1,1,0,0x80,50,9,4,0,0,1,3,1,1,0,7,5,0x81,3,8,0,10};
    assert(usb_parse_configuration(&dev,hid,sizeof(hid)) && dev.type==USB_DEV_HID_KEYBOARD && dev.intr_ep.interval==10);
    boot_info=(bootinfo_t){.framebuffer_enabled=1,.framebuffer_bpp=32,.framebuffer_base=0x120000000ULL,
        .framebuffer_width=800,.framebuffer_height=600,.framebuffer_pitch=832,.framebuffer_size=832*600*4,
        .framebuffer_red_mask=0xff0000,.framebuffer_green_mask=0xff00,.framebuffer_blue_mask=0xff};
    assert(framebuffer_valid(&boot_info) && framebuffer_pack(0x123456)==0x123456);
    boot_info.framebuffer_red_mask=0xff; boot_info.framebuffer_blue_mask=0xff0000;
    assert(framebuffer_valid(&boot_info) && framebuffer_pack(0x123456)==0x563412);
    boot_info.framebuffer_red_mask=0x3ff00000; boot_info.framebuffer_green_mask=0xffc00; boot_info.framebuffer_blue_mask=0x3ff;
    assert(framebuffer_valid(&boot_info) && framebuffer_pack(0xffffff)==0x3fffffff);
    boot_info.framebuffer_pitch=799; assert(!framebuffer_valid(&boot_info)); boot_info.framebuffer_pitch=832;
    --boot_info.framebuffer_size; assert(!framebuffer_valid(&boot_info)); ++boot_info.framebuffer_size;
    boot_info.framebuffer_base=UINT64_MAX-1024; assert(!framebuffer_valid(&boot_info));
    boot_info.framebuffer_base=0x120000000ULL; boot_info.framebuffer_red_mask=0x55; assert(!framebuffer_valid(&boot_info));
    return 0;
}
'''
    run("USB descriptors and GOP layout/colour contracts", code)


def storage():
    code = COMMON + source("include/usb.h") + source("include/block.h")
    code += '''
static unsigned guards;
static void spinlock_preempt_disable(void) { ++guards; }
static void spinlock_preempt_enable(void) { assert(guards); --guards; }
static void process_yield(void) { abort(); }
static void serial_printf(const char *format,...) { (void)format; }
static void devfs_register_block_devices(void) { }
static void spinlock_init(spinlock_t *lock) { lock->value=0; }
static uint64_t spinlock_lock_irqsave(spinlock_t *lock) { assert(!lock->value); lock->value=1; return 0; }
static void spinlock_unlock_irqrestore(spinlock_t *lock,uint64_t flags) { (void)flags; assert(lock->value); lock->value=0; }
'''
    code += source("src/kernel/block.c") + source("src/drivers/usb_storage.c")
    code += '''
static usb_device_t device={.type=USB_DEV_STORAGE,.bulk_in={.endpoint=1,.max_packet=512},.bulk_out={.endpoint=2,.max_packet=512}};
static bot_cbw_t current;
static unsigned phase,resets,clears,commands,writes,last_opcode,mode;
size_t usb_bus_device_count(void) { return 1; }
usb_device_t *usb_bus_device_at(size_t i) { return i==0?&device:NULL; }
bool usb_control_transfer(usb_device_t *dev,const usb_setup_packet_t *setup,void *buffer,uint16_t length) {
    (void)dev;(void)length;
    if(setup->bRequest==0xfe) { *(uint8_t*)buffer=0; return true; }
    if(setup->bRequest==0xff) { ++resets; phase=0; }
    if(setup->bRequest==1) ++clears;
    return true;
}
bool usb_bulk_transfer(usb_device_t *dev,usb_endpoint_t *ep,bool input,void *buffer,uint32_t length,uint32_t *got) {
    (void)dev;(void)ep; *got=length;
    if(phase==0) {
        assert(!input && length==31); memcpy(&current,buffer,31); assert(current.signature==0x43425355);
        phase=current.length?1:2; ++commands; last_opcode=current.cdb[0];
        if(last_opcode==0x2a || last_opcode==0x8a) ++writes;
        return true;
    }
    if(phase==1) {
        assert(length==current.length); phase=2;
        if(input) {
            memset(buffer,0,length); uint8_t *b=buffer;
            if(last_opcode==0x25) { put_be32(b,4095); put_be32(b+4,512); }
            if(last_opcode==3) b[2]=7;
            if(mode==5) *got=length-1;
        }
        return true;
    }
    assert(input && length==13); phase=0;
    bot_csw_t *csw=buffer;
    *csw=(bot_csw_t){.signature=0x53425355,.tag=current.tag};
    if(mode==1) ++csw->tag;
    if(mode==2) csw->status=2;
    if(mode==3) csw->residue=current.length+1;
    if(mode==4 && (last_opcode==0x2a || last_opcode==0x8a)) csw->status=1;
    return true;
}
int main(void) {
    block_init(); usb_storage_init(); block_device_t *block=block_find("usb0");
    assert(block && block->sector_count==4096 && block->sector_size==512 && commands==3);
    uint8_t buffer[512]={0};
    assert(block_read(block,1,1,buffer) && last_opcode==0x28);
    assert(block_write(block,1,1,buffer) && last_opcode==0x2a);
    assert(block_flush(block) && last_opcode==0x35);
    unsigned previous=commands;
    assert(!block_read(block,UINT64_MAX,2,buffer) && !block_write(block,4095,2,buffer) && commands==previous);
    for(unsigned error=1;error<=3;error++) { mode=error; assert(!block_read(block,1,1,buffer)); assert(resets==error); }
    mode=5; assert(!block_read(block,1,1,buffer) && resets==4);
    mode=4; unsigned before=writes;
    assert(!block_write(block,1,1,buffer) && writes==before+1);
    assert(!block_write(block,1,1,buffer) && writes==before+1); /* sense key DATA PROTECT */
    usb_disk_t *disk=block->driver_data; disk->read_only=false; mode=0;
    block->sector_count=1ULL<<42;
    assert(block_read(block,1ULL<<40,1,buffer) && last_opcode==0x88);
    assert(block_write(block,1ULL<<40,1,buffer) && last_opcode==0x8a);
    assert(guards==0 && clears==resets*2);
    return 0;
}
'''
    run("BOT integrity, recovery, read-only media and 64-bit LBA contracts", code)


def boot_memory():
    entry = (ROOT / "src/arch/x86/kernel_entry.c").read_text()
    overlap = entry[entry.index("static bool chunk_overlaps_framebuffer("):entry.index("static bool __attribute__((unused)) e820_chunk_usable(")]
    configure = entry[entry.index("static void configure_heap_from_e820("):entry.index("static void zero_bytes(")]
    configure = configure.replace('__asm__ volatile ("cli; hlt")', 'abort()')
    code = COMMON + source("include/bootinfo.h") + """
bootinfo_t boot_info;
#define KERNEL_HEAP_SIZE 0x20000000ULL
#define __kernel_vma_end ((uint8_t *)0x11000000ULL)
static uintptr_t kernel_heap_base, kernel_heap_end, kernel_heap_size;
static void serial_printf(const char *format,...) { (void)format; }
""" + overlap + configure + """
int main(void) {
    boot_info.e820_entry_count=1;
    boot_info.e820[0]=(bootinfo_e820_entry_t){.base=0x11000000,.length=0x60000000,.type=1};
    /* The committed policy reserves one quarter of usable RAM, capped at the
     * configured maximum: 1.5 GiB supplies a 384 MiB heap here. */
    configure_heap_from_e820(); assert(kernel_heap_base==0x11000000 && kernel_heap_size==0x18000000ULL);
    boot_info.framebuffer_enabled=1; boot_info.framebuffer_base=0x20000000; boot_info.framebuffer_size=0x1000000;
    configure_heap_from_e820(); assert(kernel_heap_base>=0x21000000 && kernel_heap_size==0x18000000ULL);
    boot_info.framebuffer_base=0x60000000;
    configure_heap_from_e820(); assert(kernel_heap_base==0x11000000 && kernel_heap_end<=0x60000000);
    boot_info.framebuffer_base=0x11000000; boot_info.framebuffer_size=0x1300000;
    configure_heap_from_e820(); assert(kernel_heap_base>=0x12300000 && !(kernel_heap_base&0x1fffff));
    boot_info.e820_entry_count=2; boot_info.e820[0].type=2;
    boot_info.e820[1]=(bootinfo_e820_entry_t){.base=0x40000000,.length=0x20000000,.type=1};
    configure_heap_from_e820(); assert(kernel_heap_base==0x40000000 && kernel_heap_size==0x08000000ULL);
    return 0;
}
"""
    run("Boot heap reservation and GOP aperture exclusion", code)


if __name__ == "__main__":
    descriptors_and_framebuffer()
    storage()
    boot_memory()
