#!/usr/bin/env python3
"""Exercise production USB/PS2 selection and bounded mouse polling on the host."""
from pathlib import Path
import argparse,os,re,shlex,subprocess,sys,tempfile
sys.dont_write_bytecode=True
from audio_stream_contract_test import ROOT,function_definition
parser=argparse.ArgumentParser();parser.add_argument('--source-tree',type=Path,default=ROOT);args=parser.parse_args()
mouse=(args.source_tree/'src/drivers/mouse.c').read_text();keyboard=(args.source_tree/'src/drivers/keyboard.c').read_text()
for source in [mouse,keyboard]:
    assert '#include "build_features.h"' in source,'driver must explicitly use the shared feature configuration'
feature_mouse=re.search(r'#if ENABLE_USB\n.*?#endif',mouse,re.S).group(0)
feature_keyboard=re.search(r'#if ENABLE_USB\n.*?#endif',keyboard,re.S).group(0)
budget=re.search(r'#define MOUSE_POLL_BYTE_BUDGET\s+\d+u',mouse).group(0)
paths='\n'.join(line for line in keyboard.splitlines() if line.startswith('#define KEYBOARD_REPEAT_'))
program=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "build_features.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"input polling line %d: %s\n",__LINE__,#x); abort(); } } while(0)
#define KBD_STATUS 0x64
#define KBD_DATA 0x60
static bool irq_enabled=true, buffer_ready;
static uint8_t buffered;
static unsigned status_reads,data_reads,processed,restores,resets,mode,disable_after;
static unsigned software_resets,repeat_updates,controller_inits,proc_directories,proc_files;
static unsigned g_kbd_buffer_lock;
static unsigned g_initial_repeat_entry,g_repeat_interval_entry;
static struct { void (*on_change)(bool); } g_multi_repeat_entry;
bool mouse_ps2_active(void);
bool keyboard_ps2_enabled(void);
void mouse_disable_ps2(void);
static uint64_t mouse_irq_save(void) { uint64_t old=irq_enabled; irq_enabled=false;return old; }
static void mouse_irq_restore(uint64_t old) { CHECK(!irq_enabled);++restores;irq_enabled=old!=0; }
static void mouse_queue_reset(void) { ++resets; }
static uint8_t inb(unsigned port) {
    if(port==KBD_STATUS) {
        ++status_reads;
        if(mode==0)return 0xff; /* Absent i8042 when q35 uses i8042=off. */
        if(mode==1)return 0;    /* No pending byte. */
        if(mode==2)return 1;    /* Keyboard byte belongs to keyboard reader. */
        if(mode==3)return 0x21; /* Stuck/continuous auxiliary producer. */
        if(mode==4)return status_reads<=2 ? 0x21 : 1;
        CHECK(false);
    }
    CHECK(port==KBD_DATA&&mode!=0&&mode!=1);
    ++data_reads;return 0x08;
}
static void mouse_process_byte(uint8_t byte) {
    CHECK(!irq_enabled&&byte==0x08);++processed;
    if(disable_after&&processed==disable_after)mouse_disable_ps2();
}
static bool buffer_pop(uint8_t *out) {
    if(!buffer_ready)return false;*out=buffered;buffer_ready=false;return true;
}
static void spinlock_init(unsigned *lock) { *lock=0; }
static void ps2_controller_init(void) { ++controller_inits; }
static void keyboard_reset_state(void) { ++software_resets; }
static void keyboard_update_repeat_ticks(void) { ++repeat_updates; }
static void keyboard_set_multi_mode(bool enabled) { (void)enabled; }
static void keyboard_proc_value_read(void) {}
static void keyboard_proc_value_write(void) {}
static void keyboard_proc_bool_read(void) {}
static void keyboard_proc_bool_write(void) {}
static bool procfs_mkdir(const char *name) { CHECK(name);++proc_directories;return true; }
static void *procfs_create_file_at(const char *name,void(*read)(void),void(*write)(void),void *context) {
    CHECK(name&&read&&write&&context);++proc_files;return context;
}
static void serial_printf(const char *format,...) { (void)format;CHECK(false); }
'''
program+=feature_mouse+'\n'+feature_keyboard+'\n'+budget+'\n'+paths+'\n'
for source,signature in [(mouse,'bool mouse_ps2_active('),(mouse,'void mouse_disable_ps2('),(mouse,'void mouse_poll('),
                         (keyboard,'bool keyboard_ps2_enabled('),(keyboard,'void keyboard_disable_ps2('),
                         (keyboard,'static bool read_scancode('),(keyboard,'void keyboard_init(')]:
    program+=function_definition(source,signature)+'\n'
program+=r'''
static void reset_poll(unsigned next_mode,bool enabled) {
    mode=next_mode;status_reads=data_reads=processed=restores=disable_after=0;irq_enabled=enabled;
    __atomic_store_n(&g_mouse_ps2_enabled,true,__ATOMIC_RELEASE);
}
int main(void) {
#if ENABLE_USB
    CHECK(!mouse_ps2_active()&&!keyboard_ps2_enabled());
#else
    CHECK(mouse_ps2_active()&&keyboard_ps2_enabled());
#endif
    keyboard_init();CHECK(software_resets==1&&repeat_updates==1&&proc_directories==2&&proc_files==3);
    CHECK(g_multi_repeat_entry.on_change==keyboard_set_multi_mode);
    CHECK(controller_inits==(ENABLE_USB?0u:1u)&&keyboard_ps2_enabled()==!ENABLE_USB);
    /* USB-injected software scancodes remain usable while hardware is disabled. */
    keyboard_disable_ps2();buffer_ready=true;buffered=0x1c;uint8_t code=0;
    CHECK(read_scancode(&code)&&code==0x1c&&!status_reads&&!data_reads);
    CHECK(!read_scancode(&code)&&!status_reads&&!data_reads);
    for(unsigned if_state=0;if_state<2;++if_state) {
        reset_poll(0,if_state);mouse_poll();CHECK(status_reads==1&&!data_reads&&!processed&&restores==1&&irq_enabled==if_state);
        reset_poll(1,if_state);mouse_poll();CHECK(status_reads==1&&!data_reads&&restores==1&&irq_enabled==if_state);
        reset_poll(2,if_state);mouse_poll();CHECK(status_reads==1&&!data_reads&&restores==1&&irq_enabled==if_state);
        reset_poll(3,if_state);mouse_poll();CHECK(status_reads==MOUSE_POLL_BYTE_BUDGET&&data_reads==MOUSE_POLL_BYTE_BUDGET&&processed==MOUSE_POLL_BYTE_BUDGET&&restores==MOUSE_POLL_BYTE_BUDGET&&irq_enabled==if_state);
        reset_poll(4,if_state);mouse_poll();CHECK(status_reads==3&&data_reads==2&&processed==2&&restores==3&&irq_enabled==if_state);
        reset_poll(3,if_state);disable_after=2;unsigned before=resets;mouse_poll();CHECK(status_reads==2&&data_reads==2&&restores==2&&!mouse_ps2_active()&&resets==before+1&&irq_enabled==if_state);
        status_reads=data_reads=0;mouse_poll();CHECK(!status_reads&&!data_reads&&irq_enabled==if_state);
    }
    __atomic_store_n(&ps2_enabled,true,__ATOMIC_RELEASE);mode=2;status_reads=data_reads=0;
    CHECK(read_scancode(&code)&&code==0x08&&status_reads==1&&data_reads==1);
    mode=0;status_reads=data_reads=0;CHECK(!read_scancode(&code)&&status_reads==1&&!data_reads);
    printf("Input polling contracts: PASS USB=%d absent=1 bounded=%u live_disable=1 keyboard_owner=1 irq_restore=1 software_queue=1 common_init=1\n",ENABLE_USB,MOUSE_POLL_BYTE_BUDGET);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='alix-input-poll-') as directory:
    directory=Path(directory);path=directory/'input.c';path.write_text(program)
    for usb in [1,0]:
        for sanitize in [False,True]:
            output=directory/f'input-{usb}-{sanitize}'
            flags=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if sanitize else []
            compiler=shlex.split(os.environ.get('HOST_CC','cc'))
            subprocess.run([*compiler,'-std=c11','-O2','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-iquote',str(ROOT/'include'),*flags,*(['-DENABLE_USB=0'] if not usb else []),str(path),'-o',str(output)],check=True)
            subprocess.run([str(output)],check=True,timeout=5)
