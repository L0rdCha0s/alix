#!/usr/bin/env python3
"""Verify physical navigation events and preserved terminal ANSI translation."""
from audio_stream_contract_test import ROOT, compile_and_run, function_definition
from audio_hda_state_test import typedef


def main():
    source = (ROOT/'src/drivers/keyboard.c').read_text()
    ui = (ROOT/'src/kernel/user_atk.c').read_text()
    code = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(c) do{if(!(c)){fprintf(stderr,"keyboard event line %d: %s\n",__LINE__,#c);abort();}}while(0)
static uint64_t ticks;
static uint64_t timer_ticks(void){return ticks;}
static uint32_t timer_frequency(void){return 100;}
static uint8_t key_down[128];
static uint8_t bytes[256];static size_t byte_count,byte_index;
static bool read_scancode(uint8_t*out){if(byte_index==byte_count)return false;*out=bytes[byte_index++];return true;}
static void inject(const char*data,size_t count){CHECK(byte_index==byte_count&&count<=sizeof(bytes));memcpy(bytes,data,count);byte_index=0;byte_count=count;}
'''
    code += typedef((ROOT/'include/keyboard.h').read_text(), 'keyboard_event_t')+'\n'
    code += source[source.index('static uint8_t left_shift_pressed'):source.index('#define KBD_BUFFER_SIZE')]
    code += source[source.index('static char normal_map'):source.index('#define KEYBOARD_REPEAT_INITIAL_PATH')]
    code += source[source.index('static uint32_t repeat_initial_delay_ms'):source.index('typedef struct\n{\n    uint32_t *value_ms')]
    code += '''static bool pending_pop_char(char*);
static void pending_push_sequence(const char*,size_t);
static bool keyboard_emit_char(uint8_t,bool,bool,bool,char*);
'''
    for signature in ('static bool pending_pop_char(', 'static void pending_push_char(', 'static void pending_push_sequence(',
        'static void keyboard_clear_event(', 'static void keyboard_repeat_reset(',
        'static uint32_t keyboard_ms_to_ticks(', 'static void keyboard_update_repeat_ticks(',
        'static keyboard_repeat_entry_t *keyboard_repeat_find(', 'static keyboard_repeat_entry_t *keyboard_repeat_alloc(',
        'static void keyboard_set_multi_mode(', 'static void keyboard_start_repeat(', 'static void keyboard_stop_repeat(',
        'static bool keyboard_repeatable_navigation(', 'static bool keyboard_repeat_due(',
        'static bool keyboard_emit_arrow_sequence(', 'static bool keyboard_emit_char(',
        'bool keyboard_try_read_event(', 'bool keyboard_try_read('):
        code += function_definition(source,signature)+'\n'
    code += r'''
static void reset(void){memset(key_down,0,sizeof(key_down));left_shift_pressed=right_shift_pressed=caps_lock_enabled=left_ctrl_pressed=right_ctrl_pressed=extended_code_pending=0;pending_start=pending_count=byte_count=byte_index=0;ticks=0;keyboard_repeat_reset();keyboard_set_multi_mode(false);keyboard_update_repeat_ticks();}
static void physical_events(void){
 keyboard_event_t*event=calloc(1,sizeof(*event));char*out=calloc(1,1);CHECK(event&&out);
 reset();inject("\xe0\x4b",2);CHECK(keyboard_try_read_event(event)&&event->extended&&!event->released&&!event->repeat&&!event->ch&&event->scancode==0x4b);
 CHECK(!keyboard_try_read_event(event)&&!pending_count);ticks=20;
 CHECK(keyboard_try_read_event(event)&&event->repeat&&event->extended&&!event->ch&&event->scancode==0x4b&&!pending_count);
 inject("\xe0\xcb",2);CHECK(keyboard_try_read_event(event)&&event->released&&event->scancode==0x4b);ticks=200;CHECK(!keyboard_try_read_event(event)&&!pending_count);
 reset();inject("\xe0\x4b",2);CHECK(keyboard_try_read(out)&&*out==27&&keyboard_try_read(out)&&*out=='['&&keyboard_try_read(out)&&*out=='D'&&!pending_count);
 ticks=20;CHECK(keyboard_try_read(out)&&*out==27&&keyboard_try_read(out)&&*out=='['&&keyboard_try_read(out)&&*out=='D');
 inject("\xe0\xcb",2);CHECK(!keyboard_try_read(out));ticks=200;CHECK(!keyboard_try_read(out));
 reset();inject("\x1e\x9e",2);CHECK(keyboard_try_read_event(event)&&event->ch=='a'&&!event->released);CHECK(keyboard_try_read_event(event)&&event->released&&!event->ch);CHECK(!keyboard_try_read_event(event));
 reset();keyboard_set_multi_mode(true);inject("\xe0\x48\xe0\x4d",4);CHECK(keyboard_try_read_event(event)&&event->scancode==0x48&&!event->ch);CHECK(keyboard_try_read_event(event)&&event->scancode==0x4d&&!event->ch);ticks=20;
 CHECK(keyboard_try_read_event(event)&&event->repeat&&!event->ch);CHECK(keyboard_try_read_event(event)&&event->repeat&&!event->ch&&!pending_count);
 free(event);free(out);
}
'''
    code += '\n'.join(line for line in (ROOT/'include/user_atk_defs.h').read_text().splitlines() if not line.startswith('#include '))+'\n'
    code += r'''
#define USER_ATK_DEBUG 0
typedef struct {unsigned flags,refs,count;bool closed;user_atk_event_t events[8];}user_atk_window_t;
static user_atk_window_t*g_focus_window;static bool window_locked;
static void user_atk_windows_lock(void){CHECK(!window_locked);window_locked=true;}
static void user_atk_windows_unlock(void){CHECK(window_locked);window_locked=false;}
static void user_atk_window_retain(user_atk_window_t*w){CHECK(window_locked&&w&&!w->refs);++w->refs;}
static void user_atk_window_release(user_atk_window_t*w){CHECK(!window_locked&&w&&w->refs==1);--w->refs;}
static void user_atk_queue_event(user_atk_window_t*w,const user_atk_event_t*e){CHECK(!window_locked&&w->refs==1&&w->count<8);w->events[w->count++]=*e;}
static void user_atk_queue_key_sequence(user_atk_window_t*,const keyboard_event_t*,const char*,size_t);
'''
    code += function_definition(ui,'bool user_atk_route_key_event(')+'\n'
    code += function_definition(ui,'static void user_atk_queue_key_sequence(')+'\n'
    code += r'''
static void routing(void){
 user_atk_window_t*w=calloc(1,sizeof(*w));keyboard_event_t*key=calloc(1,sizeof(*key));CHECK(w&&key);g_focus_window=w;
 key->extended=true;key->scancode=0x4b;
 CHECK(user_atk_route_key_event(key)&&w->count==3&&!w->refs&&w->events[0].data0==27&&w->events[1].data0=='['&&w->events[2].data0=='D');
 w->count=0;w->flags=USER_ATK_WINDOW_FLAG_RAW_KEYS;
 CHECK(user_atk_route_key_event(key)&&w->count==1&&!w->events[0].data0&&w->events[0].data1==0x4b&&(w->events[0].flags&USER_ATK_KEY_FLAG_EXTENDED));
 w->count=0;key->released=true;CHECK(user_atk_route_key_event(key)&&w->count==1&&(w->events[0].flags&USER_ATK_KEY_FLAG_RELEASE));
 w->count=0;key->released=false;key->repeat=true;CHECK(user_atk_route_key_event(key)&&w->count==1&&(w->events[0].flags&USER_ATK_KEY_FLAG_REPEAT));
 w->count=0;key->extended=false;key->repeat=false;key->scancode=0x1e;key->ch='a';CHECK(user_atk_route_key_event(key)&&w->count==1&&w->events[0].data0=='a');
 w->closed=true;CHECK(!user_atk_route_key_event(key)&&!g_focus_window&&!w->refs);free(w);free(key);
}
int main(void){physical_events();routing();puts("Keyboard contracts PASS: raw navigation/repeat, legacy ANSI, release and focus lifetime");return 0;}
'''
    compile_and_run('keyboard-events',code)

if __name__=='__main__':main()
