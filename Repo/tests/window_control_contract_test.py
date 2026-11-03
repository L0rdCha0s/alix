#!/usr/bin/env python3
"""Exercise production window transactions and SMP surface/close ownership."""
import os
import shlex
from audio_stream_contract_test import ROOT, compile_and_run, function_definition
from audio_hda_state_test import typedef


def main():
    source = (ROOT / "src/kernel/user_atk.c").read_text()
    windows = (ROOT / "src/atk/atk_window.c").read_text()
    code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#define CHECK(c) do {if(!(c)){fprintf(stderr,"window contract line %d: %s\n",__LINE__,#c);abort();}}while(0)
#define USER_ATK_DEBUG 0
#define ATK_WINDOW_TITLE_HEIGHT 30
typedef uint32_t video_color_t;
typedef struct { pthread_mutex_t lock; } spinlock_t;
typedef unsigned wait_queue_t;
typedef unsigned process_t;
static _Thread_local unsigned preempt,atk_depth;
static void spinlock_preempt_disable(void){++preempt;}
static void spinlock_preempt_enable(void){CHECK(preempt);--preempt;}
static void spinlock_init(spinlock_t *lock){CHECK(!pthread_mutex_init(&lock->lock,NULL));}
static void spinlock_lock(spinlock_t *lock){CHECK(!pthread_mutex_lock(&lock->lock));}
static void spinlock_unlock(spinlock_t *lock){CHECK(!pthread_mutex_unlock(&lock->lock));}
static pthread_mutex_t atk_lock=PTHREAD_MUTEX_INITIALIZER;
static uint32_t input_activity_idle_millis(void){return 0;}
static uint64_t atk_state_lock_acquire(void){CHECK(!atk_depth);CHECK(!pthread_mutex_lock(&atk_lock));++atk_depth;return 1;}
static void atk_state_lock_release(uint64_t flags){CHECK(flags==1&&atk_depth==1);--atk_depth;CHECK(!pthread_mutex_unlock(&atk_lock));}
static void atk_state_lock_init(void){}
typedef struct atk_widget {
 bool used;int x,y,width,height,stride;struct atk_widget *parent,*image;
 int layout_margin_left,layout_margin_top,layout_margin_right,layout_margin_bottom;
 void *priv,*context;uint32_t *pixels;
} atk_widget_t;
typedef struct {bool hidden,chrome_visible,shaded,surface_valid;int shade_restore_height;char title[32];} atk_window_priv_t;
typedef struct {
 atk_widget_t *dragging_window,*resizing_window,*pressed_window_button_window,*pressed_window_button,*mouse_capture_widget,*focus_widget;
 void *drag_window_surface;bool drag_active,drag_scene_valid;unsigned resize_edges;struct {bool active;}resize_band;
} atk_state_t;
static atk_state_t state;
static int atk_menu_bar_height(const atk_state_t *s){(void)s;return 24;}
static atk_state_t *atk_state_get(void){CHECK(atk_depth);return &state;}
static atk_widget_t *atk_state_focus_widget(atk_state_t *s){return s->focus_widget;}
static void atk_state_set_focus_widget(atk_state_t *s,atk_widget_t *w){s->focus_widget=w;}
static void atk_state_set_mouse_capture(atk_state_t *s,atk_widget_t *w){s->mouse_capture_widget=w;}
static atk_window_priv_t *window_priv_mut(atk_widget_t *w){return w?w->priv:NULL;}
static const atk_window_priv_t *window_priv(const atk_widget_t *w){return w?w->priv:NULL;}
static int video_screen_width(void){return 1280;}
static int video_screen_height(void){return 1024;}
static process_t owner;
static process_t *process_current(void){CHECK(preempt);return &owner;}
static _Thread_local unsigned frame_allocations,fail_frame_at;
static unsigned allocations,closes;
static void *test_malloc(size_t bytes){if(++frame_allocations==fail_frame_at)return NULL;void*p=malloc(bytes);if(p)__atomic_add_fetch(&allocations,1,__ATOMIC_RELAXED);return p;}
static void *test_calloc(size_t count,size_t bytes){void*p=calloc(count,bytes);if(p)__atomic_add_fetch(&allocations,1,__ATOMIC_RELAXED);return p;}
static void test_free(void *p){if(p){CHECK(__atomic_fetch_sub(&allocations,1,__ATOMIC_RELAXED));free(p);}}
#define malloc test_malloc
#define calloc test_calloc
#define free test_free
static void serial_printf(const char *format,...){(void)format;}
static void user_atk_log(const char *message,uint64_t value){(void)message;(void)value;}
static void wait_queue_wake_all(wait_queue_t *queue){(void)queue;}
static void user_atk_apply_priorities(void){}
static bool copy_in=true,copy_out=true;
static bool user_copy_from_user(void*d,const void*s,size_t n){if(!copy_in||!s)return false;memcpy(d,s,n);return true;}
static bool user_copy_to_user(void*d,const void*s,size_t n){if(!copy_out||!d)return false;memcpy(d,s,n);return true;}
'''
    code += "\n".join(line for line in (ROOT / "include/user_atk_defs.h").read_text().splitlines()
                       if not line.startswith("#include ")) + "\n"
    code += typedef(source, "user_atk_window_t") + r'''
static user_atk_window_t *g_windows_head,*g_focus_window,*g_capture_window;
static bool g_capture_forced,g_capture_relative;
static spinlock_t g_windows_lock;
static void user_atk_windows_lock(void){spinlock_lock(&g_windows_lock);}
static void user_atk_windows_unlock(void){spinlock_unlock(&g_windows_lock);}
static void atk_dirty_mark_all(void){CHECK(atk_depth);}
static void atk_window_mark_dirty(const atk_widget_t *window){CHECK(atk_depth&&window&&window->used);}
static void video_request_refresh(void){CHECK(atk_depth);}
static void video_request_refresh_window(atk_widget_t *window){
 CHECK(atk_depth&&window&&window->used);
 user_atk_window_t *win=window->context;
 CHECK(win&&win->image->pixels==win->pixels&&win->image->width==win->content_width&&win->image->height==win->content_height);
}
static bool fail_image;
static bool atk_image_set_pixels(atk_widget_t *image,uint32_t*p,int w,int h,int stride,bool owned){
 CHECK(atk_depth&&!owned&&p&&w>0&&h>0);if(fail_image){fail_image=false;return false;}
 image->pixels=p;image->width=w;image->height=h;image->stride=stride;return true;
}
static uint32_t *atk_image_pixels(atk_widget_t *image){return image->pixels;}
static void user_atk_window_resized(const atk_widget_t *window);
static void atk_window_request_layout(atk_widget_t *window){user_atk_window_resized(window);}
static bool atk_window_is_chrome_visible(const atk_widget_t *window){return window_priv(window)->chrome_visible;}
bool atk_window_is_visible(const atk_widget_t *window);
void atk_window_set_chrome_style(atk_widget_t *window,bool visible);
static const char *atk_window_title(const atk_widget_t *window){return window_priv(window)->title;}
static void atk_window_set_title_text(atk_widget_t *window,const char *title){CHECK(atk_depth);snprintf(window_priv_mut(window)->title,32,"%s",title);}
static bool atk_window_bring_to_front(atk_state_t*s,atk_widget_t*w){CHECK(s==&state&&w);return true;}
static user_atk_window_t *user_atk_from_window(const atk_widget_t *window){return window?window->context:NULL;}
static void user_atk_queue_event(user_atk_window_t *win,const user_atk_event_t *event){
 CHECK(atk_depth&&win);spinlock_lock(&win->event_lock);if(win->event_count<USER_ATK_EVENT_QUEUE_MAX)win->events[win->event_count++]=*event;spinlock_unlock(&win->event_lock);
}
static void user_atk_queue_resize_event(user_atk_window_t*win,uint32_t width,uint32_t height){user_atk_event_t e={.type=USER_ATK_EVENT_RESIZE,.data0=width,.data1=height};user_atk_queue_event(win,&e);}
static void user_atk_send_close_event(user_atk_window_t*win){user_atk_event_t e={.type=USER_ATK_EVENT_CLOSE};user_atk_queue_event(win,&e);}
static void user_atk_window_on_destroy(void *context);
static void atk_window_close(atk_state_t*s,atk_widget_t*w){
 CHECK(atk_depth&&s==&state&&w&&w->used);w->used=false;
 atk_widget_t *image=w->image;void *priv=w->priv;user_atk_window_on_destroy(w->context);
 free(image);free(priv);free(w);__atomic_add_fetch(&closes,1,__ATOMIC_RELAXED);
}
'''
    for signature in ("static void user_atk_window_retain(", "static void user_atk_window_release(",
                      "static user_atk_window_t *user_atk_find(", "static void user_atk_insert(",
                      "static void user_atk_window_on_destroy(", "static void user_atk_remove(",
                      "static bool user_atk_resize_window(", "void user_atk_window_resized(",
                      "void user_atk_focus_window(", "int64_t user_atk_sys_present(",
                      "static int64_t user_atk_close_impl(", "int64_t user_atk_sys_close(",
                      "static void user_atk_snapshot_window(", "static int user_atk_configure_window("):
        code += function_definition(source, signature) + "\n"
    for signature in ("bool atk_window_is_visible(", "static bool window_owns_widget(",
                      "void atk_window_set_visible(", "void atk_window_set_chrome_style("):
        code += function_definition(windows, signature) + "\n"
    code += function_definition(source, "int64_t user_atk_sys_control(") + r'''
static unsigned next_handle=1;
static user_atk_window_t *new_window(void){
 CHECK(preempt);user_atk_window_t *w=calloc(1,sizeof(*w));CHECK(w);w->window=calloc(1,sizeof(*w->window));w->image=calloc(1,sizeof(*w->image));
 CHECK(w->window&&w->image);w->window->priv=calloc(1,sizeof(atk_window_priv_t));CHECK(w->window->priv);
 w->window->used=true;w->window->width=80;w->window->height=64;w->window->context=w;w->window->image=w->image;
 w->image->parent=w->window;w->image->x=w->content_offset_x=8;w->image->y=w->content_offset_y=38;
 w->content_width=w->image->width=64;w->content_height=w->image->height=18;w->pixel_bytes=64*18*4;w->stride_bytes=64*4;
 w->pixels=calloc(1,w->pixel_bytes);w->back_pixels=calloc(1,w->pixel_bytes);CHECK(w->pixels&&w->back_pixels);w->image->pixels=w->pixels;
 w->handle=next_handle++;w->refcount=1;w->owner=&owner;w->flags=USER_ATK_WINDOW_FLAG_RESIZABLE;window_priv_mut(w->window)->chrome_visible=true;
 spinlock_init(&w->pixel_lock);spinlock_init(&w->presentation_lock);spinlock_init(&w->event_lock);user_atk_insert(w);return w;
}
static int command(unsigned h,unsigned op,user_atk_window_control_t*c){c->version=1;c->size=sizeof(*c);c->reserved=0;return(int)user_atk_sys_control(h,op,c,sizeof(*c));}
static void transactions(void){
 spinlock_preempt_disable();user_atk_window_t*w=new_window();spinlock_preempt_enable();unsigned handle=w->handle;
 user_atk_window_control_t*c=calloc(1,sizeof(*c));CHECK(c&&!command(handle,USER_ATK_CONTROL_QUERY,c));
 CHECK(c->width==64&&c->height==18&&c->flags==(USER_ATK_STATE_VISIBLE|USER_ATK_STATE_CHROME|USER_ATK_STATE_RESIZABLE));
 CHECK(!command(0,USER_ATK_CONTROL_DISPLAY,c)&&c->width==1280&&c->height==1024);
 for(unsigned failure=1;failure<=2;++failure){
  frame_allocations=0;fail_frame_at=failure;c->x=100;c->y=100;c->width=100;c->height=80;
  unsigned before=allocations;uint32_t*old=w->pixels;CHECK(command(handle,USER_ATK_CONTROL_BOUNDS,c)==-ENOMEM);
  CHECK(w->pixels==old&&w->pixel_bytes==64*18*4&&w->window->width==80&&w->window->height==64&&allocations==before);fail_frame_at=0;
 }
 fail_image=true;c->width=100;c->height=80;CHECK(command(handle,USER_ATK_CONTROL_BOUNDS,c)==-ENOMEM&&w->content_width==64);
 c->x=-30;c->y=200;c->width=100;c->height=80;CHECK(!command(handle,USER_ATK_CONTROL_BOUNDS,c)&&c->x==-30&&c->y==200&&c->width==100);
 for(unsigned chrome=0;chrome<2;++chrome){c->flags=chrome;CHECK(!command(handle,USER_ATK_CONTROL_CHROME,c)&&c->x==-30&&c->y==200&&c->width==100&&c->height==80);}
 CHECK(!command(handle,USER_ATK_CONTROL_FOCUS,c)&&(c->flags&USER_ATK_STATE_FOCUSED));c->flags=0;
 CHECK(!command(handle,USER_ATK_CONTROL_VISIBLE,c)&&!(c->flags&(USER_ATK_STATE_VISIBLE|USER_ATK_STATE_FOCUSED))&&w->window->used&&w->listed);
 c->flags=1;CHECK(!command(handle,USER_ATK_CONTROL_VISIBLE,c));strcpy(c->title,"Read back title");CHECK(!command(handle,USER_ATK_CONTROL_TITLE,c)&&!strcmp(c->title,"Read back title"));
 copy_out=false;strcpy(c->title,"Rejected title");CHECK(command(handle,USER_ATK_CONTROL_TITLE,c)==-EFAULT);copy_out=true;
 CHECK(!command(handle,USER_ATK_CONTROL_QUERY,c)&&!strcmp(c->title,"Read back title"));
 c->width=0;CHECK(command(handle,USER_ATK_CONTROL_BOUNDS,c)==-EINVAL&&w->content_width==100);
 CHECK(!user_atk_sys_close(handle)&&command(handle,USER_ATK_CONTROL_QUERY,c)==-EBADF);free(c);
}
typedef struct {pthread_t thread;unsigned handle,mode,ready;bool*go;uint32_t*pixels;user_atk_window_t*owned;user_atk_window_control_t control;} race_t;
static void *racer(void*pointer){
 race_t*r=pointer;__atomic_store_n(&r->ready,1,__ATOMIC_RELEASE);while(!__atomic_load_n(r->go,__ATOMIC_ACQUIRE))sched_yield();
 if(r->mode==2){user_atk_remove(r->owned,false);user_atk_window_release(r->owned);return NULL;}
 for(unsigned i=0;i<64;++i){
  if(!r->mode)CHECK(!user_atk_sys_present(r->handle,r->pixels,128*128*4));
  else{r->control.x=32;r->control.y=48;r->control.width=32+i;r->control.height=32+i;CHECK(!command(r->handle,USER_ATK_CONTROL_BOUNDS,&r->control));}
 }return NULL;
}
static void races(void){
 race_t*r=calloc(8,sizeof(*r));bool*go=calloc(1,sizeof(*go));CHECK(r&&go);spinlock_preempt_disable();user_atk_window_t*w=new_window(),*sibling=new_window();unsigned h=w->handle,s=sibling->handle;spinlock_preempt_enable();
 for(unsigned i=0;i<8;++i){r[i].handle=h;r[i].go=go;r[i].mode=i==7;r[i].pixels=calloc(128*128,4);CHECK(r[i].pixels&&!pthread_create(&r[i].thread,NULL,racer,&r[i]));}
 for(unsigned i=0;i<8;++i)while(!__atomic_load_n(&r[i].ready,__ATOMIC_ACQUIRE))sched_yield();__atomic_store_n(go,true,__ATOMIC_RELEASE);
 for(unsigned i=0;i<8;++i){CHECK(!pthread_join(r[i].thread,NULL));free(r[i].pixels);}
 __atomic_store_n(go,false,__ATOMIC_RELEASE);spinlock_preempt_disable();
 for(unsigned i=0;i<2;++i){r[i].mode=2;r[i].ready=0;r[i].owned=user_atk_find(h,&owner);CHECK(r[i].owned);}
 spinlock_preempt_enable();for(unsigned i=0;i<2;++i)CHECK(!pthread_create(&r[i].thread,NULL,racer,&r[i]));
 for(unsigned i=0;i<2;++i)while(!__atomic_load_n(&r[i].ready,__ATOMIC_ACQUIRE))sched_yield();__atomic_store_n(go,true,__ATOMIC_RELEASE);
 for(unsigned i=0;i<2;++i)CHECK(!pthread_join(r[i].thread,NULL));
 CHECK(g_windows_head==sibling&&sibling->listed&&!sibling->next&&!sibling->prev&&!user_atk_sys_close(s));free(r);free(go);
}
int main(void){spinlock_init(&g_windows_lock);transactions();races();CHECK(!g_windows_head&&!allocations&&closes==3&&!preempt);puts("Native window contracts PASS: rollback, state, surface SMP and idempotent close");return 0;}
'''
    previous = os.environ.get("HOST_CC")
    os.environ["HOST_CC"] = shlex.join(shlex.split(previous or "cc") + ["-pthread"])
    try:
        compile_and_run("window-control", code)
    finally:
        if previous is None:
            os.environ.pop("HOST_CC", None)
        else:
            os.environ["HOST_CC"] = previous


if __name__ == "__main__":
    main()
