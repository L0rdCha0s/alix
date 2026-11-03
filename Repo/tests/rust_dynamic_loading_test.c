#include "serial.h"
static unsigned events[2];
void alix_rust_loader_event(int event)
{
    if(event==10 || event==11)__atomic_add_fetch(&events[event-10],1u,__ATOMIC_RELAXED);
}
int alix_rust_loader_event_count(int kind)
{ return kind>=0 && kind<2?(int)__atomic_load_n(&events[kind],__ATOMIC_RELAXED):-1; }
extern int alix_rust_dynamic_loading_test(void);
int main(void)
{
    int result=alix_rust_dynamic_loading_test();
    if(result){serial_printf("RUST_DYNAMIC_LOADING_TEST: FAIL stage=%d\n",result);return 1;}
    serial_printf("RUST_DYNAMIC_LOADING_TEST: PASS cpus=8 tls_updates=512 libloading=1 ash=1 imports=1 null_symbol=1 errors=1 unload=1\n");
    return 0;
}
