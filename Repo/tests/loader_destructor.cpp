#include <stdlib.h>
extern "C" void loader_event(int);
extern "C" void *__dso_handle;
extern "C" int __cxa_thread_atexit_impl(void(*)(void*),void*,void*);
struct Item { int value; };
__attribute__((constructor)) static void initialize(){loader_event(30);}
__attribute__((destructor)) static void finalize(){loader_event(31);}
static void destroy(void *opaque)
{
    Item *item=static_cast<Item*>(opaque);loader_event(100+item->value);free(item);
}
extern "C" int loader_register_destructor(int value)
{
    Item *item=static_cast<Item*>(malloc(sizeof(*item)));if(!item)return -1;item->value=value;
    if(__cxa_thread_atexit_impl(destroy,item,__dso_handle)){free(item);return -1;}return 0;
}
