#include "stdlib.h"
#include "string.h"
extern void loader_event(int);
extern int loader_dep_value(void);
extern int loader_missing_weak(void) __attribute__((weak));
int loader_plugin_data=23;
int *const loader_relro_pointer=&loader_plugin_data;
_Thread_local int loader_plugin_tls=3;
__attribute__((constructor)) static void initialize(void){loader_event(20);}
__attribute__((destructor)) static void finalize(void){loader_event(21);}
int loader_plugin_value(void)
{
    char *data=malloc(16);if(!data)return -1;
    strcpy(data,"native");int okay=!strcmp(data,"native");free(data);
    return okay && !loader_missing_weak ? loader_dep_value()+*loader_relro_pointer : -2;
}
int loader_plugin_tls_increment(void){return ++loader_plugin_tls;}
