#include "stdlib.h"
#include "string.h"
extern void alix_rust_loader_event(int);
static _Thread_local unsigned counter=3;
__attribute__((constructor)) static void initialize(void){alix_rust_loader_event(10);}
__attribute__((destructor)) static void finalize(void){alix_rust_loader_event(11);}
unsigned rust_loader_increment(void){return ++counter;}
int rust_loader_answer(void)
{
    char *bytes=malloc(16);if(!bytes)return -1;
    strcpy(bytes,"native");int result=!strcmp(bytes,"native")?42:-1;free(bytes);return result;
}
