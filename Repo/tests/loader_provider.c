extern void loader_event(int);
__attribute__((constructor)) static void initialize(void){loader_event(40);}
__attribute__((destructor)) static void finalize(void){loader_event(41);}
int loader_provider_value(void){return 41;}
