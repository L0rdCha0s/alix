extern void loader_event(int);
extern int loader_provider_value(void);
__attribute__((constructor)) static void initialize(void){loader_event(50);}
__attribute__((destructor)) static void finalize(void){loader_event(51);}
int loader_consumer_value(void){return loader_provider_value()+1;}
