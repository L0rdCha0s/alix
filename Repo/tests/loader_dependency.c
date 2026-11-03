extern void loader_event(int);
int loader_dep_data=19;
int *loader_dep_pointer=&loader_dep_data;
__attribute__((constructor)) static void initialize(void){loader_event(10);}
__attribute__((destructor)) static void finalize(void){loader_event(11);}
int loader_dep_value(void){return *loader_dep_pointer;}
