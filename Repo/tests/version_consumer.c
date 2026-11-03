extern int version_events;
extern int version_constructor_calls;
extern int versioned_value(void),old_value(void);
extern int versioned_data,old_data;
__asm__(".symver old_value,versioned_value@ALIX_1\n.symver old_data,versioned_data@ALIX_1");
int version_consumer_value(void){return old_value()+versioned_value()+old_data+versioned_data;}
__attribute__((constructor))static void begin(void){version_events+=100;++version_constructor_calls;}
__attribute__((destructor))static void end(void){version_events-=100;}
