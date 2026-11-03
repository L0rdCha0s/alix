extern int version_events;
extern int version_constructor_calls;
int value_v1(void){return 11;}
int value_v2(void){return 22;}
int data_v1=3,data_v2=7;
__thread int tls_v1=101,tls_v2=202;
__asm__(".symver value_v1,versioned_value@ALIX_1\n.symver value_v2,versioned_value@@ALIX_2\n"
        ".symver data_v1,versioned_data@ALIX_1\n.symver data_v2,versioned_data@@ALIX_2\n"
        ".symver tls_v1,versioned_tls@ALIX_1\n.symver tls_v2,versioned_tls@@ALIX_2");
__attribute__((constructor))static void begin(void){version_events+=10;++version_constructor_calls;}
__attribute__((destructor))static void end(void){version_events-=10;}
