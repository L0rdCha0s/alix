#include "sys/mman.h"
#include "fcntl.h"
#include "unistd.h"
#include "errno.h"
#include "serial.h"
int main(void)
{
    if(shm_open("/legacy-shm",O_CREAT|O_RDWR,0600)!=-1 || errno!=ENOTSUP) return 4;
    if(shm_unlink("/legacy-shm")!=-1 || errno!=ENOTSUP) return 5;
    int fd=open("/tmp/legacy-map",O_CREAT|O_TRUNC|O_RDWR, 0666);
    if(fd<0 || write(fd,"safe",4)!=4) return 1;
    if(mmap(NULL,4096,PROT_READ,MAP_SHARED,fd,0)!=MAP_FAILED || errno!=ENOTSUP) return 2;
    void *memory=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(memory==MAP_FAILED || msync(memory,4096,MS_SYNC) || munmap(memory,4096) || close(fd)) return 3;
    serial_printf("FILE_MAPPING_LEGACY: PASS unsupported=1 anonymous_sync=1 shm_namespace=isolated\n");
    return 0;
}
