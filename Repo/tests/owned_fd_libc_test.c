#include "fcntl.h"
#include "unistd.h"
#include "stdio.h"
#include "sys/stat.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "serial.h"

#define CHECK(c,label) do { if (!(c)) { serial_printf("OWNED_FD_LIBC_TEST: FAIL %s errno=%d\n",label,errno); return 1; } } while(0)
int main(void)
{
    char *buffer=calloc(1,128);
    struct stat *stat=calloc(1,sizeof(*stat));
    CHECK(buffer&&stat,"heap state");
    CHECK(read(0,buffer,1)==0,"standard stdin EOF");
    CHECK(fstat(1,stat)==0&&S_ISCHR(stat->st_mode),"standard stdout character");
    int file=open("/tmp/owned-fd-libc",O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0666);
    CHECK(file==3&&fcntl(file,F_GETFD)==FD_CLOEXEC,"standard open and flags");
    CHECK(write(file,"abcdef",6)==6&&lseek(file,0,SEEK_SET)==0,"standard write/seek");
    int copy=dup(file);
    CHECK(copy==4&&fcntl(copy,F_GETFD)==0,"standard dup");
    CHECK(read(file,buffer,2)==2&&!memcmp(buffer,"ab",2)&&read(copy,buffer,2)==2&&!memcmp(buffer,"cd",2),
          "standard aliases share offset");
    CHECK(fcntl(copy,F_SETFD,FD_CLOEXEC)==0&&fcntl(copy,F_GETFD)==FD_CLOEXEC,"set descriptor flags");
    int high=fcntl(copy,F_DUPFD_CLOEXEC,17);
    CHECK(high==17&&fcntl(high,F_GETFD)==FD_CLOEXEC,"dup minimum with CLOEXEC");
    CHECK(dup2(file,copy)==copy&&fcntl(copy,F_GETFD)==0,"dup2 clears replacement flags");
    CHECK(dup3(file,copy,O_CLOEXEC)==copy&&fcntl(copy,F_GETFD)==FD_CLOEXEC,"dup3 atomic flags");
    CHECK(dup3(file,file,O_CLOEXEC)==-1&&errno==EINVAL,"dup3 rejects self");
    CHECK(fcntl(file,F_SETFD,2)==-1&&errno==EINVAL,"flag error to errno");
    CHECK(close(high)==0&&close(copy)==0&&close(file)==0,"close files");
    CHECK(read(copy,buffer,1)==-1&&errno==EBADF,"read error to errno");
    CHECK(open("/tmp/owned-fd-absent",O_RDONLY)==-1&&errno==ENOENT,"open error to errno");
    errno=EDOM;CHECK(fcntl(1,F_GETFD)==0&&errno==EDOM,"successful fcntl preserves errno");
    FILE *stream=fopen("/tmp/owned-fd-stdio","w+");
    CHECK(stream&&fputs("stdio works\n",stream)>=0&&fflush(stream)==0,"stdio output on owned descriptors");
    CHECK(fseek(stream,0,SEEK_SET)==0&&fgets(buffer,128,stream)&&!strcmp(buffer,"stdio works\n"),"stdio input on owned descriptors");
    CHECK(fclose(stream)==0,"stdio close");
    int saved=dup(1);
    file=open("/tmp/owned-fd-redirect",O_RDWR|O_CREAT|O_TRUNC, 0666);
    CHECK(saved>=3&&file>=3&&dup2(file,1)==1,"redirect standard stdout");
    CHECK(fputs("redirected\n",stdout)>=0&&fflush(stdout)==0,"stdout uses private replacement");
    CHECK(dup2(saved,1)==1&&close(saved)==0&&lseek(file,0,SEEK_SET)==0,"restore stdout");
    CHECK(read(file,buffer,11)==11&&!memcmp(buffer,"redirected\n",11)&&close(file)==0,"redirected bytes");
    CHECK(fputs("OWNED_LIBC_STDOUT_ONCE\n",stdout)>=0&&fflush(stdout)==0,"ordinary standard output once");
    free(stat);free(buffer);
    serial_printf("OWNED_FD_LIBC_TEST: PASS open=1 shared_offsets=1 fcntl=1 dup3=1 errno=1 stdio=1 redirect=1\n");
    return 0;
}
