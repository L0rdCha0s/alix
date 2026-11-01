#include "unistd.h"
#include "signal.h"
#include "sys/wait.h"
#include "usyscall.h"
#include "serial.h"
#include "string.h"

__attribute__((naked,noinline)) void wait_status_ud2(void) { __asm__ volatile("ud2"); }

int main(int argc, char **argv)
{
    const char *mode=argc>1?argv[1]:"normal";
    if(!strcmp(mode,"normal"))
    {
        if(!WIFEXITED(141<<8)||WEXITSTATUS(141<<8)!=141||WIFSIGNALED(141<<8))return 1;
        serial_printf("WAIT_STATUS_TEST: normal armed pid=%d tid=%llu expected=36096\n",
                      getpid(),(unsigned long long)sys_thread_self());
        return 141;
    }
    int number=!strcmp(mode,"fault")?SIGILL:!strcmp(mode,"kill")?SIGTERM:SIGPIPE;
    if(!WIFSIGNALED(number)||WTERMSIG(number)!=number||WIFEXITED(number))return 1;
    serial_printf("WAIT_STATUS_TEST: armed pid=%d tid=%llu signo=%d status=%d vector=%d site=0x%llX\n",
                  getpid(),(unsigned long long)sys_thread_self(),number,128+number,
                  number==SIGILL?6:0,number==SIGILL?(unsigned long long)(uintptr_t)&wait_status_ud2:0ULL);
    if(number==SIGILL)wait_status_ud2();
    else if(number==SIGTERM)(void)kill(getpid(),number);
    else (void)raise(number);
    serial_printf("WAIT_STATUS_TEST: FAIL terminal operation returned\n");
    return 1;
}
