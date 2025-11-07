#include "syscall.h"

#include "syscall_defs.h"
#include "process.h"
#include "serial.h"

void syscall_dispatch(syscall_frame_t *frame, uint64_t vector)
{
    (void)vector;

    if (!frame)
    {
        return;
    }

    switch (frame->rax)
    {
        case SYSCALL_EXIT:
            process_exit((int)frame->rdi);
            break;
        default:
            {
                uint64_t syscall_id = frame->rax;
                frame->rax = (uint64_t)-1;
            serial_write_string("syscall: unhandled id=");
                serial_write_hex64(syscall_id);
            serial_write_string("\r\n");
            break;
            }
    }
}
