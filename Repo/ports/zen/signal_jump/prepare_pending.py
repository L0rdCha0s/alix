#!/usr/bin/env python3
"""Stage native nonlocal signal-frame unwind; never edit the active runtime."""
from pathlib import Path
import difflib,hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];STAGE=HERE/'pending'
changes={}
def read(name):return (ROOT/name).read_text()
def one(text,old,new):
    assert text.count(old)==1,old
    return text.replace(old,new,1)
name='include/signal_abi.h';text=read(name)
wire='''
#define ALIX_SIGJUMP_VERSION 1u
#define ALIX_SIGJUMP_CAPTURE 0u
#define ALIX_SIGJUMP_RESTORE 1u
#define ALIX_SIGJUMP_SAVE_MASK 1u
#define ALIX_SIGJUMP_REGISTER_BYTES 64u

typedef struct
{
    uint64_t rbx, rbp, r12, r13, r14, r15, rsp, rip;
    uint32_t version, size;
    uint64_t owner_tid, epoch, frame_sequence, saved_mask;
    uint32_t flags, reserved;
    uint64_t reserved_words[2];
} alix_sigjmp_state_t;
'''
text=one(text,'#endif',wire+'\n#endif');changes[name]=text
name='include/setjmp.h';text=read(name);text=one(text,'#include "types.h"','#include "types.h"\n#include "signal_abi.h"')
text=one(text,'typedef alix_jmp_buf_t jmp_buf[1];','typedef alix_jmp_buf_t jmp_buf[1];\ntypedef alix_sigjmp_state_t sigjmp_buf[1];')
text=one(text,'int setjmp(jmp_buf env)', 'int sigsetjmp(sigjmp_buf env, int savemask) __attribute__((returns_twice));\nvoid siglongjmp(sigjmp_buf env, int value) __attribute__((noreturn));\n\nint setjmp(jmp_buf env)');changes[name]=text
name='include/syscall_defs.h';text=read(name);text=one(text,'    SYSCALL_SLEEP_INTERRUPTIBLE = 65,','    SYSCALL_SLEEP_INTERRUPTIBLE = 65,\n    SYSCALL_SIGNAL_JUMP = 67,');changes[name]=text
name='include/process_internal.h';text=read(name);text=one(text,'    uint64_t signal_sequence;','    uint64_t signal_sequence;\n    uint64_t signal_jump_epoch;');changes[name]=text
name='include/process_signal.h';text=read(name);text=one(text,'int process_signal_return(', 'int process_signal_jump(syscall_frame_t *, uint32_t, uintptr_t, size_t, uint64_t);\nint process_signal_return(');changes[name]=text
name='src/kernel/process/process_signal.c';text=read(name)
text+='\n_Static_assert(sizeof(alix_sigjmp_state_t) == 128 && __builtin_offsetof(alix_sigjmp_state_t, version) == 64 &&\n               __builtin_offsetof(alix_sigjmp_state_t, reserved_words) == 112, "native signal checkpoint wire");\n'
text+=(HERE/'kernel_addition.c').read_text();changes[name]=text
name='src/kernel/syscall.c';text=read(name)
text=one(text,'        case SYSCALL_RAISE:', '''        case SYSCALL_SIGNAL_JUMP:
        {
            uint32_t operation = (uint32_t)frame->rdi;
            result = process_signal_jump(frame, operation, frame->rsi, frame->rdx, frame->r10);
            if (result == 0 && operation == ALIX_SIGJUMP_RESTORE)
            { process_signal_syscall_return(frame, 0); return frame->rax; }
            break;
        }
        case SYSCALL_RAISE:''');changes[name]=text
name='user/lib/setjmp.c';text=read(name);text=one(text,'#include "setjmp.h"','#include "setjmp.h"\n#include "syscall_defs.h"');text=text.replace('int setjmp(jmp_buf env)', 'int setjmp(jmp_buf env __attribute__((unused)))').replace('void longjmp(jmp_buf env, int value)', 'void longjmp(jmp_buf env __attribute__((unused)), int value __attribute__((unused)))');text+=(HERE/'user_addition.c').read_text();changes[name]=text
name='user/lib/usyscall.h';text=read(name);text=one(text,'int sys_sigreturn(uintptr_t frame);','int sys_sigreturn(uintptr_t frame);\nint sys_signal_jump(uint32_t operation, alix_sigjmp_state_t *environment, size_t size, int argument);');changes[name]=text
name='user/lib/syscall.c';text=read(name);text+='\nint sys_signal_jump(uint32_t operation, alix_sigjmp_state_t *environment, size_t size, int argument)\n{ return (int)syscall4(SYSCALL_SIGNAL_JUMP, operation, (long)environment, (long)size, argument); }\n';changes[name]=text
name='ports/zen/signals/host_model.h';text=read(name);text=one(text,'    uint64_t signal_sequence;','    uint64_t signal_sequence;\n    uint64_t signal_jump_epoch;');changes[name]=text
for name,text in changes.items():
    path=STAGE/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
patch=[];manifest=[]
for name,text in sorted(changes.items()):
    before=read(name);patch.extend(difflib.unified_diff(before.splitlines(True),text.splitlines(True),fromfile='a/Repo/'+name,tofile='b/Repo/'+name))
    manifest.append({'path':name,'before':hashlib.sha256(before.encode()).hexdigest(),'after':hashlib.sha256(text.encode()).hexdigest()})
(HERE/'signal-jump.pending.patch').write_text(''.join(patch));(HERE/'pending.json').write_text(json.dumps({'applied':False,'files':manifest},indent=2)+'\n')
print('Staged',len(manifest),'signal-jump files; active source unchanged')
