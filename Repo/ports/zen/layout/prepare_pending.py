#!/usr/bin/env python3
"""Prepare reviewable layout edits without modifying the active Alix tree."""
from pathlib import Path
import difflib
import hashlib
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
OVERLAY=HERE/"pending"

CONTRACT='''/* Native user VA contract; checked against include/memory_layout.h. */
__alix_user_pointer_base = 0x0000000100000000;
__alix_user_pointer_limit = 0x00003FFFFFFFFFFF;
__alix_user_stack_top = 0x0000000140000000;
__alix_user_stack_size = 0x00800000;
__alix_user_stack_guard_size = 0x1000;
__alix_user_image_end = __alix_user_stack_top - __alix_user_stack_size - __alix_user_stack_guard_size;
__alix_user_heap_base = 0x0000000180000000;
__alix_user_heap_size = 0x0000000400000000;
__alix_user_vm_heap_gap = 0x01000000;
__alix_user_thread_pool_size = 0x0000000200000000;
__alix_user_stub_code_base = __alix_user_pointer_limit + 1 - 0x2000;
__alix_user_vm_start = __alix_user_heap_base + __alix_user_heap_size + __alix_user_vm_heap_gap;
__alix_user_vm_end = __alix_user_stub_code_base - __alix_user_thread_pool_size;
ASSERT(__alix_user_pointer_base >= 0x100000000, "user range overlaps low kernel identity map")
ASSERT(__alix_user_pointer_limit < 0x800000000000, "user range exceeds SpiderMonkey 47-bit pointers")
ASSERT(__alix_user_pointer_base < __alix_user_image_end, "empty user ELF arena")
ASSERT(__alix_user_stack_top <= __alix_user_heap_base, "user stack overlaps heap")
ASSERT(__alix_user_vm_start < __alix_user_vm_end, "user heap overlaps VM or auxiliary pool")
ASSERT((__alix_user_image_end & 0xFFF) == 0, "user image boundary is not page aligned")
ASSERT((__alix_user_vm_start & 0xFFF) == 0 && (__alix_user_vm_end & 0xFFF) == 0, "VM boundary is not page aligned")

'''

def replace(text,old,new):
    if text.count(old)!=1: raise RuntimeError("active source no longer matches expected edit: "+old[:100])
    return text.replace(old,new,1)

def main():
    originals={}
    changed={}
    def read(name):
        originals[name]=(ROOT/name).read_text()
        return originals[name]
    name="include/memory_layout.h";text=read(name)
    text=replace(text,"#define USER_DEFAULT_POINTER_LIMIT 0x00000001FFFFFFFFULL","#define USER_DEFAULT_POINTER_LIMIT 0x00003FFFFFFFFFFFULL")
    text=replace(text,"#define USER_DEFAULT_STACK_TOP_OFFSET 0x01000000ULL","#define USER_DEFAULT_STACK_TOP_OFFSET 0x40000000ULL")
    text=replace(text,"#define USER_DEFAULT_STACK_SIZE   (1024ULL * 1024ULL)","#define USER_DEFAULT_STACK_SIZE   (8ULL * 1024ULL * 1024ULL)")
    text=replace(text,"#define USER_DEFAULT_HEAP_BASE_OFFSET 0x02000000ULL","#define USER_DEFAULT_HEAP_BASE_OFFSET 0x80000000ULL")
    text=replace(text,"#define USER_DEFAULT_HEAP_SIZE    (1024ULL * 1024ULL * 1024ULL)",'''#define USER_DEFAULT_HEAP_SIZE    (16ULL * 1024ULL * 1024ULL * 1024ULL)
#define USER_DEFAULT_STACK_GUARD_SIZE 4096ULL
#define USER_DEFAULT_VM_HEAP_GAP  (16ULL * 1024ULL * 1024ULL)
#define USER_DEFAULT_THREAD_POOL_SIZE (8ULL * 1024ULL * 1024ULL * 1024ULL)
#define USER_DEFAULT_IMAGE_END (USER_DEFAULT_POINTER_BASE + USER_DEFAULT_STACK_TOP_OFFSET - USER_DEFAULT_STACK_SIZE - USER_DEFAULT_STACK_GUARD_SIZE)''')
    changed[name]=text

    for name in ("user/lib/link.ld","src/arch/x86/uefi.ld"):
        text=read(name)
        text=CONTRACT+text
        if name.startswith("user/"):
            text=replace(text,"    . = 0x0000000100000000;","    . = __alix_user_pointer_base;")
            text=replace(text,"        __bss_end = .;\n    } :data\n}",'''        __bss_end = .;
    } :data
    __alix_user_image_loaded_end = ALIGN(., 0x1000);
    ASSERT(__alix_user_image_loaded_end <= __alix_user_image_end, "user ELF image overlaps reserved main stack guard")
}''')
        else:
            text=replace(text,"  __kernel_vma_end   = ALIGN(__bss_end, 0x1000);","  __kernel_vma_end   = ALIGN(__bss_end, 0x1000);\n  ASSERT(__kernel_vma_end <= __alix_user_pointer_base, \"kernel image overlaps user VA contract\")")
        changed[name]=text

    name="src/kernel/process/process_vm.c";text=read(name)
    text=replace(text,"#define VM_THREAD_POOL_BYTES (256ULL * 1024ULL * 1024ULL)","#define VM_THREAD_POOL_BYTES USER_DEFAULT_THREAD_POOL_SIZE")
    text=replace(text,"#define VM_HEAP_GAP_BYTES (16ULL * 1024ULL * 1024ULL)","#define VM_HEAP_GAP_BYTES USER_DEFAULT_VM_HEAP_GAP")
    text=replace(text,"        (address && !vm_range_valid(address, rounded)) ||\n        ((flags & fixed) && !address)","        ((flags & fixed) && !vm_range_valid(address, rounded)) ||\n        ((flags & fixed) && !address)")
    text=replace(text,"    protection = vm_protection_normalize(protection);\n    uint64_t irq_flags = vm_lock_ready(process);",'''    /* Nonfixed addresses are advisory. Ignore impossible hints and round
     * usable hints down to a page; fixed mappings remain exact and strict. */
    if (!(flags & fixed) && address)
    {
        address = align_down_uintptr(address, VM_PAGE_SIZE);
        if (!vm_range_valid(address, rounded)) address = 0;
    }
    protection = vm_protection_normalize(protection);
    uint64_t irq_flags = vm_lock_ready(process);''')
    changed[name]=text

    name="src/kernel/process/process_memory.c";text=read(name)
    text=replace(text,"        uintptr_t stack_bottom = process_stack_bottom(process);\n        if ((process->user_heap_limit",'''        uintptr_t stack_bottom = process_stack_bottom(process);
        uintptr_t guarded_stack_bottom = stack_bottom >= USER_DEFAULT_STACK_GUARD_SIZE
                                           ? stack_bottom - USER_DEFAULT_STACK_GUARD_SIZE : stack_bottom;
        if ((process->user_heap_limit''')
    text=replace(text,"                                    stack_bottom, process->user_stack_top)) ||","                                    guarded_stack_bottom, process->user_stack_top)) ||")
    changed[name]=text

    name="src/kernel/process/process_api.c";text=read(name)
    text=replace(text,"        info->guard_size = main_thread ? 0 : PAGE_SIZE_BYTES_LOCAL;","        info->guard_size = main_thread ? USER_DEFAULT_STACK_GUARD_SIZE : PAGE_SIZE_BYTES_LOCAL;")
    changed[name]=text

    name="src/kernel/elf.c";text=read(name)
    text=replace(text,"    const elf64_ehdr_t *ehdr = (const elf64_ehdr_t *)image;\n    if (ehdr->magic",'''    if (g_mem_layout.user_stack_size > g_mem_layout.user_stack_top ||
        g_mem_layout.user_stack_top - g_mem_layout.user_stack_size < USER_DEFAULT_STACK_GUARD_SIZE)
        return false;
    uintptr_t image_end = g_mem_layout.user_stack_top - g_mem_layout.user_stack_size - USER_DEFAULT_STACK_GUARD_SIZE;
    if (image_end <= g_mem_layout.user_pointer_base) return false;

    const elf64_ehdr_t *ehdr = (const elf64_ehdr_t *)image;
    if (ehdr->magic''')
    text=replace(text,"        if (seg_end == 0 || seg_end - 1 > g_mem_layout.user_pointer_limit ||","        if (seg_end == 0 || seg_end > image_end || seg_end - 1 > g_mem_layout.user_pointer_limit ||")
    changed[name]=text

    name="tests/elf_validation_host_test.c";text=read(name)
    text=replace(text,"    .user_pointer_limit = USER_DEFAULT_POINTER_LIMIT,","    .user_pointer_limit = USER_DEFAULT_POINTER_LIMIT,\n    .user_stack_top = USER_DEFAULT_POINTER_BASE + USER_DEFAULT_STACK_TOP_OFFSET,\n    .user_stack_size = USER_DEFAULT_STACK_SIZE,")
    text=replace(text,"    image.phdr.vaddr = USER_DEFAULT_POINTER_LIMIT - 0xFFF;","    image.phdr.vaddr = USER_DEFAULT_IMAGE_END - 0x1000;")
    text=replace(text,'                       "segment may end one byte beyond inclusive limit");','''                       "segment may end exactly at the exclusive image limit");
    image.phdr.memsz += 1;
    failures += expect(!elf_validate_image((const uint8_t *)&image, sizeof(image), NULL),
                       "segment cannot enter the main-stack guard");
    image = valid_image();
    image.phdr.vaddr = USER_DEFAULT_POINTER_LIMIT - 0xFFF;
    image.ehdr.entry = image.phdr.vaddr;
    failures += expect(!elf_validate_image((const uint8_t *)&image, sizeof(image), NULL),
                       "ELF cannot occupy high auxiliary or stub addresses");
    image = valid_image();
    image.phdr.memsz = 32ULL * 1024 * 1024;
    failures += expect(elf_validate_image((const uint8_t *)&image, sizeof(image), NULL),
                       "large native image exceeds the old 15MiB ceiling");''')
    changed[name]=text

    for name in ("tests/native_vm_contract_test.py","tests/auxiliary_pool_test.py","tests/vm_reclamation_test.py"):
        text=read(name)
        count=text.count("    program = r'''")
        if count!=(2 if name.endswith("native_vm_contract_test.py") else 1):
            raise RuntimeError("unexpected host harness structure: "+name)
        text=text.replace("    program = r'''", """    layout_defines = chr(10).join(line for line in (ROOT / "include/memory_layout.h").read_text().splitlines()
                                if line.startswith("#define USER_DEFAULT_"))
    program = layout_defines + r'''""")
        if name.endswith("native_vm_contract_test.py"):
            text=replace(text,"#define USER_HEAP_BASE 0x102000000UL\n#define USER_HEAP_SIZE 0x40000000UL\n#define USER_STUB_CODE_BASE 0x1FFFFE000UL",'''#define USER_HEAP_BASE (USER_DEFAULT_POINTER_BASE+USER_DEFAULT_HEAP_BASE_OFFSET)
#define USER_HEAP_SIZE USER_DEFAULT_HEAP_SIZE
#define USER_STUB_CODE_BASE (USER_DEFAULT_POINTER_LIMIT+1ULL-8192ULL)''')
            text=replace(text,"    CHECK(process_vm_map(&process,0x100000000,4096,3,anonymous_flags)==-22);",'''    CHECK(process_vm_map(&process,0x100000000,4096,3,anonymous_flags|16)==-22);''')
            text=replace(text,"    CHECK(metadata_live==0 && physical_live==0);",'''    CHECK(metadata_live==0 && physical_live==0);
    /* Advisory hints must never make a legal nonfixed reservation fail. */
    const uintptr_t hints[]={1,USER_HEAP_BASE,USER_STUB_CODE_BASE,UINTPTR_MAX};
    for(unsigned i=0;i<sizeof(hints)/sizeof(hints[0]);++i) {
        CHECK(process_vm_map(&process,hints[i],4096,0,anonymous_flags)==(int64_t)vm_arena_start());
        clear_process();
    }
    uintptr_t hint=vm_arena_start()+17*4096;
    CHECK(process_vm_map(&process,hint+123,4096,0,anonymous_flags)==(int64_t)hint);
    CHECK(process_vm_map(&process,hint,4096,0,anonymous_flags)==(int64_t)vm_arena_start());
    CHECK(process_vm_map(&process,hint+1,4096,0,anonymous_flags|16)==-22);
    CHECK(process_vm_map(&process,hint+1,4096,0,anonymous_flags|0x100000)==-22);
    clear_process();
    /* Real address scale, no 12GiB backing or leaf preparation. */
    uintptr_t high=(32ULL<<40)-(6ULL<<30);
    size_t huge=12ULL<<30;
    CHECK(process_vm_map(&process,high,huge,0,anonymous_flags)==(int64_t)high);
    CHECK(!process.vm_areas->pages && physical_live==0 && leaf_count==0);
    CHECK(process_vm_protect(&process,high,4096,3)==0);
    CHECK(process_vm_protect(&process,high+huge-4096,4096,3)==0);
    CHECK(physical_live==2 && resolve(high,true) && resolve(high+huge-4096,true));
    CHECK(process_vm_unmap(&process,high,huge)==0 && physical_live==0 && metadata_live==0);
    clear_process();''')
        elif name.endswith("auxiliary_pool_test.py"):
            text=replace(text,"#define POOL_BASE 0x180000000UL","#define POOL_BASE (USER_DEFAULT_POINTER_LIMIT+1ULL-8192ULL-USER_DEFAULT_THREAD_POOL_SIZE)")
        else:
            text=replace(text,"#define USER_ADDRESS_SPACE_BASE 0x100000000UL\n#define USER_ADDRESS_SPACE_LIMIT 0x1FFFFFFFFUL","#define USER_ADDRESS_SPACE_BASE USER_DEFAULT_POINTER_BASE\n#define USER_ADDRESS_SPACE_LIMIT USER_DEFAULT_POINTER_LIMIT")
        changed[name]=text

    name="tests/cpp_runtime_qemu_test.py";text=read(name)
    text=replace(text,"                   forbidden_markers=()):","                   forbidden_markers=(), download_timeout_seconds=10):")
    text=replace(text,'harness.wait_for(runner, "test download", lambda log: command_complete(log, offset), 10)',
                 'harness.wait_for(runner, "test download", lambda log: command_complete(log, offset), download_timeout_seconds)')
    changed[name]=text

    name="docs/kernel/memory.md";text=read(name)
    old='''The initial VM arena starts 16 MiB above the existing sbrk heap limit and ends
256 MiB below the top-of-user-space stubs. That leaves a separate descending
thread/TLS pool, while the existing ELF origin, main stack and heap remain at
their current addresses. Legacy segment allocation rejects this arena even
where no VMA currently exists. The current 4–8 GiB user window provides roughly
2.7 GiB of native VM space; larger browser reservations will require the planned
address-layout expansion.'''
    new='''The native user address window is 4 GiB through 64 TiB minus one, below
SpiderMonkey's 47-bit pointer ceiling. Static ELF images start at 4 GiB and must
end before the guard beneath the 8 MiB main stack, whose top is 5 GiB. The brk
heap reserves 16 GiB starting at 6 GiB; its initial two-level directory costs
64 KiB, and physical pages are committed as brk grows. Main-stack backing
metadata costs 16 KiB and its pages are committed on stack growth.

The anonymous VM arena starts 16 MiB above the heap limit and ends beneath an
8 GiB descending thread/TLS pool. Two stub pages remain at the top of the user
window. Legacy segment allocation rejects the whole anonymous arena, including
uncommitted holes. Nonfixed mmap addresses are advisory: usable hints are
page-rounded, while occupied/out-of-range hints fall back to free space. Fixed
and NOREPLACE addresses retain strict bounds/alignment checks.

`include/memory_layout.h`, `user/lib/link.ld` and `src/arch/x86/uefi.ld` expose
the same checked contract. Both linker scripts publish absolute layout symbols
and reject overlap; ELF validation independently enforces the image ceiling and
main-stack guard. `make user-layout-contract-test` compares C values with both
linked symbol sets and proves oversized images fail their linker assertions.
The separate `ports/zen/layout/user_layout_test.c` fixture contains a real
32 MiB constant payload and reserves 12 GiB across PML4 entries 63/64, committing
only eight pages. It checks high syscall copies, eight-CPU protection/TLS and
high generated code; compilation alone is not guest acceptance.'''
    text=replace(text,old,new)
    changed[name]=text

    name="tests/user_layout_contract_test.py"
    if (ROOT/name).exists(): raise RuntimeError("preserving existing layout contract test")
    originals[name]=""
    changed[name]='''#!/usr/bin/env python3
"""Compare active C and both ELF linker layout contracts and overlap guards."""
from pathlib import Path
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/"ports/zen/layout"))
import check_pending as contract

contract.PENDING=ROOT
with tempfile.TemporaryDirectory(prefix="alix-layout-contract-") as temporary:
    contract.linker_contract(Path(temporary))
'''
    name="Makefile";text=read(name)
    if "user-layout-contract-test:" in text: raise RuntimeError("preserving existing layout target")
    text+='''
# C constants and both static ELF scripts must describe one address contract.
.PHONY: user-layout-contract-test
user-layout-contract-test:
\tpython3 tests/user_layout_contract_test.py
'''
    changed[name]=text

    records=[];patch=[]
    for name,text in changed.items():
        destination=OVERLAY/name;destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_text(text)
        records.append({"path":name,"base_sha256":hashlib.sha256(originals[name].encode()).hexdigest() if (ROOT/name).exists() else None,
                        "pending_sha256":hashlib.sha256(text.encode()).hexdigest()})
        patch.extend(difflib.unified_diff(originals[name].splitlines(True),text.splitlines(True),
                                         fromfile="a/Repo/"+name if (ROOT/name).exists() else "/dev/null",tofile="b/Repo/"+name))
    (HERE/"memory-layout.pending.patch").write_text("".join(patch))
    (HERE/"pending.json").write_text(json.dumps({"applied":False,"files":records},indent=2)+"\n")
    print(f"Prepared {len(changed)} pending files; active sources unchanged")

if __name__=="__main__":main()
