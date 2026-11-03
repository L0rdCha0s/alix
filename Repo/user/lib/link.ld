/* Native user VA contract; checked against include/memory_layout.h. */
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

ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(0x5); /* R + X */
    data PT_LOAD FLAGS(0x6); /* R + W */
    tls PT_TLS FLAGS(0x4); /* Per-thread template; instantiated by the loader. */
}

/* Kernel bootstrap stack/page tables are loader allocated below 4 GiB.
 * The native user virtual-address contract below remains unchanged. */
SECTIONS
{
    . = __alix_user_pointer_base;

    .text : ALIGN(16)
    {
        *(.text*)
        *(.ltext*)
    } :text

    .rodata : ALIGN(16)
    {
        *(.rodata*)
        *(.lrodata*)
        *(.eh_frame*)
        *(.gcc_except_table*)
    } :text

    /* Keep optional executable build notes in the existing text arena. */
    .note.gnu.build-id : ALIGN(4)
    {
        KEEP(*(.note.gnu.build-id))
    } :text

    /* Optional standard export metadata; executables remain fixed ET_EXEC. */
    .dynsym : ALIGN(8) { *(.dynsym) } :text
    .dynstr : ALIGN(1) { *(.dynstr) } :text
    .hash : ALIGN(8) { *(.hash) } :text
    .gnu.hash : ALIGN(8) { *(.gnu.hash) } :text
    __alix_user_text_end = .;

    . = ALIGN(0x1000);
    __alix_user_data_start = .;

    .data : ALIGN(16)
    {
        *(.data*)
        *(.ldata*)
    } :data

    .got : ALIGN(8) { *(.got) *(.got.plt) } :data
    .dynamic : ALIGN(8)
    {
        __alix_dynamic_start = .;
        *(.dynamic)
        __alix_dynamic_end = .;
    } :data

    .preinit_array : ALIGN(8)
    {
        __preinit_array_start = .;
        KEEP(*(.preinit_array.alix_runtime))
        KEEP(*(.preinit_array))
        __preinit_array_end = .;
    } :data

    .init_array : ALIGN(8)
    {
        __init_array_start = .;
        /* Bare-metal GCC emits .ctors.N, using inverted priority numbers. */
        KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
        KEEP(*(.init_array))
        KEEP(*(EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o) .ctors))
        __init_array_end = .;
    } :data

    .fini_array : ALIGN(8)
    {
        __fini_array_start = .;
        KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
        KEEP(*(.fini_array))
        KEEP(*(EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o) .dtors))
        __fini_array_end = .;
    } :data

    .tdata : ALIGN(16)
    {
        *(.tdata .tdata.* .gnu.linkonce.td.*)
    } :data :tls

    .tbss : ALIGN(16)
    {
        *(.tbss .tbss.* .gnu.linkonce.tb.*)
        *(.tcommon)
    } :data :tls
    __alix_static_tls_start = SIZEOF(.tdata) ? ADDR(.tdata) : ADDR(.tbss);
    __alix_static_tls_end = SIZEOF(.tbss) ? ADDR(.tbss) + SIZEOF(.tbss) : ADDR(.tdata) + SIZEOF(.tdata);
    __alix_static_tls_bytes = __alix_static_tls_end - __alix_static_tls_start;

    .bss : ALIGN(16)
    {
        __bss_start = .;
        *(.bss*)
        *(.lbss*)
        *(COMMON)
        __bss_end = .;
    } :data
    __alix_user_image_loaded_end = ALIGN(., 0x1000);
    ASSERT(__alix_user_image_loaded_end <= __alix_user_image_end, "user ELF image overlaps reserved main stack guard")
}
