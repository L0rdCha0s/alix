ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(0x5); /* R + X */
    data PT_LOAD FLAGS(0x6); /* R + W */
    tls PT_TLS FLAGS(0x4); /* Per-thread template; instantiated by the loader. */
}

SECTIONS
{
    . = 0x0000000100000000;

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

    . = ALIGN(0x1000);

    .data : ALIGN(16)
    {
        *(.data*)
        *(.ldata*)
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

    .bss : ALIGN(16)
    {
        __bss_start = .;
        *(.bss*)
        *(.lbss*)
        *(COMMON)
        __bss_end = .;
    } :data
}
