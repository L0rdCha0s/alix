ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(0x5); /* R + X */
    data PT_LOAD FLAGS(0x6); /* R + W */
}

SECTIONS
{
    . = 0x0000000000400000;

    .text : ALIGN(16)
    {
        *(.text*)
    } :text

    .rodata : ALIGN(16)
    {
        *(.rodata*)
    } :text

    .data : ALIGN(16)
    {
        *(.data*)
    } :data

    .bss : ALIGN(16)
    {
        *(.bss*)
        *(COMMON)
    } :data
}
