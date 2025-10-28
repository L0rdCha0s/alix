ENTRY(start16)

SECTIONS
{
  . = 0x0000000000010000;

  .start16 :
  {
    KEEP(*(.start16))
  }

  .pmode ALIGN(16) :
  {
    *(.pmode)
  }

  .longmode ALIGN(16) :
  {
    *(.longmode)
  }

  .text ALIGN(16) :
  {
    *(.text*)
  }

  .rodata ALIGN(16) :
  {
    *(.rodata*)
  }

  .data ALIGN(16) :
  {
    *(.data*)
  }

  .bss ALIGN(16) :
  {
    __bss_start = .;
    *(.bss*)
    *(COMMON)
    __bss_end = .;
  }
}
