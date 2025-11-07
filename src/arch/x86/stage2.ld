ENTRY(start16)

STAGE2_LOAD_BASE = 0x0000000000009000;
KERNEL_VMA_BASE  = 0x0000000000100000;

SECTIONS
{
  . = STAGE2_LOAD_BASE;

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

  . = ALIGN(16);
  __kernel_lma_start = .;

  . = KERNEL_VMA_BASE;

  .text ALIGN(16) : AT(__kernel_lma_start)
  {
    __kernel_text_start = .;
    *(.text*)
    __kernel_text_end = .;
  }

  __kernel_text_lma = LOADADDR(.text);
  __kernel_text_size = SIZEOF(.text);
  __kernel_lma_after_text = LOADADDR(.text) + SIZEOF(.text);

  /* Merge rodata into data so all literals live in a plain RW segment. */
  . = ALIGN(0x1000);
  .data ALIGN(0x1000) : AT(__kernel_lma_after_text)
  {
    __kernel_data_start = .;
    *(.data*)
    *(.rodata*)
    __kernel_data_end = .;
  }
  __kernel_data_lma = LOADADDR(.data);
  __kernel_data_size = SIZEOF(.data);

  __kernel_vma_start = ADDR(.text);

  . = ALIGN(0x1000);

  .bss ALIGN(16) :
  {
    __bss_start = .;
    *(.bss*)
    *(COMMON)
    __bss_end = .;
  }
}
