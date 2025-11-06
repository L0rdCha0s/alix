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
    __kernel_text_start = .;
    *(.text*)
    __kernel_text_end = .;
  }

  /* Merge rodata into data so all literals live in a plain RW segment.
     This avoids early-boot issues with accessing .rodata before any
     higher-half or relocation scheme exists. */
  .data ALIGN(0x1000) :
  {
    __kernel_data_start = .;
    *(.data*)
    *(.rodata*)
    __kernel_data_end = .;
  }

  . = 0x0000000000106000;

  .bss ALIGN(16) :
  {
    __bss_start = .;
    *(.bss*)
    *(COMMON)
    __bss_end = .;
  }
}
