ENTRY(kernel_entry)

KERNEL_VMA_BASE = 0x0000000000100000;

SECTIONS
{
  . = KERNEL_VMA_BASE;

  .text ALIGN(16) :
  {
    __kernel_text_start = .;
    *(.text*)
    __kernel_text_end = .;
  }

  . = ALIGN(0x1000);

  .data ALIGN(0x1000) :
  {
    __kernel_data_start = .;
    *(.data*)
    *(.rodata*)
    __kernel_data_end = .;
  }

  . = ALIGN(16);
  __bss_start = .;
  .bss ALIGN(16) :
  {
    *(.bss*)
    *(COMMON)
  }
  __bss_end = .;

  __kernel_vma_start = KERNEL_VMA_BASE;
  __kernel_vma_end = __bss_end;
}
