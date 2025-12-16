ENTRY(kernel_entry)

KERNEL_VMA_BASE = 0x0000000000100000;

SECTIONS
{
  /* SMP AP trampoline lives in low physical memory at 0x8000 */
  .ap_trampoline 0x0000000000008000 :
  {
    KEEP(*(.ap_trampoline))
  }

  /* Kernel proper starts here */
  . = KERNEL_VMA_BASE;

  .text ALIGN(16) :
  {
    __kernel_text_start = .;
    *(.text*)
    __kernel_text_end = .;
  }

  /* Align to page before data */
  . = ALIGN(0x1000);

  .data ALIGN(0x1000) :
  {
    __kernel_data_start = .;
    *(.data*)
    *(.rodata*)
    __kernel_data_end = .;
  }

  /* Page-align start of BSS, keep 16-byte alignment inside if needed */
  . = ALIGN(0x1000);
  __bss_start = .;
  .bss ALIGN(16) :
  {
    *(.bss*)
    *(COMMON)
  }
  __bss_end = .;

  __kernel_vma_start = KERNEL_VMA_BASE;
  /* Page-aligned end-of-kernel for heap / page allocator */
  __kernel_vma_end   = ALIGN(__bss_end, 0x1000);
}
