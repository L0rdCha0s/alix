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

ENTRY(kernel_entry)

KERNEL_VMA_BASE = 0x0000000010000000;

SECTIONS
{
  /* The loader reserves the fixed AP real-mode mailbox/trampoline separately.
   * Bootstrap stack and page-table pages are allocated by firmware and passed
   * in bootinfo_t; neither is an implicitly free linker address anymore. */
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
  ASSERT(__kernel_vma_end <= __alix_user_pointer_base, "kernel image overlaps user VA contract")
}
