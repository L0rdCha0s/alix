#include "process_internal.h"

/* x86-64 ELF variant-II static TLS. FS:0 is the thread pointer itself;
 * FS:8 records the static TLS block base for the future compiler resolver.
 * Compiler local-exec offsets address initialized/zeroed data below FS. */
#define USER_TLS_TCB_BYTES (2u * sizeof(uintptr_t))

bool process_set_user_tls_template(process_t *process, const uint8_t *image,
                                   size_t file_size, size_t memory_size,
                                   size_t alignment, uintptr_t image_address)
{
    if (!process || file_size > memory_size || (file_size && !image))
    {
        return false;
    }
    if (alignment == 0)
    {
        alignment = 1;
    }
    if ((alignment & (alignment - 1)) != 0)
    {
        return false;
    }
    /* Preserve the first byte's alignment skew from PT_TLS. Aligning only
     * memsz is incorrect when p_vaddr is not itself p_align-aligned. */
    size_t padding = (0u - memory_size - image_address) & (alignment - 1);
    size_t tp_alignment = alignment < 16 ? 16 : alignment;
    if (memory_size > SIZE_MAX - padding ||
        memory_size + padding > SIZE_MAX - USER_TLS_TCB_BYTES ||
        memory_size + padding + USER_TLS_TCB_BYTES > SIZE_MAX - tp_alignment ||
        memory_size + padding + USER_TLS_TCB_BYTES + tp_alignment >
            USER_ADDRESS_SPACE_LIMIT - USER_ADDRESS_SPACE_BASE)
    {
        return false;
    }
    uint8_t *copy = file_size ? malloc(file_size) : NULL;
    if (file_size && !copy)
    {
        return false;
    }
    if (file_size)
    {
        memcpy(copy, image, file_size);
    }
    /* Templates are installed by the loader before the process is runnable. */
    free(process->user_tls_image);
    process->user_tls_image = copy;
    process->user_tls_filesz = file_size;
    process->user_tls_memsz = memory_size;
    process->user_tls_align = tp_alignment;
    process->user_tls_offset = memory_size + padding;
    return true;
}

void process_clear_user_tls_template(process_t *process)
{
    free(process->user_tls_image);
    process->user_tls_image = NULL;
    process->user_tls_filesz = process->user_tls_memsz = 0;
    process->user_tls_align = process->user_tls_offset = 0;
}

bool process_allocate_user_tls(process_t *process, process_tls_allocation_t *out)
{
    if (!process || !out)
    {
        return false;
    }
    *out = (process_tls_allocation_t){0};
    if (process->user_tls_memsz == 0)
    {
        return true;
    }
    size_t alignment = process->user_tls_align;
    size_t offset = process->user_tls_offset;
    size_t requested = offset + alignment + USER_TLS_TCB_BYTES;
    if (requested > SIZE_MAX - (PAGE_SIZE_BYTES_LOCAL - 1))
    {
        return false;
    }
    size_t total = align_up_size(requested, PAGE_SIZE_BYTES_LOCAL);
    uint64_t flags = process_memory_lock(process);
    uintptr_t base = 0;
    void *host = NULL;
    if (!process_allocate_aux_user_segment_locked(process, total, &base, &host))
    {
        process_memory_unlock(process, flags);
        return false;
    }
    uintptr_t tp = (base + offset + alignment - 1) & ~(uintptr_t)(alignment - 1);
    uintptr_t block = tp - offset;
    memset(host, 0, total);
    if (process->user_tls_filesz)
    {
        memcpy((uint8_t *)host + (block - base), process->user_tls_image, process->user_tls_filesz);
    }
    uintptr_t *tcb = (uintptr_t *)((uint8_t *)host + (tp - base));
    tcb[0] = tp;
    tcb[1] = block;
    out->base = base;
    out->size = total;
    out->thread_pointer = tp;
    process_memory_unlock(process, flags);
    if (!process_complete_user_mapping(process))
    {
        (void)process_unmap_user_segment(process, base, total);
        *out = (process_tls_allocation_t){0};
        return false;
    }
    return true;
}
