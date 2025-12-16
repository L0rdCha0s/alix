#include "user_memory.h"

#include "pmm.h"
#include "serial.h"

#define USER_MEMORY_PAGE_SIZE 4096ULL

void user_memory_init(void)
{
    if (!pmm_is_ready())
    {
        serial_printf("%s", "[umem] init skipped (pmm not ready)\n");
        return;
    }
    serial_printf("[umem] ready avail=0x%016llX\n",
                  (unsigned long long)((uint64_t)pmm_available_bytes()));
}

paddr_t user_memory_alloc(size_t bytes)
{
    if (bytes == 0 || !pmm_is_ready())
    {
        return 0;
    }
    paddr_t base = 0;
    if (!pmm_alloc_range(bytes, USER_MEMORY_PAGE_SIZE, PMM_ALLOC_ANY, &base))
    {
        serial_printf("[umem] alloc failed bytes=0x%016llX avail=0x%016llX\n",
                      (unsigned long long)bytes,
                      (unsigned long long)((uint64_t)pmm_available_bytes()));
        return 0;
    }
    return base;
}

void user_memory_free(paddr_t addr, size_t bytes)
{
    if (!pmm_is_ready() || addr == 0 || bytes == 0)
    {
        return;
    }
    pmm_free_range(addr, bytes);
}

size_t user_memory_available(void)
{
    return pmm_available_bytes();
}

bool user_memory_alloc_page(paddr_t *phys_out)
{
    if (!phys_out)
    {
        return false;
    }
    if (!pmm_is_ready())
    {
        return false;
    }
    return pmm_alloc_page(PMM_ALLOC_ANY, phys_out);
}

void user_memory_free_page(paddr_t phys)
{
    if (!pmm_is_ready() || phys == 0)
    {
        return;
    }
    pmm_free_page(phys);
}
