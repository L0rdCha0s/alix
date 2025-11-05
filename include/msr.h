// msr.h
#pragma once
#include <stdint.h>

static inline uint64_t rdmsr(uint32_t msr){ uint32_t lo,hi; __asm__ volatile("rdmsr":"=a"(lo),"=d"(hi):"c"(msr)); return ((uint64_t)hi<<32)|lo; }
static inline void wrmsr(uint32_t msr, uint64_t v){ uint32_t lo=v, hi=v>>32; __asm__ volatile("wrmsr"::"c"(msr),"a"(lo),"d"(hi)); }
