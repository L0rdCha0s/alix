#ifndef TYPES_H
#define TYPES_H

#ifdef TTF_HOST_BUILD
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#else
typedef unsigned char      uint8_t;
typedef signed char        int8_t;
typedef unsigned short     uint16_t;
typedef signed short       int16_t;
typedef unsigned int       uint32_t;
typedef signed int         int32_t;
typedef unsigned long      uint64_t;
typedef signed long        int64_t;

typedef unsigned long      size_t;
typedef long               ssize_t;
typedef unsigned long      uintptr_t;
typedef signed long        intptr_t;

#ifndef __cplusplus
/* Match C++ bool and avoid include-order-dependent enum/_Bool ABI changes. */
#include <stdbool.h>
#endif

#ifndef NULL
#ifdef __cplusplus
#define NULL 0
#else
#define NULL ((void*)0)
#endif
#endif
#endif

typedef uint64_t paddr_t;
typedef uintptr_t vaddr_t;


#endif
