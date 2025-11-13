#ifndef TYPES_H
#define TYPES_H

#ifdef TTF_HOST_BUILD
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
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

typedef enum { false = 0, true = 1 } bool;

#define NULL ((void*)0)
#endif


#endif
