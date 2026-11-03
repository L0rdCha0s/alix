#ifndef ALIX_ENDIAN_H
#define ALIX_ENDIAN_H

#include "types.h"

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#endif
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif
#ifndef __BYTE_ORDER
#define __BYTE_ORDER __BYTE_ORDER__
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif
#ifndef BYTE_ORDER
#define BYTE_ORDER __BYTE_ORDER__
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htole16(value) ((uint16_t)(value))
#define htole32(value) ((uint32_t)(value))
#define htole64(value) ((uint64_t)(value))
#define htobe16(value) __builtin_bswap16((uint16_t)(value))
#define htobe32(value) __builtin_bswap32((uint32_t)(value))
#define htobe64(value) __builtin_bswap64((uint64_t)(value))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htobe16(value) ((uint16_t)(value))
#define htobe32(value) ((uint32_t)(value))
#define htobe64(value) ((uint64_t)(value))
#define htole16(value) __builtin_bswap16((uint16_t)(value))
#define htole32(value) __builtin_bswap32((uint32_t)(value))
#define htole64(value) __builtin_bswap64((uint64_t)(value))
#else
#error Unsupported native byte order
#endif

#define le16toh(value) htole16(value)
#define le32toh(value) htole32(value)
#define le64toh(value) htole64(value)
#define be16toh(value) htobe16(value)
#define be32toh(value) htobe32(value)
#define be64toh(value) htobe64(value)

#endif
