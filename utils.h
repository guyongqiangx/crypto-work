#ifndef __UTILS__H
#include <stdlib.h>

/*
 * from: linux/arch/arm/kernel/setup.c
 */
static union { char c[4]; unsigned long l; } endian_test = { { 'l', '?', '?', 'b' } }; 

#define ENDIANNESS ((char)endian_test.l)
#define ENDIAN_LITTLE 'l'
#define ENDIAN_BIG    'b'

/*
 * from: /usr/include/x86_64-linux-gnu/bits/byteswap.h
 */
/* Swap bytes in 16 bit value.  */
#ifndef __bswap_constant_16
#define __bswap_constant_16(x) \
     ((unsigned short int)     \
	  ((((x) >> 8) & 0xff)     \
	 | (((x) & 0xff) << 8)))
#endif

/* Swap bytes in 32 bit value.  */
#ifndef __bswap_constant_32
#define __bswap_constant_32(x)     \
     ((((x) & 0xff000000) >> 24)   \
	 | (((x) & 0x00ff0000) >>  8) \
	 | (((x) & 0x0000ff00) <<  8) \
	 | (((x) & 0x000000ff) << 24))
#endif

/* Swap bytes in 64 bit value.  */
#ifndef __bswap_constant_64
#define __bswap_constant_64(x)                \
     ((((x) & 0xff00000000000000ull) >> 56)  \
     | (((x) & 0x00ff000000000000ull) >> 40) \
     | (((x) & 0x0000ff0000000000ull) >> 24) \
     | (((x) & 0x000000ff00000000ull) >>  8) \
     | (((x) & 0x00000000ff000000ull) <<  8) \
     | (((x) & 0x0000000000ff0000ull) << 24) \
     | (((x) & 0x000000000000ff00ull) << 40) \
     | (((x) & 0x00000000000000ffull) << 56))
#endif

/*
 * host to big endian
 */
#ifndef htobe16
#define htobe16(x) \
	((ENDIANNESS == ENDIAN_LITTLE) ? __bswap_constant_16(x) : (x))
#endif

#ifndef htobe32
#define htobe32(x) \
	((ENDIANNESS == ENDIAN_LITTLE) ? __bswap_constant_32(x) : (x))
#endif

#ifndef htobe64
#define htobe64(x) \
	((ENDIANNESS == ENDIAN_LITTLE) ? __bswap_constant_64(x) : (x))
#endif

/*
 * unsigned short int htobe16(unsigned short int x)
 * {
 * 	return (ENDIANNESS == ENDIAN_LITTLE) ? __bswap_constant_16(x) : (x);
 * }
 *
 * unsigned int htobe32(unsigned int x)
 * {
 * 	return (ENDIANNESS == ENDIAN_LITTLE) ? __bswap_constant_32(x) : (x);
 * }
 *
 * unsigned long long htobe64(unsigned long long x)
 * {
 * 	return (ENDIANNESS == ENDIAN_LITTLE) ? __bswap_constant_64(x) : (x);
 * }
 */

int print_buffer(const void *buf, size_t len);

#endif
