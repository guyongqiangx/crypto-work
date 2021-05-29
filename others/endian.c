#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

#define DUMP_LINE_SIZE 16
int print_buffer(const void *buf, uint32_t len)
{
	uint32_t i = 0;
	for (i=0; i<len; i++)
	{
		if (i%DUMP_LINE_SIZE == 0)
			printf("%04X:", i);

		printf(" %02x", ((uint8_t *)buf)[i]);

		if (i%DUMP_LINE_SIZE == (DUMP_LINE_SIZE-1))
			printf("\n");
	}

    if (i%DUMP_LINE_SIZE != (DUMP_LINE_SIZE-1))
	    printf("\n");

	return 0;
}

/*
 * # linux/arch/arm/kernel/setup.c
 * static union { char c[4]; unsigned long l; } endian_test __initdata = { { 'l', '?', '?', 'b' } }; 
 * #define ENDIANNESS ((char)endian_test.l)
 */

static union {
	char c[4];
	unsigned long l;
} endian_test = {
	{ 'l', '?', '?', 'b' }
}; 

/* host to network --VS.-- network to host
 *  htons,  ntohs: shot int
 *  htonl,  ntohl: long int
 * htonll, ntohll: long long int
 */

/*
 * uint64_t htonll(uint64_t val)
 * {
 *     return (((uint64_t) htonl(val)) << 32) + htonl(val >> 32);
 * }
 *
 * uint64_t ntohll(uint64_t val)
 * {
 *     return (((uint64_t) ntohl(val)) << 32) + ntohl(val >> 32);
 * }
 */
#define ENDIANNESS ((char)endian_test.l)

int main(void)
{
	union endian {
		int a;
		char b;
	}ed;

	ed.a = 1;

	printf("sizeof(ed)=%lu\n", sizeof(ed));
	print_buffer(&ed, sizeof(ed));

	if (ed.b == 1)
	{
		printf("little endian\n");
	}
	else /* (ed.b == 0) */
	{
		printf("big endian\n");
	}

	/* linux way */
	if (ENDIANNESS == 'l')
		printf("little endian...\n");
	else
		printf("big endian...\n");
	
	return 0;
}

