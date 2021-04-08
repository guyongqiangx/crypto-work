#include <stdio.h>
#include <string.h>

#include "md5.h"

#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...)
#endif

#define MD5_BLOCK_SIZE		64	/* 512 bits = 64 bytes */
#define MD5_LEN_SIZE	 	 8	/*  64 bits =  8 bytes */
#define MD5_LEN_OFFSET      (MD5_BLOCK_SIZE - MD5_LEN_SIZE)
#define MD5_DIGEST_SIZE     16  /* 128 bits = 16 bytes */

#define MD5_PADDING_PATTERN 	0x80
#define MD5_ROUND_NUM			64

#define HASH_BLOCK_SIZE		MD5_BLOCK_SIZE
#define HASH_LEN_SIZE		MD5_LEN_SIZE
#define HASH_LEN_OFFSET		MD5_LEN_OFFSET
#define HASH_DIGEST_SIZE	MD5_DIGEST_SIZE

#define HASH_PADDING_PATTERN	MD5_PADDING_PATTERN
#define HASH_ROUND_NUM			MD5_ROUND_NUM

typedef uint32_t (*md5_func)(uint32_t x, uint32_t y, uint32_t z);

/* SHA1 Constants */
static uint32_t T[64] = 
{
    /* Round 1 */
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 

    /* Round 2 */
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 

    /* Round 3 */
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 

    /* Round 4 */
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391, 
};

/* ROTate Left (circular left shift) */
static uint32_t ROTL(uint32_t x, uint8_t shift)
{
	return (x << shift) | (x >> (32 - shift));
}

#if 0
/* ROTate Right (cirular right shift) */
static uint32_t ROTR(uint32_t x, uint8_t shift)
{
	return (x >> shift) | (x << (32 - shift));
}

/* Right SHift */
static uint32_t SHR(uint32_t x, uint8_t shift)
{
	return (x >> shift);
}
#endif

static uint32_t F(uint32_t x, uint32_t y, uint32_t z)
{
	//DBG("F(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
	return (x & y) | ((~x) & z);
}

static uint32_t G(uint32_t x, uint32_t y, uint32_t z)
{
	//DBG("G(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
	return (x & z) | (y & (~z));
}

static uint32_t H(uint32_t x, uint32_t y, uint32_t z)
{
	//DBG("H(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
	return x ^ y ^ z;
}

static uint32_t I(uint32_t x, uint32_t y, uint32_t z)
{
	//DBG("I(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
	return y ^ (x | (~z));;
}


/* SHA1 Functions */
static md5_func g[4] =
{
	F, G, H, I
};

static uint64_t swap64(uint64_t a)
{
  return ((a & 0x00000000000000FFULL) << 56) |
         ((a & 0x000000000000FF00ULL) << 40) |
         ((a & 0x0000000000FF0000ULL) << 24) |
         ((a & 0x00000000FF000000ULL) <<  8) |
         ((a & 0x000000FF00000000ULL) >>  8) |
         ((a & 0x0000FF0000000000ULL) >> 24) |
         ((a & 0x00FF000000000000ULL) >> 40) |
         ((a & 0xFF00000000000000ULL) >> 56);
}

static uint32_t swap32(uint32_t a)
{
  return ((a & 0x000000FF) << 24) |
         ((a & 0x0000FF00) << 8) |
         ((a & 0x00FF0000) >> 8) |
         ((a & 0xFF000000) >> 24);
}

#define DUMP_LINE_SIZE 16
int print_buffer(const void *buf, uint32_t len)
{
	uint32_t i;
	for (i=0; i<len; i++)
	{
		if (i%DUMP_LINE_SIZE == 0)
			printf("%04X:", i);

		printf(" %02x", ((uint8_t *)buf)[i]);

		if (i%DUMP_LINE_SIZE == (DUMP_LINE_SIZE-1))
			printf("\n");
	}
	printf("\n");

	return 0;
}

/*
 * "abc" -->   0x61,     0x62,     0x63
 *   Origin: 0b0110 0001 0110 0010 0110 0011
 *  Padding: 0b0110 0001 0110 0010 0110 0011 1000 0000 .... 0000 0000  0000 0000 .... 0001 1000
 *                                          (|<-------------------->|)(|<------- 0x18 ------->|)
 *   Format: "abc" + 1 + 0 x 423 + 0x18
 */

struct md5_context {
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;

	uint64_t processed_bits;

	uint32_t rest; /* rest size in last block */
	uint8_t last_block[HASH_BLOCK_SIZE];

};

static struct md5_context *get_md5_context(void)
{
	static struct md5_context _md5;

	return &_md5;
}

int md5_init(void)
{
	struct md5_context *context;

	context = get_md5_context();

	memset(context, 0, sizeof(struct md5_context));
	context->a = 0x67452301; /* little endian */
	context->b = 0xEFCDAB89;
	context->c = 0x98BADCFE;
	context->d = 0x10325476;

	context->processed_bits = 0;
	context->rest = 0;

	return 0;
}

#if 0
static uint32_t prepare_schedule_word(const void *block, uint32_t *w)
{
	uint32_t t;
	for (t=0; t<HASH_ROUND_NUM; t++)
	{
		if (t<=15) /*  0 <= t <= 15 */
			w[t] = swap32(WORD(block, t));
		else	   /* 16 <= t <= 79 */
			w[t] = ROTL(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
	}

	return 0;
}
#endif

#if 0
#define MD5_OP(a,b,c,d,k,s,i) \
    a = b + ((a + (g[(i-1)/16])(b, c, d) + X[k] + T[i-1])<<(s))
#else
#define MD5_OP(a,b,c,d,k,s,i) \
    a = b + ROTL(a + (g[(i-1)/16])(b, c, d) + X[k] + T[i-1], s); \
    DBG("%02d: a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x, X=0x%08x, T=0x%08x\n", i-1, a, b, c, d, X[k], T[i-1]);
#endif

#define WORD(b,i) (((uint32_t *)b)[i])

static uint32_t md5_process_block(const void *block)
{
    uint32_t i;
	//uint32_t t;
	uint32_t X[16];
	//uint32_t T;
    //uint32_t AA, BB, CC, DD;
	uint32_t a, b, c, d;
	struct md5_context *context;

	context = get_md5_context();

#ifdef DEBUG
	printf("block: %lld\n", context->processed_bits >> 9); /* block size: 2^9 = 512 */
	print_buffer(block, HASH_BLOCK_SIZE);
#endif

	/* prepare schedule word */
	// prepare_schedule_word(block, X);
	printf("\n");
    for (i=0; i<16; i++)
    {
        //X[i] = swap32(WORD(block, i));
        X[i] = WORD(block, i);
        printf("0x%08x ", X[i]);
    }
    printf("\n");

    //print_buffer(block, 64);
    print_buffer(&X, 64);

	a = context->a;
	b = context->b;
	c = context->c;
	d = context->d;

    /* Round 1 */
    MD5_OP(a, b, c, d,  0,  7,  1); MD5_OP(d, a, b, c,  1, 12,  2); MD5_OP(c, d, a, b,  2, 17,  3); MD5_OP(b, c, d, a,  3, 22,  4);
    MD5_OP(a, b, c, d,  4,  7,  5); MD5_OP(d, a, b, c,  5, 12,  6); MD5_OP(c, d, a, b,  6, 17,  7); MD5_OP(b, c, d, a,  7, 22,  8);
    MD5_OP(a, b, c, d,  8,  7,  9); MD5_OP(d, a, b, c,  9, 12, 10); MD5_OP(c, d, a, b, 10, 17, 11); MD5_OP(b, c, d, a, 11, 22, 12);
    MD5_OP(a, b, c, d, 12,  7, 13); MD5_OP(d, a, b, c, 13, 12, 14); MD5_OP(c, d, a, b, 14, 17, 15); MD5_OP(b, c, d, a, 15, 22, 16);


    /* Round 2 */
    MD5_OP(a, b, c, d,  1,  5, 17); MD5_OP(d, a, b, c,  6,  9, 18); MD5_OP(c, d, a, b, 11, 14, 19); MD5_OP(b, c, d, a,  0, 20, 20);
    MD5_OP(a, b, c, d,  5,  5, 21); MD5_OP(d, a, b, c, 10,  9, 22); MD5_OP(c, d, a, b, 15, 14, 23); MD5_OP(b, c, d, a,  4, 20, 24);
    MD5_OP(a, b, c, d,  9,  5, 25); MD5_OP(d, a, b, c, 14,  9, 26); MD5_OP(c, d, a, b,  3, 14, 27); MD5_OP(b, c, d, a,  8, 20, 28);
    MD5_OP(a, b, c, d, 13,  5, 29); MD5_OP(d, a, b, c,  2,  9, 30); MD5_OP(c, d, a, b,  7, 14, 31); MD5_OP(b, c, d, a, 12, 20, 32);

    /* Round 3 */
    MD5_OP(a, b, c, d,  5,  4, 33); MD5_OP(d, a, b, c,  8, 11, 34); MD5_OP(c, d, a, b, 11, 16, 35); MD5_OP(b, c, d, a, 14, 23, 36);
    MD5_OP(a, b, c, d,  1,  4, 37); MD5_OP(d, a, b, c,  4, 11, 38); MD5_OP(c, d, a, b,  7, 16, 39); MD5_OP(b, c, d, a, 10, 23, 40);
    MD5_OP(a, b, c, d, 13,  4, 41); MD5_OP(d, a, b, c,  0, 11, 42); MD5_OP(c, d, a, b,  3, 16, 43); MD5_OP(b, c, d, a,  6, 23, 44);
    MD5_OP(a, b, c, d,  9,  4, 45); MD5_OP(d, a, b, c, 12, 11, 46); MD5_OP(c, d, a, b, 15, 16, 47); MD5_OP(b, c, d, a,  2, 23, 48);

    /* Round 4 */
    MD5_OP(a, b, c, d,  0,  6, 49); MD5_OP(d, a, b, c,  7, 10, 50); MD5_OP(c, d, a, b, 14, 15, 51); MD5_OP(b, c, d, a,  5, 21, 52);
    MD5_OP(a, b, c, d, 12,  6, 53); MD5_OP(d, a, b, c,  3, 10, 54); MD5_OP(c, d, a, b, 10, 15, 55); MD5_OP(b, c, d, a,  1, 21, 56);
    MD5_OP(a, b, c, d,  8,  6, 57); MD5_OP(d, a, b, c, 15, 10, 58); MD5_OP(c, d, a, b,  6, 15, 59); MD5_OP(b, c, d, a, 13, 21, 60);
    MD5_OP(a, b, c, d,  4,  6, 61); MD5_OP(d, a, b, c, 11, 10, 62); MD5_OP(c, d, a, b,  2, 15, 63); MD5_OP(b, c, d, a,  9, 21, 64);

#if 0
	for (t=0; t<HASH_ROUND_NUM; t++)
	{
	    T= b + ((a + (g[t/16])(b, c, d) + X[k] + T[t])<<<s)
		//T = ROTL(a, 5) + (F[t/20])(b, c, d) + e + K[t/20] + W[t];
		d = c;
		c = b;
		b = T;
		a = d;

#ifdef DEBUG
		DBG("%02d:\n", t);
		DBG("T=0x%08x, W=0x%08x\n", T, W[t]);
		DBG("a=0x%08x, b=0x%08x, c=0x%02x, d=0x%08x\n", a, b, c, d);
#endif
	}
#endif

	context->a += a;
	context->b += b;
	context->c += c;
	context->d += d;

	//context->processed_bits += HASH_BLOCK_SIZE << 3;

#ifdef DEBUG
	DBG("hash:\n");
	DBG("%08x%08x%08x%08x\n", context->a, context->b, context->c, context->d);
#endif

	return 0;
}

int md5_update(const void *data, uint64_t size)
{
	uint64_t len = 0;

	struct md5_context *context;

	context = get_md5_context();

	/* has rest data */
	if (context->rest != 0)
	{
		/* less than 1 block in total, combine data */
		if (context->rest + size < HASH_BLOCK_SIZE)
		{
			memcpy(&context->last_block[context->rest], data, size);
			context->rest += size;

			return 0;
		}
		else /* more than 1 block */
		{
			/* process the block in context buffer */
			len = HASH_BLOCK_SIZE - context->rest;
			memcpy(&context->last_block[context->rest], data, len);
			md5_process_block(&context->last_block);

            context->processed_bits += HASH_BLOCK_SIZE << 3;

			data = (uint8_t *)data + len;
			size -= len;

			/* reset context buffer */
			memset(&context->last_block[0], 0, HASH_BLOCK_SIZE);
			context->rest = 0;
		}
	}

	/* less than 1 block, copy to context buffer */
	if (size < HASH_BLOCK_SIZE)
	{
		memcpy(&context->last_block[context->rest], data, size);
		context->rest += size;

		return 0;
	}
	else
	{
		/* process data blocks */
		while (size > HASH_BLOCK_SIZE)
		{
			md5_process_block(data);
            context->processed_bits += HASH_BLOCK_SIZE << 3;

			data = (uint8_t *)data + HASH_BLOCK_SIZE;
			size -= HASH_BLOCK_SIZE;
		}

		/* copy the reset to context buffer */
		memcpy(&context->last_block[0], data, size);
		context->rest = size;
	}

	return 0;
}

int md5_final(uint8_t *hash)
{
	uint64_t total;
	uint32_t *buf;

	struct md5_context *context;

	context = get_md5_context();

	/* Last block should be less thant HASH_BLOCK_SIZE - HASH_LEN_SIZE */
	if (context->rest >= (HASH_BLOCK_SIZE - HASH_LEN_SIZE))
	{
	    total = context->processed_bits + (context->rest << 3);

		/* one more block */
		context->last_block[context->rest] = HASH_PADDING_PATTERN;
        context->rest++;

		memset(&context->last_block[context->rest], 0, HASH_BLOCK_SIZE - context->rest);
		md5_process_block(&context->last_block);

		context->rest = 0;

		memset(&context->last_block[0], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE);
		//*(uint64_t *)&(context->last_block[HASH_LEN_OFFSET]) = swap64(total);
		*(uint32_t *)&(context->last_block[HASH_LEN_OFFSET]) = total & 0xFFFFFFFF;
        *(uint32_t *)&(context->last_block[HASH_LEN_OFFSET+3]) = (total >> 32) & 0xFFFFFFFF;
		md5_process_block(&context->last_block);
	}
	else /* 0 <= rest < HASH_BLOCK_SIZE - HASH_LEN_SIZE */
	{
		/* calc, don't need to accumulate the padding block */
		total = context->processed_bits + (context->rest << 3);

		/* one more block */
		context->last_block[context->rest] = HASH_PADDING_PATTERN;
		context->rest++;

		memset(&context->last_block[context->rest], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE - context->rest);

		//*(uint64_t *)&(context->last_block[HASH_LEN_OFFSET]) = swap64(total);
		*(uint32_t *)&(context->last_block[HASH_LEN_OFFSET]) = total & 0xFFFFFFFF;
        *(uint32_t *)&(context->last_block[HASH_LEN_OFFSET+3]) = (total >> 32) & 0xFFFFFFFF;
		md5_process_block(&context->last_block);
	}

	DBG("%08x %08x %08x %08x\n", context->a, context->b, context->c, context->d);
	//snprintf(hash, HASH_DIGEST_SIZE, "%08x%08x%08x%08x%08x", context->a, context->b, context->c, context->d, context->e);
	buf = (uint32_t *)hash;
	//buf[0] = swap32(context->a);
	//buf[1] = swap32(context->b);
	//buf[2] = swap32(context->c);
	//buf[3] = swap32(context->d);
	buf[0] = context->a;
	buf[1] = context->b;
	buf[2] = context->c;
	buf[3] = context->d;

	return 0;
}
