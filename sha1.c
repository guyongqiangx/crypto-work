#include <stdio.h>
#include <string.h>

#include "sha1.h"

//#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...)
#endif

#define SHA1_BLOCK_SIZE		64	/* 512 bits = 64 Bytes */
#define SHA1_LEN_SIZE	 	8	/* 64 bits = 8 bytes */
#define SHA1_LEN_OFFSET 	(SHA1_BLOCK_SIZE - SHA1_LEN_SIZE)
#define SHA1_DIGEST_SIZE	20 /* 160 bits = 20 bytes */

#define SHA1_PADDING_PATTERN 	0x80
#define SHA1_ROUND_NUM			80

typedef uint32_t (*sha1_func)(uint32_t x, uint32_t y, uint32_t z);

/* SHA1 Constants */
static uint32_t K[4] = 
{
	0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
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

/* Ch ... choose */
static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
	DBG("    Ch(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
	return (x & y) ^ (~x & z) ;
}

/* Par ... parity */
static uint32_t Parity(uint32_t x, uint32_t y, uint32_t z)
{
	DBG("Parity(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
	return x ^ y ^ z;
}

/* Maj ... majority */
static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
	DBG("   Maj(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
	return (x & y) ^ (x & z) ^ (y & z);
}

/* SHA1 Functions */
static sha1_func F[4] =
{
	Ch, Parity, Maj, Parity
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
int print_buffer(void *buf, uint32_t len)
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

struct sha1_context {
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t e;

	uint64_t processed_bits;

	uint32_t rest; /* rest size in last block */
	uint8_t last_block[SHA1_BLOCK_SIZE];

};

static struct sha1_context *get_sha1_context(void)
{
	static struct sha1_context _sha1;

	return &_sha1;
}

int sha1_init(void)
{
	struct sha1_context *context;

	context = get_sha1_context();

	memset(context, 0, sizeof(struct sha1_context));
	context->a = 0x67452301;
	context->b = 0xEFCDAB89;
	context->c = 0x98BADCFE;
	context->d = 0x10325476;
	context->e = 0xC3D2E1F0;

	context->processed_bits = 0;
	context->rest = 0;

	return 0;
}

#define WORD(b,i) (((uint32_t *)b)[i])
static uint32_t prepare_schedule_word(const void *block, uint32_t *w)
{
	uint32_t i;
	for (i=0; i<SHA1_ROUND_NUM; i++)
	{
		if (i<=15)
			w[i] = swap32(WORD(block, i));
		else
			w[i] = ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
	}

	return 0;
}

static uint32_t sha1_process_block(const void *block)
{
	uint32_t W[SHA1_ROUND_NUM];
	uint32_t t, T;
	uint32_t a, b, c, d, e;
	struct sha1_context *context;

	context = get_sha1_context();

#ifdef DEBUG
	printf("block: %d\n", context->processed_bits >> 9); /* block size: 2^9 = 512 */
	print_buffer(block, SHA1_BLOCK_SIZE);
#endif

	/* prepare schedule word */
	prepare_schedule_word(block, W);

	a = context->a;
	b = context->b;
	c = context->c;
	d = context->d;
	e = context->e;

	for (t=0; t<SHA1_ROUND_NUM; t++)
	{
		T = ROTL(a, 5) + (F[t/20])(b, c, d) + e + K[t/20] + W[t];
		e = d;
		d = c;
		c = ROTL(b, 30);
		b = a;
		a = T;

#if 0 //def DEBUG
		DBG("%02d:\n", t);
		DBG("T=0x%08x, W=0x%08x\n", T, W[t]);
		DBG("e=0x%08x, d=0x%08x, c=0x%08x, b=0x%02x, a=0x%08x\n", e, d, c, b, a);
#endif
	}

	context->a += a;
	context->b += b;
	context->c += c;
	context->d += d;
	context->e += e;

	context->processed_bits += 512;

#if 0 //def DEBUG
	DBG("hash:\n");
	DBG("%08x%08x%08x%08x%08x\n", context->a, context->b, context->c, context->d, context->e);
#endif

	return 0;
}

int sha1_update(const void *data, uint64_t size)
{
	uint64_t len = 0;

	struct sha1_context *context;

	context = get_sha1_context();

	/* has rest data */
	if (context->rest != 0)
	{
		/* less than 1 block in total, combine data */
		if (context->rest + size < SHA1_BLOCK_SIZE)
		{
			memcpy(&context->last_block[context->rest], data, size);
			context->rest += size;

			return 0;
		}
		else /* more than 1 block */
		{
			/* process the block in context buffer */
			len = SHA1_BLOCK_SIZE - context->rest;
			memcpy(&context->last_block[context->rest], data, len);
			sha1_process_block(&context->last_block);

			data = (uint8_t *)data + len;
			size -= len;

			/* reset context buffer */
			memset(&context->last_block[0], 0, SHA1_BLOCK_SIZE);
			context->rest = 0;
		}
	}

	/* less than 1 block, copy to context buffer */
	if (size < SHA1_BLOCK_SIZE)
	{
		memcpy(&context->last_block[context->rest], data, size);
		context->rest += size;

		return 0;
	}
	else
	{
		/* process data blocks */
		while (size > SHA1_BLOCK_SIZE)
		{
			sha1_process_block(data);

			data = (uint8_t *)data + SHA1_BLOCK_SIZE;
			size -= SHA1_BLOCK_SIZE;
		}

		/* copy the reset to context buffer */
		memcpy(&context->last_block[0], data, size);
		context->rest = size;
	}

	return 0;
}

int sha1_final(uint8_t *hash)
{
	uint64_t total;
	uint32_t *buf;

	struct sha1_context *context;

	context = get_sha1_context();

	/* Last block should be less thant SHA1_BLOCK_SIZE - SHA1_LEN_SIZE */
	if (context->rest >= (SHA1_BLOCK_SIZE - SHA1_LEN_SIZE))
	{
		/* one more block */
		context->last_block[context->rest] = SHA1_PADDING_PATTERN;

		/* Note:
		 *      processed_bits will be updated in sha1_process_block,
		 *      need to calc total here,
		 *      don't need to accumulate the padding block
		 */
		total = context->processed_bits + context->rest * 8;

		context->rest++;

		memset(&context->last_block[context->rest], 0, SHA1_BLOCK_SIZE - context->rest);
		sha1_process_block(&context->last_block);

		context->rest = 0;

		memset(&context->last_block[0], 0, SHA1_BLOCK_SIZE - SHA1_LEN_SIZE);
		*(uint64_t *)&(context->last_block[SHA1_LEN_OFFSET]) = swap64(total);
		sha1_process_block(&context->last_block);
	}
	else /* 0 <= rest < SHA1_BLOCK_SIZE - SHA1_LEN_SIZE */
	{
		/* one more block */
		context->last_block[context->rest] = SHA1_PADDING_PATTERN;

		/* calc, don't need to accumulate the padding block */
		total = context->processed_bits + context->rest * 8;

		context->rest++;

		memset(&context->last_block[context->rest], 0, SHA1_BLOCK_SIZE - SHA1_LEN_SIZE - context->rest);

		*(uint64_t *)&context->last_block[SHA1_LEN_OFFSET] = swap64(total);
		sha1_process_block(&context->last_block);
	}

	DBG("%08x %08x %08x %08x %08x\n", context->a, context->b, context->c, context->d, context->e);
	//snprintf(hash, SHA1_DIGEST_SIZE, "%08x%08x%08x%08x%08x", context->a, context->b, context->c, context->d, context->e);
	buf = (uint32_t *)hash;
	buf[0] = swap32(context->a);
	buf[1] = swap32(context->b);
	buf[2] = swap32(context->c);
	buf[3] = swap32(context->d);
	buf[4] = swap32(context->e);

	return 0;
}
