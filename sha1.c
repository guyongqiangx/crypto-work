#include <stdio.h>
#include <string.h>

#include "sha1.h"

#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#define DUMP_BLOCK_DATA 1
#define DUMP_BLOCK_HASH 1
#define DUMP_ROUND_DATA 1
#else
#define DBG(...)
#define DUMP_BLOCK_DATA 0
#define DUMP_BLOCK_HASH 0
#define DUMP_ROUND_DATA 0
#endif

#define SHA1_BLOCK_SIZE		64	/* 512 bits = 64 Bytes */
#define SHA1_LEN_SIZE	 	8	/* 64 bits = 8 bytes */
#define SHA1_LEN_OFFSET 	(SHA1_BLOCK_SIZE - SHA1_LEN_SIZE)
#define SHA1_DIGEST_SIZE	20 /* 160 bits = 20 bytes */

#define SHA1_PADDING_PATTERN 	0x80
#define SHA1_ROUND_NUM			80

#define HASH_BLOCK_SIZE		SHA1_BLOCK_SIZE
#define HASH_LEN_SIZE		SHA1_LEN_SIZE
#define HASH_LEN_OFFSET		SHA1_LEN_OFFSET
#define HASH_DIGEST_SIZE	SHA1_DIGEST_SIZE

#define HASH_PADDING_PATTERN	SHA1_PADDING_PATTERN
#define HASH_ROUND_NUM			SHA1_ROUND_NUM

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
	//DBG("    Ch(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
	return (x & y) ^ (~x & z) ;
}

/* Par ... parity */
static uint32_t Parity(uint32_t x, uint32_t y, uint32_t z)
{
	//DBG("Parity(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
	return x ^ y ^ z;
}

/* Maj ... majority */
static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
	//DBG("   Maj(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
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

struct sha1_context {
    /* message length in bits */
    uint64_t total_bits;

    /* intermedia hash value for each block */
    struct {
        uint32_t a;
        uint32_t b;
        uint32_t c;
        uint32_t d;
        uint32_t e;
    }hash; 

    /* last block buffer */
    struct {
        uint32_t size;                  /* size in bytes */
        uint8_t  buf[HASH_BLOCK_SIZE];  /* buffer */
    }last;
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

    /* reset all fields to 0 */
	memset(context, 0, sizeof(struct sha1_context));

	context->hash.a = 0x67452301;
	context->hash.b = 0xEFCDAB89;
	context->hash.c = 0x98BADCFE;
	context->hash.d = 0x10325476;
	context->hash.e = 0xC3D2E1F0;

	return ERR_OK;
}

#define WORD(b,i) (((uint32_t *)b)[i])
static int prepare_schedule_word(const void *block, uint32_t *w)
{
	uint32_t t;

    if ((NULL == block) || (NULL == w))
    {
        return ERR_INV_PARAM;
    }

	for (t=0; t<HASH_ROUND_NUM; t++)
	{
		if (t<=15) /*  0 <= t <= 15 */
			w[t] = swap32(WORD(block, t));
		else	   /* 16 <= t <= 79 */
			w[t] = ROTL(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
	}

	return ERR_OK;
}

static int sha1_process_block(const void *block)
{
	uint32_t t;
	uint32_t W[HASH_ROUND_NUM];
	uint32_t T;
	uint32_t a, b, c, d, e;
	struct sha1_context *context;

	context = get_sha1_context();

    if (NULL == block)
    {
        return ERR_INV_PARAM;
    }

#if (DUMP_BLOCK_DATA == 1)
	DBG("block %llu:\n", context->total_bits >> 9); /* block size: 2^9 = 512 */
	print_buffer(block, HASH_BLOCK_SIZE);
#endif

	/* prepare schedule word */
	prepare_schedule_word(block, W);

	a = context->hash.a;
	b = context->hash.b;
	c = context->hash.c;
	d = context->hash.d;
	e = context->hash.e;

	for (t=0; t<HASH_ROUND_NUM; t++)
	{
		T = ROTL(a, 5) + (F[t/20])(b, c, d) + e + K[t/20] + W[t];
		e = d;
		d = c;
		c = ROTL(b, 30);
		b = a;
		a = T;

#if (DUMP_ROUND_DATA == 1)
		DBG("  %02d: T=0x%08x, W=0x%08x, a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x, e=0x%08x\n", t, T, W[t], a, b, c, d, e);
#endif
	}

	context->hash.a += a;
	context->hash.b += b;
	context->hash.c += c;
	context->hash.d += d;
	context->hash.e += e;

#if (DUMP_BLOCK_HASH == 1)
	DBG("hash: %08x %08x %08x %08x %08x\n", context->hash.a, context->hash.b, context->hash.c, context->hash.d, context->hash.e);
#endif

	return ERR_OK;
}

int sha1_update(const void *data, uint64_t size)
{
	uint64_t len = 0;
	struct sha1_context *context;

	context = get_sha1_context();

    if (NULL == data)
    {
        return ERR_INV_PARAM;
    }

	/* has last.size data */
	if (context->last.size != 0)
	{
		/* less than 1 block in total, combine data */
		if (context->last.size + size < HASH_BLOCK_SIZE)
		{
			memcpy(&context->last.buf[context->last.size], data, size);
			context->last.size += size;

			return ERR_OK;
		}
		else /* more than 1 block */
		{
			/* process the block in context buffer */
			len = HASH_BLOCK_SIZE - context->last.size;
			memcpy(&context->last.buf[context->last.size], data, len);
			sha1_process_block(&context->last.buf);
            context->total_bits += HASH_BLOCK_SIZE << 3;

			data = (uint8_t *)data + len;
			size -= len;

			/* reset context buffer */
			memset(&context->last.buf[0], 0, HASH_BLOCK_SIZE);
			context->last.size = 0;
		}
	}

	/* less than 1 block, copy to context buffer */
	if (size < HASH_BLOCK_SIZE)
	{
		memcpy(&context->last.buf[context->last.size], data, size);
		context->last.size += size;

		return ERR_OK;
	}
	else
	{
		/* process data blocks */
		while (size > HASH_BLOCK_SIZE)
		{
			sha1_process_block(data);
            context->total_bits += HASH_BLOCK_SIZE << 3;

			data = (uint8_t *)data + HASH_BLOCK_SIZE;
			size -= HASH_BLOCK_SIZE;
		}

		/* copy rest data to context buffer */
		memcpy(&context->last.buf[0], data, size);
		context->last.size = size;
	}

	return ERR_OK;
}

int sha1_final(uint8_t *hash)
{
	uint32_t *buf;
	struct sha1_context *context;

	context = get_sha1_context();

    if (NULL == hash)
    {
        return ERR_INV_PARAM;
    }

	/* Last block should be less thant HASH_BLOCK_SIZE - HASH_LEN_SIZE */
	if (context->last.size >= (HASH_BLOCK_SIZE - HASH_LEN_SIZE))
	{
	    context->total_bits += context->last.size << 3;

		/* one more block */
		context->last.buf[context->last.size] = HASH_PADDING_PATTERN;
		context->last.size++;

		memset(&context->last.buf[context->last.size], 0, HASH_BLOCK_SIZE - context->last.size);
		sha1_process_block(&context->last.buf);

		context->last.size = 0;

		memset(&context->last.buf[0], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE);
		*(uint64_t *)&(context->last.buf[HASH_LEN_OFFSET]) = swap64(context->total_bits);
		sha1_process_block(&context->last.buf);
	}
	else /* 0 <= last.size < HASH_BLOCK_SIZE - HASH_LEN_SIZE */
	{
	    context->total_bits += context->last.size << 3;

		/* one more block */
		context->last.buf[context->last.size] = HASH_PADDING_PATTERN;
		context->last.size++;

        /* padding 0s */
		memset(&context->last.buf[context->last.size], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE - context->last.size);

		*(uint64_t *)&context->last.buf[HASH_LEN_OFFSET] = swap64(context->total_bits);
		sha1_process_block(&context->last.buf);
	}

	buf = (uint32_t *)hash;
	buf[0] = swap32(context->hash.a);
	buf[1] = swap32(context->hash.b);
	buf[2] = swap32(context->hash.c);
	buf[3] = swap32(context->hash.d);
	buf[4] = swap32(context->hash.e);

	return ERR_OK;
}
