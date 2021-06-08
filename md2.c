#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "md2.h"

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

#define MD4_BLOCK_SIZE		64	/* 512 bits = 64 bytes */
#define MD4_LEN_SIZE	 	 8	/*  64 bits =  8 bytes */
#define MD4_LEN_OFFSET      (MD4_BLOCK_SIZE - MD4_LEN_SIZE)
#define MD4_DIGEST_SIZE     16  /* 128 bits = 16 bytes */

#define MD4_PADDING_PATTERN 	0x80
#define MD4_ROUND_NUM			64

#define HASH_BLOCK_SIZE		MD4_BLOCK_SIZE
#define HASH_LEN_SIZE		MD4_LEN_SIZE
#define HASH_LEN_OFFSET		MD4_LEN_OFFSET
#define HASH_DIGEST_SIZE	MD4_DIGEST_SIZE

#define HASH_PADDING_PATTERN	MD4_PADDING_PATTERN
#define HASH_ROUND_NUM			MD4_ROUND_NUM

typedef uint32_t (*md5_func)(uint32_t x, uint32_t y, uint32_t z);

static const pi[256] =
{
    0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01,
    0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
    0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C,
    0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
    0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16,
    0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
    0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49,
    0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
    0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F,
    0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
    0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27,
    0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
    0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1,
    0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
    0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6,
    0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
    0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20,
    0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
    0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6,
    0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
    0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A,
    0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
    0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09,
    0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
    0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA,
    0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
    0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D,
    0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
    0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4,
    0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
    0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A,
    0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14,
};

/* SHA1 Constants */
static uint32_t T[3] = 
{
    0x00000000, /* Round 1, nothing */
    0x5A827999, /* Round 2, square root of 2 */
    0x6ED9EBA1, /* Round 3, square root of 3 */
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

/* Condition */
static uint32_t F(uint32_t x, uint32_t y, uint32_t z)
{
	//DBG("F(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
	return (x & y) | ((~x) & z);
}

/* Majority */
static uint32_t G(uint32_t x, uint32_t y, uint32_t z)
{
	//DBG("G(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
	//return (x & z) | (y & (~z));
	return (x & y) | (x & z) | (y & z);
}

/* Parity */
static uint32_t H(uint32_t x, uint32_t y, uint32_t z)
{
	//DBG("H(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
	return x ^ y ^ z;
}


/* MD4 Functions */
static md5_func g[3] =
{
	F, G, H
};


/*
 * "abc" -->   0x61,     0x62,     0x63
 *   Origin: 0b0110 0001 0110 0010 0110 0011
 *  Padding: 0b0110 0001 0110 0010 0110 0011 1000 0000 .... 0000 0000  0000 0000 .... 0001 1000
 *                                          (|<-------------------->|)(|<------- 0x18 ------->|)
 *   Format: "abc" + 1 + 0 x 423 + 0x18
 */

int MD4_Init(MD4_CTX *c)
{
	if (NULL == c)
    {
        return ERR_INV_PARAM;
    }

	memset(c, 0, sizeof(MD4_CTX));

	c->hash.a = 0x67452301; /* little endian */
	c->hash.b = 0xEFCDAB89;
	c->hash.c = 0x98BADCFE;
	c->hash.d = 0x10325476;

	c->total = 0;
	c->last.used = 0;

	return ERR_OK;
}

static int MD4_PrepareScheduleWord(const void *block, uint32_t *X)
{
	uint32_t i;

    if ((NULL == block) || (NULL == X))
    {
        return ERR_INV_PARAM;
    }

    for (i=0; i<16; i++)
    {
        X[i] = DWORD(block, i);
    }

	return ERR_OK;
}

#if 0
#define MD4_OP(a,b,c,d,k,s,i) \
    a = b + ((a + (g[(i-1)/16])(b, c, d) + X[k] + T[i-1])<<(s))
#else
#define MD4_OP(a,b,c,d,k,s) \
    a = ROTL(a + (g[idx/16])(b, c, d) + X[k] + T[idx/16], s); \
    DBG("%02d: a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x, X=0x%08x, T=0x%08x\n", idx, a, b, c, d, X[k], T[idx/16]); \
    idx ++;
#endif

static int MD4_ProcessBlock(MD4_CTX *ctx, const void *block)
{
    //uint32_t i;
	//uint32_t t;
	uint32_t X[16];
	//uint32_t T;
    //uint32_t AA, BB, CC, DD;
	uint32_t a, b, c, d;
    uint32_t idx;

    if ((NULL == ctx) || (NULL == block))
    {
        return ERR_INV_PARAM;
    }

#if (DUMP_BLOCK_DATA == 1)
    DBG("BLOCK: %llu\n", ctx->total/HASH_BLOCK_SIZE);
    print_buffer(block, HASH_BLOCK_SIZE, " ");
#endif

	/* prepare schedule word */
	MD4_PrepareScheduleWord(block, X);

	a = ctx->hash.a;
	b = ctx->hash.b;
	c = ctx->hash.c;
	d = ctx->hash.d;

    idx = 0;

    /* Round 1 */
    MD4_OP(a, b, c, d,  0,  3); MD4_OP(d, a, b, c,  1,  7); MD4_OP(c, d, a, b,  2, 11); MD4_OP(b, c, d, a,  3, 19);
    MD4_OP(a, b, c, d,  4,  3); MD4_OP(d, a, b, c,  5,  7); MD4_OP(c, d, a, b,  6, 11); MD4_OP(b, c, d, a,  7, 19);
    MD4_OP(a, b, c, d,  8,  3); MD4_OP(d, a, b, c,  9,  7); MD4_OP(c, d, a, b, 10, 11); MD4_OP(b, c, d, a, 11, 19);
    MD4_OP(a, b, c, d, 12,  3); MD4_OP(d, a, b, c, 13,  7); MD4_OP(c, d, a, b, 14, 11); MD4_OP(b, c, d, a, 15, 19);

    /* Round 2 */
    MD4_OP(a, b, c, d,  0,  3); MD4_OP(d, a, b, c,  4,  5); MD4_OP(c, d, a, b,  8,  9); MD4_OP(b, c, d, a, 12, 13);
    MD4_OP(a, b, c, d,  1,  3); MD4_OP(d, a, b, c,  5,  5); MD4_OP(c, d, a, b,  9,  9); MD4_OP(b, c, d, a, 13, 13);
    MD4_OP(a, b, c, d,  2,  3); MD4_OP(d, a, b, c,  6,  5); MD4_OP(c, d, a, b, 10,  9); MD4_OP(b, c, d, a, 14, 13);
    MD4_OP(a, b, c, d,  3,  3); MD4_OP(d, a, b, c,  7,  5); MD4_OP(c, d, a, b, 11,  9); MD4_OP(b, c, d, a, 15, 13);

    /* Round 3 */
    MD4_OP(a, b, c, d,  0,  3); MD4_OP(d, a, b, c,  8,  9); MD4_OP(c, d, a, b,  4, 11); MD4_OP(b, c, d, a, 12, 15);
    MD4_OP(a, b, c, d,  2,  3); MD4_OP(d, a, b, c, 10,  9); MD4_OP(c, d, a, b,  6, 11); MD4_OP(b, c, d, a, 14, 15);
    MD4_OP(a, b, c, d,  1,  3); MD4_OP(d, a, b, c,  9,  9); MD4_OP(c, d, a, b,  5, 11); MD4_OP(b, c, d, a, 13, 15);
    MD4_OP(a, b, c, d,  3,  3); MD4_OP(d, a, b, c, 11,  9); MD4_OP(c, d, a, b,  7, 11); MD4_OP(b, c, d, a, 15, 15);

#if 0
	for (t=0; t<HASH_ROUND_NUM; t++)
	{
	    T= b + ((a + (g[t/16])(b, c, d) + X[k] + T[t])<<<s)
		//T = ROTL(a, 5) + (F[t/20])(b, c, d) + e + K[t/20] + W[t];
		d = c;
		c = b;
		b = T;
		a = d;

#if (DUMP_ROUND_DATA == 1)
		DBG("   %02d: T=0x%08x, W=0x%08x, a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x\n",
                t, T, W[t], a, b, c, d);
#endif
	}
#endif

	ctx->hash.a += a;
	ctx->hash.b += b;
	ctx->hash.c += c;
	ctx->hash.d += d;
#if (DUMP_BLOCK_HASH == 1)
	DBG(" HASH: %08x%08x%08x%08x\n",
		ctx->hash.a, ctx->hash.b, ctx->hash.c, ctx->hash.d);
#endif

	return ERR_OK;
}

int MD4_Update(MD4_CTX *c, const void *data, unsigned long len)
{
	uint32_t copy_len = 0;

    if ((NULL == c) || (NULL == data))
    {
        return ERR_INV_PARAM;
    }

	/* has used data */
	if (c->last.used != 0)
	{
		/* less than 1 block in total, combine data */
		if (c->last.used + len < HASH_BLOCK_SIZE)
		{
			memcpy(&c->last.buf[c->last.used], data, len);
			c->last.used += len;

			return ERR_OK;
		}
		else /* more than 1 block */
		{
			/* process the block in context buffer */
			copy_len = HASH_BLOCK_SIZE - c->last.used;
			memcpy(&c->last.buf[c->last.used], data, copy_len);
			MD4_ProcessBlock(c, &c->last.buf);

            c->total += HASH_BLOCK_SIZE;

			data = (uint8_t *)data + copy_len;
			len -= copy_len;

			/* reset context buffer */
			memset(&c->last.buf[0], 0, HASH_BLOCK_SIZE);
			c->last.used = 0;
		}
	}

	/* less than 1 block, copy to context buffer */
	if (len < HASH_BLOCK_SIZE)
	{
		memcpy(&c->last.buf[c->last.used], data, len);
		c->last.used += len;

		return ERR_OK;
	}
	else
	{
		/* process data blocks */
		while (len > HASH_BLOCK_SIZE)
		{
			MD4_ProcessBlock(c, data);
            c->total += HASH_BLOCK_SIZE;

			data = (uint8_t *)data + HASH_BLOCK_SIZE;
			len -= HASH_BLOCK_SIZE;
		}

		/* copy rest data to context buffer */
		memcpy(&c->last.buf[0], data, len);
		c->last.used = len;
	}

	return ERR_OK;
}

int MD4_Final(unsigned char *md, MD4_CTX *c)
{
	uint32_t *buf;

    if ((NULL == c) || (NULL == md))
    {
        return ERR_INV_PARAM;
    }

	/* Last block should be less thant HASH_BLOCK_SIZE - HASH_LEN_SIZE */
	if (c->last.used >= (HASH_BLOCK_SIZE - HASH_LEN_SIZE))
	{
	    c->total += c->last.used;

		/* one more block */
		c->last.buf[c->last.used] = HASH_PADDING_PATTERN;
        c->last.used++;

		memset(&c->last.buf[c->last.used], 0, HASH_BLOCK_SIZE - c->last.used);
		MD4_ProcessBlock(c, &c->last.buf);

		memset(&c->last.buf[0], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE);
		c->last.used = 0;

		//*(uint32_t *)&(c->last.buf[HASH_LEN_OFFSET]) = total & 0xFFFFFFFF;
        //*(uint32_t *)&(c->last.buf[HASH_LEN_OFFSET+3]) = (total >> 32) & 0xFFFFFFFF;
        htole32c(&(c->last.buf[HASH_LEN_OFFSET]), (c->total << 3) & 0xFFFFFFFF);
        htole32c(&(c->last.buf[HASH_LEN_OFFSET + 3]), ((c->total << 3) >> 32) & 0xFFFFFFFF);
		MD4_ProcessBlock(c, &c->last.buf);
	}
	else /* 0 <= last.used < HASH_BLOCK_SIZE - HASH_LEN_SIZE */
	{
		c->total += c->last.used;

		/* one more block */
		c->last.buf[c->last.used] = HASH_PADDING_PATTERN;
		c->last.used++;

        /* padding 0s */
		memset(&c->last.buf[c->last.used], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE - c->last.used);

		//*(uint32_t *)&(c->last.buf[HASH_LEN_OFFSET]) = total & 0xFFFFFFFF;
        //*(uint32_t *)&(c->last.buf[HASH_LEN_OFFSET+3]) = (total >> 32) & 0xFFFFFFFF;
        htole32c(&(c->last.buf[HASH_LEN_OFFSET]), (c->total << 3) & 0xFFFFFFFF);
        htole32c(&(c->last.buf[HASH_LEN_OFFSET + 3]), ((c->total << 3) >> 32) & 0xFFFFFFFF);
		MD4_ProcessBlock(c, &c->last.buf);
	}

    /* LE format, different from SHA family(big endian) */
	buf = (uint32_t *)md;
	buf[0] = c->hash.a;
	buf[1] = c->hash.b;
	buf[2] = c->hash.c;
	buf[3] = c->hash.d;

	return ERR_OK;
}

unsigned char *MD4(const unsigned char *d, unsigned long n, unsigned char *md)
{
    MD4_CTX c;

    if ((NULL == d) || (NULL == md))
    {
        return NULL;
    }

    MD4_Init(&c);
    MD4_Update(&c, d, n);
    MD4_Final(md, &c);

    return md;
}
