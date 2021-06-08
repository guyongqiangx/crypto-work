#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "sm3.h"

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

#define HASH_BLOCK_SIZE		    64	/* 512 bits = 64 Bytes */
#define HASH_LEN_SIZE	 	    8	/* 64 bits = 8 bytes */
#define HASH_LEN_OFFSET         (HASH_BLOCK_SIZE - HASH_LEN_SIZE)

#define HASH_DIGEST_SIZE        32 /* 256 bits = 32 bytes */

#define HASH_PADDING_PATTERN 	0x80
#define HASH_ROUND_NUM			64

/* SM3 Constants */
static uint32_t T[2] = 
{
	0x79CC4519, 0x7A879D8A
};

/* ROTate Left (circular left shift) */
static uint32_t ROTL(uint32_t x, uint8_t shift)
{
    shift %= 32;
	return (x << shift) | (x >> (32 - shift));
}

#if 0
/* ROTate Right (cirular right shift) */
static uint32_t ROTR(uint32_t x, uint8_t shift)
{
	return (x >> shift) | (x << (32 - shift));
}
#endif

/* Right SHift */
static uint32_t SHR(uint32_t x, uint8_t shift)
{
	return (x >> shift);
}

static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, uint32_t j)
{
    if (j<16) /* 0 <= j <= 15 */
    {
        return x ^ y ^ z;
    }
    else /* 16 <= j <= 63 */
    {
        return (x & y) | (x & z) | (y & z);
    }
}

static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, uint32_t j)
{
    if (j<16) /* 0 <= j <= 15 */
    {
        return x ^ y ^ z;
    }
    else /* 16 <= j <= 63 */
    {
        return (x & y) | (~x & z);
    }
}

#if 0
/* Ch ... choose */
static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
	//DBG("    Ch(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
	return (x & y) ^ (~x & z) ;
}

/* Maj ... majority */
static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
	//DBG("   Maj(0x%08x, 0x%08x, 0x%08x);\n", x, y, z);
	return (x & y) ^ (x & z) ^ (y & z);
}

/* SIGMA0 */
static uint32_t SIGMA0(uint32_t x)
{
	return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

/* SIGMA1 */
static uint32_t SIGMA1(uint32_t x)
{
	return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

/* sigma0, different from SIGMA0 */
static uint32_t sigma0(uint32_t x)
{
	return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
}

/* sigma1, different from SIGMA1 */
static uint32_t sigma1(uint32_t x)
{
	return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
}
#endif

/* P0, Permutation 0 */
static uint32_t P0(uint32_t x)
{
    return x ^ ROTL(x, 9) ^ ROTL(x, 17);
}

/* P1, Permutation 1 */
static uint32_t P1(uint32_t x)
{
    return x ^ ROTL(x, 15) ^ ROTL(x, 23);
}

int SM3_Init(SM3_CTX *c)
{
    if (NULL == c)
    {
        return ERR_INV_PARAM;
    }

	memset(c, 0, sizeof(SM3_CTX));

	/* Initial Value for SM3 */
	c->hash.a = 0x7380166f;
	c->hash.b = 0x4914b2b9;
	c->hash.c = 0x172442d7;
	c->hash.d = 0xda8a0600;
	c->hash.e = 0xa96f30bc;
	c->hash.f = 0x163138aa;
	c->hash.g = 0xe38dee4d;
	c->hash.h = 0xb0fb0e4e;

	return ERR_OK;
}

static int SM3_PrepareScheduleWord(const void *block, uint32_t *W, uint32_t *WP)
{
	uint32_t j;

    if ((NULL == block) || (NULL == W))
    {
        return ERR_INV_PARAM;
    }

    /* Array W */
	for (j=0; j<(HASH_ROUND_NUM+4); j++)
	{
		if (j<=15) /*  0 <= j <= 15 */
			W[j] = be32toh(DWORD(block, j));
		else	   /* 16 <= j <= 67 */
			W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j-13],7) ^ W[j-6];
	}

    /* Array W Prime */
    for (j=0; j<HASH_ROUND_NUM; j++)
    {
        WP[j] = W[j] ^ W[j+4];
    }

	return ERR_OK;
}

static int SM3_ProcessBlock(SM3_CTX *ctx, const void *block)
{
	uint32_t j;
	uint32_t W[HASH_ROUND_NUM+4], WP[HASH_ROUND_NUM];
    uint32_t SS1, SS2;
	uint32_t TT1, TT2;
	uint32_t A, B, C, D, E, F, G, H;

    if ((NULL == ctx) || (NULL == block))
    {
        return ERR_INV_PARAM;
    }

#if (DUMP_BLOCK_DATA == 1)
	DBG("BLOCK: %llu\n", ctx->total/HASH_BLOCK_SIZE);
	print_buffer(block, HASH_BLOCK_SIZE, " ");
#endif

	/* prepare schedule word */
	SM3_PrepareScheduleWord(block, W, WP);

	A = ctx->hash.a;
	B = ctx->hash.b;
	C = ctx->hash.c;
	D = ctx->hash.d;
	E = ctx->hash.e;
	F = ctx->hash.f;
	G = ctx->hash.g;
	H = ctx->hash.h;

#if (DUMP_BLOCK_HASH == 1)
	DBG(" LAST: %08x%08x%08x%08x%08x%08x%08x%08x\n",
		ctx->hash.a, ctx->hash.b, ctx->hash.c, ctx->hash.d, ctx->hash.e, ctx->hash.f, ctx->hash.g, ctx->hash.h);
#endif

	for (j=0; j<HASH_ROUND_NUM; j++)
	{
	    SS1 = ROTL(ROTL(A, 12) + E + ROTL(T[j<16?0:1], j), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF(A, B, C, j) + D + SS2 + WP[j];
        TT2 = GG(E, F, G, j) + H + SS1 + W[j];
          D = C;
          C = ROTL(B, 9);
          B = A;
          A = TT1;
          H = G;
          G = ROTL(F, 19);
          F = E;
          E = P0(TT2);

#if (DUMP_ROUND_DATA == 1)
		DBG("   %02d: SS1=0x%08x, SS2=0x%08x, TT1=0x%08x, TT2=0x%08x, W=0x%08x, WP=0x%08x, \n"\
			"         A=0x%08x,    B=0x%08x,   C=0x%08x,   D=0x%08x, E=0x%08x, F=0x%08x, G=0x%08x, H=0x%08x\n", \
				j, SS1, SS2, TT1, TT2, W[j], WP[j], A, B, C, D, E, F, G, H);
#endif
	}

	ctx->hash.a += A;
	ctx->hash.b += B;
	ctx->hash.c += C;
	ctx->hash.d += D;
	ctx->hash.e += E;
	ctx->hash.f += F;
	ctx->hash.g += G;
	ctx->hash.h += H;

#if (DUMP_BLOCK_HASH == 1)
	DBG(" HASH: %08x%08x%08x%08x%08x%08x%08x%08x\n\n",
		ctx->hash.a, ctx->hash.b, ctx->hash.c, ctx->hash.d, ctx->hash.e, ctx->hash.f, ctx->hash.g, ctx->hash.h);
#endif

	return ERR_OK;
}


int SM3_Update(SM3_CTX *c, const void *data, size_t len)
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
			SM3_ProcessBlock(c, &c->last.buf);
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
			SM3_ProcessBlock(c, data);
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

int SM3_Final(unsigned char *md, SM3_CTX *c)
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
		SM3_ProcessBlock(c, &c->last.buf);

		memset(&c->last.buf[0], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE);
        c->last.used = 0;
 
		//*(uint64_t *)&(c->last.buf[HASH_LEN_OFFSET]) = htobe64(c->total << 3);
		htobe64c(&(c->last.buf[HASH_LEN_OFFSET]), c->total << 3);

		SM3_ProcessBlock(c, &c->last.buf);
	}
	else /* 0 <= last.used < HASH_BLOCK_SIZE - HASH_LEN_SIZE */
	{
	    c->total += c->last.used;

		/* one more block */
		c->last.buf[c->last.used] = HASH_PADDING_PATTERN;
		c->last.used++;

        /* padding 0s */
		memset(&c->last.buf[c->last.used], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE - c->last.used);

		//*(uint64_t *)&c->last.buf[HASH_LEN_OFFSET] = htobe64(c->total << 3);
		htobe64c(&(c->last.buf[HASH_LEN_OFFSET]), c->total << 3);

		SM3_ProcessBlock(c, &c->last.buf);
	}

	buf = (uint32_t *)md;
	buf[0] = htobe32(c->hash.a);
	buf[1] = htobe32(c->hash.b);
	buf[2] = htobe32(c->hash.c);
	buf[3] = htobe32(c->hash.d);
	buf[4] = htobe32(c->hash.e);
	buf[5] = htobe32(c->hash.f);
	buf[6] = htobe32(c->hash.g);
	buf[7] = htobe32(c->hash.h);

	return ERR_OK;
}

unsigned char *SM3(const unsigned char *d, size_t n, unsigned char *md)
{
	SM3_CTX c;

	if ((NULL == d) || (NULL == md))
	{
		return NULL;
	}

	SM3_Init(&c);
	SM3_Update(&c, d, n);
	SM3_Final(md, &c);

	return md;
}