#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "sha3.h"

//#define DEBUG

#define DWORD(b,i) (((uint32_t *)(b))[(i)])
#define QWORD(b,i) (((uint64_t *)(b))[(i)])


#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#define DUMP_SCHED_DATA 1
#define DUMP_BLOCK_DATA 1
#define DUMP_BLOCK_HASH 1
#define DUMP_ROUND_DATA 1
#else
#define DBG(...)
#define DUMP_SCHED_DATA 0
#define DUMP_BLOCK_DATA 0
#define DUMP_BLOCK_HASH 0
#define DUMP_ROUND_DATA 0
#endif

/*
 * |---------------|------------------------|
 * | Padding Bytes | Padding Message        |
 * |---------------|------------------------|
 * | q=1           | M||0x86                |
 * |---------------|------------------------|
 * | q=2           | M||0x0680              |
 * |---------------|------------------------|
 * | q>2           | M||0x06||0x00...||0x80 |
 * |---------------|------------------------|
 *
 * refer:
 *   https://cryptologie.net/article/387/byte-ordering-and-bit-numbering-in-keccak-and-sha-3/
 */

/*
 * SHA3 Delimiter + Padding
 *             01 + 10*1
 */

/* 01 10 0001 <--reverse-- 1000 01 10, 1 byte, 0x86 */
#define SHA3_PADDING_PAT1        0x86

/* 01 10 0000....0000 0001 <--reverse-- 0000 01 10....1000 0000, 2 bytes, 0x06...0x80 */
#define SHA3_PADDING_PAT2_BEGIN  0x06
#define SHA3_PADDING_PAT2_END    0x80

/*
 * SHA3 XOF Delimiter + Padding
 *               1111 + 10*1
 */
/* 1111 1001 <--reverse-- 1001 1111, 1 byte, 0x9F */
#define SHA3_PADDING_PAT3        0x9F

/* 1111 1000....0000 0001 <--reverse 0001 1111....1000 0000, 2 bytes, 0x1F...0x80 */
#define SHA3_PADDING_PAT4_BEGIN  0x1F
#define SHA3_PADDING_PAT4_END    0x80

/* ROTate Left (circular left shift) */
static uint64_t ROTL(uint64_t x, uint8_t shift)
{
	return (x << shift) | (x >> (64 - shift));
}

static uint32_t theta(uint64_t A[5][5])
{
    uint32_t x, y;
    uint64_t Ap[5][5];
    uint64_t C[5], D[5];

    memset(C, 0, sizeof(C));
    memset(D, 0, sizeof(D));
    memset(Ap, 0, sizeof(Ap));

    for (x=0; x<5; x++)
    {
        C[x] = A[0][x] ^ A[1][x] ^ A[2][x] ^ A[3][x] ^ A[4][x];
    }

    for (x=0; x<5; x++)
    {
     /* D[x] = C[x-1]     ^ ROTR(C[x+1],     1) */
        D[x] = C[(x+4)%5] ^ ROTL(C[(x+1)%5], 1);
    }

    for (y=0; y<5; y++)
    {
        for (x=0; x<5; x++)
        {
            Ap[y][x] = A[y][x] ^ D[x];
        }
    }

    memcpy(A, Ap, sizeof(Ap));
    return 0;
}

/* rotation constants, aka rotation offsets */
static uint32_t Rp[5][5] =
{
    {   0,   1,  190,  28,  91},
    {  36, 300,    6,  55, 276},
    {   3,  10,  171, 153, 231},
    { 105,  45,   15,  21, 136},
    { 210,  66,  253, 120,  78}
};
static uint32_t rho(uint64_t A[5][5])
{
    uint64_t Ap[5][5];
    uint32_t x, y, m;
    uint32_t t;

    memset(Ap, 0, sizeof(Ap));
    /* let A'[0,0,z]=A[0,0,z] */
    memcpy(Ap[0], A[0], sizeof(Ap[0]));

    /* let (x,y) = (1,0) */
    x = 1;
    y = 0;
    #if 0
    /* calculate directly */
    for (t=0; t<24; t++)
    {
        Ap[y][x] = ROTL(A[y][x], ((t+1)*(t+2)/2)%64);
        m = x;
        x = y;
        y = (2*m + 3*y) % 5;
    }
    #else
    /* look up table */
    for (t=0; t<24; t++)
    {
        Ap[y][x] = ROTL(A[y][x], Rp[y][x]%64);
        /* let (x,y) = (y,(2x+3y)%5) */
        m = x;
        x = y;
        y = (2*m+3*y) % 5;
    }
    #endif

    memcpy(A, Ap, sizeof(Ap));
    return 0;
}

static uint32_t pi(uint64_t A[5][5])
{
    uint64_t Ap[5][5];
    uint32_t x, y;

    memset(Ap, 0, sizeof(Ap));
    for (y=0; y<5; y++)
    {
        for (x=0; x<5; x++)
        {
            Ap[y][x] = A[x][(x+3*y)%5];
        }
    }

    memcpy(A, Ap, sizeof(Ap));
    return 0;
}

static void dump_lane(uint64_t lane[5][5])
{
    uint32_t x, y;

    for (y=0; y<5; y++) /* row */
    {
        for (x=0; x<5; x++) /* col */
        {
            DBG("[%d, %d]: %016llx  ", x, y, lane[y][x]);
        }
        DBG("\n");
    } 
    return;
}

static uint32_t chi(uint64_t A[5][5])
{
    uint64_t Ap[5][5];
    uint32_t x, y;

    memset(Ap, 0, sizeof(Ap));
    for (y=0; y<5; y++)
    {
        for (x=0; x<5; x++)
        {
            Ap[y][x] = A[y][x] ^ ((~A[y][(x+1)%5]) & A[y][(x+2)%5]);
        }
    }

    memcpy(A, Ap, sizeof(Ap));
    return 0;
}

static uint64_t RC[24] =
{
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
};
static uint32_t iota(uint64_t A[5][5], uint32_t i)
{
    A[0][0] = A[0][0] ^ RC[i];

    return 0;
}


/*
 * "abc" -->   0x61,     0x62,     0x63
 *   Origin: 0b0110 0001 0110 0010 0110 0011
 *  Padding: 0b0110 0001 0110 0010 0110 0011 1000 0000 .... 0000 0000  0000 0000 .... 0001 1000
 *                                          (|<-------------------->|)(|<------- 0x18 ------->|)
 *   Format: "abc" + 1 + 0 x 423 + 0x18
 */

int SHA3_Init(SHA3_CTX *c, SHA3_ALG alg)
{
    if (NULL == c)
    {
        return ERR_INV_PARAM;
    }

    if ((alg == SHAKE128) || (alg == SHAKE256))
    {
        return ERR_INV_PARAM;
    }

	memset(c, 0, sizeof(SHA3_CTX));

    /* bits */
    c->l = 6;
    c->w = 64; /* c->w = 2 ^ l */

    /* bytes */
	c->b = 200; /* 1600 bits, c->b = 25 * 2 ^ c->l; */
    switch (alg)
    {
        case SHA3_224:
            c->r  = 144; /* 1152 bits */
            c->c  =  56; /*  448 bits */
            c->ol =  28; /*  224 bits */
            break;
        case SHA3_256:
            c->r  = 136; /* 1088 bits */
            c->c  =  64; /*  512 bits */
            c->ol =  32; /*  256 bits */
            break;
        case SHA3_384:
            c->r  = 104; /*  832 bits */
            c->c  =  96; /*  768 bits */
            c->ol =  48; /*  384 bits */
            break;
        case SHA3_512:
            c->r  =  72; /*  576 bits */
            c->c  = 128; /* 1024 bits */
            c->ol =  64; /*  512 bits */
            break;
        default: /* default Keccak setting: SHA3_512 */
            c->r  =  72;
            c->c  = 128;
            c->ol =  64;
            break;
    }

    c->nr = 24; /* nr = 24 = 12 + 2 * l */

	return ERR_OK;
}

static int SHA3_PrepareScheduleWord(SHA3_CTX *ctx, const void *block)
{
	uint32_t i;
    uint64_t *data;
    uint64_t temp[25];

    if ((NULL == ctx) || (NULL == block))
    {
        return ERR_INV_PARAM;
    }

    for (i=0; i<ctx->b/8; i++)
    {
        if (i<ctx->r/8)
        {
            //temp[i] = be64toh(QWORD(block, i));
            temp[i] = QWORD(block, i);
        }
        else
        {
            temp[i] = 0x0;
        }
    }
#if (DUMP_SCHED_DATA == 1)
    DBG("Data to absorbed:\n");
    //dump_lane(ctx->lane);
    print_buffer(temp, ctx->b, " ");
#endif

#if (DUMP_SCHED_DATA == 1)
    DBG("SchedWord: [before]\n");
    //dump_lane(ctx->lane);
    print_buffer(&ctx->lane[0][0], ctx->b, " ");
#endif

    /* initial S */
    data = &ctx->lane[0][0];

    for (i=0; i<ctx->b/8; i++)
    {
        data[i] ^= temp[i];
    }

#if (DUMP_SCHED_DATA == 1)
    DBG("SchedWord: [after]\n");
    //dump_lane(ctx->lane);
    print_buffer(&ctx->lane[0][0], ctx->b, " ");
    dump_lane(ctx->lane);
#endif

	return ERR_OK;
}

/* r bytes for each block */
static int SHA3_ProcessBlock(SHA3_CTX *ctx, const void *block)
{
	uint32_t t;

    if ((NULL == ctx) || (NULL == block))
    {
        return ERR_INV_PARAM;
    }

#if (DUMP_BLOCK_DATA == 1)
    DBG("BLOCK DATA:\n");
    print_buffer(block, ctx->r, " ");
#endif

    SHA3_PrepareScheduleWord(ctx, block);

    for (t=0; t<ctx->nr; t++)
    {
#if (DUMP_ROUND_DATA == 1)
        DBG("Round #%d:\n", t);
#endif

        theta(ctx->lane);
#if (DUMP_ROUND_DATA == 1)
        DBG("After Theta:\n");
        print_buffer(&ctx->lane[0][0], ctx->b, " ");
#endif
        //rho_and_pi(ctx->lane);
        rho(ctx->lane);
#if (DUMP_ROUND_DATA == 1)
        DBG("After Rho:\n");
        print_buffer(&ctx->lane[0][0], ctx->b, " ");
#endif
        pi(ctx->lane);
#if (DUMP_ROUND_DATA == 1)
        DBG("After Pi:\n");
        print_buffer(&ctx->lane[0][0], ctx->b, " ");
#endif
        chi(ctx->lane);
#if (DUMP_ROUND_DATA == 1)
        DBG("After Chi:\n");
        print_buffer(&ctx->lane[0][0], ctx->b, " ");
#endif
        iota(ctx->lane, t);
#if (DUMP_ROUND_DATA == 1)
        DBG("After Iota:\n");
        print_buffer(&ctx->lane[0][0], ctx->b, " ");
#endif
    }

#if (DUMP_BLOCK_HASH == 1)
    DBG("After Permutation:\n");
    print_buffer(&ctx->lane[0][0], ctx->b, " ");
#endif

	return ERR_OK;
}

int SHA3_Update(SHA3_CTX *c, const void *data, size_t len)
{
	uint64_t copy_len = 0;

    if ((NULL == c) || (NULL == data))
    {
        return ERR_INV_PARAM;
    }

	/* has used data */
	if (c->last.used != 0)
	{
		/* less than 1 block in total, combine data */
		if (c->last.used + len < c->r)
		{
			memcpy(&c->last.buf[c->last.used], data, len);
			c->last.used += len;

			return ERR_OK;
		}
		else /* more than 1 block */
		{
			/* process the block in context buffer */
			copy_len = c->r - c->last.used;
			memcpy(&c->last.buf[c->last.used], data, copy_len);
			SHA3_ProcessBlock(c, &c->last.buf);

			data = (uint8_t *)data + copy_len;
			len -= copy_len;

			/* reset context buffer */
			memset(&c->last.buf[0], 0, c->r);
			c->last.used = 0;
		}
	}

	/* less than 1 block, copy to context buffer */
	if (len < c->r)
	{
		memcpy(&c->last.buf[c->last.used], data, len);
		c->last.used += len;

		return ERR_OK;
	}
	else
	{
		/* process data blocks */
        while (len >= c->r)
		{
			SHA3_ProcessBlock(c, data);

			data = (uint8_t *)data + c->r;
			len -= c->r;
		}

		/* copy rest data to context buffer */
		memcpy(&c->last.buf[0], data, len);
		c->last.used = len;
	}

	return ERR_OK;
}

int SHA3_Final(unsigned char *md, SHA3_CTX *c)
{
    if ((NULL == c) || (NULL == md))
    {
        return ERR_INV_PARAM;
    }

    /* more than 2 bytes left, padding 0x06...0x80 (0x */
    if (c->last.used <= (c->r - 2))
    {
        /* one more block */
        c->last.buf[c->last.used] = SHA3_PADDING_PAT2_BEGIN;
        c->last.used++;

        memset(&c->last.buf[c->last.used], 0, (c->r - 1) - c->last.used);
        c->last.used = c->r - 1;

        c->last.buf[c->last.used] = SHA3_PADDING_PAT2_END;
        c->last.used++;
    }
    else /* if (c->last.used == (c->r - 1)) */ /* only 1 bytes left, padding 0x86(0x61 in reverse) */
    {
        c->last.buf[c->last.used] = SHA3_PADDING_PAT1;
        c->last.used++;
    }

    SHA3_ProcessBlock(c, &c->last.buf);
    c->last.used = 0;

    dump_lane(c->lane);

    memcpy(md, &c->lane[0][0], c->ol);

	return ERR_OK;
}

unsigned char *SHA3(SHA3_ALG alg, const unsigned char *d, size_t n, unsigned char *md)
{
    SHA3_CTX c;

    SHA3_Init(&c, alg);
    SHA3_Update(&c, d, n);
    SHA3_Final(md, &c);

    return md;
}

