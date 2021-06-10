#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "sha3.h"

#define DEBUG

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

#if 0
#define SHA3_BLOCK_SIZE			128	/* 1024 bits = 128 bytes */
#define SHA3_LEN_SIZE	 			 16	/*  128 bits =  16 bytes */
#define SHA3_LEN_OFFSET 			(SHA3_BLOCK_SIZE - SHA3_LEN_SIZE)
#define SHA3_DIGEST_SIZE			 64 /*  512 bits =  64 bytes */

#define SHA3_PADDING_PATTERN 	   0x80
#define SHA3_ROUND_NUM			 80

#define SHA384_DIGEST_SIZE			 48 /*  384 bits =  48 bytes */
#define SHA3_224_DIGEST_SIZE	     28 /*  224 bits =  28 bytes */
#define SHA3_256_DIGEST_SIZE	     32 /*  256 bits =  32 bytes */

#define HASH_BLOCK_SIZE		SHA3_BLOCK_SIZE
#define HASH_LEN_SIZE		SHA3_LEN_SIZE
#define HASH_LEN_OFFSET		SHA3_LEN_OFFSET

#define HASH_DIGEST_SIZE	SHA3_DIGEST_SIZE

#define HASH_PADDING_PATTERN	SHA3_PADDING_PATTERN
#define HASH_ROUND_NUM			SHA3_ROUND_NUM

/* SHA3 Constants */
static const uint64_t K512[HASH_ROUND_NUM] =
{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};
#else
/* b'01 100001, 0x61 */
#define SHA3_PADDING_PAT1        0x61

/* b'01 100000...00000001, 0x60...0x01 */
#define SHA3_PADDING_PAT2_BEGIN  0x60
#define SHA3_PADDING_PAT2_END    0x01
#endif

#if 1
/* ROTate Left (circular left shift) */
static uint64_t ROTL(uint64_t x, uint8_t shift)
{
	return (x << shift) | (x >> (64 - shift));
}
#endif

/* ROTate Right (cirular right shift) */
static uint64_t ROTR(uint64_t x, uint8_t shift)
{
	return (x >> shift) | (x << (64 - shift));
}

#if 0
/* Right SHift */
static uint64_t SHR(uint64_t x, uint8_t shift)
{
	return (x >> shift);
}

/* Ch ... choose */
static uint64_t Ch(uint64_t x, uint64_t y, uint64_t z)
{
	//DBG("    Ch(0x%016llx, 0x%016llx, 0x%016llx);\n", x, y, z);
	return (x & y) ^ (~x & z) ;
}

/* Maj ... majority */
static uint64_t Maj(uint64_t x, uint64_t y, uint64_t z)
{
	//DBG("   Maj(0x%016llx, 0x%016llx, 0x%016llx);\n", x, y, z);
	return (x & y) ^ (x & z) ^ (y & z);
}

/* SIGMA0 */
static uint64_t SIGMA0(uint64_t x)
{
	return ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39);
}

/* SIGMA1 */
static uint64_t SIGMA1(uint64_t x)
{
	return ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41);
}

/* sigma0, different from SIGMA0 */
static uint64_t sigma0(uint64_t x)
{
	return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7);
}

/* sigma1, different from SIGMA1 */
static uint64_t sigma1(uint64_t x)
{
	return ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6);
}
#endif

static uint32_t theta(uint64_t A[5][5])
{
    uint32_t x, y;
    uint64_t C[5], D[5];

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
            A[y][x] = A[y][x] ^ D[x];
        }
    }

    return 0;
}

/* rotation constants, aka rotation offsets */
static uint32_t R[5][5] =
{
    {  0, 36,  3, 41, 18},
    {  1, 44, 10, 45,  2},
    { 62,  6, 43, 15, 61},
    { 28, 55, 25, 21, 56},
    { 27, 20, 39,  8, 14}
};
static uint32_t rho_and_pi(uint64_t A[5][5])
{
    uint64_t B[5][5];
    uint32_t x, y;

    for (x=0; x<5; x++)
    {
        for (y=0; y<5; y++)
        {
            B[y][(2*x+3*y)%5] = ROTR(A[x][y], R[x][y]);
        }
    }

    memcpy(A, B, sizeof(B));
    return 0;
}

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
    x = 1;
    y = 0;
    #if 0
    /* Note: Ap[0][0] is not been set */
    for (t=0; t<24; t++)
    {
        printf("[%u, %u]=%3d ", y, x, (t+1)*(t+2)/2);
        if (t%5==4)
            printf("\n");
        Ap[y][x] = ROTL(A[y][x], ((t+1)*(t+2)/2)%64);
        m = x;
        x = y;
        y = (2*m + 3*y) % 5;
    }
    printf("\n");
    #else
    /* Note: Ap[0][0] is not been set */
    for (t=0; t<24; t++)
    {
        Ap[y][x] = ROTL(A[y][x], Rp[y][x]%64);
        m = x;
        x = y;
        y = (2*m + 3*y) % 5;
    }
    #endif

    memcpy(A, Ap, sizeof(Ap));
    return 0;
}

static uint32_t pi(uint64_t A[5][5])
{
    uint64_t B[5][5];
    uint32_t x, y;

    for (x=0; x<5; x++)
    {
        for (y=0; y<5; y++)
        {
            B[y][(2*x+3*y)%5] = ROTR(A[x][y], R[x][y]);
        }
    }

    memcpy(A, B, sizeof(B));
    return 0;
}

#if 0
static uint32_t pi(uint64_t A[5][5])
{
    return 0;
}
#endif

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

static uint32_t chi(uint64_t B[5][5])
{
    uint64_t A[5][5];
    uint32_t x, y;

    for (x=0; x<5; x++)
    {
        for (y=0; y<5; y++)
        {
            A[x][y] = B[x][y] ^ ((~B[(x+2)%5][y]) & B[(x+2)%5][y]);
        }
    }

    memcpy(B, A, sizeof(A));
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
static uint32_t iota(uint64_t B[5][5], uint32_t i)
{
    B[0][0] ^= B[0][0] ^ RC[i];
    
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

    if ((NULL == ctx) || (NULL == block))
    {
        return ERR_INV_PARAM;
    }

#if (DUMP_SCHED_DATA == 1)
    DBG("SchedWord: [before]\n");
    //dump_lane(ctx->lane);
    print_buffer(&ctx->lane[0][0], ctx->b, " ");
#endif

    /* initial S */
    data = &ctx->lane[0][0];

    memset(data, 0, ctx->b);
    for (i=0; i<ctx->b/8; i++)
    {
        if (i<ctx->r/8)
        {
            data[i] ^= be64toh(QWORD(block, i));
        }
        else
        {
            data[i] ^= 0x0000000000000000;
        }
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
    print_buffer(block, ctx->r, " ");
#endif

    SHA3_PrepareScheduleWord(ctx, block);

    for (t=0; t<ctx->nr; t++)
    {
        theta(ctx->lane);
#if (DUMP_SCHED_DATA == 1)
        DBG("After Theta:\n");
        print_buffer(&ctx->lane[0][0], ctx->b, " ");
#endif
        //rho_and_pi(ctx->lane);
        rho(ctx->lane);
#if (DUMP_SCHED_DATA == 1)
        DBG("After Rho:\n");
        print_buffer(&ctx->lane[0][0], ctx->b, " ");
#endif
        pi(ctx->lane);
#if (DUMP_SCHED_DATA == 1)
        DBG("After Pi:\n");
        print_buffer(&ctx->lane[0][0], ctx->b, " ");
#endif
        chi(ctx->lane);
#if (DUMP_SCHED_DATA == 1)
        DBG("After Chi:\n");
        print_buffer(&ctx->lane[0][0], ctx->b, " ");
#endif
        iota(ctx->lane, t);

#if (DUMP_ROUND_DATA == 1)
        DBG("%02d:\n", t);
        dump_lane(ctx->lane);
#endif
    }

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
		while (len > c->r)
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
	uint64_t *buf;
    uint64_t *S;
    uint32_t i;

    if ((NULL == c) || (NULL == md))
    {
        return ERR_INV_PARAM;
    }

    /* more than 2 bytes left, padding 0x60...0x01 */
    if (c->last.used <= (c->r - 2))
    {
        /* one more block */
        c->last.buf[c->last.used] = SHA3_PADDING_PAT2_BEGIN;
        c->last.used++;

        memset(&c->last.buf[c->last.used], 0, (c->r - 1) - c->last.used);
        c->last.used = c->r - 1;

        c->last.buf[c->last.used] = SHA3_PADDING_PAT2_BEGIN;
        c->last.used++;
    }
    else /* if (c->last.used == (c->r - 1)) */ /* only 1 bytes left, padding 0x61 */
    {
        c->last.buf[c->last.used] = SHA3_PADDING_PAT1;
        c->last.used++;
    }

    SHA3_ProcessBlock(c, &c->last.buf);
    c->last.used = 0;

    dump_lane(c->lane);

	buf = (uint64_t *)md;
    S = (uint64_t *)c->lane[0][0];
    for (i=0; i<c->ol/8; i++)
    {
        buf[i] = htobe64(S[i]);
    }

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

