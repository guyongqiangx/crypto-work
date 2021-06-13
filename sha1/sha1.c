#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "sha1.h"

//#define DEBUG

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

#if 0
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
#else
#define HASH_BLOCK_SIZE		    64	/* 512 bits = 64 Bytes */
#define HASH_LEN_SIZE	 	    8	/* 64 bits = 8 bytes */
#define HASH_LEN_OFFSET         (HASH_BLOCK_SIZE - HASH_LEN_SIZE)
#define HASH_DIGEST_SIZE        20 /* 160 bits = 20 bytes */

#define HASH_PADDING_PATTERN 	0x80
#define HASH_ROUND_NUM			80
#endif

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

int SHA1_Init(SHA_CTX *c)
{
    if (NULL == c)
    {
        return ERR_INV_PARAM;
    }

    memset(c, 0, sizeof(SHA_CTX));

    c->hash.a = 0x67452301;
    c->hash.b = 0xEFCDAB89;
    c->hash.c = 0x98BADCFE;
    c->hash.d = 0x10325476;
    c->hash.e = 0xC3D2E1F0;

    c->total = 0;
    c->last.used = 0;

    return ERR_OK;
}

static int SHA1_PrepareScheduleWord(const void *block, uint32_t *W)
{
    uint32_t t;

    if ((NULL == block) || (NULL == W))
    {
        return ERR_INV_PARAM;
    }

    for (t=0; t<HASH_ROUND_NUM; t++)
    {
        if (t<=15) /*  0 <= t <= 15 */
            W[t] = be32toh(DWORD(block, t));
        else	   /* 16 <= t <= 79 */
            W[t] = ROTL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    return ERR_OK;
}

static int SHA1_ProcessBlock(SHA_CTX *ctx, const void *block)
{
    uint32_t t;
    uint32_t W[HASH_ROUND_NUM];
    uint32_t T;
    uint32_t a, b, c, d, e;

    if ((NULL == ctx) || (NULL == block))
    {
        return ERR_INV_PARAM;
    }

#if (DUMP_BLOCK_DATA == 1)
    DBG("BLOCK: %llu\n", ctx->total/HASH_BLOCK_SIZE);
    print_buffer(block, HASH_BLOCK_SIZE, " ");
#endif

    /* prepare schedule word */
    SHA1_PrepareScheduleWord(block, W);

    a = ctx->hash.a;
    b = ctx->hash.b;
    c = ctx->hash.c;
    d = ctx->hash.d;
    e = ctx->hash.e;

#if (DUMP_BLOCK_HASH == 1)
    DBG(" LAST: %08x%08x%08x%08x%08x\n",
        ctx->hash.a, ctx->hash.b, ctx->hash.c, ctx->hash.d, ctx->hash.e);
#endif

    for (t=0; t<HASH_ROUND_NUM; t++)
    {
        T = ROTL(a, 5) + (F[t/20])(b, c, d) + e + K[t/20] + W[t];
        e = d;
        d = c;
        c = ROTL(b, 30);
        b = a;
        a = T;

#if (DUMP_ROUND_DATA == 1)
        DBG("   %02d: T=0x%08x, W=0x%08x, a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x, e=0x%08x\n",
                t, T, W[t], a, b, c, d, e);
#endif
    }

    ctx->hash.a += a;
    ctx->hash.b += b;
    ctx->hash.c += c;
    ctx->hash.d += d;
    ctx->hash.e += e;

#if (DUMP_BLOCK_HASH == 1)
    DBG(" HASH: %08x%08x%08x%08x%08x\n",
        ctx->hash.a, ctx->hash.b, ctx->hash.c, ctx->hash.d, ctx->hash.e);
#endif

    return ERR_OK;
}

int SHA1_Update(SHA_CTX *c, const void *data, size_t len)
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
            SHA1_ProcessBlock(c, &c->last.buf);
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
        while (len >= HASH_BLOCK_SIZE)
        {
            SHA1_ProcessBlock(c, data);
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

int SHA1_Final(unsigned char *md, SHA_CTX *c)
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
        SHA1_ProcessBlock(c, &c->last.buf);

        memset(&c->last.buf[0], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE);
        c->last.used = 0;
 
        // *(uint64_t *)&(c->last.buf[HASH_LEN_OFFSET]) = htobe64(c->total << 3);
        htobe64c(&(c->last.buf[HASH_LEN_OFFSET]), c->total << 3);
        SHA1_ProcessBlock(c, &c->last.buf);
    }
    else /* 0 <= last.used < HASH_BLOCK_SIZE - HASH_LEN_SIZE */
    {
        c->total += c->last.used;

        /* one more block */
        c->last.buf[c->last.used] = HASH_PADDING_PATTERN;
        c->last.used++;

        /* padding 0s */
        memset(&c->last.buf[c->last.used], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE - c->last.used);

        // *(uint64_t *)&c->last.buf[HASH_LEN_OFFSET] = htobe64(c->total << 3);
        htobe64c(&(c->last.buf[HASH_LEN_OFFSET]), c->total << 3);
        SHA1_ProcessBlock(c, &c->last.buf);
    }

    buf = (uint32_t *)md;
    buf[0] = htobe32(c->hash.a);
    buf[1] = htobe32(c->hash.b);
    buf[2] = htobe32(c->hash.c);
    buf[3] = htobe32(c->hash.d);
    buf[4] = htobe32(c->hash.e);

    return ERR_OK;
}

unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md)
{
    SHA_CTX c;

    if ((NULL == d) || (NULL == md))
    {
        return NULL;
    }

    SHA1_Init(&c);
    SHA1_Update(&c, d, n);
    SHA1_Final(md, &c);

    return md;
}
