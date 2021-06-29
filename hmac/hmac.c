#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "type.h"

#include "hash.h"
#include "hmac.h"
#include "utils.h"

/* inner pad */
#define HMAC_IPAD   0x36
/* outer pad */
#define HMAC_OPAD   0x5c

/* HMAC_ALG to HASH_ALG mapping */
static struct hmac2hash {
    HMAC_ALG hmac_alg;
    HASH_ALG hash_alg;
    uint32_t block_size;/* block size for hash */
    uint32_t md_size;   /* message digest size, same as default hmac size */
    uint32_t flag;      /* 0: fixed md_size; 1: variable md_size; */
} hmac_lists[HMAC_ALG_MAX] =
{
  /* HMAC_ALG,            HASH_ALG,     block_size, md_size, flag */
    {HMAC_ALG_MD2,        HASH_ALG_MD2,         16,      16, 0},
    {HMAC_ALG_MD4,        HASH_ALG_MD4,         64,      16, 0},
    {HMAC_ALG_MD5,        HASH_ALG_MD5,         64,      16, 0},
    {HMAC_ALG_SHA1,       HASH_ALG_SHA1,        64,      20, 0},
    {HMAC_ALG_SHA224,     HASH_ALG_SHA224,      64,      28, 0},
    {HMAC_ALG_SHA256,     HASH_ALG_SHA256,      64,      32, 0},
    {HMAC_ALG_SHA384,     HASH_ALG_SHA384,      128,     48, 0},
    {HMAC_ALG_SHA512,     HASH_ALG_SHA512,      128,     64, 0},
    {HMAC_ALG_SHA512_224, HASH_ALG_SHA512_224,  128,     28, 0},
    {HMAC_ALG_SHA512_256, HASH_ALG_SHA512_256,  128,     32, 0},
    {HMAC_ALG_SHA512_T,   HASH_ALG_SHA512_T,    128,     0,  1},
    {HMAC_ALG_SHA3_224,   HASH_ALG_SHA3_224,    144,     28, 0},
    {HMAC_ALG_SHA3_256,   HASH_ALG_SHA3_256,    136,     32, 0},
    {HMAC_ALG_SHA3_384,   HASH_ALG_SHA3_384,    104,     48, 0},
    {HMAC_ALG_SHA3_512,   HASH_ALG_SHA3_512,    72,      64, 0},
    {HMAC_ALG_SHAKE128,   HASH_ALG_SHAKE128,    168,     0,  1},
    {HMAC_ALG_SHAKE256,   HASH_ALG_SHAKE256,    136,     0,  1},
    {HMAC_ALG_SM3,        HASH_ALG_SM3,         64,      32, 0},
};

int HMAC_Init(HMAC_CTX *ctx, HMAC_ALG alg, const void *key, unsigned int key_len)
{
    int rc = ERR_OK;
    struct hmac2hash *item = NULL;
    unsigned char *kp = NULL;
    uint32_t kp_len = 0;

    unsigned char *S= NULL; /* Pointer for buffer Si, So */

    HASH_CTX *hashi = NULL;
    HASH_CTX *hasho = NULL;

    uint32_t i;

    /* check key */
    if ((NULL == key) || (0 == key_len))
    {
        return ERR_INV_PARAM;
    }

    /* check ctx and algorithm */
    if ((NULL == ctx) || (alg >= HMAC_ALG_INVALID) || (alg != hmac_lists[alg].hmac_alg))
    {
        return ERR_INV_PARAM;
    }

    memset(ctx, 0, sizeof(HMAC_CTX));

    item = &hmac_lists[alg];
    ctx->hmac_alg = item->hmac_alg;
    ctx->hash_alg = item->hash_alg;
    ctx->block_size = item->block_size;
    ctx->md_size = item->md_size;

    /* prepare kp and kp_len */
    if (key_len > ctx->md_size)
    {
        kp_len = ctx->md_size;
        kp = (unsigned char *)malloc(kp_len);
        if (NULL == kp)
        {
            printf("Out of memory in %s\n", __FUNCTION__);
            rc = ERR_OUT_OF_MEMORY;
            goto clean;
        }
        HASH(ctx->hash_alg, key, key_len, kp);
    }
    else
    {
        kp_len = key_len;
        kp = (unsigned char *)key;
    }

    /* prepare Si */
    S = malloc(ctx->block_size);
    if (NULL == S)
    {
        printf("Out of memory in %s\n", __FUNCTION__);
        rc = ERR_OUT_OF_MEMORY;
        goto clean;
    }

    memcpy(S, kp, kp_len);
    memset(&S[kp_len], 0, ctx->block_size-kp_len);
    for (i=0; i<ctx->block_size; i++)
    {
        S[i] ^= HMAC_IPAD;
    }

    hashi = (HASH_CTX *)malloc(sizeof(HASH_CTX));
    if (NULL == hashi)
    {
        printf("Out of memory in %s\n", __FUNCTION__);
        rc = ERR_OUT_OF_MEMORY;
        goto clean;
    }

    HASH_Init(hashi, ctx->hash_alg);
    HASH_Update(hashi, S, ctx->block_size);
    ctx->hashi = hashi;

    /* resue S for So */
    memcpy(S, kp, kp_len);
    memset(&S[kp_len], 0, ctx->block_size-kp_len);
    for (i=0; i<ctx->block_size; i++)
    {
        S[i] ^= HMAC_OPAD;
    }

    hasho = (HASH_CTX *)malloc(sizeof(HASH_CTX));
    if (NULL == hasho)
    {
        printf("Out of memory: %s\n", __FUNCTION__);
        free(hashi);
        hashi = NULL;
        rc = ERR_OUT_OF_MEMORY;
        goto clean;
    }

    HASH_Init(hasho, ctx->hash_alg);
    HASH_Update(hasho, S, ctx->block_size);
    ctx->hasho = hasho;

clean:
    if (S != NULL)
    {
        free(S);
        S = NULL;
    }
    if ((NULL != kp) && (key != kp))
    {
        free(kp);
        kp = NULL;
    }

    return rc;
}

int HMAC_Update(HMAC_CTX *ctx, const void *data, size_t len)
{
    if ((NULL == ctx) || (NULL == data))
    {
        return ERR_INV_PARAM;
    }

    HASH_Update(ctx->hashi, data, len);

    return ERR_OK;
}

int HMAC_Final(unsigned char *md, HMAC_CTX *ctx)
{
    unsigned char *temp = NULL;

    if ((NULL == ctx) || (NULL == md))
    {
        return ERR_INV_PARAM;
    }

    temp = (unsigned char *)malloc(ctx->md_size);
    if (NULL == temp)
    {
        printf("Out of memory in %s\n", __FUNCTION__);
        return ERR_OUT_OF_MEMORY;
    }

    HASH_Final(temp, ctx->hashi);

    HASH_Update(ctx->hasho, temp, ctx->md_size);
    HASH_Final(md, ctx->hasho);

    free(temp);
    temp = NULL;

    return ERR_OK;
}

unsigned char *HMAC(HMAC_ALG alg, const void *key, unsigned int key_len, const unsigned char *data, size_t n, unsigned char *md)
{
    HMAC_CTX ctx;

    if ((NULL == key) || (NULL == data) || (NULL == md) || (0 == key_len) || (alg >= HMAC_ALG_INVALID))
    {
        return NULL;
    }

    HMAC_Init(&ctx, alg, key, key_len);
    HMAC_Update(&ctx, data, n);
    HMAC_Final(md, &ctx);
    HMAC_UnInit(&ctx);

    return md;
}

int HMAC_UnInit(HMAC_CTX *ctx)
{
    if (NULL == ctx)
    {
        return ERR_INV_PARAM;
    }

    if (ctx->hashi)
    {
        free(ctx->hashi);
        ctx->hashi = NULL;
    }

    if (ctx->hasho)
    {
        free(ctx->hasho);
        ctx->hasho = NULL;
    }

    memset(ctx, 0, sizeof(HMAC_CTX));

    return ERR_OK;
}

int HMAC_Init_Ex(HMAC_CTX *ctx, HMAC_ALG alg, const void *key, unsigned int key_len, uint32_t ext)
{
    return ERR_OK;
}

unsigned char *HMAC_Ex(HMAC_ALG alg,  const void *key, unsigned int key_len, const unsigned char *data, size_t n, unsigned char *md, uint32_t ext)
{
    return ERR_OK;
}