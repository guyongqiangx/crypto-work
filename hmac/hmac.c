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

int HMAC_Init(HMAC_CTX *ctx, HASH_ALG alg, const void *key, unsigned int key_len)
{
    int rc = ERR_OK;

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
    if ((NULL == ctx) || (alg >= HASH_ALG_MAX)
      || (HASH_ALG_SHA512_T == alg) || (HASH_ALG_SHAKE128 == alg) || (HASH_ALG_SHAKE256 == alg))
    {
        return ERR_INV_PARAM;
    }

    memset(ctx, 0, sizeof(HMAC_CTX));
    ctx->alg = alg;
    ctx->block_size = HMAC_GetBlockSize(alg);
    ctx->digest_size = HMAC_GetDigestSize(alg, 0);

    /*
     * prepare kp and kp_len
     */
    /* if K > B, hash K to obtain an L byte string, will append 0 later. (i.e., K0 = H(K) || 00...00). */
    if (key_len > ctx->block_size)
    {
        kp_len = ctx->digest_size;
        kp = (unsigned char *)malloc(kp_len);
        if (NULL == kp)
        {
            printf("Out of memory in %s\n", __FUNCTION__);
            rc = ERR_OUT_OF_MEMORY;
            goto clean;
        }
        HASH(ctx->alg, key, key_len, kp);
    }
    else /* if K <= B, will append 0 directly. (i.e., K0 = K || 00...00). */
    {
        kp_len = key_len;
        kp = (unsigned char *)key;
    }

    /* calculate Si in advance */
    S = malloc(ctx->block_size);
    if (NULL == S)
    {
        printf("Out of memory in %s\n", __FUNCTION__);
        rc = ERR_OUT_OF_MEMORY;
        goto clean;
    }

    /* copy kp and append 0 */
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

    HASH_Init(hashi, ctx->alg);
    HASH_Update(hashi, S, ctx->block_size);
    ctx->hashi = hashi;

    /* calculate So in advance */
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

    HASH_Init(hasho, ctx->alg);
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
    if ((NULL == ctx) || (NULL == ctx->hashi) || (NULL == ctx->hasho) || (NULL == data))
    {
        return ERR_INV_PARAM;
    }

    HASH_Update(ctx->hashi, data, len);

    return ERR_OK;
}

int HMAC_Final(unsigned char *md, HMAC_CTX *ctx)
{
    unsigned char *temp = NULL;

    if ((NULL == ctx) || (NULL == ctx->hashi) || (NULL == ctx->hasho) || (NULL == md))
    {
        return ERR_INV_PARAM;
    }

    temp = (unsigned char *)malloc(ctx->digest_size);
    if (NULL == temp)
    {
        printf("Out of memory in %s\n", __FUNCTION__);
        return ERR_OUT_OF_MEMORY;
    }

    HASH_Final(temp, ctx->hashi);

    HASH_Update(ctx->hasho, temp, ctx->digest_size);
    HASH_Final(md, ctx->hasho);

    free(temp);
    temp = NULL;

    /* free context hashi and hasho */
    free(ctx->hashi);
    ctx->hashi = NULL;

    free(ctx->hasho);
    ctx->hasho = NULL;

    return ERR_OK;
}

unsigned char *HMAC(HASH_ALG alg, const void *key, unsigned int key_len, const unsigned char *data, size_t n, unsigned char *md)
{
    HMAC_CTX ctx;

    if ((NULL == key) || (NULL == data) || (NULL == md) || (0 == key_len))
    {
        return NULL;
    }

    if ((alg >= HASH_ALG_MAX) || (HASH_ALG_SHA512_T == alg) || (HASH_ALG_SHAKE128 == alg) || HASH_ALG_SHAKE256 == alg)
    {
        return NULL;
    }

    HMAC_Init(&ctx, alg, key, key_len);
    HMAC_Update(&ctx, data, n);
    HMAC_Final(md, &ctx);

    return md;
}

int HMAC_Init_Ex(HMAC_CTX *ctx, HASH_ALG alg, const void *key, unsigned int key_len, uint32_t ext)
{
    int rc = ERR_OK;

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
    if ((NULL == ctx) || (alg >= HASH_ALG_MAX)
      || ((HASH_ALG_SHA512_T != alg) && (HASH_ALG_SHAKE128 != alg) && (HASH_ALG_SHAKE256 != alg)))
    {
        return ERR_INV_PARAM;
    }

    memset(ctx, 0, sizeof(HMAC_CTX));
    ctx->alg = alg;
    ctx->block_size = HMAC_GetBlockSize(alg);
    ctx->digest_size = HMAC_GetDigestSize(alg, ext);

    /*
     * prepare kp and kp_len
     */
    /* if K > B, hash K to obtain an L byte string, then append 0. (i.e., K0 = H(K) || 00...00). */
    if (key_len > ctx->block_size)
    {
        kp_len = ctx->digest_size;
        kp = (unsigned char *)malloc(kp_len);
        if (NULL == kp)
        {
            printf("Out of memory in %s\n", __FUNCTION__);
            rc = ERR_OUT_OF_MEMORY;
            goto clean;
        }
        HASH_Ex(ctx->alg, key, key_len, kp, ext);
    }
    else /* if K <= B, append 0 directly. (i.e., K0 = K || 00...00). */
    {
        kp_len = key_len;
        kp = (unsigned char *)key;
    }

    /* calculate Si in advance */
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

    HASH_Init_Ex(hashi, ctx->alg, ext);
    HASH_Update(hashi, S, ctx->block_size);
    ctx->hashi = hashi;

    /* calculate So in advance */
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

    HASH_Init_Ex(hasho, ctx->alg, ext);
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

unsigned char *HMAC_Ex(HASH_ALG alg,  const void *key, unsigned int key_len, const unsigned char *data, size_t n, unsigned char *md, uint32_t ext)
{
    HMAC_CTX ctx;

    if ((NULL == key) || (NULL == data) || (NULL == md) || (0 == key_len))
    {
        return NULL;
    }

    if ((alg >= HASH_ALG_MAX)
      || ((HASH_ALG_SHA512_T != alg) && (HASH_ALG_SHAKE128 != alg) && (HASH_ALG_SHAKE256 != alg)))
    {
        return NULL;
    }

    HMAC_Init_Ex(&ctx, alg, key, key_len, ext);
    HMAC_Update(&ctx, data, n);
    HMAC_Final(md, &ctx);

    return md;
}

uint32_t HMAC_GetBlockSize(HASH_ALG alg)
{
    return HASH_GetBlockSize(alg);
}

uint32_t HMAC_GetDigestSize(HASH_ALG alg, uint32_t ext)
{
    return HASH_GetDigestSize(alg, ext);
}