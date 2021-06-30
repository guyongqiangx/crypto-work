/*
 * @        file: hash.c
 * @ description: implementation for Hash(Message Digest) Algorithm
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "type.h"

#include "hash_tables.h"
#include "hash.h"
#include "utils.h"

int HASH_Init(HASH_CTX *ctx, HASH_ALG alg)
{
    int rc = ERR_OK;
    HASH_STRUCT *impl = NULL;

    if ((NULL == ctx)
      || (alg >= HASH_ALG_MAX) || (HASH_ALG_SHA512_T == alg) || (HASH_ALG_SHAKE128 == alg) || (HASH_ALG_SHAKE256 == alg))
    {
        return ERR_INV_PARAM;
    }

    impl = create_hash_struct(alg, 0);

    ctx->impl = impl;
    if (impl->init != NULL)
    {
        rc = impl->init(impl->context);
    }

    return rc;
}

int HASH_Update(HASH_CTX *ctx, const void *data, size_t len)
{
    HASH_STRUCT *impl;
    if ((NULL == ctx) || (NULL == ctx->impl) || (NULL == data))
    {
        return ERR_INV_PARAM;
    }

    impl = (HASH_STRUCT *)ctx->impl;
    return impl->update(impl->context, data, len);
}

int HASH_Final(unsigned char *md, HASH_CTX *ctx)
{
    int rc = ERR_OK;
    HASH_STRUCT *impl;
    if ((NULL == ctx) || (NULL == ctx->impl) || (NULL == md))
    {
        return ERR_INV_PARAM;
    }

    impl = (HASH_STRUCT *)ctx->impl;
    rc = impl->final(md, impl->context);

    destroy_hash_struct(ctx->impl);
    ctx->impl = NULL;

    return rc;
}

unsigned char *HASH(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md)
{
    int rc = ERR_OK;
    HASH_CTX ctx;

    if ((alg >= HASH_ALG_MAX) || (NULL == data) || (NULL == md))
    {
        return NULL;
    }

    rc = HASH_Init(&ctx, alg);
    if (rc != ERR_OK)
    {
        return NULL;
    }

    rc = HASH_Update(&ctx, data, n);
    if (rc != ERR_OK)
    {
        return NULL;
    }

    HASH_Final(md, &ctx);

    return md;
}

int HASH_Init_Ex(HASH_CTX *ctx, HASH_ALG alg, uint32_t ext)
{
    int rc = ERR_OK;
    HASH_STRUCT *impl = NULL;

    if ((NULL == ctx)
      || ((HASH_ALG_SHA512_T != alg) && (HASH_ALG_SHAKE128 != alg) && (HASH_ALG_SHAKE256 != alg)))
    {
        return ERR_INV_PARAM;
    }

    impl = create_hash_struct(alg, ext);

    ctx->impl = impl;
    if (impl->init_ex != NULL)
    {
        rc = impl->init_ex(impl->context, impl->ext);
    }

    return rc;
}

unsigned char *HASH_Ex(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md, uint32_t ext)
{
    int rc = ERR_OK;
    HASH_CTX ctx;

    if ((alg >= HASH_ALG_MAX) || (NULL == data) || (NULL == md))
    {
        return NULL;
    }

    rc = HASH_Init_Ex(&ctx, alg, ext);
    if (rc != ERR_OK)
    {
        return NULL;
    }

    rc = HASH_Update(&ctx, data, n);
    if (rc != ERR_OK)
    {
        return NULL;
    }

    HASH_Final(md, &ctx);

    return md;
}
