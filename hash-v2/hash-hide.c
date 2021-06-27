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

#include "md2.h"
#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "sha3ex.h"
#include "sm3.h"
#include "hash.h"
#include "utils.h"

typedef int (* OP_INIT)(void *ctx);
typedef int (* OP_UPDATE)(void *ctx, const void *data, size_t len);
typedef int (* OP_FINAL)(unsigned char *md, void *ctx);
typedef unsigned char * (* OP_HASH)(const unsigned char *data, size_t n, unsigned char *md);
typedef int (* OP_INIT_EX)(void *ctx, unsigned int ext);
typedef unsigned char * (* OP_HASH_EX)(const unsigned char *data, size_t n, unsigned char *md, unsigned int ext);

static struct hash_item {
    HASH_ALG   alg;

    uint32_t   st_size;

    OP_INIT    init;
    OP_UPDATE  update;
    OP_FINAL   final;
    OP_HASH    hash;

    OP_INIT_EX init_ex;
    OP_HASH_EX hash_ex;
} hash_lists[HASH_ALG_MAX] =
{
 /* { alg,                 st_size,            init,                     pdate,                        final,                      hash,                init_ex,                        hash_ex } */
    { HASH_ALG_MD2,        sizeof(MD2_CTX),    (OP_INIT)MD2_Init,        (OP_UPDATE)MD2_Update,        (OP_FINAL)MD2_Final,        (OP_HASH)MD2,        (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_MD4,        sizeof(MD4_CTX),    (OP_INIT)MD4_Init,        (OP_UPDATE)MD4_Update,        (OP_FINAL)MD4_Final,        (OP_HASH)MD4,        (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_MD5,        sizeof(MD5_CTX),    (OP_INIT)MD5_Init,        (OP_UPDATE)MD5_Update,        (OP_FINAL)MD5_Final,        (OP_HASH)MD5,        (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA1,       sizeof(SHA_CTX),    (OP_INIT)SHA1_Init,       (OP_UPDATE)SHA1_Update,       (OP_FINAL)SHA1_Final,       (OP_HASH)SHA1,       (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA224,     sizeof(SHA256_CTX), (OP_INIT)SHA224_Init,     (OP_UPDATE)SHA224_Update,     (OP_FINAL)SHA224_Final,     (OP_HASH)SHA224,     (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA256,     sizeof(SHA256_CTX), (OP_INIT)SHA256_Init,     (OP_UPDATE)SHA256_Update,     (OP_FINAL)SHA256_Final,     (OP_HASH)SHA256,     (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA384,     sizeof(SHA512_CTX), (OP_INIT)SHA384_Init,     (OP_UPDATE)SHA384_Update,     (OP_FINAL)SHA384_Final,     (OP_HASH)SHA384,     (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA512,     sizeof(SHA512_CTX), (OP_INIT)SHA512_Init,     (OP_UPDATE)SHA512_Update,     (OP_FINAL)SHA512_Final,     (OP_HASH)SHA512,     (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA512_224, sizeof(SHA512_CTX), (OP_INIT)SHA512_224_Init, (OP_UPDATE)SHA512_224_Update, (OP_FINAL)SHA512_224_Final, (OP_HASH)SHA512_224, (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA512_256, sizeof(SHA512_CTX), (OP_INIT)SHA512_256_Init, (OP_UPDATE)SHA512_256_Update, (OP_FINAL)SHA512_256_Final, (OP_HASH)SHA512_256, (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA512_T,   sizeof(SHA512_CTX), (OP_INIT)NULL,            (OP_UPDATE)SHA512t_Update,    (OP_FINAL)SHA512t_Final,    (OP_HASH)NULL,       (OP_INIT_EX)SHA512t_Init,       (OP_HASH_EX)SHA512t},
    { HASH_ALG_SHA3_224,   sizeof(SHA3_CTX),   (OP_INIT)SHA3_224_Init,   (OP_UPDATE)SHA3_Update,       (OP_FINAL)SHA3_Final,       (OP_HASH)SHA3_224,   (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA3_256,   sizeof(SHA3_CTX),   (OP_INIT)SHA3_256_Init,   (OP_UPDATE)SHA3_Update,       (OP_FINAL)SHA3_Final,       (OP_HASH)SHA3_256,   (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA3_384,   sizeof(SHA3_CTX),   (OP_INIT)SHA3_384_Init,   (OP_UPDATE)SHA3_Update,       (OP_FINAL)SHA3_Final,       (OP_HASH)SHA3_384,   (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA3_512,   sizeof(SHA3_CTX),   (OP_INIT)SHA3_512_Init,   (OP_UPDATE)SHA3_Update,       (OP_FINAL)SHA3_Final,       (OP_HASH)SHA3_512,   (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHAKE128,   sizeof(SHA3_CTX),   (OP_INIT)NULL,            (OP_UPDATE)SHA3_XOF_Update,   (OP_FINAL)SHA3_XOF_Final,   (OP_HASH)NULL,       (OP_INIT_EX)SHA3_SHAKE128_Init, (OP_HASH_EX)SHA3_SHAKE128 },
    { HASH_ALG_SHAKE256,   sizeof(SHA3_CTX),   (OP_INIT)NULL,            (OP_UPDATE)SHA3_XOF_Update,   (OP_FINAL)SHA3_XOF_Final,   (OP_HASH)NULL,       (OP_INIT_EX)SHA3_SHAKE256_Init, (OP_HASH_EX)SHA3_SHAKE256 },
    { HASH_ALG_SM3,        sizeof(SM3_CTX),    (OP_INIT)SM3_Init,        (OP_UPDATE)SM3_Update,        (OP_FINAL)SM3_Final,        (OP_HASH)SM3,        (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL }
};

typedef struct {
    HASH_ALG   alg;
    uint32_t   ext;

    OP_INIT    init;
    OP_UPDATE  update;
    OP_FINAL   final;
    OP_HASH    hash;

    OP_INIT_EX init_ex;
    OP_HASH_EX hash_ex;

    void *priv;
} HASH_IMPL;

int Hash_Init(HASH_CTX *ctx, HASH_ALG alg)
{
    int rc = ERR_OK;
    struct hash_item *item = NULL;
    HASH_IMPL *impl = NULL;

    if ((NULL == ctx) || (alg >= HASH_ALG_MAX))
    {
        return ERR_INV_PARAM;
    }

    item = &hash_lists[alg];

    impl = (HASH_IMPL *)malloc(sizeof(HASH_IMPL));
    if (NULL == impl)
    {
        printf("Out Of Memory in %s\n", __FUNCTION__);
        return ERR_ERR;
    }

    impl->priv = malloc(item->st_size);
    if (NULL == impl->priv)
    {
        printf("Out Of Memory in %s\n", __FUNCTION__);
        free(impl);
        impl = NULL;
        return ERR_ERR;
    }

    memset(impl, 0, sizeof(HASH_IMPL));
    impl->alg = alg;
    impl->ext = 0;

    impl->init = item->init;
    impl->update = item->update;
    impl->final = item->final;
    impl->hash = item->hash;

    impl->init_ex = item->init_ex;
    impl->hash_ex = item->hash_ex;

    memset(ctx, 0, sizeof(HASH_CTX));
    ctx->alg = alg;
    ctx->impl = impl;

    if (NULL != impl->init)
    {
        rc = impl->init(impl->priv);
    }

    /*
     * ctx->init_ex should be called in Hash_Init_Ex
     */

    return rc;
}

int Hash_Update(HASH_CTX *ctx, const void *data, size_t len)
{
    HASH_IMPL *impl = NULL;

    if ((NULL == ctx) || (NULL == data))
    {
        return ERR_INV_PARAM;
    }

    impl = (HASH_IMPL *)ctx->impl;
    if (NULL == impl)
    {
        return ERR_INV_PARAM;
    }

    return impl->update(impl->priv, data, len);
}

int Hash_Final(unsigned char *md, HASH_CTX *ctx)
{
    HASH_IMPL *impl = NULL;

    if ((NULL == ctx) || (NULL == md))
    {
        return ERR_INV_PARAM;
    }

    impl = (HASH_IMPL *)ctx->impl;
    if (NULL == impl)
    {
        return ERR_INV_PARAM;
    }

    return impl->final(md, impl->priv);
}

unsigned char *Hash(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md)
{
    int rc = ERR_OK;
    HASH_CTX ctx;

    if ((alg >= HASH_ALG_MAX) || (NULL == data) || (NULL == md))
    {
        return NULL;
    }

    rc = Hash_Init(&ctx, alg);
    if (rc != ERR_OK)
    {
        return NULL;
    }

    rc = Hash_Update(&ctx, data, n);
    if (rc != ERR_OK)
    {
        return NULL;
    }

    Hash_Final(md, &ctx);
    Hash_UnInit(&ctx);

    return md;
}

int Hash_UnInit(HASH_CTX *ctx)
{
    HASH_IMPL *impl = NULL;

    if ((NULL == ctx) || (NULL == ctx->impl))
    {
        return ERR_INV_PARAM;
    }

    impl = (HASH_IMPL *)ctx->impl;

    /* free private date first */
    if (NULL != impl->priv)
    {
        free(impl->priv);
    }

    /* free outer implementation */
    free(ctx->impl);
    ctx->impl = NULL;
    memset(ctx, 0, sizeof(HASH_CTX));

    return ERR_OK;
}

int Hash_Init_Ex(HASH_CTX *ctx, HASH_ALG alg, uint32_t ext)
{
    int rc = ERR_OK;
    HASH_IMPL *impl = NULL;

    rc = Hash_Init(ctx, alg);
    impl = ctx->impl;
    impl->ext = ext;

    if (rc == ERR_OK)
    {
        if (NULL != impl->init_ex)
        {
            rc = impl->init_ex(impl->priv, impl->ext);
        }
    }

    return rc;
}
// int Hash_Update_Ex(HASH_CTX *ctx, const void *data, size_t len);
// int Hash_Final_Ex(unsigned char *md, HASH_CTX *ctx);
unsigned char *Hash_Ex(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md, uint32_t ext)
{
    int rc = ERR_OK;
    HASH_CTX ctx;

    if ((alg >= HASH_ALG_MAX) || (NULL == data) || (NULL == md))
    {
        return NULL;
    }

    rc = Hash_Init_Ex(&ctx, alg, ext);
    if (rc != ERR_OK)
    {
        return NULL;
    }

    rc = Hash_Update(&ctx, data, n);
    if (rc != ERR_OK)
    {
        return NULL;
    }

    Hash_Final(md, &ctx);
    Hash_UnInit(&ctx);

    return md;
}
