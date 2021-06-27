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

typedef struct hash_struct {
    HASH_ALG alg;

    uint32_t st_size;

    int (* init)(void *ctx, HASH_ALG alg);
    int (* update)(void *ctx, const void *data, size_t len);
    int (* final)(unsigned char *md, void *ctx);
    unsigned char * (* hash)(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md);

    int (* init_ex)(void *ctx, HASH_ALG alg, unsigned int md_size);
    unsigned char * (* hash_ex)(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md, unsigned int md_size);
}HASH_ST;

static HASH_ST hash_sts[HASH_ALG_MAX] =
{
 /* { alg,                 st_size,            init,            update,            final,            hash,       init_ex,       Hash_Ex } */
    { HASH_ALG_MD2,        sizeof(MD2_CTX),    MD2_Init,        MD2_Update,        MD2_Final,        MD2,        NULL,          NULL },
    { HASH_ALG_MD4,        sizeof(MD4_CTX),    MD4_Init,        MD4_Update,        MD4_Final,        MD4,        NULL,          NULL },
    { HASH_ALG_MD5,        sizeof(MD5_CTX),    MD5_Init,        MD5_Update,        MD5_Final,        MD5,        NULL,          NULL },
    { HASH_ALG_SHA1,       sizeof(SHA_CTX),    SHA1_Init,       SHA1_Update,       SHA1_Final,       SHA1,       NULL,          NULL },
    { HASH_ALG_SHA224,     sizeof(SHA256_CTX), SHA224_Init,     SHA224_Update,     SHA224_Final,     SHA224,     NULL,          NULL },
    { HASH_ALG_SHA256,     sizeof(SHA256_CTX), SHA256_Init,     SHA256_Update,     SHA256_Final,     SHA256,     NULL,          NULL },
    { HASH_ALG_SHA384,     sizeof(SHA512_CTX), SHA384_Init,     SHA384_Update,     SHA384_Final,     SHA384,     NULL,          NULL },
    { HASH_ALG_SHA512,     sizeof(SHA512_CTX), SHA512_Init,     SHA512_Update,     SHA512_Final,     SHA512,     NULL,          NULL },
    { HASH_ALG_SHA512_224, sizeof(SHA512_CTX), SHA512_224_Init, SHA512_224_Update, SHA512_224_Final, SHA512_224, NULL,          NULL },
    { HASH_ALG_SHA512_256, sizeof(SHA512_CTX), SHA512_256_Init, SHA512_256_Update, SHA512_256_Final, SHA512_256, NULL,          NULL },
    { HASH_ALG_SHA512_T,   sizeof(SHA512_CTX), NULL,            SHA512t_Update,    SHA512t_Final,    NULL,       SHA512t_Init,  SHA512t},
    { HASH_ALG_SHA3_224,   sizeof(SHA3_CTX),   SHA3_224_Init,   SHA3_Update,       SHA3_Final,       SHA3_224,   NULL,          NULL },
    { HASH_ALG_SHA3_256,   sizeof(SHA3_CTX),   SHA3_256_Init,   SHA3_Update,       SHA3_Final,       SHA3_256,   NULL,          NULL },
    { HASH_ALG_SHA3_384,   sizeof(SHA3_CTX),   SHA3_384_Init,   SHA3_Update,       SHA3_Final,       SHA3_384,   NULL,          NULL },
    { HASH_ALG_SHA3_512,   sizeof(SHA3_CTX),   SHA3_512_Init,   SHA3_Update,       SHA3_Final,       SHA3_512,   NULL,          NULL },
    { HASH_ALG_SHAKE128,   sizeof(SHA3_CTX),   NULL,            SHA3_XOF_Update,   SHA3_XOF_Final,   NULL,       SHA3_SHAKE128_Init, SHA3_SHAKE128 },
    { HASH_ALG_SHAKE256,   sizeof(SHA3_CTX),   NULL,            SHA3_XOF_Update,   SHA3_XOF_Final,   NULL,       SHA3_SHAKE256_Init, SHA3_SHAKE256 },
    { HASH_ALG_SM3,        sizeof(SM3_CTX),    SM3_Init,        SM3_Update,        SM3_Final,        SM3,        NULL,          NULL }
};

int Hash_Init(HASH_CTX *ctx, HASH_ALG alg)
{
    int rc = ERR_OK;
    HASH_ST *st = NULL;

    if ((NULL == ctx) || (alg >= HASH_ALG_MAX))
    {
        return ERR_INV_PARAM;
    }

    st = &hash_sts[alg];

    memset(ctx, 0, sizeof(HASH_CTX));

    ctx->alg = alg;

    ctx->init = st->init;
    ctx->update = st->update;
    ctx->final = st->final;
    ctx->hash = st->hash;

    ctx->init_ex = st->init_ex;
    ctx->hash_ex = st->hash_ex;

    ctx->impl = malloc(st->st_size);
    if (NULL == ctx->impl)
    {
        printf("Out Of Memory in %s\n", __FUNCTION__);
        return ERR_ERR;
    }

    if (ctx->init != NULL)
    {
        rc = ctx->init(ctx->impl);
    }

    /*
     * ctx->init_ex should be called in Hash_Init_Ex
     */

    return rc;
}

int Hash_Update(HASH_CTX *ctx, const void *data, size_t len)
{
    if ((NULL == ctx) || (NULL == data))
    {
        return ERR_INV_PARAM;
    }

    return ctx->update(ctx->impl, data, len);
}

int Hash_Final(unsigned char *md, HASH_CTX *ctx)
{
    if ((NULL == ctx) || (NULL == md))
    {
        return ERR_INV_PARAM;
    }

    return ctx->final(md, ctx->impl);
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
    if (NULL == ctx)
    {
        return ERR_INV_PARAM;
    }

    free(ctx->impl);
    ctx->impl = NULL;
    memset(ctx, 0, sizeof(HASH_CTX));

    return ERR_OK;
}

int Hash_Init_Ex(HASH_CTX *ctx, HASH_ALG alg, uint32_t ext)
{
    int rc = ERR_OK;

    rc = Hash_Init(ctx, alg);

    if (rc == ERR_OK)
    {
        rc = ctx->init_ex(ctx->impl, ext);
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
