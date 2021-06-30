/*
 * @        file: hash_tables.c
 * @ description: supported hash algorithm lists
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

#include "hash_tables.h"
#include "utils.h"

static HASH_STRUCT hash_lists[HASH_ALG_MAX] =
{
 /* { alg,                 *ctx, ctx_size,          block, digest, flag, ext,  init,                     update,                        final,                      hash,               init_ex,                        hash_ex } */
    { HASH_ALG_MD2,        NULL, sizeof(MD2_CTX),      16,     16,    0,   0,  (OP_INIT)MD2_Init,        (OP_UPDATE)MD2_Update,        (OP_FINAL)MD2_Final,        (OP_HASH)MD2,        (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_MD4,        NULL, sizeof(MD4_CTX),      64,     16,    0,   0,  (OP_INIT)MD4_Init,        (OP_UPDATE)MD4_Update,        (OP_FINAL)MD4_Final,        (OP_HASH)MD4,        (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_MD5,        NULL, sizeof(MD5_CTX),      64,     16,    0,   0,  (OP_INIT)MD5_Init,        (OP_UPDATE)MD5_Update,        (OP_FINAL)MD5_Final,        (OP_HASH)MD5,        (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA1,       NULL, sizeof(SHA_CTX),      64,     20,    0,   0,  (OP_INIT)SHA1_Init,       (OP_UPDATE)SHA1_Update,       (OP_FINAL)SHA1_Final,       (OP_HASH)SHA1,       (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA224,     NULL, sizeof(SHA256_CTX),   64,     28,    0,   0,  (OP_INIT)SHA224_Init,     (OP_UPDATE)SHA224_Update,     (OP_FINAL)SHA224_Final,     (OP_HASH)SHA224,     (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA256,     NULL, sizeof(SHA256_CTX),   64,     32,    0,   0,  (OP_INIT)SHA256_Init,     (OP_UPDATE)SHA256_Update,     (OP_FINAL)SHA256_Final,     (OP_HASH)SHA256,     (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA384,     NULL, sizeof(SHA512_CTX),  128,     48,    0,   0,  (OP_INIT)SHA384_Init,     (OP_UPDATE)SHA384_Update,     (OP_FINAL)SHA384_Final,     (OP_HASH)SHA384,     (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA512,     NULL, sizeof(SHA512_CTX),  128,     64,    0,   0,  (OP_INIT)SHA512_Init,     (OP_UPDATE)SHA512_Update,     (OP_FINAL)SHA512_Final,     (OP_HASH)SHA512,     (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA512_224, NULL, sizeof(SHA512_CTX),  128,     28,    0,   0,  (OP_INIT)SHA512_224_Init, (OP_UPDATE)SHA512_224_Update, (OP_FINAL)SHA512_224_Final, (OP_HASH)SHA512_224, (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA512_256, NULL, sizeof(SHA512_CTX),  128,     32,    0,   0,  (OP_INIT)SHA512_256_Init, (OP_UPDATE)SHA512_256_Update, (OP_FINAL)SHA512_256_Final, (OP_HASH)SHA512_256, (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA512_T,   NULL, sizeof(SHA512_CTX),  128,      0,    1,   0,  (OP_INIT)NULL,            (OP_UPDATE)SHA512t_Update,    (OP_FINAL)SHA512t_Final,    (OP_HASH)NULL,       (OP_INIT_EX)SHA512t_Init,       (OP_HASH_EX)SHA512t},
    { HASH_ALG_SHA3_224,   NULL, sizeof(SHA3_CTX),    144,     28,    0,   0,  (OP_INIT)SHA3_224_Init,   (OP_UPDATE)SHA3_Update,       (OP_FINAL)SHA3_Final,       (OP_HASH)SHA3_224,   (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA3_256,   NULL, sizeof(SHA3_CTX),    136,     32,    0,   0,  (OP_INIT)SHA3_256_Init,   (OP_UPDATE)SHA3_Update,       (OP_FINAL)SHA3_Final,       (OP_HASH)SHA3_256,   (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA3_384,   NULL, sizeof(SHA3_CTX),    104,     48,    0,   0,  (OP_INIT)SHA3_384_Init,   (OP_UPDATE)SHA3_Update,       (OP_FINAL)SHA3_Final,       (OP_HASH)SHA3_384,   (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHA3_512,   NULL, sizeof(SHA3_CTX),     72,     64,    0,   0,  (OP_INIT)SHA3_512_Init,   (OP_UPDATE)SHA3_Update,       (OP_FINAL)SHA3_Final,       (OP_HASH)SHA3_512,   (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL },
    { HASH_ALG_SHAKE128,   NULL, sizeof(SHA3_CTX),    168,     16,    1,   0,  (OP_INIT)NULL,            (OP_UPDATE)SHA3_XOF_Update,   (OP_FINAL)SHA3_XOF_Final,   (OP_HASH)NULL,       (OP_INIT_EX)SHA3_SHAKE128_Init, (OP_HASH_EX)SHA3_SHAKE128 },
    { HASH_ALG_SHAKE256,   NULL, sizeof(SHA3_CTX),    136,     32,    1,   0,  (OP_INIT)NULL,            (OP_UPDATE)SHA3_XOF_Update,   (OP_FINAL)SHA3_XOF_Final,   (OP_HASH)NULL,       (OP_INIT_EX)SHA3_SHAKE256_Init, (OP_HASH_EX)SHA3_SHAKE256 },
    { HASH_ALG_SM3,        NULL, sizeof(SM3_CTX),      64,     32,    0,   0,  (OP_INIT)SM3_Init,        (OP_UPDATE)SM3_Update,        (OP_FINAL)SM3_Final,        (OP_HASH)SM3,        (OP_INIT_EX)NULL,               (OP_HASH_EX)NULL }
};

HASH_STRUCT *create_hash_struct(HASH_ALG alg, uint32_t ext)
{
    HASH_STRUCT *hash;
    void *ctx;

    if ((alg >= HASH_ALG_MAX)
       || ((HASH_ALG_SHA512_T == alg) && (0 == ext))
       || ((HASH_ALG_SHAKE128 == alg) && (0 == ext))
       || ((HASH_ALG_SHAKE256 == alg) && (0 == ext)))
    {
        return NULL;   
    }

    hash = malloc(sizeof(HASH_STRUCT));
    if (NULL == hash)
    {
        printf("Out Of Memory!\n");
        return NULL;
    }

    memcpy(hash, &hash_lists[alg], sizeof(HASH_STRUCT));

    ctx = malloc(hash->context_size);
    if (NULL == ctx)
    {
        printf("Out Of Memory!\n");
        free(hash);
        hash = NULL;
        return NULL;
    }
    memset(ctx, 0, sizeof(hash->context_size));
    hash->context = ctx;

    if ((HASH_ALG_SHA512_T == alg) || (HASH_ALG_SHAKE128 == alg) || (HASH_ALG_SHAKE256 == alg))
    {
        hash->ext = ext;
        hash->digest_size = ext / 8;
    }

    return hash;
}

int destroy_hash_struct(HASH_STRUCT *hash)
{
    if (NULL == hash)
    {
        return ERR_INV_PARAM;
    }

    /* free hash context */
    if (NULL != hash->context)
    {
        free(hash->context);
        hash->context = NULL;
    }

    /* free structure itself */
    free(hash);
    hash = NULL;

    return ERR_OK;
}

uint32_t get_hash_block_size(HASH_ALG alg)
{
    if (alg >= HASH_ALG_MAX)
    {
        return 0;
    }

    return hash_lists[alg].block_size;
}

uint32_t get_hash_digest_size(HASH_ALG alg, uint32_t ext)
{
    uint32_t digest_size = 0;

    if (alg >= HASH_ALG_MAX)
    {
        return 0;
    }

    if ((HASH_ALG_SHA512_T == alg) || (HASH_ALG_SHAKE128 == alg) || (HASH_ALG_SHAKE256 == alg))
    {
        digest_size = ext / 8;
    }
    else
    {
        digest_size = hash_lists[alg].digest_size;
    }

    return digest_size;
}