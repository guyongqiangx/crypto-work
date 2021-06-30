/*
 * @        file: hash_tables.h
 * @ description: definition for HASH_STRUCT to abstract all hash implementations
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#ifndef __ROCKY_HASHTABLES__H
#define __ROCKY_HASHTABLES__H

#include "type.h"
#include "hash.h"

typedef           int  (* OP_INIT   )(void *ctx);
typedef           int  (* OP_UPDATE )(void *ctx, const void *data, size_t len);
typedef           int  (* OP_FINAL  )(unsigned char *md, void *ctx);
typedef unsigned char *(* OP_HASH   )(const unsigned char *data, size_t n, unsigned char *md);

typedef           int  (* OP_INIT_EX)(void *ctx, unsigned int ext);
typedef unsigned char *(* OP_HASH_EX)(const unsigned char *data, size_t n, unsigned char *md, unsigned int ext);

typedef struct hash_struct {
    HASH_ALG    alg;

    void       *context;
    uint32_t    context_size;

    uint32_t    block_size;
    uint32_t    digest_size;

    uint32_t    flag;   /* indicator for ext/init_ex/hash_ex */
    uint32_t    ext;    /* t for SHA-512/t, or d for SHAKE128/SHAKE256 */

    OP_INIT     init;
    OP_UPDATE   update;
    OP_FINAL    final;
    OP_HASH     hash;

    OP_INIT_EX  init_ex;
    OP_HASH_EX  hash_ex;
} HASH_STRUCT;

HASH_STRUCT *create_hash_struct(HASH_ALG alg, uint32_t ext);
int destroy_hash_struct(HASH_STRUCT *hash);

uint32_t get_hash_block_size(HASH_ALG alg);
uint32_t get_hash_digest_size(HASH_ALG alg, uint32_t ext);

#endif