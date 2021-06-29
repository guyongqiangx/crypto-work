/*
 * @        file: hash.h
 * @ description: header file for hash.c
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#ifndef __ROCKY_HASH__H
#define __ROCKY_HASH__H
#include "type.h"

typedef struct hash_context {
    HASH_ALG alg;
    uint32_t md_size;

    void *impl;

    int (* init)(void *ctx);
    int (* update)(void *ctx, const void *data, size_t len);
    int (* final)(unsigned char *md, void *ctx);
    unsigned char * (* hash)(const unsigned char *data, size_t n, unsigned char *md);

    int (* init_ex)(void *ctx, unsigned int ext);
    unsigned char * (* hash_ex)(const unsigned char *data, size_t n, unsigned char *md, unsigned int ext);
}HASH_CTX;

int HASH_Init(HASH_CTX *ctx, HASH_ALG alg);
int HASH_Update(HASH_CTX *ctx, const void *data, size_t len);
int HASH_Final(unsigned char *md, HASH_CTX *ctx);
unsigned char *HASH(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md);
int HASH_UnInit(HASH_CTX *ctx);

/*
 * For SHA-512t, SHAKE128, SHAKE256
 */
int HASH_Init_Ex(HASH_CTX *ctx, HASH_ALG alg, uint32_t ext);
unsigned char *HASH_Ex(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md, uint32_t ext);

#endif