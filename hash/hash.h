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
    void *impl;
}HASH_CTX;

int HASH_Init(HASH_CTX *ctx, HASH_ALG alg);
int HASH_Update(HASH_CTX *ctx, const void *data, size_t len);
int HASH_Final(unsigned char *md, HASH_CTX *ctx);
unsigned char *HASH(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md);
int HASH_UnInit(HASH_CTX *ctx);

int HASH_Init_Ex(HASH_CTX *ctx, HASH_ALG alg, uint32_t ext);
unsigned char *HASH_Ex(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md, uint32_t ext);

#endif