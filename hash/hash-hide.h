/*
 * @        file: 
 * @ description: 
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
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
    void *impl;
}HASH_CTX;

int Hash_Init(HASH_CTX *ctx, HASH_ALG alg);
int Hash_Update(HASH_CTX *ctx, const void *data, size_t len);
int Hash_Final(unsigned char *md, HASH_CTX *ctx);
unsigned char *Hash(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md);
int Hash_UnInit(HASH_CTX *ctx);

int Hash_Init_Ex(HASH_CTX *ctx, HASH_ALG alg, uint32_t ext);
unsigned char *Hash_Ex(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md, uint32_t ext);

#endif