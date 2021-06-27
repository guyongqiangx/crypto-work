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

    // unsigned char *md;
    uint32_t md_size;

    void *impl;

    int (* init)(void *ctx);
    int (* update)(void *ctx, const void *data, size_t len);
    int (* final)(unsigned char *md, void *ctx);
    unsigned char * (* hash)(const unsigned char *data, size_t n, unsigned char *md);

    int (* init_ex)(void *ctx, unsigned int ext);
    unsigned char * (* hash_ex)(const unsigned char *data, size_t n, unsigned char *md, unsigned int ext);
}HASH_CTX;

int Hash_Init(HASH_CTX *ctx, HASH_ALG alg);
int Hash_Update(HASH_CTX *ctx, const void *data, size_t len);
int Hash_Final(unsigned char *md, HASH_CTX *ctx);
unsigned char *Hash(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md);
int Hash_UnInit(HASH_CTX *ctx);

int Hash_Init_Ex(HASH_CTX *ctx, HASH_ALG alg, uint32_t ext);
// int Hash_Update_Ex(void *ctx, const void *data, size_t len);
// int Hash_Final_Ex(unsigned char *md, void *ctx);
unsigned char *Hash_Ex(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md, uint32_t ext);

#endif