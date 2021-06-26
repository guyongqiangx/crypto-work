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
    unsigned char * (* hash)(const unsigned char *d, size_t n, unsigned char *md);

    int (* init_ex)(void *ctx, unsigned int md_size);
    unsigned char * (* hash_ex)(const unsigned char *d, size_t n, unsigned char *md, unsigned int md_size);
}HASH_CTX;

int HASH_Init(HASH_CTX *ctx, HASH_ALG alg);
int HASH_Update(HASH_CTX *ctx, const void *data, size_t len);
int HASH_Final(unsigned char *md, HASH_CTX *ctx);
unsigned char *HASH(HASH_ALG alg, const unsigned char *d, size_t n, unsigned char *md);
int HASH_UnInit(HASH_CTX *ctx);

int HASH_Init_Ex(HASH_CTX *ctx, HASH_ALG alg, uint32_t ext);
// int HASH_Update_Ex(void *ctx, const void *data, size_t len);
// int HASH_Final_Ex(unsigned char *md, void *ctx);
unsigned char *HASH_Ex(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md, uint32_t ext);

#endif