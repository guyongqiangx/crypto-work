#ifndef __ROCKY_HASH__H
#define __ROCKY_HASH__H
#include "type.h"

/* Hash Algorithm List */
typedef enum {
    HASH_MD2,
    HASH_MD4,
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA224,
    HASH_SHA256,
    HASH_SHA384,
    HASH_SHA512,
    HASH_SHA512_224,
    HASH_SHA512_256,
    HASH_SHA512_T,
    HASH_SHA3_224,
    HASH_SHA3_256,
    HASH_SHA3_384,
    HASH_SHA3_512,
    HASH_SHAKE128,
    HASH_SHAKE256
} HASH_ALG;

typedef struct hash_context {
    void *impl;

    HASH_ALG alg;
    unsigned char *md;
    uint32_t md_size;

    int (* init)(void *c, HASH_ALG alg);
    int (* update)(void *c, const void *data, size_t len);
    int (* final)(unsigned char *md, void *c);
    unsigned char * (* hash)(HASH_ALG alg, const unsigned char *d, size_t n, unsigned char *md);

    int (* init_ex)(void *c, HASH_ALG alg, unsigned int md_size);
    unsigned char * (* hash_ex)(HASH_ALG alg, const unsigned char *d, size_t n, unsigned char *md, unsigned int md_size);

}HASH_CTX;

int HASH_Init(void *c);
int HASH_Update(void *c, const void *data, size_t len);
int HASH_Final(unsigned char *md, void *c);
unsigned char *HASH(const unsigned char *d, size_t n, unsigned char *md);

int HASH_Init_Ex(void *c, HASH_ALG alg, uint32_t ext);
int HASH_Update_Ex(void *c, const void *data, size_t len);
int HASH_Final_Ex(unsigned char *md, void *c);
unsigned char *HASH_Ex(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md, uint32_t ext);

#endif