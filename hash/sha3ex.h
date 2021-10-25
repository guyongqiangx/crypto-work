#ifndef __ROCKY_SHA3EXT__H
#define __ROCKY_SHA3EXT__H
#include "err.h"
#include "sha3.h"

/*
 * Wrap SHA3 functions
 */
int SHA3_224_Init(SHA3_CTX *c);
unsigned char *SHA3_224(const unsigned char *data, size_t n, unsigned char *md);
 
int SHA3_256_Init(SHA3_CTX *c);
unsigned char *SHA3_256(const unsigned char *data, size_t n, unsigned char *md);
 
int SHA3_384_Init(SHA3_CTX *c);
unsigned char *SHA3_384(const unsigned char *data, size_t n, unsigned char *md);
 
int SHA3_512_Init(SHA3_CTX *c);
unsigned char *SHA3_512(const unsigned char *data, size_t n, unsigned char *md);

int SHA3_SHAKE128_Init(SHA3_CTX *c, uint32_t d);
unsigned char *SHA3_SHAKE128(const unsigned char *data, size_t n, unsigned char *md, uint32_t d);

int SHA3_SHAKE256_Init(SHA3_CTX *c, uint32_t d);
unsigned char *SHA3_SHAKE256(const unsigned char *data, size_t n, unsigned char *md, uint32_t d);

#endif