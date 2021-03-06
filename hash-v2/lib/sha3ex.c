#include <stdlib.h>
#include "sha3ex.h"

int SHA3_224_Init(SHA3_CTX *c)
{
    return SHA3_Init(c, SHA3_ALG_224);
}

unsigned char *SHA3_224(const unsigned char *data, size_t n, unsigned char *md)
{
    return SHA3(SHA3_ALG_224, data, n, md);
}
 
int SHA3_256_Init(SHA3_CTX *c)
{
    return SHA3_Init(c, SHA3_ALG_256);
}

unsigned char *SHA3_256(const unsigned char *data, size_t n, unsigned char *md)
{
    return SHA3(SHA3_ALG_256, data, n, md);
}
 
int  SHA3_384_Init(SHA3_CTX *c)
{
    return SHA3_Init(c, SHA3_ALG_384);
}

unsigned char *SHA3_384(const unsigned char *data, size_t n, unsigned char *md)
{
    return SHA3(SHA3_ALG_384, data, n, md);
}
 
int SHA3_512_Init(SHA3_CTX *c)
{
    return SHA3_Init(c, SHA3_ALG_512);
}
unsigned char *SHA3_512(const unsigned char *data, size_t n, unsigned char *md)
{
    return SHA3(SHA3_ALG_512, data, n, md);
}

int SHA3_SHAKE128_Init(SHA3_CTX *c, uint32_t d)
{
    return SHA3_XOF_Init(c, SHA3_ALG_SHAKE128, d);
}
unsigned char *SHA3_SHAKE128(const unsigned char *data, size_t n, unsigned char *md, uint32_t d)
{
    return SHA3_XOF(SHA3_ALG_SHAKE128, data, n, md, d);
}

int SHA3_SHAKE256_Init(SHA3_CTX *c, uint32_t d)
{
    return SHA3_XOF_Init(c, SHA3_ALG_SHAKE256, d);
}

unsigned char *SHA3_SHAKE256(const unsigned char *data, size_t n, unsigned char *md, uint32_t d)
{
    return SHA3_XOF(SHA3_ALG_SHAKE256, data, n, md, d);
}
