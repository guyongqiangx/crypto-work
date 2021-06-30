#ifndef __ROCKY_HMAC__H
#define __ROCKY_HMAC__H
#include "type.h"

typedef struct hmac_context {

    HASH_ALG alg;
    uint32_t block_size;
    uint32_t digest_size;

    void *hashi;
    void *hasho;
}HMAC_CTX;

int HMAC_Init(HMAC_CTX *ctx, HASH_ALG alg, const void *key, unsigned int key_len);
int HMAC_Update(HMAC_CTX *ctx, const void *data, size_t len);
int HMAC_Final(unsigned char *md, HMAC_CTX *ctx);
unsigned char *HMAC(HASH_ALG alg, const void *key, unsigned int key_len, const unsigned char *data, size_t n, unsigned char *md);

/*
 * For SHA-512t, SHAKE128, SHAKE256
 */
int HMAC_Init_Ex(HMAC_CTX *ctx, HASH_ALG alg, const void *key, unsigned int key_len, uint32_t ext);
unsigned char *HMAC_Ex(HASH_ALG alg,  const void *key, unsigned int key_len, const unsigned char *data, size_t n, unsigned char *md, uint32_t ext);

uint32_t HMAC_GetBlockSize(HASH_ALG alg);
uint32_t HMAC_GetDigestSize(HASH_ALG alg, uint32_t ext);

#endif