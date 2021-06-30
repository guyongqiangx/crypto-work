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

/*
 * https://www.openssl.org/docs/man1.1.1/man3/HMAC.html
 * unsigned char *HMAC(const EVP_MD *evp_md, const void *key,
 *                     int key_len, const unsigned char *d, size_t n,
 *                     unsigned char *md, unsigned int *md_len);
 *
 * HMAC_CTX *HMAC_CTX_new(void);
 * int HMAC_CTX_reset(HMAC_CTX *ctx);
 *
 * int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,
 *                  const EVP_MD *md, ENGINE *impl);
 * int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len);
 * int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
 *
 * void HMAC_CTX_free(HMAC_CTX *ctx);
 *
 * int HMAC_CTX_copy(HMAC_CTX *dctx, HMAC_CTX *sctx);
 * void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags);
 * const EVP_MD *HMAC_CTX_get_md(const HMAC_CTX *ctx);
 *
 * size_t HMAC_size(const HMAC_CTX *e);
 */

int HMAC_Init(HMAC_CTX *ctx, HASH_ALG alg, const void *key, unsigned int key_len);
int HMAC_Update(HMAC_CTX *ctx, const void *data, size_t len);
int HMAC_Final(unsigned char *md, HMAC_CTX *ctx);
unsigned char *HMAC(HASH_ALG alg, const void *key, unsigned int key_len, const unsigned char *data, size_t n, unsigned char *md);

int HMAC_Init_Ex(HMAC_CTX *ctx, HASH_ALG alg, const void *key, unsigned int key_len, uint32_t ext);
unsigned char *HMAC_Ex(HASH_ALG alg,  const void *key, unsigned int key_len, const unsigned char *data, size_t n, unsigned char *md, uint32_t ext);

uint32_t HMAC_GetBlockSize(HASH_ALG alg);
uint32_t HMAC_GetDigestSize(HASH_ALG alg, uint32_t ext);

#endif