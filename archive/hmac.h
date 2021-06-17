/*
 * @  File: 
 * @Author: Gu Yongqiang
 * @  Blog: https://blog.csdn.net/guyongqiangx
 */
#ifndef __HMAC__H

/*
 * #include <openssl/hmac.h>
 *
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
#include "sha256.h"

typedef enum hmac_alg{
    MHAC_MD4,
	HMAC_MD5,
	HMAC_SHA1,
	HMAC_SHA224,
	HMAC_SHA256,
    HMAC_SHA256_224,

	HMAC_SHA384,
	HMAC_SHA512,

    HMAC_SHA512_224,
    HMAC_SHA512_256,
    HMAC_SHA512_384,

    HMAC_SM3,
}HMAC_ALG;

typedef struct hmac_context {
    HMAC_ALG alg;
    void *impl;
    uint32_t block_size;
    uint32_t digest_size;
    uint8_t padding[64];
    uint8_t inner[64];
    uint8_t outer[64];
}HMAC_CTX;

typedef char EVP_MD;
typedef void ENGINE;

int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,
                 const EVP_MD *md, ENGINE *impl);
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len);
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);


#if 0
struct hmac_context {
    /* message length in bits */
    uint64_t total_bits;

    /* intermedia hash value for each block */
    struct {
        uint32_t a;
        uint32_t b;
        uint32_t c;
        uint32_t d;
        uint32_t e;
    }hash;

    /* last block buffer */
    struct {
        uint32_t size;                  /* size in bytes */
        uint8_t  buf[HASH_BLOCK_SIZE];  /* buffer */
    }last;
};

int hmac_init(HMAC_CTX *ctx, const void *key, int key_len,
                  const EVP_MD *md, ENGINE *impl);
#endif

#endif
