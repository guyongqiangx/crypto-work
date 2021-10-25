/*
 * @        file: hash.h
 * @ description: header file for hash.c
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#ifndef __ROCKY_HASH__H
#define __ROCKY_HASH__H

/*
 * According to NIST SP 800-107 Rev 1, Recommendation for Applications Using Approved Hash Algorithms, 08/2012
 * Section 4. Approved Hash Algorithms
 *   Currently, there are seven approved hash algorithms specified in FIPS 180-4:
 *   SHA-1, SHA-224, SHA-256, SHA-384 SHA-512, SHA-512/224 and SHA-512/256.
 *   These hash algorithms produce outputs of 160, 224, 256, 384, 512, 224 and 256 bits, respectively.
 *   The output of a hash algorithm is commonly known as a message digest, a hash value or a hash output.
 */

/* Hash Algorithm List */
typedef enum {
    HASH_ALG_MD2,
    HASH_ALG_MD4,
    HASH_ALG_MD5,
    HASH_ALG_SHA1,
    HASH_ALG_SHA224,
    HASH_ALG_SHA256,
    HASH_ALG_SHA384,
    HASH_ALG_SHA512,
    HASH_ALG_SHA512_224,
    HASH_ALG_SHA512_256,
    HASH_ALG_SHA512_T,
    HASH_ALG_SHA3_224,
    HASH_ALG_SHA3_256,
    HASH_ALG_SHA3_384,
    HASH_ALG_SHA3_512,
    HASH_ALG_SHAKE128,
    HASH_ALG_SHAKE256,
    HASH_ALG_SM3,
    HASH_ALG_MAX,
    HASH_ALG_INVALID
} HASH_ALG;

typedef struct hash_context {
    /*
     * currently we don't use below 3 stuffs,
     * just for future use, like hmac, hash_drbg, hmac_drbg and so on.
     */
    HASH_ALG alg;
    unsigned long block_size;
    unsigned long digest_size;

    void     *impl;
}HASH_CTX;

int HASH_Init(HASH_CTX *ctx, HASH_ALG alg);
int HASH_Update(HASH_CTX *ctx, const void *data, size_t len);
int HASH_Final(unsigned char *md, HASH_CTX *ctx);
unsigned char *HASH(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md);

/*
 * For SHA-512t, SHAKE128, SHAKE256
 */
int HASH_Init_Ex(HASH_CTX *ctx, HASH_ALG alg, unsigned long ext);
unsigned char *HASH_Ex(HASH_ALG alg, const unsigned char *data, size_t n, unsigned char *md, unsigned long ext);

unsigned long HASH_GetBlockSize(HASH_ALG alg);
unsigned long HASH_GetDigestSize(HASH_ALG alg, unsigned long ext);

#endif