#ifndef __ROCKY_TYPE__H
#define __ROCKY_TYPE__H

#define ERR_OK             0
#define ERR_ERR           -1  /* generic error */
#define ERR_INV_PARAM     -2  /* invalid parameter */
#define ERR_TOO_LONG      -3  /* too long */
#define ERR_STATE_ERR     -4  /* state error */
#define ERR_OUT_OF_MEMORY -5  /* out of memory */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef struct {
    uint64_t high; /* high 64 bits */
    uint64_t low;  /*  low 64 bits */
} uint128_t;

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

/* HMAC Algorithm List */
typedef enum {
    HMAC_ALG_MD2,
    HMAC_ALG_MD4,
    HMAC_ALG_MD5,
    HMAC_ALG_SHA1,
    HMAC_ALG_SHA224,
    HMAC_ALG_SHA256,
    HMAC_ALG_SHA384,
    HMAC_ALG_SHA512,
    HMAC_ALG_SHA512_224,
    HMAC_ALG_SHA512_256,
    HMAC_ALG_SHA512_T,
    HMAC_ALG_SHA3_224,
    HMAC_ALG_SHA3_256,
    HMAC_ALG_SHA3_384,
    HMAC_ALG_SHA3_512,
    HMAC_ALG_SHAKE128,
    HMAC_ALG_SHAKE256,
    HMAC_ALG_SM3,
    HMAC_ALG_MAX,
    HMAC_ALG_INVALID
} HMAC_ALG;

#endif