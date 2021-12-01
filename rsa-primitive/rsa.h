#ifndef __ROCKY_RSA__H
#define __ROCKY_RSA__H

#include "hash.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define ERR_OK           0
#define ERR_ERR         -1  /* generic error */
#define ERR_INV_PARAM   -2  /* invalid parameter */
#define ERR_TOO_LONG    -3  /* too long */
#define ERR_STATE_ERR   -4  /* state error */

#define ERR_RSA_PUB_KEY_INVALD      -32
#define ERR_RSA_PRIV_KEY_INVALID    -33
#define ERR_RSA_MSG_OUT_OF_RANGE    -34
#define ERR_RSA_CIPHER_OUT_OF_RANGE -35
#define ERR_RSA_SIG_OUT_OF_RANGE    -36

/* RSAES-OAEP-Encrypt/Decrypt */
#define ERR_RSA_LABEL_TOO_LONG      -37
#define ERR_RSA_MSG_TOO_LONG        -38
#define ERR_RSA_OAEP_ENCODING_ERR   -39
#define ERR_RSA_OAEP_DECODING_ERR   -40
#define ERR_RSA_ENCRYPTION_ERR      -41
#define ERR_RSA_DECRYPTION_ERR      -42

/* RSAES-PKCS1-v1_5-Encrypt/Decrypt */

/* RSASSA-PSS */
#define ERR_RSA_INVALID_SIGNATURE   -43

typedef struct RSAPrivateKey {
    int type; /* 0: unused; 1:(n, d); 2:(p, q, dP, dQ, qInv) */
    mpz_t n, d;
    mpz_t p, q, dP, dQ, qInv;
}RSAPrivateKey;

typedef struct RSAPublicKey {
    mpz_t n, e;
}RSAPublicKey;

int RSA_PublicKey_Init(const char *n, const char *e, RSAPublicKey *key);
int RSA_PublicKey_UnInit(RSAPublicKey *key);
int RSA_PrivateKey_Init(const char *n, const char *d, RSAPrivateKey *key);
int RSA_PrivateKey_Init_MultiPrime(const char *p, const char *q, const char *dP, const char *dQ, const char *qInv, RSAPrivateKey *key);
int RSA_PrivateKey_UnInit(RSAPrivateKey *key);

unsigned long RSA_Modulus_Octet_Length(mpz_t n);
unsigned long RSA_Modulus_Bit_Length(mpz_t n);

/*
 * @description: I2OSP, Integer-to-Octet-String Primitive
 * @param {mpz_t} x, nonnegative integer to be converted
 * @param {unsigned long} xLen, intended length of the resulting octet string
 * @param {unsigned char} *X, corresponding octet string of length xLen
 * @return {*} 0, OK; -1 Fail;
 */
int I2OSP(mpz_t x, unsigned char *X, unsigned long xLen);

/**
 * @description: OS2IP, Octet-String-to-Integer Primitive
 * @param {unsigned char} *X, octet string to be converted
 * @param {unsigned long} xLen, length of octet string
 * @param {mpz_t} x, corresponding nonegative integer
 * @return {*} 0, OK; -1 Fail;
 */
int OS2IP(const unsigned char *X, unsigned long xLen, mpz_t x);

/**
 * @description: RSAEP, RSA Encryption Primitive
 * @param {RSAPublicKey} *key, RSA public key
 * @param {mpz_t} m, message representative, an integer between 0 and n-1
 * @param {mpz_t} c, ciphertext representative, an integer between 0 and n-1
 * @return {*}, 0, OK; -1 Fail;
 */
int RSAEP(RSAPublicKey *key, mpz_t m, mpz_t c);

/**
 * @description: RSADP, RSA Decryption Primitive
 * @param {RSAPrivateKey} *key, RSA private key
 * @param {mpz_t} c, ciphertext representative, an integer between 0 and n-1
 * @param {mpz_t} m, message representative, an integer between 0 and n-1
 * @return {*}, 0, OK; -1, Fail;
 */
int RSADP(RSAPrivateKey *key, mpz_t c, mpz_t m);

/**
 * @description: RSASP1, RSA Signature Primitive, version 1
 * @param {RSAPrivateKey} *key, RSA private key
 * @param {mpz_t} em, encoded message representative, an integer between 0 and n-1
 * @param {mpz_t} s, signature representative, an integer between 0 and n-1
 * @return {*}, 0, OK; -1, Fail;
 */
int RSASP1(RSAPrivateKey *key, mpz_t em, mpz_t s);

/**
 * @description: RSAVP1, RSA Verification Primitive, version 1
 * @param {RSAPublicKey} *key, RSA public key
 * @param {mpz_t} s, signature representative, an integer between 0 and n-1
 * @param {mpz_t} em, encoded message representative, an integer between 0 and n-1
 * @return {*}, 0, OK; -1, Fail;
 */
int RSAVP1(RSAPublicKey *key, mpz_t s, mpz_t em);

int RSAES_OAEP_Encrypt(RSAPublicKey *key, unsigned char *M, unsigned long mLen, const char *L, unsigned long lLen, HASH_ALG alg, unsigned char *C, unsigned long cLen);
int RSAES_OAEP_Decrypt(RSAPrivateKey *key, unsigned char *C, unsigned long cLen, const char *L, unsigned long lLen, HASH_ALG alg, unsigned char *M, unsigned long *mLen);

int RSAES_PKCS1_v1_5_Encrypt(RSAPublicKey *key, unsigned char *M, unsigned long mLen, unsigned char *C, unsigned long cLen);
int RSAES_PKCS1_v1_5_Decrypt(RSAPrivateKey *key, unsigned char *C, unsigned long cLen, unsigned char *M, unsigned long *mLen);

int RSASSA_PSS_Sign(RSAPrivateKey *key, unsigned char *M, unsigned long mLen, HASH_ALG alg, unsigned char *S, unsigned long *sLen);
int RSASSA_PSS_Verify(RSAPublicKey *key, unsigned char *M, unsigned long mLen, HASH_ALG alg, unsigned char *S, unsigned long sLen);

#ifdef __cplusplus
}
#endif
#endif