#ifndef __ROCKY_RSA__H
#define __ROCKY_RSA__H
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

#if 0
/*
 * I2OSP: Integer(nonnegative) to Octet String Primitive
 */
int I2OSP(mpz_t x, int *xLen, char *X);

/*
 * OS2IP: Octet String to Integer(nonnegative)
 */
int OS2IP(char *X, mpz_t x);
#endif

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

#ifdef __cplusplus
}
#endif
#endif