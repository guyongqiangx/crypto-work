#ifndef __ROCKY_RSA__H
#define __ROCKY_RSA__H
#ifdef __cplusplus
extern "C"
{
#endif

typedef struct RSAPrivateKey {
    int type; /* 0:(n, d); 1:(p, q, dP, dQ, qInv) */
    mpz_t n, e, d;
    mpz_t p, q, dP, dQ, qInv;
}RSAPrivateKey;

typedef struct RSAPublicKey {
    mpz_t n, e;
}RSAPublicKey;

/*
 * I2OSP: Integer(nonnegative) to Octet String Primitive
 */
int I2OSP(mpz_t x, int *xLen, char *X);

/*
 * OS2IP: Octet String to Integer(nonnegative)
 */
int OS2IP(char *X, mpz_t x);

/*
 * RSAEP: RSA Encryption Primitive
 */
int RSAEP(RSAPublicKey *k, mpz_t m, mpz_t c);

/*
 * RSADP: RSA Decryption Primitive
 */
int RSADP(RSAPrivateKey *k, mpz_t c, mpz_t m);

/*
 * RSASP1: RSA Signature Primitive Version 1
 */
int RSASP1(RSAPrivateKey *k, mpz_t m, mpz_t s);

/*
 * RSAVP1: RSA Verification Primitive Version 1
 */
int RSAVP1(RSAPublicKey *k, mpz_t s, mpz_t m);

#ifdef __cplusplus
}
#endif
#endif