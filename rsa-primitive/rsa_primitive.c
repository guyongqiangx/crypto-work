#include <stdio.h>
#include <string.h>
#include "gmp.h"
#include "rsa.h"

#define DEBUG

#ifdef DEBUG
#define DBG_PRINT(x) printf(x)
#else
#define DBG_PRINT(x)
#endif

/*
 * Example Octets String in ASN.1:
 *   data: {0xDB, 0xFE, 0xED, 0x6A, 0xB4};
 *   type: {0x04}, octets string;
 * length: {0x05}, 5 bytes;
 * Octets String: 04 05 DB FE ED 6A B4
 */

/*
 * @description: I2OSP, Integer-to-Octet-String Primitive
 * @param {mpz_t} x, nonnegative integer to be converted
 * @param {unsigned long} xLen, intended length of the resulting octet string
 * @param {unsigned char} *X, corresponding octet string of length xLen
 * @return {*} 0, OK; -1 Fail;
 */
int I2OSP(mpz_t x, unsigned char *X, unsigned long xLen)
{
    int res;
    mpz_t max;
    char buf[512];
    size_t count;

    if (NULL == X)
    {
        return -1;
    }

    res = 0;

    mpz_init(max);
    mpz_ui_pow_ui(max, 256, xLen); /* max = 256 ^ xLen */
    if (mpz_cmp(x, max) >= 0)
    {
        printf("integer too large\n");
        res = -1;
    }
    else
    {
        /*
         * it's octect string in ASN.1, which is different from a common string
         * 0x1234567890ABCDEF: 1. {12 34 56 78 90 AB CD EF}, octet string; 2. '1234567890ABCDEF' (string) 
         */
        mpz_export(buf, &count, 1, 1, 0, 0, x);
        memset(X, 0, xLen-count);
        memcpy(X+xLen-count, buf, count);
    }
    mpz_clear(max);

    return res;
}

/**
 * @description: OS2IP, Octet-String-to-Integer Primitive
 * @param {unsigned char} *X, octet string to be converted
 * @param {unsigned long} xLen, length of octet string
 * @param {mpz_t} x, corresponding nonegative integer
 * @return {*} 0, OK; -1 Fail;
 */
int OS2IP(const unsigned char *X, unsigned long xLen, mpz_t x)
{
    if (NULL == X)
    {
        return -1;
    }

    mpz_import(x, xLen, 1, 1, 0, 0, X);

    return 0;
}

/**
 * @description: RSAEP, RSA Encryption Primitive
 * @param {RSAPublicKey} *key, RSA public key
 * @param {mpz_t} m, message representative, an integer between 0 and n-1
 * @param {mpz_t} c, ciphertext representative, an integer between 0 and n-1
 * @return {*}, 0, OK; -1 Fail;
 */
int RSAEP(RSAPublicKey *key, mpz_t m, mpz_t c)
{
    int res = ERR_OK;

    res = mpz_cmp(m, key->n);
    if (res >= 0)
    {
        DBG_PRINT("message representative out of range\n");
        return ERR_RSA_MSG_OUT_OF_RANGE;
    }

    mpz_powm(c, m, key->e, key->n); // c = m ^ e (mod n)

    return ERR_OK;
}

/**
 * @description: RSADP, RSA Decryption Primitive
 * @param {RSAPrivateKey} *key, RSA private key
 * @param {mpz_t} c, ciphertext representative, an integer between 0 and n-1
 * @param {mpz_t} m, message representative, an integer between 0 and n-1
 * @return {*}, 0, OK; -1, Fail;
 */
int RSADP(RSAPrivateKey *key, mpz_t c, mpz_t m)
{
    mpz_t m1, m2, h, temp;

    int res = ERR_OK;

    switch (key->type)
    {
    case 1: // (n, d)
        mpz_powm(m, c, key->d, key->n);
        break;
    case 2: // (p, q, dP, dQ, qInv)
        mpz_inits(m1, m2, h, temp, NULL);

        mpz_powm(m1, c, key->dP, key->p);   //   m1 = c ^ dP mod p
        mpz_powm(m2, c, key->dQ, key->q);   //   m2 = c ^ dQ mod q

        mpz_sub(temp, m1, m2);              // temp = m1 - m2
        mpz_mul(temp, temp, key->qInv);     // temp = temp * qInv = (m1 - m2) * qInv
        mpz_mod(h, temp, key->p);           //    h = temp mod p  = (m1 - m2) * qInv mod p

        mpz_addmul(m2, key->q, h);          //   m2 = m2 + q * h
        mpz_set(m, m2);                     //    m = m2 = m2 + q * h

        mpz_clears(m1, m2, h, temp, NULL);
        break;
    default:
        DBG_PRINT("Not Implemented Yet!\n");
        res = ERR_ERR;
        break;
    }

    return res;
}

/**
 * @description: RSASP1, RSA Signature Primitive, version 1
 * @param {RSAPrivateKey} *key, RSA private key
 * @param {mpz_t} em, encoded message representative, an integer between 0 and n-1
 * @param {mpz_t} s, signature representative, an integer between 0 and n-1
 * @return {*}, 0, OK; -1, Fail;
 */
int RSASP1(RSAPrivateKey *key, mpz_t em, mpz_t s)
{
    mpz_t s1, s2, h, temp;
    int res = ERR_OK;

    res = mpz_cmp(em, key->n);
    if (res >= 0)
    {
        DBG_PRINT("message representative out of range\n");
        return -1;
    }

    switch (key->type)
    {
    case 1: // (n, d)
        mpz_powm(s, em, key->d, key->n); // s = em ^ d (mod n)
        break;
    case 2: // (p, q, dP, dQ, qInv)
        mpz_inits(s1, s2, h, temp, NULL);

        mpz_powm(s1, em, key->dP, key->p);  // s1 = em ^ dP mod p
        mpz_powm(s2, em, key->dQ, key->q);  // s2 = em ^ dQ mod q

        mpz_sub(temp, s1, s2);              // temp = s1 - s2
        mpz_mul(temp, temp, key->qInv);     // temp = temp * qInv = (s1 - s2) * qInv
        mpz_mod(h, temp, key->p);           //    h = temp mod p  = (s1 - s2) * qInv mod p

        mpz_addmul(s2, key->q, h);          //   s2 = s2 + q * h
        mpz_set(s, s2);                     //    s = s2 = s2 + q * h

        mpz_clears(s1, s2, h, temp, NULL);
        break;
    default:
        DBG_PRINT("Not Implemented Yet!\n");
        break;
    }

    return ERR_OK;
}

/**
 * @description: RSAVP1, RSA Verification Primitive, version 1
 * @param {RSAPublicKey} *key, RSA public key
 * @param {mpz_t} s, signature representative, an integer between 0 and n-1
 * @param {mpz_t} em, encoded message representative, an integer between 0 and n-1
 * @return {*}, 0, OK; -1, Fail;
 */
int RSAVP1(RSAPublicKey *key, mpz_t s, mpz_t em)
{
    int res = ERR_OK;

    res = mpz_cmp(s, key->n);
    if (res >= 0)
    {
        DBG_PRINT("signature representative out of range\n");
        return ERR_RSA_SIG_OUT_OF_RANGE;
    }

    mpz_powm(em, s, key->e, key->n); // em = s ^ e (mod n)

    return ERR_OK;
}