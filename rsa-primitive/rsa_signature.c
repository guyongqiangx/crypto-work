#include <stdio.h>
#include <string.h> /* memcmp */
#include "gmp.h"
#include "hash.h"
#include "pss.h"
#include "pkcs1-v1_5.h"
#include "rsa.h"

int RSASSA_PSS_Sign(RSAPrivateKey *key, unsigned char *M, unsigned long mLen, HASH_ALG alg, unsigned char *S, unsigned long *sLen)
{
    mpz_t em, s;
    unsigned char buf[256];
    unsigned long k, modBits, emLen, saltLen;
    int res = ERR_OK;

    saltLen = HASH_GetDigestSize(alg, 0);

    k = RSA_Modulus_Octet_Length(key->n);
    modBits = RSA_Modulus_Bit_Length(key->n);
    emLen = (modBits + 7) / 8;

    res = PSS_Encode(alg, M, mLen, saltLen, buf, emLen, modBits-1);
    if (ERR_OK != res)
    {
        return res;
    }

    mpz_inits(em, s, NULL);

    res = OS2IP(buf, emLen, em);
    if (ERR_OK != res)
    {
        goto exit;
    }

    res = RSASP1(key, em, s);
    if (ERR_OK != res)
    {
        goto exit;
    }

    res = I2OSP(s, S, k);
    if (ERR_OK != res)
    {
        goto exit;
    }

    *sLen = k;

exit:
    mpz_clears(em, s, NULL);
    return res;
}

int RSASSA_PSS_Verify(RSAPublicKey *key, unsigned char *M, unsigned long mLen, HASH_ALG alg, unsigned char *S, unsigned long sLen)
{
    mpz_t em, s;
    unsigned char buf[256];
    unsigned long k, modBits, emLen, saltLen;
    int res = ERR_OK;

    saltLen = HASH_GetDigestSize(alg, 0);

    k = RSA_Modulus_Octet_Length(key->n);
    modBits = RSA_Modulus_Bit_Length(key->n);
    emLen = (modBits + 7) / 8;

    if (k != sLen)
    {
        return ERR_RSA_INVALID_SIGNATURE;
    }

    mpz_inits(em, s, NULL);

    res = OS2IP(S, sLen, s);
    if (ERR_OK != res)
    {
        res = ERR_RSA_INVALID_SIGNATURE;
        goto exit;
    }

    res = RSAVP1(key, s, em);
    if (ERR_OK != res)
    {
        res = ERR_RSA_INVALID_SIGNATURE;
        goto exit;
    }

    res = I2OSP(em, buf, emLen);
    if (ERR_OK != res)
    {
        res = ERR_RSA_INVALID_SIGNATURE;
        goto exit;
    }

    res = PSS_Verify(alg, M, mLen, saltLen, buf, emLen, modBits-1);
    if (ERR_OK != res)
    {
        res = ERR_RSA_INVALID_SIGNATURE;
        goto exit;
    }

exit:
    mpz_clears(em, s, NULL);
    return res;
}

int RSASSA_PKCS1_v1_5_Sign(RSAPrivateKey *key, unsigned char *M, unsigned long mLen, HASH_ALG alg, unsigned char *S, unsigned long *sLen)
{
    mpz_t em, s;
    unsigned char buf[256];
    unsigned long k;
    int res = ERR_OK;

    k = RSA_Modulus_Octet_Length(key->n);
    res = EMSA_PKCS1_v1_5_Encode(alg, M, mLen, k, buf);
    if (ERR_OK != res)
    {
        return res;
    }

    mpz_inits(em, s, NULL);

    res = OS2IP(buf, k, em);
    if (ERR_OK != res)
    {
        goto exit;
    }

    res = RSASP1(key, em, s);
    if (ERR_OK != res)
    {
        goto exit;
    }

    res = I2OSP(s, S, k);
    if (ERR_OK != res)
    {
        goto exit;
    }

    *sLen = k;

exit:
    mpz_clears(em, s, NULL);
    return res;
}

int RSASSA_PKCS1_v1_5_Verify(RSAPublicKey *key, unsigned char *M, unsigned long mLen, HASH_ALG alg, unsigned char *S, unsigned long sLen)
{
    mpz_t em, s;
    unsigned char buf[256], buf2[256];
    unsigned long k;
    int res = ERR_OK;

    k = RSA_Modulus_Octet_Length(key->n);
    if (sLen != k)
    {
        return ERR_RSA_INVALID_SIGNATURE;
    }

    mpz_inits(em, s, NULL);

    res = OS2IP(S, sLen, s);
    if (ERR_OK != res)
    {
        res = ERR_RSA_INVALID_SIGNATURE;
        goto exit;
    }

    res = RSAVP1(key, s, em);
    if (ERR_OK != res)
    {
        res = ERR_RSA_INVALID_SIGNATURE;
        goto exit;
    }

    res = I2OSP(em, buf, k);
    if (ERR_OK != res)
    {
        res = ERR_RSA_INVALID_SIGNATURE;
        goto exit;
    }

    res = EMSA_PKCS1_v1_5_Encode(alg, M, mLen, k, buf2);
    if (ERR_OK != res)
    {
        res = ERR_RSA_INVALID_SIGNATURE;
        goto exit;
    }

    // 比较解密得到的消息和填充得到的消息
    res = memcmp(buf, buf2, k);
    if (res != 0)
    {
        res = ERR_RSA_INVALID_SIGNATURE;
    }

exit:
    mpz_clears(em, s, NULL);
    return res;
}