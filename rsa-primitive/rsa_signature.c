#include <stdio.h>
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
    int i;

    saltLen = HASH_GetDigestSize(alg, 0);

    k = RSA_Modulus_Octet_Length(key->n);
    modBits = RSA_Modulus_Bit_Length(key->n);
    emLen = (modBits + 7) / 8;

    res = PSS_Encode(alg, M, mLen, saltLen, buf, emLen, modBits-1);
    if (ERR_OK != res)
    {
        return res;
    }

    printf("-->EM:");
    for (i=0; i<emLen; i++)
    {
        if (i%16 == 0)
            printf("\n");
        printf("%02x ", ((unsigned char *)buf)[i]);
    }
    printf("\n");

    mpz_inits(em, s, NULL);

    res = OS2IP(buf, emLen, em);
    if (ERR_OK != res)
    {
        printf("1ERR: res=%d\n", res);
        goto exit;
    }

    res = RSASP1(key, em, s);
    if (ERR_OK != res)
    {
        printf("2ERR: res=%d\n", res);
        goto exit;
    }

    res = I2OSP(s, S, k);
    if (ERR_OK != res)
    {
        printf("3ERR: res=%d\n", res);
        goto exit;
    }

    *sLen = k;

    printf("-->Signature:");
    for (i=0; i<k; i++)
    {
        if (i%16 == 0)
            printf("\n");
        printf("%02x ", ((unsigned char *)S)[i]);
    }
    printf("\n");

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
    int i;

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
        printf("1ERR: res=%d\n", res);
        res = ERR_RSA_INVALID_SIGNATURE;
        goto exit;
    }

    res = RSAVP1(key, s, em);
    if (ERR_OK != res)
    {
        printf("2ERR: res=%d\n", res);
        res = ERR_RSA_INVALID_SIGNATURE;
        goto exit;
    }

    res = I2OSP(em, buf, emLen);
    if (ERR_OK != res)
    {
        printf("3ERR: res=%d\n", res);
        res = ERR_RSA_INVALID_SIGNATURE;
        goto exit;
    }

    printf("-->Encode Message:");
    for (i=0; i<emLen; i++)
    {
        if (i%16 == 0)
            printf("\n");
        printf("%02x ", ((unsigned char *)buf)[i]);
    }
    printf("\n");

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