#include <stdio.h>
#include "oaep.h"
#include "gmp.h"
#include "rsa.h"

int RSAES_OAEP_Encrypt(RSAPublicKey *key, char *M, unsigned long mLen, const char *L, unsigned long lLen, HASH_ALG alg, char *C, unsigned long cLen)
{
    mpz_t m, c;
    unsigned long k, hLen;
    int res = ERR_OK;
    char buf[512];

    if ((NULL == key) || (NULL == M) || (NULL == C))
    {
        return ERR_INV_PARAM;
    }

    if (lLen > (1 << 31)) /* length of L less than the limitation for hash function, lLen < 2^61-1 for SHA-1 */
    {
        return ERR_RSA_LABEL_TOO_LONG;
    }

    k = RSA_Modulus_Octet_Length(key->n);
    hLen = HASH_GetDigestSize(alg, 0);
    if (mLen > k - 2 * hLen - 2)
    {
        return ERR_RSA_MSG_TOO_LONG;
    }

    res = OAEP_Encoding(alg, k, M, mLen, L, lLen, buf, k);
    if (ERR_OK != res)
    {
        return ERR_RSA_OAEP_ENCODING_ERR;
    }

    mpz_inits(m, c, NULL);

    res = OS2IP(buf, k, m);
    if (ERR_OK != res)
    {
        goto exit;
    }

    res = RSAEP(key, m, c);
    if (ERR_OK != res)
    {
        goto exit;
    }

    res = I2OSP(c, C, cLen);
    if (ERR_OK != res)
    {
        goto exit;
    }

exit:
    mpz_clears(m, c, NULL);
    return res;
}

int RSAES_OAEP_Decrypt(RSAPrivateKey *key, char *C, unsigned long cLen, const char *L, unsigned long lLen, HASH_ALG alg, char *M, unsigned long *mLen)
{
    mpz_t m, c;
    unsigned long k, hLen;
    int res = ERR_OK;
    char buf[512];

    if ((NULL == key) || (NULL == C) || (NULL == M))
    {
        return ERR_INV_PARAM;
    }

    if (lLen > (1 << 31)) /* length of L less than the limitation for hash function, lLen < 2^61-1 for SHA-1 */
    {
        return ERR_RSA_DECRYPTION_ERR;
    }

    k = RSA_Modulus_Octet_Length(key->n);
    hLen = HASH_GetDigestSize(alg, 0);

    if (cLen != k)
    {
        return ERR_RSA_DECRYPTION_ERR;
    }

    if (k < 2 * hLen + 2)
    {
        return ERR_RSA_DECRYPTION_ERR;
    }

    mpz_inits(m, c, NULL);

    res = OS2IP(C, cLen, c);
    if (ERR_OK != res)
    {
        res = ERR_RSA_DECRYPTION_ERR;
        goto exit;
    }

    res = RSADP(key, c, m);
    if (ERR_OK != res)
    {
        res = ERR_RSA_DECRYPTION_ERR;
        goto exit;
    }

    res = I2OSP(m, buf, k);
    if (ERR_OK != res)
    {
        res = ERR_RSA_DECRYPTION_ERR;
        goto exit;
    }

    res = OAEP_Decoding(alg, k, L, lLen, buf, k, M, mLen);
    if (ERR_OK != res)
    {
        res = ERR_RSA_DECRYPTION_ERR;
        goto exit;
    }

exit:
    mpz_clears(m, c, NULL);
    return res;
}