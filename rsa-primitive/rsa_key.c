#include <stdio.h>
#include "gmp.h"
#include "rsa.h"

int RSA_PublicKey_Init(const char *n, const char *e, RSAPublicKey *key)
{
    if ((NULL == n) || (NULL == e) || (NULL == key))
    {
        return ERR_INV_PARAM;
    }

    mpz_init_set_str(key->n, n, 16);
    mpz_init_set_str(key->e, e, 16);

    return ERR_OK;
}

int RSA_PublicKey_UnInit(RSAPublicKey *key)
{
    mpz_clear(key->n);
    mpz_clear(key->e);

    return ERR_OK;
}

int RSA_PrivateKey_Init(const char *n, const char *d, RSAPrivateKey *key)
{
    if ((NULL == n) || (NULL == d) || (NULL == key))
    {
        return ERR_INV_PARAM;
    }

    key->type = 1;
    mpz_init_set_str(key->n, n, 16);
    mpz_init_set_str(key->d, d, 16);

    return ERR_OK;
}

int RSA_PrivateKey_Init_MultiPrime(const char *p, const char *q, const char *dP, const char *dQ, const char *qInv, RSAPrivateKey *key)
{
    if ((NULL == p) || (NULL == q) || (NULL == dP) || (NULL == dQ) || (NULL == qInv) || (NULL == key))
    {
        return ERR_INV_PARAM;
    }

    key->type = 2;
    mpz_init_set_str(key->p, p, 16);
    mpz_init_set_str(key->q, q, 16);
    mpz_init_set_str(key->dP, dP, 16);
    mpz_init_set_str(key->dQ, dQ, 16);
    mpz_init_set_str(key->qInv, qInv, 16);

    mpz_init(key->n);
    mpz_mul(key->n, key->p, key->q);    // n = p * q

    return ERR_OK;
}

int RSA_PrivateKey_UnInit(RSAPrivateKey *key)
{
    if (NULL == key)
    {
        return ERR_INV_PARAM;
    }

    if (key->type)
    {
        key->type = 0;
        mpz_clear(key->n);
        mpz_clears(key->p, key->q, key->dP, key->dQ, key->qInv, NULL);
    }
    else
    {
        mpz_clears(key->n, key->d, NULL);
    }

    return ERR_OK;
}
