#include <stdio.h>
#include "gtest/gtest.h"
#include "gmp.h"
#include "rsa.h"

/* pkcs-1v2-1-vec\oaep-int.txt */
static char str_n[] = "bbf82f090682ce9c2338ac2b9da871f7368d07eed41043a440d6b6f07454f51f"
                      "b8dfbaaf035c02ab61ea48ceeb6fcd4876ed520d60e1ec4619719d8a5b8b807f"
                      "afb8e0a3dfc737723ee6b4b7d93a2584ee6a649d060953748834b2454598394e"
                      "e0aab12d7b61a51f527a9a41f6c1687fe2537298ca2a8f5946f8e5fd091dbdcb";
static char str_e[] = "11"; /* 0x11 */
static char str_p[] = "eecfae81b1b9b3c908810b10a1b5600199eb9f44aef4fda493b81a9e3d84f632"
                      "124ef0236e5d1e3b7e28fae7aa040a2d5b252176459d1f397541ba2a58fb6599";
static char str_q[] = "c97fb1f027f453f6341233eaaad1d9353f6c42d08866b1d05a0f2035028b9d86"
                      "9840b41666b42e92ea0da3b43204b5cfce3352524d0416a5a441e700af461503";
static char str_dP[] = "54494ca63eba0337e4e24023fcd69a5aeb07dddc0183a4d0ac9b54b051f2b13e"
                       "d9490975eab77414ff59c1f7692e9a2e202b38fc910a474174adc93c1f67c981";
static char str_dQ[] = "471e0290ff0af0750351b7f878864ca961adbd3a8a7e991c5c0556a94c3146a7"
                       "f9803f8f6f8ae342e931fd8ae47a220d1b99a495849807fe39f9245a9836da3d";
static char str_qInv[] = "b06c4fdabb6301198d265bdbae9423b380f271f73453885093077fcd39e2119f"
                         "c98632154f5883b167a967bf402b4e9e2e0f9656e698ea3666edfb25798039f7";

TEST(RSAKEY, PublicKeyTest)
{
    RSAPublicKey key;

    RSA_PublicKey_Init(str_n, str_e, &key);
    RSA_PublicKey_UnInit(&key);
}

TEST(RSAKEY, PrivateKeyTest)
{
    RSAPrivateKey key;

    RSA_PrivateKey_Init_MultiPrime(str_p, str_q, str_dP, str_dQ, str_qInv, &key);
    RSA_PrivateKey_UnInit(&key);
}

TEST(RSAKEY, MiscTest)
{
    RSAPublicKey key;
    char buf_n[128] = {
        0xbb, 0xf8, 0x2f, 0x09, 0x06, 0x82, 0xce, 0x9c, 0x23, 0x38, 0xac, 0x2b, 0x9d, 0xa8, 0x71, 0xf7,
        0x36, 0x8d, 0x07, 0xee, 0xd4, 0x10, 0x43, 0xa4, 0x40, 0xd6, 0xb6, 0xf0, 0x74, 0x54, 0xf5, 0x1f,
        0xb8, 0xdf, 0xba, 0xaf, 0x03, 0x5c, 0x02, 0xab, 0x61, 0xea, 0x48, 0xce, 0xeb, 0x6f, 0xcd, 0x48,
        0x76, 0xed, 0x52, 0x0d, 0x60, 0xe1, 0xec, 0x46, 0x19, 0x71, 0x9d, 0x8a, 0x5b, 0x8b, 0x80, 0x7f,
        0xaf, 0xb8, 0xe0, 0xa3, 0xdf, 0xc7, 0x37, 0x72, 0x3e, 0xe6, 0xb4, 0xb7, 0xd9, 0x3a, 0x25, 0x84,
        0xee, 0x6a, 0x64, 0x9d, 0x06, 0x09, 0x53, 0x74, 0x88, 0x34, 0xb2, 0x45, 0x45, 0x98, 0x39, 0x4e,
        0xe0, 0xaa, 0xb1, 0x2d, 0x7b, 0x61, 0xa5, 0x1f, 0x52, 0x7a, 0x9a, 0x41, 0xf6, 0xc1, 0x68, 0x7f,
        0xe2, 0x53, 0x72, 0x98, 0xca, 0x2a, 0x8f, 0x59, 0x46, 0xf8, 0xe5, 0xfd, 0x09, 0x1d, 0xbd, 0xcb
    };
    char buf[128];
    size_t count;

    RSA_PublicKey_Init(str_n, str_e, &key);

    memset(buf, 0, sizeof(buf));
    mpz_export(buf, &count, 1, 1, 0, 0, key.n);

    EXPECT_EQ(0, memcmp(buf, buf_n, 128));

    EXPECT_EQ(sizeof(buf_n), RSA_Modulus_Octet_Length(key.n));

    RSA_PublicKey_UnInit(&key);
}