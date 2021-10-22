#include <stdio.h>
#include "hash.h"
#include "mgf.h"

/*
 * From: https://en.wikipedia.org/wiki/Mask_generation_function
 *
 * Example outputs of MGF1:
 *
 * Python 2.7.6 (default, Sep  9 2014, 15:04:36) 
 * [GCC 4.2.1 Compatible Apple LLVM 6.0 (clang-600.0.39)] on darwin
 * Type "help", "copyright", "credits" or "license" for more information.
 * >>> from mgf1 import mgf1
 * >>> from binascii import hexlify
 * >>> from hashlib import sha256
 * >>> hexlify(mgf1('foo', 3))
 * '1ac907'
 * >>> hexlify(mgf1('foo', 5))
 * '1ac9075cd4'
 * >>> hexlify(mgf1('bar', 5))
 * 'bc0c655e01'
 * >>> hexlify(mgf1('bar', 50))
 * 'bc0c655e016bc2931d85a2e675181adcef7f581f76df2739da74faac41627be2f7f415c89e983fd0ce80ced9878641cb4876'
 * >>> hexlify(mgf1('bar', 50, sha256))
 * '382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1'
 */

/*
 * cc mgftest.c mgf.c -o mgftest -I/public/ygu/cryptography/crypto-work.git/out/include -L/public/ygu/cryptography/crypto-work.git/out/lib -lhash
 */
int main(int argc, char *argv)
{
    int i;
    char buf[1024];

    MGF1("foo", HASH_ALG_SHA1, 3, buf);
    for (i=0; i<3; i++)
    {
        printf("%02x", ((unsigned char *)buf)[i]);
    }
    printf("\n");

    MGF1("foo", HASH_ALG_SHA1, 5, buf);
    for (i=0; i<5; i++)
    {
        printf("%02x", ((unsigned char *)buf)[i]);
    }
    printf("\n");

    MGF1("bar", HASH_ALG_SHA1, 5, buf);
    for (i=0; i<5; i++)
    {
        printf("%02x", ((unsigned char *)buf)[i]);
    }
    printf("\n");

    MGF1("bar", HASH_ALG_SHA1, 50, buf);
    for (i=0; i<50; i++)
    {
        printf("%02x", ((unsigned char *)buf)[i]);
    }
    printf("\n");

    MGF1("bar", HASH_ALG_SHA256, 50, buf);
    for (i=0; i<50; i++)
    {
        printf("%02x", ((unsigned char *)buf)[i]);
    }
    printf("\n");

    return 0;
}