#include <stdio.h>
#include <string.h>

#include "mgf.h"
#include "hash.h"

/*
 * RFC 8017                      PKCS #1 v2.2                 November 2016
 *
 * B.2.1.  MGF1
 *
 *    MGF1 is a mask generation function based on a hash function.
 *
 *    MGF1 (mgfSeed, maskLen)
 *
 *    Options:
 *
 *       Hash     hash function (hLen denotes the length in octets of
 *                the hash function output)
 *
 *    Input:
 *
 *       mgfSeed  seed from which mask is generated, an octet string
 *       maskLen  intended length in octets of the mask, at most 2^32 hLen
 * 
 *    Output:
 *
 *       mask     mask, an octet string of length maskLen
 *
 *    Error: "mask too long"
 * 
 *    Steps:
 *
 *    1.  If maskLen > 2^32 hLen, output "mask too long" and stop.
 * 
 *    2.  Let T be the empty octet string.
 *
 *    3.  For counter from 0 to \ceil (maskLen / hLen) - 1, do the
 *        following:
 * 
 *        A.  Convert counter to an octet string C of length 4 octets (see
 *            Section 4.1):
 *
 *               C = I2OSP (counter, 4) .
 *
 *        B.  Concatenate the hash of the seed mgfSeed and C to the octet
 *            string T:
 *
 *               T = T || Hash(mgfSeed || C) .
 *
 *    4.  Output the leading maskLen octets of T as the octet string mask.
 */

#define MGF1_BUF_SIZE 1024
int MGF1(const char *mgfSeed, HASH_ALG alg, unsigned int maskLen, char *mask)
{
    char buf[MGF1_BUF_SIZE], *p;
    unsigned long mgfSeedLen, digestLen;
    unsigned long counter, length;

    mgfSeedLen = strlen(mgfSeed);
    if (mgfSeedLen > MGF1_BUF_SIZE - 4)
    {
        printf("MGF1 buffer is not long enough!\n");
        return -1;
    }

    // copy mgfSeed to buffer
    memcpy(buf, mgfSeed, mgfSeedLen);

    // clear rest buffer to 0
    p = buf + mgfSeedLen;
    memset(p, 0, MGF1_BUF_SIZE-mgfSeedLen);

    digestLen = HASH_GetDigestSize(alg, 0);

    counter = 0;
    length = 0;

    while (length < maskLen)
    {
        p[0] = (counter >> 0x24) & 0xff;
        p[1] = (counter >> 0x16) & 0xff;
        p[2] = (counter >> 0x08) & 0xff;
        p[3] = counter & 0xff;

        HASH(alg, buf, mgfSeedLen+4, mask);

        length += digestLen;
        mask += digestLen;
    }

    return 0;
}

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
 * cc mgf.c -o mgf -I/public/ygu/cryptography/crypto-work.git/out/include -L/public/ygu/cryptography/crypto-work.git/out/lib -lhash
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