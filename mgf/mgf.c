#include <stdio.h>
#include <string.h>

#include "hash.h"
#include "mgf.h"

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
    unsigned char buf[MGF1_BUF_SIZE], *p;
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

        HASH(alg, buf, mgfSeedLen+4, (unsigned char *)mask);

        length += digestLen;
        mask += digestLen;
    }

    return 0;
}