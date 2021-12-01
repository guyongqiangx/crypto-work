#include <stdio.h>
#include <string.h>

#include "rand.h"
#include "hash.h"
#include "pkcs1-v1_5.h"

#define PKCS_V1_5_BUF_SIZE 512 /* 4096 bits */

/*
 * RSAES-PKCS1-v1_5
 * EME: Encoding Method for Encryption
 *
 * RFC 8017                      PKCS #1 v2.2                 November 2016
 *
 * 7.2.1.  Encryption Operation
 *
 *    Steps:
 *       2.  EME-PKCS1-v1_5 encoding:
 *
 *           a.  Generate an octet string PS of length k - mLen - 3
 *               consisting of pseudo-randomly generated nonzero octets.
 *               The length of PS will be at least eight octets.
 *
 *           b.  Concatenate PS, the message M, and other padding to form
 *               an encoded message EM of length k octets as
 *
 *                  EM = 0x00 || 0x02 || PS || 0x00 || M.
 */
int EME_PKCS1_v1_5_Encode(unsigned long k, unsigned char *M, unsigned long mLen, unsigned char *EM)
{
    unsigned char *p;
    unsigned long psLen;

    if (mLen > k - 11)
    {
        printf("message too long\n");
        return -1;
    }

    // 填充非零字符串长度 psLen 不少于 8
    psLen = k - mLen - 3;
    if (psLen < 8)
    {
        printf("The length of PS will be at least eight octets.\n");
        return -1;
    }

    // 开始标记: 0x00, 0x02
    p = EM;
    *p ++ = 0x00;
    *p ++ = 0x02;

    // 填充非零字符串, 长度 psLen
    Get_Random_NonZero_Bytes(p, psLen);
    p += psLen;

    *p ++ = 0x00;

    memcpy(p, M, mLen);

    return 0;
}

/*
 *
 * RFC 8017                      PKCS #1 v2.2                 November 2016
 *
 * 7.2.2.  Decryption Operation
 *
 *    Steps:
 *       3.  EME-PKCS1-v1_5 decoding: Separate the encoded message EM into
 *           an octet string PS consisting of nonzero octets and a message
 *           M as
 *
 *              EM = 0x00 || 0x02 || PS || 0x00 || M.
 *
 *           If the first octet of EM does not have hexadecimal value 0x00,
 *           if the second octet of EM does not have hexadecimal value
 *           0x02, if there is no octet with hexadecimal value 0x00 to
 *           separate PS from M, or if the length of PS is less than 8
 *           octets, output "decryption error" and stop.  (See the note
 *           below.)
 */
int EME_PKCS1_v1_5_Decode(unsigned long k, unsigned char *EM, unsigned char *M, unsigned long *mLen)
{
    unsigned char *p;
    unsigned long psLen;

    p = EM;
    if (0x00 != *p)
    {
        printf("decryption error\n");
        return -1;
    }
    p ++;

    if (0x02 != *p)
    {
        printf("decryption error\n");
        return -1;
    }
    p ++;

    psLen = 0;
    while ((0x00 != *p) && (psLen < k - 2))
    {
        p ++;
        psLen ++;
    }

    // 填充非零字符串长度 psLen 不少于 8
    if (psLen < 8)
    {
        printf("decryption error\n");
        return -1;
    }

    // PS 结束, M 开始前有 0x00 标记, 如果没有, 则 psLen = k - 2
    if (psLen >= (k - 2))
    {
        printf("decryption error\n");
        return -1;
    }

    p ++;

    *mLen = k - 2 - psLen - 1;
    memcpy(M, p, *mLen);

    return 0;
}

/*
 * EMSA: Encoding Method for Signature with Appendix
 *
 * RFC 8017                      PKCS #1 v2.2                 November 2016
 *
 * 9.2.  EMSA-PKCS1-v1_5
 *
 *    This encoding method is deterministic and only has an encoding
 *    operation.
 *
 *    EMSA-PKCS1-v1_5-ENCODE (M, emLen)
 *
 *    Option:
 *
 *       Hash     hash function (hLen denotes the length in octets of
 *                the hash function output)
 *
 *    Input:
 *
 *       M        message to be encoded
 *       emLen    intended length in octets of the encoded message, at
 *                least tLen + 11, where tLen is the octet length of the
 *                Distinguished Encoding Rules (DER) encoding T of
 *                a certain value computed during the encoding operation
 *
 *    Output:
 *
 *       EM       encoded message, an octet string of length emLen
 *
 *    Errors:  "message too long"; "intended encoded message length too
 *       short"
 *
 *    Steps:
 *
 *       1.  Apply the hash function to the message M to produce a hash
 *           value H:
 *
 *              H = Hash(M).
 *
 *           If the hash function outputs "message too long", output
 *           "message too long" and stop.
 *
 *       2.  Encode the algorithm ID for the hash function and the hash
 *           value into an ASN.1 value of type DigestInfo (see
 *           Appendix A.2.4) with the DER, where the type DigestInfo has
 *           the syntax
 *
 *                DigestInfo ::= SEQUENCE {
 *                    digestAlgorithm AlgorithmIdentifier,
 *                    digest OCTET STRING
 *                }
 *
 *           The first field identifies the hash function and the second
 *           contains the hash value.  Let T be the DER encoding of the
 *           DigestInfo value (see the notes below), and let tLen be the
 *           length in octets of T.
 *
 *       3.  If emLen < tLen + 11, output "intended encoded message length
 *           too short" and stop.
 *
 *       4.  Generate an octet string PS consisting of emLen - tLen - 3
 *           octets with hexadecimal value 0xff.  The length of PS will be
 *           at least 8 octets.
 *
 *       5.  Concatenate PS, the DER encoding T, and other padding to form
 *           the encoded message EM as
 *
 *              EM = 0x00 || 0x01 || PS || 0x00 || T.
 *
 *       6.  Output EM.
 */

static unsigned char der_md2[] = {
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02, 0x05, 0x00,
    0x04, 0x10
};

static unsigned char der_md5[] = {
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00,
    0x04, 0x10
};

static unsigned char der_sha1[] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};

static unsigned char der_sha224[] = {
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1c
};

static unsigned char der_sha256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};

static unsigned char der_sha384[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30
};

static unsigned char der_sha512[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40
};

static unsigned char der_sha512_224[] = {
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05,
    0x00, 0x04, 0x1c
};

static unsigned char der_sha512_256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05,
    0x00, 0x04, 0x20
};

static struct hash_encoding {
    HASH_ALG alg;
    unsigned char *encoding;
    unsigned long len;
} hTable[] = {
    {HASH_ALG_MD2,        der_md2,        sizeof(der_md2)/sizeof(der_md2[0])},
    {HASH_ALG_MD5,        der_md5,        sizeof(der_md5)/sizeof(der_md5[0])},
    {HASH_ALG_SHA1,       der_sha1,       sizeof(der_sha1)/sizeof(der_sha1[0])},
    {HASH_ALG_SHA224,     der_sha224,     sizeof(der_sha224)/sizeof(der_sha224[0])},
    {HASH_ALG_SHA256,     der_sha256,     sizeof(der_sha256)/sizeof(der_sha256[0])},
    {HASH_ALG_SHA384,     der_sha384,     sizeof(der_sha384)/sizeof(der_sha384[0])},
    {HASH_ALG_SHA512,     der_sha512,     sizeof(der_sha512)/sizeof(der_sha512[0])},
    {HASH_ALG_SHA512_224, der_sha512_224, sizeof(der_sha512_224)/sizeof(der_sha512_224[0])},
    {HASH_ALG_SHA512_256, der_sha512_256, sizeof(der_sha512_256)/sizeof(der_sha512_256[0])},
};

static struct hash_encoding *get_der_hash_encoding(HASH_ALG alg)
{
    int i;

    for (i=0; i<sizeof(hTable)/sizeof(hTable[1]); i++)
    {
        if (hTable[i].alg == alg)
        {
            return &hTable[i];
        }
    }

    return NULL;
}

int EMSA_PKCS1_v1_5_Encode(HASH_ALG alg, unsigned char *M, unsigned long mLen, unsigned long emLen, unsigned char *EM)
{
    struct hash_encoding *pEncoding;
    unsigned long digestLen, tLen, psLen;

    pEncoding = get_der_hash_encoding(alg);
    if (NULL == pEncoding)
    {
        printf("unsupported hash\n");
        return -1;
    }
    digestLen = HASH_GetDigestSize(alg, 0);

    tLen = pEncoding->len + digestLen;
    if (emLen < tLen + 11)
    {
        printf("intended encoded message length too short\n");
        return -1;
    }

    psLen = emLen - tLen - 3;
    if (psLen < 8)
    {
        printf("intended encoded message length too short\n");
        return -1;
    }

    *EM ++ = 0x00;
    *EM ++ = 0x01;
    memset(EM, 0xff, psLen);
    EM += psLen;
    *EM ++= 0x00;

    memcpy(EM, pEncoding->encoding, pEncoding->len);
    EM += pEncoding->len;

    HASH(alg, M, mLen, EM);

    return 0;
}
