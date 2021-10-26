#include <stdio.h>
#include <string.h>

#include "hash.h"
#include "mgf.h"
#include "rand.h"
#include "oaep.h"

#define OAEP_BUF_SIZE 512 /* 4096 bits */

static void xor(unsigned char *dest, unsigned char *src, unsigned long len)
{
    while (len > 0)
    {
        *dest = *dest ^ *src;
        dest ++;
        src  ++;

        len --;
    }
}

/*
 * Optimal Asymmetric Encryption Padding (OAEP): 最优非对称加密填充
 *
 * EME-OAEP Encoding Operation
 *
 *                                +----------+------+--+-------+
 *                           DB = |  lHash   |  PS  |01|   M   |
 *                                +----------+------+--+-------+
 *                                               |
 *                     +----------+              |
 *                     |   seed   |              |
 *                     +----------+              |
 *                           |                   |
 *                           |-------> MGF ---> xor
 *                           |                   |
 *                  +--+     V                   |
 *                  |00|    xor <----- MGF <-----|
 *                  +--+     |                   |
 *                    |      |                   |
 *                    V      V                   V
 *                  +--+----------+----------------------------+
 *            EM =  |00|maskedSeed|          maskedDB          |
 *                  +--+----------+----------------------------+
 *
 *    DB: Data Block
 * lHash: Hash(L)
 *    PS: Padding String, k - mLen - 2hLen - 2 zero octets
 *    01: a single octet with hexadecimal value 0x01
 *     M: message to be encrypted
 *        DB = lHash || PS || 0x01 || M
 *    EM: Encoded Message
 */

/*
 * RFC 8017                      PKCS #1 v2.2                 November 2016
 *
 * 7.1.1.  Encryption Operation
 * Steps:
 *   2.  EME-OAEP encoding (see Figure 1 below):
 *
 *     a.  If the label L is not provided, let L be the empty string.
 *         Let lHash = Hash(L), an octet string of length hLen (see
 *         the note below).
 *
 *     b.  Generate a padding string PS consisting of k - mLen -
 *         2hLen - 2 zero octets.  The length of PS may be zero.
 *
 *     c.  Concatenate lHash, PS, a single octet with hexadecimal
 *         value 0x01, and the message M to form a data block DB of
 *         length k - hLen - 1 octets as
 *
 *             DB = lHash || PS || 0x01 || M.
 *
 *     d.  Generate a random octet string seed of length hLen.
 *
 *     e.  Let dbMask = MGF(seed, k - hLen - 1).
 *
 *     f.  Let maskedDB = DB \xor dbMask.
 *
 *     g.  Let seedMask = MGF(maskedDB, hLen).
 *
 *     h.  Let maskedSeed = seed \xor seedMask.
 *
 *     i.  Concatenate a single octet with hexadecimal value 0x00,
 *         maskedSeed, and maskedDB to form an encoded message EM of
 *         length k octets as
 *
 *             EM = 0x00 || maskedSeed || maskedDB.
 */
int OAEP_Encoding(HASH_ALG alg, unsigned long k, char *M, unsigned long mLen, const char *L, unsigned long lLen, char *EM, unsigned long emLen)
{
    unsigned long hLen, psLen;
    unsigned char buf[OAEP_BUF_SIZE];
    unsigned char *p, *pSeed, *pDB;
    unsigned char *maskedSeed, *maskedDB;

    //       +-- hLen --+-------  k - hLen - 1  -----+ 1+
    //       |          |                            |  |
    //       +----------+----------------------------+--+
    // buf = |   seed   |             DB             |00|
    //       +----------+----------------------------+--+

    // 检查参数
    if ((NULL == M) || (0 == mLen) ||
        (NULL == EM) || (0 == emLen) ||
        (0 == k) || (k != emLen))
    {
        return -1;
    }

    // 检查 L 长度, 假定 lLen <= 1024 字符, 文档要求 lLen < 2^61 - 1
    if ((NULL != L) && (lLen > 1024))
    {
        printf("label too long\n");
        return -1;
    }

    hLen = HASH_GetDigestSize(alg, 0);

    // 检查 mLen
    if (mLen > k - 2 * hLen - 2)
    {
        printf("message too long\n");
        return -1;
    }

    pSeed = buf;
    pDB   = buf + hLen;

    maskedSeed = EM + 1;
    maskedDB   = EM + 1 + hLen;

    p     = pDB; // p 指向 db

    /*
     * 1. 准备 DB = lHash || PS || 0x01 || M
     */
    // 取 label L 的哈希值
    if (NULL == L)
    {
        HASH(alg, "", 0, p);
    }
    else
    {
        HASH(alg, L, lLen, p);
    }
    p += hLen;

    // 填充 PS
    psLen = k - mLen - 2 * hLen - 2;
    if (0 != psLen)
    {
        memset(p, 0, psLen);
    }
    p += psLen;

    // 填充常量 0x01
    *p = 0x01;
    p ++;

    // 复制消息 M
    memcpy(p, M, mLen);

    /*
     * 2. 准备 seed
     */
    Get_Random_Bytes(pSeed, hLen);

    /*
     * 3. 设置 maskedDB
     */
    // dbMask = MGF(seed, k - hLen - 1)
    MGF1(pSeed, hLen, alg, k-hLen-1, maskedDB);

    // maskedDB = DB \xor dbMask
    xor(maskedDB, pDB, k-hLen-1);

    /*
     * 4. 设置 maskedSeed
     */
    // seedMask = MGF(maskedDB, hLen)
    MGF1(maskedDB, k-hLen-1, alg, hLen, maskedSeed);

    // maskedSeed = seed \xor seedMask
    xor(maskedSeed, pSeed, hLen);

    // 5. 填充 EM[0] = 0;
    EM[0] = 0;

    return 0;
}

/*
 * RFC 8017                      PKCS #1 v2.2                 November 2016
 *
 * 7.1.2.  Decryption Operation
 * Steps:
 *   3.  EME-OAEP decoding:
 *
 *     a.  If the label L is not provided, let L be the empty string.
 *         Let lHash = Hash(L), an octet string of length hLen (see
 *         the note in Section 7.1.1).
 *
 *     b.  Separate the encoded message EM into a single octet Y, an
 *         octet string maskedSeed of length hLen, and an octet
 *         string maskedDB of length k - hLen - 1 as
 *
 *             EM = Y || maskedSeed || maskedDB.
 *
 *     c.  Let seedMask = MGF(maskedDB, hLen).
 *
 *     d.  Let seed = maskedSeed \xor seedMask.
 *
 *     e.  Let dbMask = MGF(seed, k - hLen - 1).
 *
 *     f.  Let DB = maskedDB \xor dbMask.
 *
 *     g.  Separate DB into an octet string lHash' of length hLen, a
 *         (possibly empty) padding string PS consisting of octets
 *         with hexadecimal value 0x00, and a message M as
 *
 *             DB = lHash' || PS || 0x01 || M.
 *
 *         If there is no octet with hexadecimal value 0x01 to
 *         separate PS from M, if lHash does not equal lHash', or if
 *         Y is nonzero, output "decryption error" and stop.  (See
 *         the note below.)
 */
int OAEP_Decoding(HASH_ALG alg, unsigned long k, const char *L, unsigned long lLen, char *EM, unsigned long emLen, char *M, unsigned long *mLen)
{
    unsigned long hLen, psLen;
    unsigned char buf[OAEP_BUF_SIZE];
    unsigned char *p, *pSeed, *pDB;
    unsigned char *maskedSeed, *maskedDB;

    //       +-- hLen --+-------  k - hLen - 1  -----+ 1+
    //       |          |                            |  |
    //       +----------+----------------------------+--+
    // buf = |   seed   |             DB             |00|
    //       +----------+----------------------------+--+

    // 检查参数
    if ((NULL == M) || (NULL == EM) || (0 == k))
    {
        return -1;
    }

    // 检查 L 长度, 假定 lLen <= 1024 字符, 文档要求 lLen < 2^61 - 1
    if ((NULL != L) && (lLen > 1024))
    {
        printf("decryption error\n");
        return -1;
    }

    // 检查密文长度 emLen == k
    if (k != emLen)
    {
        printf("decryption error\n");
        return -1;
    }

    hLen = HASH_GetDigestSize(alg, 0);

    // 检查 k
    if (k < 2 * hLen + 2)
    {
        printf("decryption error\n");
        return -1;
    }

    pSeed = buf;
    pDB   = buf + hLen;

    maskedSeed = EM + 1;
    maskedDB   = EM + 1 + hLen;

    /*
     * 1. 检查 EM 数据格式 (是否以 0x00 开头)
     */

    // 检查 Y = EM[0] == 0x00
    if (EM[0] != 0x00)
    {
        printf("decryption error");
        return -1;
    }

    /*
     * 2. 解析 EM 数据得到 DB 数据
     */

    // seedMask = MGF(maskedDB, hLen)
    MGF1(maskedDB, k - hLen - 1, alg, hLen, pSeed);

    // seed = maskedSeed \xor seedMask
    xor(pSeed, maskedSeed, hLen);

    // dbMask = MGF(seed, k-hLen-1)
    MGF1(pSeed, hLen, alg, k-hLen-1, pDB);

    // DB = maskedDB \xor dbMask
    xor(pDB, maskedDB, k-hLen-1);

    /*
     * 3. 检查 DB 数据格式
     */

    // 取 label L 的哈希值
    if (NULL == L)
    {
        HASH(alg, "", 0, pSeed);
    }
    else
    {
        HASH(alg, L, lLen, pSeed);
    }

    // 检查 DB 开头的 label L 的哈希值
    if (0 != memcmp(pSeed, pDB, hLen))
    {
        printf("decryption error");
        return -1;
    }

    // 跳过填充数据 PS 直到非 0x00 数据
    p     = pDB + hLen; // p 指向 PS
    *mLen = k - 1 - hLen - hLen;
    while (*p == 0x00)
    {
        p ++;
        *mLen --;
    }

    // 检查 PS 结束的位置是否为 0x01
    if (*p != 0x01)
    {
        printf("decryption error");
        return -1;
    }

    // 跳过 0x01;
    p ++;
    *mLen --;

    // 提取最后的数据到 M 中，长度为 mLen
    memcpy(M, p, *mLen);

    return 0;
}
