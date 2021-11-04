#include <stdio.h>
#include <string.h>

#include "hash.h"
#include "mgf.h"
#include "rand.h"
#include "pss.h"

#define PSS_BUF_SIZE 512 /* 4096 bits */

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

static void clear_msb_bits(unsigned char *buf, unsigned long bit_count)
{
    unsigned char temp;

    // 清空完整的 byte
    while (bit_count >= 8)
    {
        *buf ++ = 0x00;
        bit_count -= 8;
    }

    // 清空不足 1 byte 的部分
    temp = 0;
    while (bit_count > 0)
    {
        temp |= 0x01 << (8 - bit_count);
        bit_count --;
    }
    temp ~= temp;
    *buf = *buf & temp;
}

/*
 * EMSA-PSS Encoding Operation
 *                                      +-----------+
 *                                      |     M     |
 *                                      +-----------+
 *                                            |
 *                                            V
 *                                          Hash
 *                                            |
 *                                            V
 *                              +--------+----------+----------+
 *                         M' = |Padding1|  mHash   |   salt   |
 *                              +--------+----------+----------+
 *                                             |
 *                   +--------+----------+     V
 *             DB =  |Padding2|   salt   |   Hash
 *                   +--------+----------+     |
 *                             |               |
 *                             V               |
 *                            xor <--- MGF <---|
 *                             |               |
 *                             |               |
 *                             V               V
 *                   +-------------------+----------+--+
 *             EM =  |    maskedDB       |     H    |bc|
 *                   +-------------------+----------+--+
 * 
 *    DB: Data Block
 * mHash: Hash(M)
 *   MGF: Mask Generation Function
 *    PS: Padding String, k - mLen - 2hLen - 2 zero octets
 *    01: a single octet with hexadecimal value 0x01
 *     M: Message to be Signed
 *     H: Hash Value
 *    EM: Encoded Message
 */

/*
 * RFC 8017                      PKCS #1 v2.2                 November 2016
 *
 * 9.1.1.  Encoding Operation
 * 
 *    EMSA-PSS-ENCODE (M, emBits)
 * 
 *    Options:
 * 
 *       Hash     hash function (hLen denotes the length in octets of
 *                the hash function output)
 *       MGF      mask generation function
 *       sLen     intended length in octets of the salt
 * 
 *    Input:
 * 
 *       M        message to be encoded, an octet string
 *       emBits   maximal bit length of the integer OS2IP (EM) (see Section
 *                4.2), at least 8hLen + 8sLen + 9
 * 
 *    Output:
 * 
 *       EM       encoded message, an octet string of length emLen = \ceil
 *                (emBits/8)
 * 
 *    Errors:  "Encoding error"; "message too long"
 * 
 *    Steps:
 * 
 *       1.   If the length of M is greater than the input limitation for
 *            the hash function (2^61 - 1 octets for SHA-1), output
 *            "message too long" and stop.
 * 
 *       2.   Let mHash = Hash(M), an octet string of length hLen.
 * 
 *       3.   If emLen < hLen + sLen + 2, output "encoding error" and stop.
 * 
 *       4.   Generate a random octet string salt of length sLen; if sLen =
 *            0, then salt is the empty string.
 * 
 *       5.   Let
 * 
 *               M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
 * 
 *            M' is an octet string of length 8 + hLen + sLen with eight
 *            initial zero octets.
 * 
 *       6.   Let H = Hash(M'), an octet string of length hLen.
 * 
 *       7.   Generate an octet string PS consisting of emLen - sLen - hLen
 *            - 2 zero octets.  The length of PS may be 0.
 * 
 *       8.   Let DB = PS || 0x01 || salt; DB is an octet string of length
 *            emLen - hLen - 1.
 * 
 *       9.   Let dbMask = MGF(H, emLen - hLen - 1).
 * 
 *       10.  Let maskedDB = DB \xor dbMask.
 * 
 *       11.  Set the leftmost 8emLen - emBits bits of the leftmost octet
 *            in maskedDB to zero.
 * 
 *       12.  Let EM = maskedDB || H || 0xbc.
 * 
 *       13.  Output EM.
 */

int PSS_Encoding(HASH_ALG alg, unsigned long k, char *M, unsigned long mLen, unsigned long sLen, char *EM, unsigned long emLen, unsigned long emBits);
{
    unsigned long hLen, psLen;
    unsigned char buf[PSS_BUF_SIZE];
    unsigned char *pMp, *pmHash, *psalt1;
    unsigned char *pDB, *psalt2;
    unsigned char *p;
    unsigned char *maskedDB, *H;

    //      pDb                 pMp
    //       |                   |
    //       +-------- 256 ------+-------- 256 ------+
    //       |                   |                   |
    //       +-------------------+-------------------+
    // buf = |          DB       |        M'         |
    //       +-------------------+-------------------+

    hLen = HASH_GetDigestSize(alg, 0);

    pDB = buf;
    pMp = buf + PSS_BUF_SIZE / 2;

    pmHash = pMp + 8;
    psalt1 = pmHash + hLen;

    // 检查 emLen
    if (emLen < hLen + sLen + 2)
    {
        printf("encoding error\n");
        return -1;
    }

    /*
     * 1. 构造 M' 数据块: M' = padding1 || mHash || salt
     */
    psLen = 8;
    // 设置 padding1, 填充 8 个字节的 0x00, padding1 = (0x)00 00 00 00 00 00 00 00
    memset(pMp, 0, psLen); // padding1, M'[0 - 7] = 0x00

    // 计算 mHash = Hash(M), M'[8 - 8+hLen] = mhash
    HASH(alg, M, mLen, pmHash);

    // 生成 sLen 长度的随机字符串 salt, 如果 sLen 为 0, 则 salt 为空串
    if (sLen > 0)
    {
        Get_Random_Bytes(psalt1, sLen);
    }

    /*
     * 2. 构造 DB 数据块: DB = padding2 || salt
     */
    psLen = emLen - sLen - hLen - 2;
    psalt2 = pDB + psLen + 1;

    // 设置 padding2 前面的 0, 填充 emLen - sLen - hLen - 2 的 0 字节
    memset(pDB, 0, psLen);

    // 设置 padding2 后面的 0x01 标记
    pDB[psLen] = 0x01;

    // 设置 sLen 长度的随机字符串 salt, 使用前面已经生成的结果
    if (sLen > 0)
    {
        memcpy(psalt2, psalt1, sLen);
    }

    /*
     * 3. 构造 EM 数据块: EM = maskedDB || H || 0xbc
     */
    maskedDB = EM;
    H = EM + emLen - hLen - 1;

    // 生成 M' 的哈希, H = Hash(M')
    HASH(alg, pMp, 8 + hLen + sLen, H);

    // 生成 maskedDB
    MGF1(H, hLen, alg, maskedDB);
    xor(maskedDB, DB, emLen - hLen - 1);

    // 填充 EM 末尾的 0xBC
    EM[emLen - 1] = 0xbc;

    // 设置 EM 最左侧的 8emLen - emBits 的 bits 为 0
    psLen = 8 * emLen - emBits;
    clear_msb_bits(EM, psLen);

    return 0;
}

/*
 * RFC 8017                      PKCS #1 v2.2                 November 2016
 *
 * 9.1.2.  Verification Operation
 * 
 *    EMSA-PSS-VERIFY (M, EM, emBits)
 * 
 *    Options:
 * 
 *       Hash     hash function (hLen denotes the length in octets of
 *                the hash function output)
 *       MGF      mask generation function
 *       sLen     intended length in octets of the salt
 * 
 *    Input:
 * 
 *       M        message to be verified, an octet string
 *       EM       encoded message, an octet string of length emLen = \ceil
 *                (emBits/8)
 *       emBits   maximal bit length of the integer OS2IP (EM) (see Section
 *                4.2), at least 8hLen + 8sLen + 9
 * 
 *    Output:  "consistent" or "inconsistent"
 * 
 *    Steps:
 * 
 *       1.   If the length of M is greater than the input limitation for
 *            the hash function (2^61 - 1 octets for SHA-1), output
 *            "inconsistent" and stop.
 * 
 *       2.   Let mHash = Hash(M), an octet string of length hLen.
 * 
 *       3.   If emLen < hLen + sLen + 2, output "inconsistent" and stop.
 * 
 *       4.   If the rightmost octet of EM does not have hexadecimal value
 *            0xbc, output "inconsistent" and stop.
 * 
 *       5.   Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
 *            and let H be the next hLen octets.
 * 
 *       6.   If the leftmost 8emLen - emBits bits of the leftmost octet in
 *            maskedDB are not all equal to zero, output "inconsistent" and
 *            stop.
 * 
 *       7.   Let dbMask = MGF(H, emLen - hLen - 1).
 * 
 *       8.   Let DB = maskedDB \xor dbMask.
 * 
 *       9.   Set the leftmost 8emLen - emBits bits of the leftmost octet
 *            in DB to zero.
 * 
 *       10.  If the emLen - hLen - sLen - 2 leftmost octets of DB are not
 *            zero or if the octet at position emLen - hLen - sLen - 1 (the
 *            leftmost position is "position 1") does not have hexadecimal
 *            value 0x01, output "inconsistent" and stop.
 * 
 *       11.  Let salt be the last sLen octets of DB.
 * 
 *       12.  Let
 * 
 *               M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
 * 
 *            M' is an octet string of length 8 + hLen + sLen with eight
 *            initial zero octets.
 * 
 *       13.  Let H' = Hash(M'), an octet string of length hLen.
 * 
 *       14.  If H = H', output "consistent".  Otherwise, output
 *            "inconsistent".
 */
int PSS_Decoding(HASH_ALG alg, unsigned long k, unsigned long sLen, char *EM, unsigned long emLen, char *M, unsigned long *mLen unsigned long emBits)
{

    return 0;
}