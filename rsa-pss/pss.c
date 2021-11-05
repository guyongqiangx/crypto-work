#include <stdio.h>
#include <string.h>

#include "hash.h"
#include "mgf.h"
#include "rand.h"
#include "pss.h"

#define PSS_BUF_SIZE 512 /* 4096 bits */

/**
 * @description: 将两块指定长度的数据进行 XOR 操作
 * @param {unsigned char} *dest, 缓冲区 1, 同时作为目的缓冲区
 * @param {unsigned char} *src, 缓冲区 2
 * @param {unsigned long} len, 异或操作数据的长度
 * @return {*}, 无
 */
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

/**
 * @description: 设置一块数据左侧指定数量的 bit 为 0
 * @param {unsigned char} *buf, 待操作的数据
 * @param {unsigned long} bit_count, 需要设置为 0 的 bit 数
 * @return {*}, 无
 */
static void clear_leftmost_bits(unsigned char *buf, unsigned long bit_count)
{
    unsigned char temp;

    // 清空完整的 byte
    while (bit_count >= 8)
    {
        *buf ++ = 0x00;
        bit_count -= 8;
    }

    // 逐 bit 清空不足 1 byte 的部分
    temp = 0;
    while (bit_count > 0)
    {
        temp |= 0x01 << (8 - bit_count);
        bit_count --;
    }
    temp ~= temp; /* 取反 */
    *buf = *buf & temp;
}

/**
 * @description: 检查一块数据左侧指定数量的 bit 是否为 0
 * @param {unsigned char} *buf, 待检查的数据
 * @param {unsigned long} bit_count, 需要检查为 0 的 bit 数
 * @return {*}, 满足条件返回 0, 不满足条件返回 -1
 */
static int check_leftmost_bits(unsigned char *buf, unsigned long bit_count)
{
    // 检查完整的 byte
    while (bit_count >= 8)
    {
        // 不为 0
        if (*buf != 0x00)
        {
            return -1;
        }
        buf ++;
        bit_count -= 8;
    }

    // 逐 bit 检查不足 1 byte 的部分
    while (bit_count > 0)
    {
        // 不为 0
        if ( *buf && (0x01 << (8 - bit_count)))
        {
            return -1;
        }
        bit_count --;
    }

    return 0;
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

/**
 * @description: 对一块指定的数据进行 PSS 填充
 * @param {HASH_ALG} alg, 计算消息 M 和 MGF 函数使用的哈希算法
 * @param {char} *M, 用于填充的消息 M
 * @param {unsigned long} mLen, 用于填充的消息 M 的长度(字节)
 * @param {unsigned long} sLen, 用于生成随机数字符串 salt 的长度(字节)
 * @param {char} *EM, 存放 PSS 填充后的编码消息 EM 的缓冲区
 * @param {unsigned long} emLen, 存放 PSS 填充后的编码消息 EM 的缓冲区长度
 * @param {unsigned long} emBits, PSS 填充后的编码消息 EM 的长度(比特)
 * @return {*}, 填充成功返回 0, 失败返回 -1
 */
int PSS_Encode(HASH_ALG alg, char *M, unsigned long mLen, unsigned long sLen, char *EM, unsigned long emLen, unsigned long emBits)
{
    unsigned long hLen, psLen;
    unsigned char buf[PSS_BUF_SIZE];
    unsigned char *pMp, *pmHash, *psalt1;
    unsigned char *pDB, *psalt2;
    unsigned char *maskedDB, *H;

    //      pDb                 pMp
    //       |                   |
    //       +-------- 256 ------+-------- 256 ------+
    //       |                   |                   |
    //       +-------------------+-------------------+
    // buf = |          DB       |        M'         |
    //       +-------------------+-------------------+

    // 检查参数
    if ((NULL == M) || (0 == mLen) ||
        (NULL == EM) || (0 == emLen) ||
        (0 == emBits))
    {
        return -1;
    }

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

    // 设置 EM 最左侧的 8emLen - emBits 的 bits 为 0
    psLen = 8 * emLen - emBits;
    clear_leftmost_bits(EM, psLen);

    // 填充 EM 末尾的 0xBC
    EM[emLen - 1] = 0xbc;

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

/**
 * @description: 对一块指定的数据的 PSS 填充进行校验
 * @param {HASH_ALG} alg, 计算消息 M 和 MGF 函数使用的哈希算法
 * @param {char} *M, 用于计算填充的原始消息 M
 * @param {unsigned long} mLen, 用于计算填充的原始消息 M 的长度(字节)
 * @param {unsigned long} sLen, 用于生成随机数字符串 salt 的长度(字节)
 * @param {char} *EM, 用于校验 PSS 填充消息 EM 的缓冲区
 * @param {unsigned long} emLen, 用于校验 PSS 填充消息 EM 的缓冲区的长度
 * @param {unsigned long} emBits, 用于校验 PSS 填充消息 EM 的长度(比特)
 * @return {*}, 校验一致返回 0, 不一致返回 -1
 */
int PSS_Verify(HASH_ALG alg, char *M, unsigned long mLen, unsigned long sLen, char *EM, unsigned long emLen, unsigned long emBits)
{
    unsigned long hLen, psLen;
    unsigned char buf[PSS_BUF_SIZE];
    unsigned char *pMp, *pmHash, *psalt1;
    unsigned char *pDB, *psalt2;
    unsigned char *maskedDB, *H;

    //      pDb                 pMp
    //       |                   |
    //       +-------- 256 ------+-------- 256 ------+
    //       |                   |                   |
    //       +-------------------+-------------------+
    // buf = |          DB       |        M'         |
    //       +-------------------+-------------------+

    // 检查参数
    if ((NULL == M) || (0 == mLen) ||
        (NULL == EM) || (0 == emLen) ||
        (0 == emBits))
    {
        return -1;
    }

    hLen = HASH_GetDigestSize(alg, 0);

    pDB = buf;
    pMp = buf + PSS_BUF_SIZE / 2;

    pmHash = pMp + 8;
    psalt1 = pmHash + hLen;

    if (emLen < hLen + sLen + 2)
    {
        printf("inconsistent\n");
        return -1;
    }

    if (EM[emLen] != 0xbc)
    {
        printf("inconsistent\n");
        return -1;
    }

    maskedDB = EM;
    H = EM + emLen - hLen - 1;

    // 检查最左侧的 psLen bits
    psLen = 8 * emLen - mBits;
    if (check_leftmost_bits(maskedDB, psLen) != 0)
    {
        printf("inconsistent\n");
        return -1;
    }

    /*
     * 1. 反向构造 DB 数据块: DB = padding2 || salt
     */

    // 生成 DB 数据
    MGF1(H, hLen, alg, pDB);
    xor(pDB, maskedDB, emLen - hLen - 1);

    // 设置 pDB 最左侧的 8emLen - emBits 的 bits 为 0
    clear_leftmost_bits(pDB, psLen);

    // 检查 pDB 最左侧的 emLen - hLen - sLen - 2 的 bytes 为 0
    psLen = emLen - hLen - sLen - 2;
    if (check_leftmost_bits(pDB, 8 * psLen) != 0)
    {
        printf("inconsistent\n");
        return -1;
    }

    // 检查 padding2 结束后的 0x01 标记
    if (pDB[psLen + 1] != 0x01)
    {
        printf("inconsistent\n");
        return -1;
    }
    psalt2 = maskedDB + psLen + 2;

    /*
     * 2. 反向构造 M' 数据块: M' = padding1 || mHash || salt
     */
    psLen = 8;
    // 设置 padding1, 填充 8 个字节的 0x00
    memset(pMp, 0, psLen);

    // 计算 mHash = Hash(M)
    HASH(alg, M, mLen, pmHash);

    // 复制 salt
    memcpy(psalt1, psalt2, sLen);

    // 临时计算 M' 的哈希存放到 DB 中, 并与 EM 中的哈希比较
    HASH(alg, pMp, 8 + hLen + sLen, pDB);
    if (memcmp(pDB, H, hLen) != 0x00)
    {
        printf("inconsistent\n");
        return -1;
    }

    printf("consistent\n");

    return 0;
}