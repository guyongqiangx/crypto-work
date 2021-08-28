/*
 * @        file: zuc.c
 * @ description: implementation for the zuc
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "zuc.h"

//#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...)
#endif

#include <malloc.h>

/* 取 offset 开始开始的 32 bit */
static uint32_t GetWord(uint32_t S[2], uint32_t offset)
{
    uint32_t temp;

    /*
     * 根据《C陷阱与缺陷》第 7.5 节:
     * 2. 移位计数(即移位操作的位数)允许的取值范围是什么？
     *    如果被移位对象的长度是 n 位，那么移位计数必须大于或等于0，而严格小于 n.
     *    因此，不可能做到在单次操作中将某个数值的所有位都移出。
     * 所以，如果这里只是单纯使用: (offset = 0 或 32 时就会出错)
     *    temp = (S[0] << offset) | (S[1] >> (32-offset));
     */

    if (0 == offset)
    {
        temp = S[0];
    }
    else if (32 == offset)
    {
        temp = S[1];
    }
    else
    {
        temp = (S[0] << offset) | (S[1] >> (32-offset));
    }

    return temp;
}
/*
 * 128-EIA3: EPS Integrity Algorithm 3, 完整性算法(Integrity)
 *        IK: 128-bit integrity key
 *     COUNT: 32-bit counter
 *    BEARER: 5-bit bearer identity
 * DIRECTION: 1-bit input indicating the direction of transmission
 *    LENGTH: bits of message
 *         M: message
 *       MAC: message authentication code
 */
int EIA3(unsigned char *IK, unsigned int COUNT, unsigned int BEARER, unsigned int DIRECTION, unsigned int LENGTH, unsigned int *M, unsigned int *MAC)
{
    ZUC_CTX ctx;
    int i, j;
    uint8_t iv[16];
    uint32_t L, T;
    uint32_t quotient, remainder;
    uint32_t *obs;

    if ((NULL == IK) || (NULL == M) || (NULL == MAC) || (0 == LENGTH))
    {
        return ERR_INV_PARAM;
    }

    iv[ 0] = (COUNT >> 24) & 0xFF;
    iv[ 1] = (COUNT >> 16) & 0xFF;
    iv[ 2] = (COUNT >>  8) & 0xFF;
    iv[ 3] = COUNT & 0xFF;
    iv[ 4] = ((BEARER & 0x1F) << 3);
    iv[ 5] = 0x00;
    iv[ 6] = 0x00;
    iv[ 7] = 0x00;

    memcpy(&iv[8], &iv[0], 8);
    iv[ 8] ^= (DIRECTION & 0x01) << 7;
    iv[14] ^= (DIRECTION & 0x01) << 7;

    ZUC_Init(&ctx, IK, iv);

    L = (LENGTH + 31) / 32 + 2;
    obs = (uint32_t *)malloc(L * sizeof(uint32_t));
    ZUC_GenerateKeyStream(&ctx, obs, L);

    T = 0;

    quotient = LENGTH / 32;
    remainder = LENGTH % 32;

    /* 逐字处理 32 bit 部分 */
    for (i=0; i<quotient; i++)
    {
        for (j=0; j<32; j++)
        {
            if (M[i] & (0x01 << (31-j)))
            {
                T ^= GetWord(&obs[i], j);
            }
        }
    }

    /* 处理不足 32 bit 的剩余部分 */
    if (remainder)
    {
        for (j=0; j<remainder; j++)
        {
            if (M[quotient] & (0x01 << (31-j)))
            {
                T ^= GetWord(&obs[quotient], j);
            }
        }
    }

    /* T = T ^ Zlen */
    T ^= GetWord(&obs[quotient], remainder);
    T ^= obs[L-1];

    free(obs);
    obs = NULL;

    *MAC = T;

    return ERR_OK;
}