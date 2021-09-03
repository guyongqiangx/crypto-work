/*
 * @        file: zuc.c
 * @ description: implementation for the zuc
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "zuc128.h"

//#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...)
#endif

#include <malloc.h>

static int GetBit(const uint32_t *ibs, uint32_t offset)
{
    /* word 偏移地址 */
    ibs = ibs + offset / 32;
    /* word 内 bit 偏移位置 */
    offset = offset % 32;

    return (*ibs >> (31-offset)) & 0x01;
}

static uint32_t GetWord(const uint32_t *ibs, uint32_t offset)
{
    uint32_t temp;

    /* word 偏移地址 */
    ibs = ibs + offset / 32;
    /* word 内 bit 偏移位置 */
    offset = offset % 32;

    /*
     * 根据《C陷阱与缺陷》第 7.5 节:
     * 2. 移位计数(即移位操作的位数)允许的取值范围是什么？
     *    如果被移位对象的长度是 n 位，那么移位计数必须大于或等于0，而严格小于 n.
     *    因此，不可能做到在单次操作中将某个数值的所有位都移出。
     * 所以，如果这里只是单纯使用: (offset = 0 或 32 时就会出错)
     *    temp = (S[0] << offset) | (S[1] >> (32-offset));
     */
    if (offset == 0)
    {
        temp = ibs[0];
    }
    else
    {
        temp = (ibs[0] << offset) | (ibs[1] >> (32-offset));
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

    uint8_t iv[16];
    uint32_t L, T, z;
    uint32_t *obs;

    int i;

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
    for (i=0; i<LENGTH; i++)
    {
        if (1 == GetBit(M, i))
        {
            z = GetWord(obs, i);
            T ^= z;
        }
    }
    z = GetWord(obs, LENGTH);
    T ^= z;

    T ^= obs[L-1];

    free(obs);
    obs = NULL;

    *MAC = T;

    return ERR_OK;
}