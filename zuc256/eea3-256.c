/*
 * @        file: zuc.c
 * @ description: implementation for the zuc
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "zuc256.h"

//#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...)
#endif

/*
 * 128-EEA3: EPS Encryption Algorithm 3, 机密性算法(Confidentiality)
 *        CK: 128-bit confidentiality key
 *     COUNT: 32-bit counter
 *    BEARER: 5-bit bearer identity
 * DIRECTION: 1-bit input indicating the direction of transmission
 *    LENGTH: number of bits to be encrypted/decrypted
 *       IBS: input bit stream
 *       OBS: output bit stream
 */
int EEA3(unsigned char *CK, unsigned int COUNT, unsigned int BEARER, unsigned int DIRECTION, unsigned int LENGTH, unsigned int *IBS, unsigned int *OBS)
{
    ZUC256_CTX ctx;
    int i;
    uint8_t iv[16];
    uint32_t len, quotient, remainder;

    if ((NULL == CK) || (NULL == IBS) || (NULL == OBS) || (0 == LENGTH))
    {
        return ERR_INV_PARAM;
    }

    iv[ 0] = (COUNT >> 24) & 0xFF;
    iv[ 1] = (COUNT >> 16) & 0xFF;
    iv[ 2] = (COUNT >>  8) & 0xFF;
    iv[ 3] = COUNT & 0xFF;
    iv[ 4] = ((BEARER & 0x1F) << 3) | ((DIRECTION & 0x01) << 2);
    iv[ 5] = 0x00;
    iv[ 6] = 0x00;
    iv[ 7] = 0x00;
    memcpy(&iv[8], &iv[0], 8);

    ZUC256_Init(&ctx, CK, iv);

    len = (LENGTH + 31) / 32;
    ZUC256_GenerateKeyStream(&ctx, OBS, len);

    quotient = LENGTH / 32;
    remainder = LENGTH % 32;

    /* 逐字处理 32 bit 部分 */
    for (i=0; i<quotient; i++)
    {
        *OBS++ ^= *IBS ++;
    }

    /* 处理不足 32 bit 的剩余部分 */
    if (remainder)
    {
        /* 计算最后 32 bit */
        *OBS ^= *IBS;
        /* 清除不需要的 bit */
        *OBS = (*OBS >> (32-remainder)) << (32-remainder);
    }

    return ERR_OK;
}