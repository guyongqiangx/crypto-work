/*
 * @        file: zuc.c
 * @ description: implementation for the ZUC-256 MAC
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

static int GetBit(const unsigned char *data, uint32_t offset)
{
    uint32_t *ibs;

    ibs = (uint32_t *)data;

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

static uint32_t *GetTag(const uint32_t *ibs, uint32_t offset, uint32_t *tag, uint32_t len)
{
    int i;
    uint32_t *temp;

    temp = tag;
    for (i=0; i<len/32; i++)
    {
        *temp ++ = GetWord(ibs, offset);
        offset += 32;
    }

    return tag;
}

static void XorTag(uint32_t *tag, uint32_t *w, uint32_t size)
{
    uint32_t i;
    for (i=0; i<size; i++)
    {
        *tag++ ^= *w++;
    }
}

#if 0
/* 单次处理字(word)数量 */
#define MAC_BUFFER_SIZE 128
#define BUF_WORD_COUNT 128

/*
 * 使用已经初始化好的上下文计算 n bit 的 MAC 值, 每次处理不多于 32 * BUF_WORD_COUNT 比特
 */
static void zuc256_mac_internal(ZUC256_CTX *ctx, int mode, const unsigned char *data, size_t n)
{
    int i;
    uint32_t L, size;
    uint32_t *Tag, W[4];
    uint32_t obs[BUF_WORD_COUNT+8];

    Tag = ctx->Tag;
    size = ctx->mac_size;

    L = (n + 31) / 32 + 2 * size / 32;
    ZUC256_GenerateKeyStream(ctx, obs, L);

    if (ctx->Tag[0] == 0) /* 第一次 */
    {
        GetTag(obs, 0, Tag, size);
    }

    for (i=0; i<n; i++)
    {
        if (1 == GetBit(data, i))
        {
            GetTag(obs, i, W, size);
            XorTag(Tag, W, size);
        }
    }

    if (mode == 1) /* 最后一次 */
    {
        GetTag(obs, L, W, size);
        XorTag(Tag, W, size);
    }
}

int ZUC256_MAC_Init(ZUC256_CTX *ctx, ZUC256_TYPE type, unsigned char *key, unsigned char *iv)
{
    if ((NULL==ctx) || (NULL==key) || (NULL==iv))
    {
        return ERR_INV_PARAM;
    }

    if ((type==ZUC256_TYPE_KEYSTREAM) || (type>ZUC256_TYPE_MAX))
    {
        return ERR_INV_PARAM;
    }

    ZUC256_Init(ctx, type, key, iv);

    return ERR_OK;
}

int ZUC256_MAC_Update(ZUC256_CTX *ctx, const void *data, size_t len)
{
    return ERR_OK;
}

int ZUC256_MAC_Final(unsigned char *md, ZUC256_CTX *ctx)
{
    return ERR_OK;
}
#endif

/*
 * n: 计算 MAC 的比特流长度(bit)
 */
unsigned char *ZUC256_MAC(ZUC256_TYPE type, unsigned char *key, unsigned char *iv, const unsigned char *data, size_t l, unsigned char *md)
{
    ZUC256_CTX ctx;

    uint32_t L, t;
    uint32_t *z;
    uint32_t *Tag, W[4];

    int i;
    uint32_t *temp;

    ZUC256_Init(&ctx, type, key, iv);

    t = ctx.mac_size;
    Tag = ctx.Tag;

    L = (l + 31) / 32 + 2 * (t / 32);

    z = (uint32_t *)malloc(L * sizeof(uint32_t));
    ZUC256_GenerateKeyStream(&ctx, z, L);

    GetTag(z, 0, Tag, t);
    for (i=0; i<l; i++)
    {
        if (1 == GetBit(data, i))
        {
            GetTag(z, t + i, W, t);
            XorTag(Tag, W, t/32);
        }
    }

    GetTag(z, l + t, W, t);
    XorTag(Tag, W, t/32);

    free(z);
    z = NULL;

    temp = (uint32_t *)md;
    for (i=0; i<t/32; i++)
    {
        *temp ++ = htobe32(Tag[i]);
    }

    return md;
}
