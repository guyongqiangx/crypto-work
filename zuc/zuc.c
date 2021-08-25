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

#define TEST
#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...)
#endif

#define ZUC_MOD_NUM (2<<31-1)

typedef struct zuc_context {
    /* 16 个 31 bit 变量 */
    uint32_t s[16];

    /* 32 bit 内部状态机变量 */
    uint32_t R1;
    uint32_t R2;
}ZUC_CTX;

/* 31位循环左移: ROTate Left (circular left shift) */
static uint32_t ROTL31(uint32_t x, uint8_t shift)
{
    /* Example: 0x7F00000F << 5 = 0x600001FF
     * 0111 1111 0000 0000 0000 0000 0000 1111 << 5 ---> 0110 0000 0000 0000 0000 0001 1111 1111
     */
    return ((x << shift) & 0x7FFFFFFF) | (x >> (31 - shift));
}

/* 32位循环左移: ROTate Left (circular left shift) */
static uint32_t ROTL32(uint32_t x, uint8_t shift)
{
    return (x << shift) | (x >> (32 - shift));
}

/* 线性变换 L1 */
static uint32_t L1(uint32_t x)
{
    return x ^ ROTL32(x, 2) ^ ROTL32(x, 10) ^ ROTL32(x, 18) ^ ROTL32(x, 24);
}

/* 线性变换 L2 */
static uint32_t L2(uint32_t x)
{
    return x ^ ROTL32(x, 8) ^ ROTL32(x, 14) ^ ROTL32(x, 22) ^ ROTL32(x, 30);
}

/* The S-box S0 (S0=S2, S=(S0,S1,S2,S3)) */
static uint8_t S0[256] =
{
    0x3E, 0x72, 0x5B, 0x47, 0xCA, 0xE0, 0x00, 0x33, 0x04, 0xD1, 0x54, 0x98, 0x09, 0xB9, 0x6D, 0xCB,
    0x7B, 0x1B, 0xF9, 0x32, 0xAF, 0x9D, 0x6A, 0xA5, 0xB8, 0x2D, 0xFC, 0x1D, 0x08, 0x53, 0x03, 0x90,
    0x4D, 0x4E, 0x84, 0x99, 0xE4, 0xCE, 0xD9, 0x91, 0xDD, 0xB6, 0x85, 0x48, 0x8B, 0x29, 0x6E, 0xAC,
    0xCD, 0xC1, 0xF8, 0x1E, 0x73, 0x43, 0x69, 0xC6, 0xB5, 0xBD, 0xFD, 0x39, 0x63, 0x20, 0xD4, 0x38,
    0x76, 0x7D, 0xB2, 0xA7, 0xCF, 0xED, 0x57, 0xC5, 0xF3, 0x2C, 0xBB, 0x14, 0x21, 0x06, 0x55, 0x9B,
    0xE3, 0xEF, 0x5E, 0x31, 0x4F, 0x7F, 0x5A, 0xA4, 0x0D, 0x82, 0x51, 0x49, 0x5F, 0xBA, 0x58, 0x1C,
    0x4A, 0x16, 0xD5, 0x17, 0xA8, 0x92, 0x24, 0x1F, 0x8C, 0xFF, 0xD8, 0xAE, 0x2E, 0x01, 0xD3, 0xAD,
    0x3B, 0x4B, 0xDA, 0x46, 0xEB, 0xC9, 0xDE, 0x9A, 0x8F, 0x87, 0xD7, 0x3A, 0x80, 0x6F, 0x2F, 0xC8,
    0xB1, 0xB4, 0x37, 0xF7, 0x0A, 0x22, 0x13, 0x28, 0x7C, 0xCC, 0x3C, 0x89, 0xC7, 0xC3, 0x96, 0x56,
    0x07, 0xBF, 0x7E, 0xF0, 0x0B, 0x2B, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xA6, 0x4C, 0x10, 0xFE,
    0xBC, 0x26, 0x95, 0x88, 0x8A, 0xB0, 0xA3, 0xFB, 0xC0, 0x18, 0x94, 0xF2, 0xE1, 0xE5, 0xE9, 0x5D,
    0xD0, 0xDC, 0x11, 0x66, 0x64, 0x5C, 0xEC, 0x59, 0x42, 0x75, 0x12, 0xF5, 0x74, 0x9C, 0xAA, 0x23,
    0x0E, 0x86, 0xAB, 0xBE, 0x2A, 0x02, 0xE7, 0x67, 0xE6, 0x44, 0xA2, 0x6C, 0xC2, 0x93, 0x9F, 0xF1,
    0xF6, 0xFA, 0x36, 0xD2, 0x50, 0x68, 0x9E, 0x62, 0x71, 0x15, 0x3D, 0xD6, 0x40, 0xC4, 0xE2, 0x0F,
    0x8E, 0x83, 0x77, 0x6B, 0x25, 0x05, 0x3F, 0x0C, 0x30, 0xEA, 0x70, 0xB7, 0xA1, 0xE8, 0xA9, 0x65,
    0x8D, 0x27, 0x1A, 0xDB, 0x81, 0xB3, 0xA0, 0xF4, 0x45, 0x7A, 0x19, 0xDF, 0xEE, 0x78, 0x34, 0x60,
};

/* The S-box S1 (S1=S3, S=(S0,S1,S2,S3)) */
static uint8_t S1[256] =
{
    0x55, 0xC2, 0x63, 0x71, 0x3B, 0xC8, 0x47, 0x86, 0x9F, 0x3C, 0xDA, 0x5B, 0x29, 0xAA, 0xFD, 0x77,
    0x8C, 0xC5, 0x94, 0x0C, 0xA6, 0x1A, 0x13, 0x00, 0xE3, 0xA8, 0x16, 0x72, 0x40, 0xF9, 0xF8, 0x42,
    0x44, 0x26, 0x68, 0x96, 0x81, 0xD9, 0x45, 0x3E, 0x10, 0x76, 0xC6, 0xA7, 0x8B, 0x39, 0x43, 0xE1,
    0x3A, 0xB5, 0x56, 0x2A, 0xC0, 0x6D, 0xB3, 0x05, 0x22, 0x66, 0xBF, 0xDC, 0x0B, 0xFA, 0x62, 0x48,
    0xDD, 0x20, 0x11, 0x06, 0x36, 0xC9, 0xC1, 0xCF, 0xF6, 0x27, 0x52, 0xBB, 0x69, 0xF5, 0xD4, 0x87,
    0x7F, 0x84, 0x4C, 0xD2, 0x9C, 0x57, 0xA4, 0xBC, 0x4F, 0x9A, 0xDF, 0xFE, 0xD6, 0x8D, 0x7A, 0xEB,
    0x2B, 0x53, 0xD8, 0x5C, 0xA1, 0x14, 0x17, 0xFB, 0x23, 0xD5, 0x7D, 0x30, 0x67, 0x73, 0x08, 0x09,
    0xEE, 0xB7, 0x70, 0x3F, 0x61, 0xB2, 0x19, 0x8E, 0x4E, 0xE5, 0x4B, 0x93, 0x8F, 0x5D, 0xDB, 0xA9,
    0xAD, 0xF1, 0xAE, 0x2E, 0xCB, 0x0D, 0xFC, 0xF4, 0x2D, 0x46, 0x6E, 0x1D, 0x97, 0xE8, 0xD1, 0xE9,
    0x4D, 0x37, 0xA5, 0x75, 0x5E, 0x83, 0x9E, 0xAB, 0x82, 0x9D, 0xB9, 0x1C, 0xE0, 0xCD, 0x49, 0x89,
    0x01, 0xB6, 0xBD, 0x58, 0x24, 0xA2, 0x5F, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xB8, 0x95, 0xE4,
    0xD0, 0x91, 0xC7, 0xCE, 0xED, 0x0F, 0xB4, 0x6F, 0xA0, 0xCC, 0xF0, 0x02, 0x4A, 0x79, 0xC3, 0xDE,
    0xA3, 0xEF, 0xEA, 0x51, 0xE6, 0x6B, 0x18, 0xEC, 0x1B, 0x2C, 0x80, 0xF7, 0x74, 0xE7, 0xFF, 0x21,
    0x5A, 0x6A, 0x54, 0x1E, 0x41, 0x31, 0x92, 0x35, 0xC4, 0x33, 0x07, 0x0A, 0xBA, 0x7E, 0x0E, 0x34,
    0x88, 0xB1, 0x98, 0x7C, 0xF3, 0x3D, 0x60, 0x6C, 0x7B, 0xCA, 0xD3, 0x1F, 0x32, 0x65, 0x04, 0x28,
    0x64, 0xBE, 0x85, 0x9B, 0x2F, 0x59, 0x8A, 0xD7, 0xB0, 0x25, 0xAC, 0xAF, 0x12, 0x03, 0xE2, 0xF2
};

/* S盒变换 */
static uint32_t S(uint32_t x)
{
    return (S0[(x>>24&0xff)]<<24) | (S1[(x>>16)&0xff]<<16) | (S0[(x>>8)&0xff]<<8) | S1[x&0xff];
}

/* 模 2^32-1 加法, c = (a + b) mod (2^31 - 1) */
static uint32_t modular_add(uint32_t a, uint32_t b)
{
    uint32_t c;

    /* 附录B. 模 2^31-1 加法的实现 */
    c = a + b;
    c = (c & 0x7FFFFFFF) + (c >> 31);

    return c;
}

/* LFSR 初始化模式 */
static void LFSRWithInitialisationMode(ZUC_CTX *ctx, uint32_t u)
{
    uint32_t *s;
    uint32_t s16;
    uint32_t v;

    s = ctx->s;

    //v = (ROTL31(s[15], 15) + ROTL31(s[13], 17) + ROTL31(s[10], 21) + ROTL31(s[4], 20) + ROTL31(s[0], 8) + s[0]) % (2<<31-1);
    v = modular_add(ROTL31(s[15], 15), ROTL31(s[13], 17));
    v = modular_add(v, ROTL31(s[10], 21));
    v = modular_add(v, ROTL31(s[ 4], 20));
    v = modular_add(v, ROTL31(s[ 0],  8));
    v = modular_add(v, s[ 0]);

    s16 = modular_add(v, u);

    if (0 == s16)
    {
        s16 = ZUC_MOD_NUM;
    }

    memcpy(&s[0], &s[1], 15 * sizeof(s[0]));
    s[15] = s16;
}

/* LFSR 工作模式 */
static void LFSRWithWorkMode(ZUC_CTX *ctx)
{
    uint32_t *s;
    uint32_t s16;

    s = ctx->s;

    //s16 = ROTL31(s[15], 15) + ROTL31(s[13], 17) + ROTL31(s[10], 21) + ROLT31(s[4], 20) + ROTL31(s[0], 8) + s[0] % (2<<31-1);
    s16 = modular_add(ROTL31(s[15], 15), ROTL31(s[13], 17));
    s16 = modular_add(s16, ROTL31(s[10], 21));
    s16 = modular_add(s16, ROTL31(s[ 4], 20));
    s16 = modular_add(s16, ROTL31(s[ 0],  8));
    s16 = modular_add(s16, s[ 0]);

    if (0 == s16)
    {
        s16 = ZUC_MOD_NUM;
    }

    memcpy(&s[0], &s[1], 15 * sizeof(s[0]));
    s[15] = s16;
}

/* 比特重组 BR (Bit-Reorganization) */
static void BitReconstruction(ZUC_CTX *ctx, uint32_t X[4])
{
    uint32_t *s;

    s = ctx->s;

    /*
     * 按照 3.1 运算符 一节的描述, H 取最高的 16 比特, L 取最低的 16 比特。
     * s[0]~s[15] 为 31 bit 整数, bit 15~30 代表高半部分, 而不是 bit 16~31; bit 0~15 代表低半部分, 中间 bit 15 属于重叠的部分
     * X[0]~X[ 4] 为 32 bit 整数, bit 16~31 代表高半部分
     * 31 bit 整数重组为 32 bit 整数:
     *    1. 31高->32高(左移1位)
     *    2. 31高->32低(右移15位)
     *    3. 31低->32高(左移16位)
     *    4. 31低->32低(不动)
     */
    X[0] = ((s[15] & 0x7FFF8000) <<  1) | (s[14] & 0x0000FFFF);
    X[1] = ((s[11] & 0x0000FFFF) << 16) | (s[ 9] >> 15);
    X[2] = ((s[ 7] & 0x0000FFFF) << 16) | (s[ 5] >> 15);
    X[3] = ((s[ 2] & 0x0000FFFF) << 16) | (s[ 0] >> 15);
}

#define HIGH16(x)   ((x)&0xFFFF0000)
#define  LOW16(x)   ((x)&0x0000FFFF)

/* 非线性函数 F */
static uint32_t F(ZUC_CTX *ctx, uint32_t X0, uint32_t X1, uint32_t X2)
{
    uint32_t W, W1, W2;

    W = (X0 ^ ctx->R1) + ctx->R2; /* '+' 运算符优先级高于 '^', 这里一定要加括号, 真是害死个人 */
    W1 = ctx->R1 + X1;
    W2 = ctx->R2 ^ X2;

    ctx->R1 = S(L1((LOW16(W1) << 16) | (HIGH16(W2) >> 16)));
    ctx->R2 = S(L2((LOW16(W2) << 16) | (HIGH16(W1) >> 16)));

    return W;
}

/* 240 bits 的密钥常量 */
static uint32_t D[16] =
{
    0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
    0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC
};

static void load_key(ZUC_CTX *ctx, uint8_t key[16], uint8_t iv[16])
{
    uint32_t *s;
    int i;

    s = ctx->s;
    for (i=0; i<16; i++)
    {
        s[i] = (key[i] << 23) | (D[i] << 8) | iv[i];
        DBG("s[%2d]=0x%08x\n", i, s[i]);
    }
}

/* 算法初始化阶段 */
static void initialize(ZUC_CTX *ctx, uint8_t key[16], uint8_t iv[16])
{
    int i;
    uint32_t X[4];
    uint32_t W;

    load_key(ctx, key, iv);
    ctx->R1 = 0;
    ctx->R2 = 0;

    for (i=0; i<32; i++)
    {
        BitReconstruction(ctx, X);
        W = F(ctx, X[0], X[1], X[2]);
        LFSRWithInitialisationMode(ctx, W>>1);

        DBG("%2d: X0=0x%08x, X1=0x%08x, X2=0x%08x, X3=0x%08x, R1=0x%08x, R2=0x%08x, W=0x%08x, S15=0x%08x\n",
            i, X[0], X[1], X[2], X[3], ctx->R1, ctx->R2, W, ctx->s[15]);
    }
}

/* 算法工作阶段 */
static void work(ZUC_CTX *ctx, uint32_t *out, uint32_t len)
{
    int i;
    uint32_t X[4];
    uint32_t Z;

    BitReconstruction(ctx, X);
    // F(ctx, X[0], X[1], X[2]);
    Z=F(ctx, X[0], X[1], X[2]) ^ X[3];
    LFSRWithWorkMode(ctx);
    DBG("    X0=0x%08x, X1=0x%08x, X2=0x%08x, X3=0x%08x, R1=0x%08x, R2=0x%08x, z=0x%08x, S15=0x%08x\n",
        X[0], X[1], X[2], X[3], ctx->R1, ctx->R2, Z, ctx->s[15]);

    while (len > 0)
    {
        BitReconstruction(ctx, X);
        Z = F(ctx, X[0], X[1], X[2]) ^ X[3];
        LFSRWithWorkMode(ctx);

        DBG("    X0=0x%08x, X1=0x%08x, X2=0x%08x, X3=0x%08x, R1=0x%08x, R2=0x%08x, z=0x%08x, S15=0x%08x\n",
            X[0], X[1], X[2], X[3], ctx->R1, ctx->R2, Z, ctx->s[15]);

        *out ++ = Z;
        len --;
    }
}

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
static int EEA3(uint8_t *CK, uint32_t COUNT, uint32_t BEARER, uint32_t DIRECTION, uint32_t LENGTH, uint32_t *IBS, uint32_t *OBS)
{
    ZUC_CTX ctx;
    uint8_t iv[16];
    uint32_t i, len;

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

    initialize(&ctx, CK, iv);

    len = (LENGTH + 31) / 32;
    work(&ctx, OBS, len);

    for (i=0; i<len; i++)
    {
        *OBS++ ^= *IBS ++;
    }

    return ERR_OK;
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
static unsigned int EIA3(uint8_t *IK, uint32_t COUNT, uint32_t BEARER, uint32_t DIRECTION, uint32_t LENGTH, uint32_t *M, uint32_t *MAC)
{
    return ERR_OK;
}

#ifdef TEST

#include <malloc.h>

#define TEST_OUT_KEY_LEN 2

static void TestVector(uint8_t *key, uint8_t *iv, uint32_t len)
{
    int i;
    ZUC_CTX ctx;

    uint32_t *z;

    z = (uint32_t *)malloc(len * sizeof(uint32_t));

    initialize(&ctx, key, iv);
    printf("R1=0x%08x, R2=0x%08x\n", ctx.R1, ctx.R2);
    for (i=0; i<16; i++)
    {
        printf("s[%2d]=0x%08x\n", i, ctx.s[i]);
    }
    work(&ctx, z, len);
    printf("out stream: \n");
    for (i=0; i<len; i++)
    {
        printf("0x%08x ", z[i]);
        if (i%8 == 7)
        {
            printf("\n");
        }
    }
    printf("\n");

    free(z);
    z = NULL;
}

static void TestZUC(void)
{
    /* 附录C.1 测试向量1(全0) */
    uint8_t key1[16] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t iv1[16] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    /* 附录C.2 测试向量2(全1) */
    uint8_t key2[16] =
    {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    uint8_t iv2[16] =
    {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    /* 附录C.3 测试向量3(随机) */
    uint8_t key3[16] =
    {
        0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae, 0xb5, 0x8f, 0x64, 0x1d, 0xb1, 0x7b, 0x45, 0x5b
    };

    uint8_t iv3[16] =
    {
        0x84, 0x31, 0x9a, 0xa8, 0xde, 0x69, 0x15, 0xca, 0x1f, 0x6b, 0xda, 0x6b, 0xfb, 0xd8, 0xc7, 0x66
    };

    /* 测试向量4(随机) */
    uint8_t key4[16] =
    {
        0x4d, 0x32, 0x0b, 0xfa, 0xd4, 0xc2, 0x85, 0xbf, 0xd6, 0xb8, 0xbd, 0x00, 0xf3, 0x9d, 0x8b, 0x41
    };
    uint8_t iv4[16] =
    {
        0x52, 0x95, 0x9d, 0xab, 0xa0, 0xbf, 0x17, 0x6e, 0xce, 0x2d, 0xc3, 0x15, 0x04, 0x9e, 0xb5, 0x74
    };

    printf("Test All 0...\n");
    TestVector(key1, iv1, 2);

    printf("Test All 1...\n");
    TestVector(key2, iv2, 2);

    printf("Test Random Bits...\n");
    TestVector(key3, iv3, 2);

    printf("Test Random Bits with 2000 outputs\n");
    TestVector(key4, iv4, 2000);
}

//#define TEST_EEA3_1
//#define TEST_EEA3_2
//#define TEST_EEA3_3
//#define TEST_EEA3_4
#define TEST_EEA3_5

static void TestEEA3(void)
{
    int i;
    uint32_t *obs;

#ifdef TEST_EEA3_1
    /* 附录A. 第一组加密实例 */
    {
        uint8_t ck1[16] =
        {
            0x17, 0x3d, 0x14, 0xba, 0x50, 0x03, 0x73, 0x1d, 0x7a, 0x60, 0x04, 0x94, 0x70, 0xf0, 0x0a, 0x29
        };
        uint32_t ibs1[] = {
            0x6cf65340, 0x735552ab, 0x0c9752fa, 0x6f9025fe, 0x0bd675d9, 0x005875b2, 0x00000000
        };

        obs = (uint32_t *)malloc(sizeof(ibs1));
        memset(obs, sizeof(ibs1), 0);

        EEA3(ck1, 0x66035492, 0x0f, 0, 0xc1, ibs1, obs);
        printf("Out Bit Stream:\n");
        for (i=0; i<sizeof(ibs1)/sizeof(ibs1[0]); i++)
        {
            printf("0x%08x ", obs[i]);
            if (i%8 == 7)
            {
                printf("\n");
            }
        }
        printf("\n");
        free(obs);
        obs = NULL;
    }
#endif

#ifdef TEST_EEA3_2
    /* 附录A. 第二组加密实例 */
    {
        uint8_t ck2[16] =
        {
            0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a
        };
        uint32_t ibs2[] = {
            0x14a8ef69, 0x3d678507, 0xbbe7270a, 0x7f67ff50, 0x06c3525b, 0x9807e467, 0xc4e56000, 0xba338f5d,
            0x42955903, 0x67518222, 0x46c80d3b, 0x38f07f4b, 0xe2d8ff58, 0x05f51322, 0x29bde93b, 0xbbdcaf38,
            0x2bf1ee97, 0x2fbf9977, 0xbada8945, 0x847a2a6c, 0x9ad34a66, 0x7554e04d, 0x1f7fa2c3, 0x3241bd8f,
            0x01ba220d
        };

        obs = (uint32_t *)malloc(sizeof(ibs2));
        memset(obs, sizeof(ibs2), 0);

        EEA3(ck2, 0x56823, 0x18, 1, 0x320, ibs2, obs);
        printf("Out Bit Stream:\n");
        for (i=0; i<sizeof(ibs2)/sizeof(ibs2[0]); i++)
        {
            printf("0x%08x ", obs[i]);
            if (i%8 == 7)
            {
                printf("\n");
            }
        }
        printf("\n");
        free(obs);
        obs = NULL;
    }
#endif

#ifdef TEST_EEA3_3
    /* Test Set 3 */
    {
        uint8_t ck3[16] =
        {
            0xd4, 0x55, 0x2a, 0x8f, 0xd6, 0xe6, 0x1c, 0xc8, 0x1a, 0x20, 0x09, 0x14, 0x1a, 0x29, 0xc1, 0x0b
        };
        uint32_t ibs3[] = {
            0x38f07f4b, 0xe2d8ff58, 0x05f51322, 0x29bde93b, 0xbbdcaf38, 0x2bf1ee97, 0x2fbf9977, 0xbada8945,
            0x847a2a6c, 0x9ad34a66, 0x7554e04d, 0x1f7fa2c3, 0x3241bd8f, 0x01ba220d, 0x3ca4ec41, 0xe074595f,
            0x54ae2b45, 0x4fd97143, 0x20436019, 0x65cca85c, 0x2417ed6c, 0xbec3bada, 0x84fc8a57, 0x9aea7837,
            0xb0271177, 0x242a64dc, 0x0a9de71a, 0x8edee86c, 0xa3d47d03, 0x3d6bf539, 0x804eca86, 0xc584a905,
            0x2de46ad3, 0xfced6554, 0x3bd90207, 0x372b27af, 0xb79234f5, 0xff43ea87, 0x0820e2c2, 0xb78a8aae,
            0x61cce52a, 0x0515e348, 0xd196664a, 0x3456b182, 0xa07c406e, 0x4a207912, 0x71cfeda1, 0x65d535ec,
            0x5ea2d4df, 0x40000000,
        };

        obs = (uint32_t *)malloc(sizeof(ibs3));
        memset(obs, sizeof(ibs3), 0);

        EEA3(ck3, 0x76452ec1, 0x02, 1, 1570, ibs3, obs);
        printf("Out Bit Stream:\n");
        for (i=0; i<sizeof(ibs3)/sizeof(ibs3[0]); i++)
        {
            printf("0x%08x ", obs[i]);
            if (i%8 == 7)
            {
                printf("\n");
            }
        }
        printf("\n");
        free(obs);
        obs = NULL;
    }
#endif

#ifdef TEST_EEA3_4
    /* Test Set 4 */
    {
        uint8_t ck4[16] =
        {
            0xdb, 0x84, 0xb4, 0xfb, 0xcc, 0xda, 0x56, 0x3b, 0x66, 0x22, 0x7b, 0xfe, 0x45, 0x6f, 0x0f, 0x77
        };
        uint32_t ibs4[] = {
            0xe539f3b8, 0x973240da, 0x03f2b8aa, 0x05ee0a00, 0xdbafc0e1, 0x82055dfe, 0x3d7383d9, 0x2cef40e9,
            0x2928605d, 0x52d05f4f, 0x9018a1f1, 0x89ae3997, 0xce19155f, 0xb1221db8, 0xbb0951a8, 0x53ad852c,
            0xe16cff07, 0x382c93a1, 0x57de00dd, 0xb125c753, 0x9fd85045, 0xe4ee07e0, 0xc43f9e9d, 0x6f414fc4,
            0xd1c62917, 0x813f74c0, 0x0fc83f3e, 0x2ed7c45b, 0xa5835264, 0xb43e0b20, 0xafda6b30, 0x53bfb642,
            0x3b7fce25, 0x479ff5f1, 0x39dd9b5b, 0x995558e2, 0xa56be18d, 0xd581cd01, 0x7c735e6f, 0x0d0d97c4,
            0xddc1d1da, 0x70c6db4a, 0x12cc9277, 0x8e2fbbd6, 0xf3ba52af, 0x91c9c6b6, 0x4e8da4f7, 0xa2c266d0,
            0x2d001753, 0xdf089603, 0x93c5d568, 0x88bf49eb, 0x5c16d9a8, 0x0427a416, 0xbcb597df, 0x5bfe6f13,
            0x890a07ee, 0x1340e647, 0x6b0d9aa8, 0xf822ab0f, 0xd1ab0d20, 0x4f40b7ce, 0x6f2e136e, 0xb67485e5,
            0x07804d50, 0x4588ad37, 0xffd81656, 0x8b2dc403, 0x11dfb654, 0xcdead47e, 0x2385c343, 0x6203dd83,
            0x6f9c64d9, 0x7462ad5d, 0xfa63b5cf, 0xe08acb95, 0x32866f5c, 0xa787566f, 0xca93e6b1, 0x693ee15c,
            0xf6f7a2d6, 0x89d97417, 0x98dc1c23, 0x8e1be650, 0x733b18fb, 0x34ff880e, 0x16bbd21b, 0x47ac0000,
        };

        obs = (uint32_t *)malloc(sizeof(ibs4));
        memset(obs, sizeof(ibs4), 0);

        EEA3(ck4, 0xe4850fe1, 0x10, 1, 2798, ibs4, obs);
        printf("Out Bit Stream:\n");
        for (i=0; i<sizeof(ibs4)/sizeof(ibs4[0]); i++)
        {
            printf("0x%08x ", obs[i]);
            if (i%8 == 7)
            {
                printf("\n");
            }
        }
        printf("\n");
        free(obs);
        obs = NULL;
    }
#endif

#ifdef TEST_EEA3_5
    /* Test Set 5 */
    {
        uint8_t ck5[16] =
        {
            0xe1, 0x3f, 0xed, 0x21, 0xb4, 0x6e, 0x4e, 0x7e, 0xc3, 0x12, 0x53, 0xb2, 0xbb, 0x17, 0xb3, 0xe0
        };
        uint32_t ibs5[] = {
            0x8d74e20d, 0x54894e06, 0xd3cb13cb, 0x3933065e, 0x8674be62, 0xadb1c72b, 0x3a646965, 0xab63cb7b,
            0x7854dfdc, 0x27e84929, 0xf49c64b8, 0x72a490b1, 0x3f957b64, 0x827e71f4, 0x1fbd4269, 0xa42c97f8,
            0x24537027, 0xf86e9f4a, 0xd82d1df4, 0x51690fdd, 0x98b6d03f, 0x3a0ebe3a, 0x312d6b84, 0x0ba5a182,
            0x0b2a2c97, 0x09c090d2, 0x45ed267c, 0xf845ae41, 0xfa975d33, 0x33ac3009, 0xfd40eba9, 0xeb5b8857,
            0x14b768b6, 0x97138baf, 0x21380eca, 0x49f644d4, 0x8689e421, 0x5760b906, 0x739f0d2b, 0x3f091133,
            0xca15d981, 0xcbe401ba, 0xf72d05ac, 0xe05cccb2, 0xd297f4ef, 0x6a5f58d9, 0x1246cfa7, 0x7215b892,
            0xab441d52, 0x78452795, 0xccb7f5d7, 0x9057a1c4, 0xf77f80d4, 0x6db2033c, 0xb79bedf8, 0xe60551ce,
            0x10c667f6, 0x2a97abaf, 0xabbcd677, 0x2018df96, 0xa282ea73, 0x7ce2cb33, 0x1211f60d, 0x5354ce78,
            0xf9918d9c, 0x206ca042, 0xc9b62387, 0xdd709604, 0xa50af16d, 0x8d35a890, 0x6be484cf, 0x2e74a928,
            0x99403643, 0x53249b27, 0xb4c9ae29, 0xeddfc7da, 0x6418791a, 0x4e7baa06, 0x60fa6451, 0x1f2d685c,
            0xc3a5ff70, 0xe0d2b742, 0x92e3b8a0, 0xcd6b04b1, 0xc790b8ea, 0xd2703708, 0x540dea2f, 0xc09c3da7,
            0x70f65449, 0xe84d817a, 0x4f551055, 0xe19ab850, 0x18a0028b, 0x71a144d9, 0x6791e9a3, 0x57793350,
            0x4eee0060, 0x340c69d2, 0x74e1bf9d, 0x805dcbcc, 0x1a6faa97, 0x6800b6ff, 0x2b671dc4, 0x63652fa8,
            0xa33ee509, 0x74c1c21b, 0xe01eabb2, 0x16743026, 0x9d72ee51, 0x1c9dde30, 0x797c9a25, 0xd86ce74f,
            0x5b961be5, 0xfdfb6807, 0x814039e7, 0x137636bd, 0x1d7fa9e0, 0x9efd2007, 0x505906a5, 0xac45dfde,
            0xed7757bb, 0xee745749, 0xc2963335, 0x0bee0ea6, 0xf409df45, 0x80160000,
        };

        obs = (uint32_t *)malloc(sizeof(ibs5));
        memset(obs, sizeof(ibs5), 0);

        EEA3(ck5, 0x2738cdaa, 0x1a, 0, 4019, ibs5, obs);
        printf("Out Bit Stream:\n");
        for (i=0; i<sizeof(ibs5)/sizeof(ibs5[0]); i++)
        {
            printf("0x%08x ", obs[i]);
            if (i%8 == 7)
            {
                printf("\n");
            }
        }
        printf("\n");
        free(obs);
        obs = NULL;
    }
#endif
}

void TestEIA3(void)
{

}

int main(int argc, char *argv[])
{
    //TestZUC();
    TestEEA3();

    return 0;
}
#endif