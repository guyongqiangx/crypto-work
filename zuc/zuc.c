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
#define DUMP_BLOCK_DATA 1
#define DUMP_BLOCK_HASH 1
#define DUMP_ROUND_DATA 1
#else
#define DBG(...)
#define DUMP_BLOCK_DATA 0
#define DUMP_BLOCK_HASH 0
#define DUMP_ROUND_DATA 0
#endif

#define ZUC_MOD_NUM (2<<31-1)

typedef struct zuc_context {
    uint32_t s[16];

    uint32_t R1;
    uint32_t R2;

    uint32_t W1;
    uint32_t W2;
}ZUC_CTX;

/* 31位循环左移: ROTate Left (circular left shift) */
static uint32_t ROTL31(uint32_t x, uint8_t shift)
{
    return (x << shift) | (x >> (31 - shift));
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

    /* 附录B. 模 2^31-1 和 模 2^31-1 加法的实现 */
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

#define HIGH16(x)   ((x)&0xFFFF0000)
#define  LOW16(x)   ((x)&0x0000FFFF)

/* 比特重组 BR (Bit-Reorganization) */
static void BitReconstruction(ZUC_CTX *ctx, uint32_t X[4])
{
    uint32_t *s;

    s = ctx->s;

    // X[0] = HIGH16(s[15]) | LOW16(s[14]);
    X[0] = ((s[15] & 0x7FFF8000) <<  1) |  (s[14] & 0x0000FFFF);
    X[1] = ((s[11] & 0x0000FFFF) << 16) | ((s[ 9] & 0x7FFF0000) >> 15);
    X[2] = ((s[ 7] & 0x0000FFFF) << 16) | ((s[ 5] & 0x7FFF0000) >> 15);
    X[3] = ((s[ 2] & 0x0000FFFF) << 16) | ((s[ 0] & 0x7FFF0000) >> 15);
}

/* 非线性函数 F */
static uint32_t F(ZUC_CTX *ctx, uint32_t X0, uint32_t X1, uint32_t X2)
{
    uint32_t W;

    W = X0 ^ ctx->R1 + ctx->R2;
    ctx->W1 = ctx->R1 + X1;
    ctx->W2 = ctx->R2 ^ X2;

    ctx->R1 = S(L1((LOW16(ctx->W1) << 16) | (HIGH16(ctx->W2) >> 16)));
    ctx->R2 = S(L2((LOW16(ctx->W2) << 16) | (HIGH16(ctx->W1) >> 16)));

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
        printf("s[%2d]=0x%08x\n", i, s[i]);
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

        printf("%2d: X[0]=0x%08x, X[1]=0x%08x, X[2]=0x%08x, X[3]=0x%08x, R1=0x%08x, R2=0x%08x, W=0x%08x, S15=0x%08x\n",
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
    F(ctx, X[0], X[1], X[2]);
    LFSRWithWorkMode(ctx);

    while (len > 0)
    {
        BitReconstruction(ctx, X);
        Z = F(ctx, X[0], X[1], X[2]) ^ X[3];
        LFSRWithWorkMode(ctx);

        *out ++ = Z;
        len --;
    }
}

int main(int argc, char *argv)
{
    ZUC_CTX ctx;

    uint8_t key[16] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t iv[16] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint32_t z[2];

    initialize(&ctx, key, iv);
    work(&ctx, z, 2);
    printf("0x%08x, 0x%08x\n", z[0], z[1]);

    return 0;
}