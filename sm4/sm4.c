/*
 * @        file: sm4.c
 * @ description: implementation for the SM4
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "sm4.h"

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

#define SM4_KEY_SIZE            16
#define SM4_BLOCK_SIZE          16

#define SM4_ROUND_NUM           32

static const uint8_t SBox[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

/* 系统参数 FK(FK0, FK1, FK2, FK3) */
static const uint32_t FK[4] =
{
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

/* 固定参数 CK(CK0, CK1, ..., CK31) */
static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

/* 32位循环左移: ROTate Left (circular left shift) */
static uint32_t ROTL(uint32_t x, uint8_t shift)
{
    return (x << shift) | (x >> (32 - shift));
}

/* 非线性变换: non-linear transformation */
static uint32_t tao(uint32_t x)
{
    /* （b0, b1, b2, b3) = tao(A) = (Sbox(a0), Sbox(a1), Sbox(a2), Sbox(a3))*/
    return SBox[x&0xff] | (SBox[(x>>8)&0xff]<<8) | (SBox[(x>>16)&0xff]<<16) | (SBox[(x>>24&0xff)]<<24);
}

/* 线性变换 L: linear transformation */
static uint32_t linear(uint32_t x)
{
    return x ^ ROTL(x, 2) ^ ROTL(x, 10) ^ ROTL(x, 18) ^ ROTL(x, 24);
}

/* 合成置换 T: 由非线性变换和线性变换复合而成 */
static uint32_t T(uint32_t x)
{
    return linear(tao(x));
}

/* 轮函数 F */
static uint32_t F(uint32_t X0, uint32_t X1, uint32_t X2, uint32_t X3, uint32_t rk)
{
    return X0 ^ T(X1 ^ X2 ^ X3 ^ rk);
}


/* 密钥扩展线性变换 L' */
static uint32_t LPrime(uint32_t x)
{
    return x ^ ROTL(x, 13) ^ ROTL(x, 23);
}

/* 密钥扩展合成置换 T' */
static uint32_t TPrime(uint32_t x)
{
    return LPrime(tao(x));
}

/* 轮密钥生成函数 */
static int generate_key_array(uint32_t MK[4], uint32_t rk[32])
{
    int i;
    uint32_t K[35];

    /* 大端数组转换为本地数据 */
    for (i=0; i<4; i++)
    {
        K[i] = be32toh(MK[i]) ^ FK[i];
    }

    for (i=0; i<32; i++)
    {
        rk[i] = K[i+4] = K[i] ^ TPrime(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]);
    }

    return 0;
}

int SM4_Encrypt(int mode, const unsigned char *in, const unsigned char *key, unsigned char *out)
{
    int i;
    uint32_t rk[32], X[35];
    uint32_t *p;

    generate_key_array((uint32_t *)key, rk);
    // for (i=0; i<32; i++)
    // {
    //     printf("rk[%2d]=%08x\n", i, rk[i]);
    // }

    p = (uint32_t *)in;
    /* 大端数组转换为本地数据 */
    for (i=0; i<4; i++)
    {
        X[i] = be32toh(p[i]);
    }

    for (i=0; i<32; i++)
    {
        if (mode == 1) /* mode=1, encryption */
        {
            X[i+4] = F(X[i+0], X[i+1], X[i+2], X[i+3], rk[i]);
        }
        else /* mode=0, decryption */
        {
            X[i+4] = F(X[i+0], X[i+1], X[i+2], X[i+3], rk[31-i]);
        }

        #if (DUMP_ROUND_DATA==1)
        printf("rk[%2d]=%08x\tX[%2d]=%08x\n", i, rk[i], i+4, X[i+4]);
        #endif
    }

    p = (uint32_t *)out;
    /* 本地数据转换为大端数组 */
    p[0] = htobe32(X[35]);
    p[1] = htobe32(X[34]);
    p[2] = htobe32(X[33]);
    p[3] = htobe32(X[32]);

    return ERR_OK;
}

int SM4_Encryption(const unsigned char *data, unsigned int data_len, const unsigned char *key, unsigned int key_len, const unsigned *out, unsigned int out_len)
{
    return ERR_OK;
}

int SM4_Decryption(const unsigned char *data, unsigned int data_len, const unsigned char *key, unsigned int key_len, const unsigned *out, unsigned int out_len)
{
    return ERR_OK;
}

void generate_ck(uint32_t CK[32])
{
    int i, j;
    uint8_t x[32][4];
    uint32_t *p;

    for (i=0; i<32; i++)
    {
        for (j=0; j<4; j++)
        {
            x[i][j] = (4*i+j) * 7 % 256;
        }
    }

    p = (uint32_t *)x;
    for (i=0; i<32; i++)
    {
        CK[i] = be32toh(p[i]);
        printf("CK[%2d]=%08x\n", i, CK[i]);
    }
}

int main(int argc, char* argv[])
{
    uint32_t CK[32];
    int i;

    uint8_t data[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t key[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t enc[16], dec[16];

    /*
     * 生成密钥扩展的固定参数CK
     */
    generate_ck(CK);

    /*
     * TEST 1: Encryption and Decryption
     */
    print_buffer(data, 16, "data: ");
    print_buffer(key, 16, " key: ");

    SM4_Encrypt(1, data, key, enc);
    print_buffer(enc, 16, " enc: ");

    SM4_Encrypt(0, enc, key, dec);
    print_buffer(dec, 16, " dec: ");

    /*
     * TEST 2: Encryption 1 000 000 as in A.2
     */
    memcpy(enc, data, 16);
    for (i=0; i<1000000; i++)
    {
        SM4_Encrypt(1, enc, key, dec);
        memcpy(enc, dec, 16);
    }
    print_buffer(dec, 16, "final: ");

    return 0;
}