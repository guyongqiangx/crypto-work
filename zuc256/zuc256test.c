/*
 * @        file: zuctest.c
 * @ description: test tool for zuc
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>  /* printf, fopen, fread, fclose... */
#include <stdlib.h> /* exit */
#include <string.h> /* strlen */
#include <unistd.h> /* getopt */

#include "zuc256.h"
#include "utils.h"

static void TestingZUC(uint8_t *key, uint8_t *iv, uint32_t len)
{
    int i;
    ZUC256_CTX ctx;

    uint32_t *z;

    z = (uint32_t *)malloc(len * sizeof(uint32_t));

    ZUC256_Init(&ctx, ZUC256_TYPE_KEYSTREAM, key, iv);
    printf("R1=0x%08x, R2=0x%08x\n", ctx.R1, ctx.R2);
    for (i=0; i<16; i++)
    {
        printf("s[%2d]=0x%08x\n", i, ctx.s[i]);
    }
    ZUC256_GenerateKeyStream(&ctx, z, len);
    printf("out stream: \n");
    for (i=0; i<len; i++)
    {
        printf("0x%08x ", z[i]);
        if (i%8 == 7)
        {
            printf("\n");
        }
    }
    printf("\n\n");

    free(z);
    z = NULL;
}

static void ZUCTests(void)
{
    /* 测试向量1(全0) */
    uint8_t key1[32] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t iv1[25] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*  0~15 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00                                            /* 16~24 */
    };

    /* 测试向量2(全1) */
    uint8_t key2[32] =
    {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    uint8_t iv2[25] =
    {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /*  0~15 */
        0xff, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f                                            /* 16~24 */
    };

    printf("Test All 0...\n");
    TestingZUC(key1, iv1, 20);

    printf("Test All 1...\n");
    TestingZUC(key2, iv2, 20);
}

static void TestingMAC(uint8_t *key, uint8_t *iv, unsigned char *m, uint32_t len)
{
#if 0
    uint32_t md[4];

    ZUC256_MAC(ZUC256_TYPE_MAC32, key, iv, m, len, (unsigned char *)md);
    printf(" 32 bit MAC: 0x%08x\n", be32toh(md[0]));

    ZUC256_MAC(ZUC256_TYPE_MAC64, key, iv, m, len, (unsigned char *)md);
    printf(" 64 bit MAC: 0x%08x 0x%08x\n", be32toh(md[0]), be32toh(md[1]));

    ZUC256_MAC(ZUC256_TYPE_MAC128, key, iv, m, len, (unsigned char *)md);
    printf("128 bit MAC: 0x%08x 0x%08x 0x%08x 0x%08x\n", be32toh(md[0]), be32toh(md[1]), be32toh(md[2]), be32toh(md[3]));
#else
    uint8_t md[16];
    int i;

    ZUC256_MAC(ZUC256_TYPE_MAC32, key, iv, m, len, md);
    printf(" 32 bit MAC: ");
    for (i=0; i<4; i++)
    {
        printf("%02x", md[i]);
        if (i%4 == 3)
            printf(" ");
    }
    printf("\n");

    ZUC256_MAC(ZUC256_TYPE_MAC64, key, iv, m, len, md);
    printf(" 64 bit MAC: ");
    for (i=0; i<8; i++)
    {
        printf("%02x", md[i]);
        if (i%4 == 3)
            printf(" ");
    }
    printf("\n");

    ZUC256_MAC(ZUC256_TYPE_MAC128, key, iv, m, len, md);
    printf("128 bit MAC: ");
    for (i=0; i<16; i++)
    {
        printf("%02x", md[i]);
        if (i%4 == 3)
            printf(" ");
    }
    printf("\n\n");
#endif
}

static void MACTests(void)
{
    uint8_t *m;

    {
        /* 测试向量1(全0) */
        uint8_t key[32] =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        uint8_t iv[25] =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*  0~15 */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00                                            /* 16~24 */
        };

        printf("Test 1: All 0 in K and IV, l=400, M=0x000...00\n");
        m = (uint8_t *)malloc(400/8);
        memset(m, 0x00, 400/8);
        TestingMAC(key, iv, m, 400);
        free(m);
        m = NULL;

        printf("Test 2: All 0 in K and IV, l=4000, M=0x111...11\n");
        m = (uint8_t *)malloc(4000/8);
        memset(m, 0x11, 4000/8);
        TestingMAC(key, iv, m, 4000);
        free(m);
        m = NULL;
    }

    {
        /* 测试向量2(全1) */
        uint8_t key[32] =
        {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        };
        uint8_t iv[25] =
        {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /*  0~15 */
            0xff, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f                                            /* 16~24 */
        };

        printf("Test 3: All 1 in K and IV, l=400, M=0x111...11\n");
        m = (uint8_t *)malloc(400/8);
        memset(m, 0x00, 400/8);
        TestingMAC(key, iv, m, 400);
        free(m);
        m = NULL;

        printf("Test 4: All 1 in K and IV, l=4000, M=0x111...11\n");
        m = (uint8_t *)malloc(4000/8);
        memset(m, 0x11, 4000/8);
        TestingMAC(key, iv, m, 4000);
        free(m);
        m = NULL;
    }
}

int main(int argc, char *argv[])
{
    ZUCTests();
    MACTests();

    return 0;
}
