#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "type.h"
#include "err.h"
#include "rand.h"

static void swap(uint8_t *a, uint8_t *b)
{
    uint8_t temp;
    temp = *a;
    *a = *b;
    *b = temp;
}

static int rc4_initialize(uint8_t S[256], uint8_t *K, uint32_t len)
{
    int i, j;
    uint8_t T[256];

    if (len > 256)
    {
        return ERR_INV_PARAM;
    }

    for (i=0; i<256; i++)
    {
        S[i] = i;
        T[i] = K[i % len];
    }

    j = 0;
    for (i=0; i<256; i++)
    {
        j = (j + S[i] + T[i]) % 256;

        /* Swap S[i] <--> S[j] */
        swap(&S[i], &S[j]);
    }

    return ERR_OK;
}

static int rc4_key_generation(uint8_t S[256], char *out, uint32_t out_size)
{
    int i, j, t;

    i = j = 0;
    /*
     * while (1)
     * {
     *     i = (i + 1) % 256;
     *     j = (j + S[i]) % 256;
     * 
     *     swap(&S[i], &S[j]);
     * 
     *     t = (S[i] + S[j]) % 256;
     *     k = S[t]
     * }
     */
    while (out_size)
    {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        swap(&S[i], &S[j]);

        t = (S[i] + S[j]) % 256;
        *out = S[t];

        out ++;
        out_size --;
    }
    return ERR_OK;
}

/*
 * !!! This is a fake implementation, just use RC4 alorithm to generate some pesudo random bytes
 */
int Get_Random_Bytes(char *buf, unsigned long len)
{
    uint8_t key[256], key_size;
    uint8_t S[256];
    int i;

    time_t t;

    /* 初始化随机数发生器 */
    srand((unsigned) time(&t));

    /* 随机获得一个小于 1~256 的 key_size */
    key_size = rand() % 256 + 1;

    /* 基于 key_size 填充一个随机数组 key 作为 RC4 的种子 */
    for (i=0; i<key_size; i++)
    {
        key[i] = rand() % 256;
    }

    /* 用获取的随机数组 key 初始化 RC4 算法 */
    rc4_initialize(S, key, key_size);

    rc4_key_generation(S, buf, len);
    
    return 0;
}

int Get_Random_NonZero_Bytes(char *buf, unsigned long len)
{
    uint8_t key[256], key_size;
    uint8_t S[256];
    int i;
    char x;

    time_t t;

    /* 初始化随机数发生器 */
    srand((unsigned) time(&t));

    /* 随机获得一个小于 1~256 的 key_size */
    key_size = rand() % 256 + 1;

    /* 基于 key_size 填充一个随机数组 key 作为 RC4 的种子 */
    for (i=0; i<key_size; i++)
    {
        key[i] = rand() % 256;
    }

    /* 用获取的随机数组 key 初始化 RC4 算法 */
    rc4_initialize(S, key, key_size);

    for (i=0; i<len; i++)
    {
        // 每次生成 1 byte
        rc4_key_generation(S, &x, 1);
        while (!x) // 确保 x != 0
        {
            rc4_key_generation(S, &x, 1);
        };
        *buf ++ = x;
    }

    return 0;
}
