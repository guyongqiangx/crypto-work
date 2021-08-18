/*
 * @        file: rc4.c
 * @ description: implementation for the RC4
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "rc4.h"

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

static void swap(uint8_t *a, uint8_t *b)
{
    uint8_t temp;
    temp = *a;
    *a = *b;
    *b = temp;
}

static int initialize(uint8_t S[256], uint8_t *K, uint32_t len)
{
    int i, j, temp;
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

    print_buffer(S, 256, "S: ");
    print_buffer(T, 256, "T: ");

    j = 0;
    for (i=0; i<256; i++)
    {
        j = (j + S[i] + T[i]) % 256;

        /* Swap S[i] <--> S[j] */
        swap(&S[i], &S[j]);
    }

    return ERR_OK;
}

static int key_generation(uint8_t S[256], uint8_t *out, uint32_t out_size)
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

int RC4(unsigned char *in, unsigned int in_size, unsigned char *key, unsigned int key_size, unsigned char *out)
{
    uint8_t S[256], k;
    int i, j, t;

    initialize(S, key, key_size);
    while (in_size > 0)
    {
        i = (i = 1) % 256;
        j = (j = S[i]) % 256;

        swap(&S[i], &S[j]);

        t = (S[i] + S[j]) % 256;
        k = S[t];

        *out ++ = k ^ (*in ++);
        in_size --;
    }

    return ERR_OK;
}

#define KEY_OUT_SIZE (4096+16)

static void test_key_generation(uint8_t *key, unsigned int size)
{
    uint8_t S[256];
    uint8_t buf[KEY_OUT_SIZE];

    initialize(S, key, size);
    key_generation(S, buf, KEY_OUT_SIZE);
    print_buffer(buf, KEY_OUT_SIZE, "");
}

int main(int argc, char *argv[])
{
    uint8_t key40[]  = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t key56[]  = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t key64[]  = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t key128[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t key192[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    };
    uint8_t key256[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    printf("40 bits key: \n");
    test_key_generation(key40, sizeof(key40)/sizeof(uint8_t));

    printf("56 bits key: \n");
    test_key_generation(key56, sizeof(key56)/sizeof(uint8_t));

    printf("64 bits key: \n");
    test_key_generation(key64, sizeof(key64)/sizeof(uint8_t));

    printf("128 bits key: \n");
    test_key_generation(key128, sizeof(key128)/sizeof(uint8_t));

    printf("192 bits key: \n");
    test_key_generation(key192, sizeof(key192)/sizeof(uint8_t));

    printf("256 bits key: \n");
    test_key_generation(key256, sizeof(key256)/sizeof(uint8_t));

    return 0;
}