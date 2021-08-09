/*
 * @        file: aes-ofb.c
 * @ description: implementation for the AES Output Feedback (OFB) Mode
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "aes.h"

#define AES_BLOCK_SIZE      16

static void xor(const uint8_t *in1, const uint8_t *in2, int size, uint8_t *out)
{
    int i;

    for (i=0; i<size; i++)
    {
        *out ++ = (*in1 ++) ^ (*in2 ++);
    }
}

int AES_OFB_Encrypt(AES_ALG alg, const unsigned char *in, unsigned int size, const unsigned char *key, const unsigned char *iv, unsigned char *out)
{
    unsigned char vector[AES_BLOCK_SIZE], temp[AES_BLOCK_SIZE];

    if ((NULL == in) || (NULL == key) || (NULL == iv) || (NULL == out) || (0 == size))
    {
        return ERR_INV_PARAM;
    }

    memcpy(vector, iv, AES_BLOCK_SIZE);

    while (size >= AES_BLOCK_SIZE)
    {
        AES_Encrypt(alg, vector, key, temp);

        xor(temp, in, AES_BLOCK_SIZE, out);

        in   += AES_BLOCK_SIZE;
        out  += AES_BLOCK_SIZE;
        size -= AES_BLOCK_SIZE;

        memcpy(vector, temp, AES_BLOCK_SIZE);
    }

    if (size > 0)
    {
        AES_Encrypt(alg, vector, key, temp);

        xor(temp, in, size, out);
    }

    return ERR_OK;
}

int AES_OFB_Decrypt(AES_ALG alg, const unsigned char *in, unsigned int size, const unsigned char *key, const unsigned char *iv, unsigned char *out)
{
    return AES_OFB_Encrypt(alg, in, size, key, iv, out);
}