/*
 * @        file: aes-cbc.c
 * @ description: implementation for the AES Electronic Codebook (ECB) Mode
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "aes.h"

#define AES_BLOCK_SIZE      16

int AES_ECB_Encrypt(AES_ALG alg, const unsigned char *in, unsigned int size, const unsigned char *key, unsigned char *out)
{
    unsigned char temp[AES_BLOCK_SIZE];

    if ((NULL == in) || (NULL == key) || (NULL == out) || (0 == size))
    {
        return ERR_INV_PARAM;
    }

    while (size >= AES_BLOCK_SIZE)
    {
        AES_Encrypt(alg, in, key, out);

        in   += AES_BLOCK_SIZE;
        out  += AES_BLOCK_SIZE;

        size -= AES_BLOCK_SIZE;
    }

    if (size > 0)
    {
        memcpy(temp, size, in);  /* index: 0 ~ size-1 */
        temp[size] = 0x80;       /* index: size */
        memset(&temp[size+1], 0, AES_BLOCK_SIZE-size-1);

        AES_Encrypt(alg, temp, key, out);
    }

    return ERR_OK;
}

int AES_ECB_Decrypt(AES_ALG alg, const unsigned char *in, unsigned int size, const unsigned char *key, unsigned char *out)
{
    unsigned char temp[AES_BLOCK_SIZE];
    int i;

    if ((NULL == in) || (NULL == key) || (NULL == out) || (0 == size))
    {
        return ERR_INV_PARAM;
    }

    while (size >= AES_BLOCK_SIZE)
    {
        AES_Decrypt(alg, in, key, out);

        in   += AES_BLOCK_SIZE;
        out  += AES_BLOCK_SIZE;

        size -= AES_BLOCK_SIZE;
    }

    if (size > 0)
    {
        memcpy(temp, in, size);     /* index: 0 ~ size-1 */
        temp[size] = 0x80;          /* index: size */
        memset(&temp[size+1], 0, AES_BLOCK_SIZE-size-1); /* size ~ AES_BLOCK_SIZE-1 */

        AES_Decrypt(alg, temp, key, out);
    }

    return ERR_OK;
}