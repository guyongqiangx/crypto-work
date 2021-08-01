/*
 * @        file: aes-cbc.c
 * @ description: implementation for the AES Cipher Block Chaining (CBC) Mode
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "aes.h"

#define AES_BLOCK_SIZE      16

static void xor(const uint8_t *iv, const uint8_t *in, uint8_t *out)
{
    int i;
    for (i=0; i<AES_BLOCK_SIZE; i++)
    {
        *out ++ = (*iv ++) ^ (*in ++);
    }
}

int AES_CBC_Encrypt(AES_ALG alg, const unsigned char *in, unsigned int size, const unsigned char *key, const unsigned char *iv, unsigned char *out)
{
    unsigned char vector[AES_BLOCK_SIZE], temp[AES_BLOCK_SIZE];
    int i;

    if ((NULL == in) || (NULL == key) || (NULL == iv) || (NULL == out) || (0 == size))
    {
        return ERR_INV_PARAM;
    }

    memcpy(vector, iv, AES_BLOCK_SIZE);

    while (size >= AES_BLOCK_SIZE)
    {
        xor(vector, in, temp);

        AES_Encrypt(alg, temp, key, out);

        memcpy(vector, out, AES_BLOCK_SIZE);
        in  += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;

        size -= AES_BLOCK_SIZE;
    }

    if (size > 0)
    {
        memcpy(temp, in, size);     /* 0 ~ size-1 */
        temp[size] = 0x80;          /* size */
        memset(&temp[size+1], 0, AES_BLOCK_SIZE-size-1); /* size ~ AES_BLOCK_SIZE-1 */

        xor(vector, temp, temp);

        AES_Encrypt(alg, temp, key, out);
    }

    return ERR_OK;
}

int AES_CBC_Decrypt(AES_ALG alg, const unsigned char *in, unsigned int size, const unsigned char *key, const unsigned char *iv, unsigned char *out)
{
    unsigned char vector[AES_BLOCK_SIZE], temp[AES_BLOCK_SIZE];
    int i;

    if ((NULL == in) || (NULL == key) || (NULL == iv) || (NULL == out) || (0 == size))
    {
        return ERR_INV_PARAM;
    }

    memcpy(vector, iv, AES_BLOCK_SIZE);

    while (size >= AES_BLOCK_SIZE)
    {
        AES_Decrypt(alg, in, key, temp);
        
        xor(vector, temp, out);

        memcpy(vector, in, AES_BLOCK_SIZE);
        in  += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;

        size -= AES_BLOCK_SIZE;
    }

    if (size > 0)
    {
        memcpy(temp, in, size);     /* 0 ~ size-1 */
        temp[size] = 0x80;          /* size */
        memset(&temp[size+1], 0, AES_BLOCK_SIZE-size-1); /* size ~ AES_BLOCK_SIZE-1 */

        AES_Decrypt(alg, temp, key, temp);
        xor(vector, temp, out);
    }

    return ERR_OK;
}