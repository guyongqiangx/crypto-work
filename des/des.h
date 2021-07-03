/*
 * @        file: des.h
 * @ description: header file for des.c
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#ifndef __ROCKY_DES__H
#define __ROCKY_DES__H

#define ERR_OK           0
#define ERR_ERR         -1  /* generic error */
#define ERR_INV_PARAM   -2  /* invalid parameter */
#define ERR_TOO_LONG    -3  /* too long */
#define ERR_STATE_ERR   -4  /* state error */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

#define DES_KEY_SIZE    8
#define DES_BLOCK_SIZE   8

typedef struct des_context {
    /* message total length in bytes */
    uint64_t total;

    uint8_t data[DES_BLOCK_SIZE];
    uint8_t key[DES_KEY_SIZE];
}DES_CTX;

int DES_Encryption(const unsigned char *data, unsigned int data_len, const unsigned char *key, unsigned int key_len, const unsigned *out, unsigned int out_len);
int DES_Decryption(const unsigned char *data, unsigned int data_len, const unsigned char *key, unsigned int key_len, const unsigned *out, unsigned int out_len);

#endif
