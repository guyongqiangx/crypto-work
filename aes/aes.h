/*
 * @        file: des.h
 * @ description: header file for aes.c
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

typedef enum aes_algorithm {
    AES128,
    AES192,
    AES256,
}AES_ALG;

int AES_Encrypt(AES_ALG alg, const unsigned char *in, const unsigned char *key, unsigned char *out);
int AES_Decrypt(AES_ALG alg, const unsigned char *in, const unsigned char *key, unsigned char *out);
#endif
