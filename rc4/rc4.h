/*
 * @        file: rc4.h
 * @ description: header file for rc4.c
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#ifndef __ROCKY_RC4__H
#define __ROCKY_RC4__H

#define ERR_OK           0
#define ERR_ERR         -1  /* generic error */
#define ERR_INV_PARAM   -2  /* invalid parameter */
#define ERR_TOO_LONG    -3  /* too long */
#define ERR_STATE_ERR   -4  /* state error */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

int RC4_Encryption(const unsigned char *data, unsigned int data_len, const unsigned char *key, unsigned int key_len, const unsigned *out, unsigned int out_len);
int RC4_Decryption(const unsigned char *data, unsigned int data_len, const unsigned char *key, unsigned int key_len, const unsigned *out, unsigned int out_len);

#endif
