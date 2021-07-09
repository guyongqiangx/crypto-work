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

int SM4_Encryption(const unsigned char *data, unsigned int data_len, const unsigned char *key, unsigned int key_len, const unsigned *out, unsigned int out_len)
{
    return ERR_OK;
}

int SM4_Decryption(const unsigned char *data, unsigned int data_len, const unsigned char *key, unsigned int key_len, const unsigned *out, unsigned int out_len)
{
    return ERR_OK;
}