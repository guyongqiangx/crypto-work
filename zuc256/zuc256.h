/*
 * @        file: zuc128.h
 * @ description: header file for zuc256.c
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#ifndef __ROCKY_ZUC__H
#define __ROCKY_ZUC__H

#define ERR_OK           0
#define ERR_ERR         -1  /* generic error */
#define ERR_INV_PARAM   -2  /* invalid parameter */
#define ERR_TOO_LONG    -3  /* too long */
#define ERR_STATE_ERR   -4  /* state error */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef enum {
    ZUC_STATE_INVALID = 0,
    ZUC_STATE_INITIALIZED,
    ZUC_STATE_WORKING,
    ZUC_STATE_MAX = ZUC_STATE_WORKING
} ZUC_STATE;

typedef enum {
    ZUC256_TYPE_KEYSTREAM = 0,
    ZUC256_TYPE_MAC32,
    ZUC256_TYPE_MAC64,
    ZUC256_TYPE_MAC128,
    ZUC256_TYPE_MAX = ZUC256_TYPE_MAC128
} ZUC256_TYPE;

typedef struct zuc256_context {
    ZUC_STATE state;

    /* 16 个 31 bit 变量 */
    uint32_t s[16];

    /* 4 个 32 bit 重组变量 */
    uint32_t X[4];

    /* 32 bit 内部状态机变量 */
    uint32_t R1;
    uint32_t R2;
}ZUC256_CTX;

int ZUC256_Init(ZUC256_CTX *ctx, unsigned char *key, unsigned char *iv);
int ZUC256_GenerateKeyStream(ZUC256_CTX *ctx, unsigned int *out, unsigned int len);

int ZUC256(unsigned char *key, unsigned char *iv, unsigned int length, unsigned int *ibs, unsigned int *obs);

typedef struct zuc256_mac_context {
    ZUC256_CTX ctx;
    ZUC256_TYPE type;
}ZUC256_MAC_CTX;

int ZUC256_MAC_Init(ZUC256_MAC_CTX *c, ZUC256_TYPE type, unsigned char *key, unsigned char *iv);
int ZUC256_MAC_Update(ZUC256_MAC_CTX *c, const void *data, size_t len);
int ZUC256_MAC_Final(unsigned char *md, ZUC256_MAC_CTX *c);
unsigned char *ZUC256_MAC(ZUC256_TYPE type, const unsigned char *d, size_t n, unsigned char *md);
#endif
