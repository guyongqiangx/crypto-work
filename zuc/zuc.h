/*
 * @        file: zuc.h
 * @ description: header file for zuc.c
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

typedef struct zuc_context {
    ZUC_STATE state;

    /* 16 个 31 bit 变量 */
    uint32_t s[16];

    /* 4 个 32 bit 重组变量 */
    uint32_t X[4];

    /* 32 bit 内部状态机变量 */
    uint32_t R1;
    uint32_t R2;
}ZUC_CTX;

int ZUC_Init(ZUC_CTX *ctx, unsigned char *key, unsigned char *iv);
int ZUC_GenerateKeyStream(ZUC_CTX *ctx, unsigned int *out, unsigned int len);

int EEA3(unsigned char *CK, unsigned int COUNT, unsigned int BEARER, unsigned int DIRECTION, unsigned int LENGTH, unsigned int *IBS, unsigned int *OBS);
int EIA3(unsigned char *IK, unsigned int COUNT, unsigned int BEARER, unsigned int DIRECTION, unsigned int LENGTH, unsigned int *M, unsigned int *MAC);
#endif
