/*
 * @        file: 
 * @ description: 
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#ifndef __ROCKY_TYPE__H
#define __ROCKY_TYPE__H

#define ERR_OK             0
#define ERR_ERR           -1  /* generic error */
#define ERR_INV_PARAM     -2  /* invalid parameter */
#define ERR_TOO_LONG      -3  /* too long */
#define ERR_STATE_ERR     -4  /* state error */
#define ERR_OUT_OF_MEMORY -5  /* out of memory */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
#ifndef uint64_t
typedef unsigned long long uint64_t;
#endif

#ifndef uint128_t
typedef struct {
    uint64_t high; /* high 64 bits */
    uint64_t low;  /*  low 64 bits */
} uint128_t;
#endif

#endif