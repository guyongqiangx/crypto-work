/*
 * @        file: 
 * @ description: 
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#ifndef __ROCKY_TYPE__H
#define __ROCKY_TYPE__H

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