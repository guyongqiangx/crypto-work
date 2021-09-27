/*
 * @        file: int_gcd.c
 * @ description: 整数的最大公约数，和扩展欧几里得算法求乘法逆元的实现
 * @      author: Yongqiang Gu
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include "gcd.h"

/**
 * @description: 使用欧几里得算法(辗转相除)求最大公约数的递归版本
 * @param {int} a 整数a
 * @param {int} b 整数b
 * @return {*} 返回整数 (a, b) 的最大公约数
 */
/*
 * int int_gcd(int a, int b)
 * {
 *     if (b == 0)
 *     {
 *         return a;
 *     }
 *     else
 *     {
 *         return int_gcd(b, a % b);
 *     }
 * }
 */

/**
 * @description: 使用欧几里得算法(辗转相除)求最大公约数的非递归版本
 * @param {int} a 整数a
 * @param {int} b 整数b
 * @return {*} 返回整数 (a, b) 的最大公约数
 */
int int_gcd(int a, int b)
{
    int t;

    while (b != 0)
    {
        t = a % b;
        a = b;
        b = t;
    }

    return a;
}

/**
 * @description: 使用扩展欧几里得算法: Extend Euclidean Algorithm (EEA) 计算等式 a x ia + b x ib = gcd(a, b) 中的 ia, ib 和 gcd(a, b)
 * @param {int} a 整数 a
 * @param {int} b 整数 b
 * @param {int} *ia 整数 a 的系数 ia
 * @param {int} *ib 整数 b 的系数 ib
 * @return {*} 返回整数 (a, b) 的最大公约数 gcd(a, b)
 */
int int_gcd_ex(int a, int b, int *ia, int *ib)
{
    int x, y, x0, y0, x1, y1;
    int q, r;

    /* 消除警告: "warning: ‘x’/‘y’ may be used uninitialized in this function" */
    x = y = 0;

    /* 初始化最初两项系数 */
    x0 = 1; y0 = 0;
    x1 = 0; y1 = 1;

    q = a / b;
    r = a % b;

    while (r != 0)
    {
        /* 计算当前项 x/y */
        x = x0 - q * x1;
        y = y0 - q * y1;

        /* 依次保存前两项到 x0/y0, x1/y1 */
        x0 = x1; x1 = x;
        y0 = y1; y1 = y;

        a = b;
        b = r; /* 前一次的余数 */

        q = a / b;
        r = a % b;
    }

    *ia = x;
    *ib = y;

    return b;
}

/**
 * @description: 基于扩展欧几里得算法计算整数 a 关于 整数 b 的乘法逆元
 * @param {int} a 整数 a
 * @param {int} b 整数 b
 * @return {*} 返回整数 a 关于整数 b 的最小正整数乘法逆元, 乘法逆元不存在(gcd(a, b) != 1)则返回 0;
 */
int int_inv(int a, int b)
{
    int res, ia, ib;

    res = int_gcd_ex(a, b, &ia, &ib);

    /* No Inverse, 没有乘法逆元 */
    if (res != 1)
    {
        return 0;
    }

    /* 调整小于 0 的情况 */
    if (ia < 0)
    {
        ia += b;
    }

    return ia;
}