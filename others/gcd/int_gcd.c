#include "gcd.h"

/*
 * 最大公约数: Greatest Common Divisor (GCD)
 * 示例:
 * gcd(3, 0) = 3
 * gcd(0, 3) = gcd(3, 0) = 3
 * gcd(50, 30) = gcd(30, 20) = gcd(20, 10) = gcd(10, 0) = 10
 * gcd(30, 50) = gcd(50, 30) = ...
 */
/*
 * 递归版本
 *
 * int int_gcd(int a, int b)
 * {
 *     if (b == 0)
 *     {
 *         return a;
 *     }
 *     else
 *     {
 *         return gcd(b, a % b);
 *     }
 * }
 */

/*
 * 非递归版本
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

/*
 * 扩展欧几里得算法: Extend Euclidean Algorithm (EEA)
 * ax + by = 1 = gcd(a, b)
 * 使用扩展欧几里得算法计算正整数 a 和 b 的系数 x 和 y, 使得 ax + by = gcd(a, b)
 * 返回 a 和 b 的最大公约数 gcd(a, b)
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

/*
 * 计算整数 a 关于 b 的乘法逆元
 * 返回整数 a 关于整数 b 的最小正整数乘法逆元
 * 如果逆元不存在 gcd(a, b) != 1, 则返回 0
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