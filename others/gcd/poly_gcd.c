#include "gcd.h"

/*
 * GF(2^8) 内的多项式乘法
 * 0x13 x 0xcc = 0xd94
 */
static int gf2n_mul(int p1, int p2)
{
    int i, x;

    x = 0;
    i = 0;
    while (p2 != 0)
    {
        if (p2 & 0x01)
        {
            x ^= p1 << i;
        }
        i ++;
        p2 >>= 1;
    }

    return x;
}

/*
 * 获取最高位为 1 的位置(从 0 开始)
 */
static int get_msb1_pos(int x)
{
    int i;

    i = -1;
    while (x)
    {
        x >>= 1;
        i ++;
    }

    return i;
}

/*
 * GF(2^n) 内的多项式求余
 * p1 = 0x0d94: x^11 + x^10 + x^8  + x^7  + x^4  + x^2
 * p2 = 0x011b: x^8  + x^4  + x^3  + x^1  + 1
 * p1 mod p2 = 0xd98 mod 0x11b = 0x3d: x^5  + x^4  + x^3  + x^1  + 1
 */
static int gf2n_mod(int p1, int p2)
{
    int i, j;

    // 找到 p2 的最高位
    j = get_msb1_pos(p2);
    if (p1 < (0x1 << j))
    {
        return p1;
    }

    // 找到 p1 的最高位
    i = get_msb1_pos(p1);

    return gf2n_mod(p1 ^ (p2 << (i-j)), p2);
}

/*
 * GF(2^n) 内的多项式求商
 * p1 = 0x007f: x^6  + x^5  + x^4  + x^3  + x^2  + x^1  + 1
 * p2 = 0x0017: x^4  + x^2  + x^1  + 1
 * p1 mod p2 = 0x007f mod 0x0017 = 0x0006: x^2  + x^1
 */
static int gf2n_div(int p1, int p2)
{
    int i, j;

    // 找到 p2 的最高位
    j = get_msb1_pos(p2);
    if (p1 < (0x1 << j))
    {
        return 0;
    }

    // 找到 p1 的最高位
    i = get_msb1_pos(p1);

    return (0x1 << (i-j)) | gf2n_div(p1 ^ (p2 << (i-j)), p2);
}


/*
 * 最大公约数: Greatest Common Divisor (GCD)
 * 示例:
 * gcd(3, 0) = 3
 */
/*
 * 递归版本
 *
 * int poly_gcd(int p1, int p2)
 * {
 *     if (p2 == 0)
 *     {
 *         return p1;
 *     }
 *     else
 *     {
 *         return poly_gcd(p2, gf2n_mod(p1, p2)); // poly_gcd(p2, p1 % p2);
 *     }
 * }
 */

/*
 * 非递归版本
 */
int poly_gcd(int p1, int p2)
{
    int t;

    while (p2 != 0)
    {
        t = gf2n_mod(p1, p2); // t = p1 % p2;
        p1 = p2;
        p2 = t;
    }

    return p1;
}

///*
// * 扩展欧几里得算法: Extend Euclidean Algorithm (EEA)
// * ax + by = 1 = gcd(a, b)
// * 使用扩展欧几里得算法计算多项式 a 和 b 的系数 x 和 y, 使得 ax + by = gcd(a, b)
// * 返回 a 和 b 的最大公约数 gcd(a, b)
// */
///*
// * 递归版本
// */
//int poly_gcd_ex(int a, int b, int *ia, int *ib)
//{
//    int r, x, y;
//
//    if (b == 0)
//    {
//        *ia = 1;
//        *ib = 0;
//
//        return a;
//    }
//
//    r = poly_gcd_ex(b, gf2n_mod(a, b), &x, &y);
//    *ia = y;
//    *ib = x ^ gf2n_mul(gf2n_div(a, b), y);
//
//    return r;
//}

/*
 * 扩展欧几里得算法: Extend Euclidean Algorithm (EEA)
 * ax + by = 1 = gcd(a, b)
 * 使用扩展欧几里得算法计算多项式 a 和 b 的系数 x 和 y, 使得 ax + by = gcd(a, b)
 * 返回 a 和 b 的最大公约数 gcd(a, b)
 */
/*
 * 非递归版本
 */
int poly_gcd_ex(int a, int b, int *ia, int *ib)
{
    int x, y, x0, y0, x1, y1;
    int q, r;

    /* 消除警告: "warning: ‘x’/‘y’ may be used uninitialized in this function" */
    x = y = 0;

    /* 初始化最初两项系数 */
    x0 = 1; y0 = 0;
    x1 = 0; y1 = 1;

    q = gf2n_div(a, b); // q = a / b;
    r = gf2n_mod(a, b); // r = a % b;

    while (r != 0)
    {
        /* 计算当前项 x/y */
        x = x0 ^ gf2n_mul(q, x1); // x = x0 - q * x1;
        y = y0 ^ gf2n_mul(q, y1); // y = y0 - q * y1;

        /* 依次保存前两项到 x0/y0, x1/y1 */
        x0 = x1; x1 = x;
        y0 = y1; y1 = y;

        a = b;
        b = r;

        q = gf2n_div(a, b); // q = a / b;
        r = gf2n_mod(a, b); // r = a % b;
    }

    *ia = x;
    *ib = y;

    return b;
}

///*
// * 计算多项式 a 关于 b 的乘法逆元 (递归版本)
// * 返回多项式 a 关于多项式 b 的多项式乘法逆元
// * 如果逆元不存在 gcd(a, b) != 1, 则返回 0
// */
//int poly_inv(int a, int b)
//{
//    int res, ia, ib;
//
//    res = poly_gcd_ex(a, b, &ia, &ib);
//
//    /* No Inverse, 没有乘法逆元 */
//    if (res != 1)
//    {
//        return 0;
//    }
//
//    return ia;
//}

/*
 * 计算多项式 a 关于 b 的乘法逆元 (非递归版本)
 * 返回多项式 a 关于多项式 b 的多项式乘法逆元
 * 如果逆元不存在 gcd(a, b) != 1, 则返回 0
 */
int poly_inv(int a, int b)
{
    int x, x0, x1;
    int q, r;

    /* 消除警告: "warning: ‘x’ may be used uninitialized in this function" */
    x = 0;

    /* 初始化最初两项系数 */
    x0 = 1; x1 = 0;

    q = gf2n_div(a, b); // q = a / b;
    r = gf2n_mod(a, b); // r = a % b;

    while (r != 0)
    {
        /* 计算当前项 x */
        x = x0 ^ gf2n_mul(q, x1); // x = x0 - q * x1;

        /* 依次保存前两项到 x0, x1 */
        x0 = x1; x1 = x;

        a = b;
        b = r;

        q = gf2n_div(a, b); // q = a / b;
        r = gf2n_mod(a, b); // r = a % b;
    }

    /* No Inverse, 没有乘法逆元 */
    if (b != 1)
    {
        return 0;
    }

    return x;
}