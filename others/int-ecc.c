#include <stdio.h>

/* a = b * q + r, 0 < r < |b| */
static int mod(int a, int b)
{
    int r;

    r = a % b;

    return r < 0 ? r + b : r;
}

/**
 * @description: 使用扩展欧几里得算法(EEA)计算等式 a x ia + b x ib = gcd(a, b) 中的系数 ia, ib 和 gcd(a, b), 递归版本, 推导和证明参考: https://blog.csdn.net/lincifer/article/details/49391175
 * @param {int} a 整数 a
 * @param {int} b 整数 b
 * @param {int} *ia 整数 a 的系数 ia
 * @param {int} *ib 整数 b 的系数 ib
 * @return {*} 返回整数 (a, b) 的最大公约数 gcd(a, b)
 */
static int int_gcd_ex(int a, int b, int *ia, int *ib)
{
    int x, y;
    int q, r;

    if (b == 0)
    {
        *ia = 1;
        *ib = 0;

        return a;
    }

    r = int_gcd_ex(b, mod(a, b), &x, &y);

    *ia = y;
    *ib = x - a / b * y;

    return r;
}

/**
 * @description: 基于扩展欧几里得算法计算整数 a 关于 整数 b 的乘法逆元
 * @param {int} a 整数 a
 * @param {int} b 整数 b
 * @return {*} 返回整数 a 关于整数 b 的最小正整数乘法逆元, 乘法逆元不存在(gcd(a, b) != 1)则返回 0;
 */
static int int_inv(int a, int b)
{
    int res, ia, ib;

    res = int_gcd_ex(a, b, &ia, &ib);

    /* gcd(a, b) != 1, 没有乘法逆元 */
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

static int get_slope_by_tangent(int p, int a, int x1, int y1)
{
    int x, y;

    x = mod(3 * x1 * x1 + a, p); //x = (3 * x1 * x1 + a) % p;
    y = int_inv(2*y1, p);

    return x * y % p;
}

int ecc_points_double(int p, int a, int x1, int y1, int *x, int *y)
{
    int s;
    int x3, y3;

    s = get_slope_by_tangent(p, a, x1, y1);

    x3 = mod(s * s - 2 * x1, p);
    y3 = mod(s * (x1 - x3) - y1, p);

    *x = x3;
    *y = y3;

    return 0;
}

int get_slope_by_line(int p, int x1, int y1, int x2, int y2)
{
    int x, y;

    y = mod(y2 - y1, p);

    x = x2 - x1;
    while (x < 0)
    {
        x += p;
    }
    x = int_inv(x, p);

    return mod(y * x, p);
}

int ecc_points_add(int p, int x1, int y1, int x2, int y2, int *x, int *y)
{
    int s;
    int x3, y3;

    s = get_slope_by_line(p, x1, y1, x2, y2);

    x3 = mod(s * s - x1 - x2, p);
    y3 = mod(s * (x1 - x3) - y1, p);

    *x = x3;
    *y = y3;

    return 0;
}

int main(int argc, char *argv)
{
    int p, a, b;
    int x1, y1, x2, y2, x, y;
    int i;

    /*
     * 深入浅出密码学, p232
     * Elliptic Curve: y^2 = x^3 + 2x + 2 mod 17
     * Base Point (5, 1)
     */
    p = 17; a = 2; b = 2;
    x1 = 5; y1 = 1;

    i = 1;
    printf("%2dP(%2d, %2d)\n", i, x1, y1);

    i++;
    ecc_points_double(p, a, x1, y1, &x2, &y2);
    printf("%2dP(%2d, %2d)\n", i, x2, y2);

    while (x2 != x1)
    {
        i++;
        ecc_points_add(p, x1, y1, x2, y2, &x, &y);
        printf("%2dP(%2d, %2d)\n", i, x, y);
        x2 = x;
        y2 = y;
    }

    return 0;
}