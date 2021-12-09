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

struct point {
    int x;
    int y;
};

static int get_slope_by_tangent(int p, int a, const struct point *p1)
{
    int x, y;

    x = mod(3 * p1->x * p1->x + a, p);
    y = int_inv(2 * p1->y, p);

    return mod(x * y, p);
}

static int get_slope_by_points(int p, const struct point *p1, const struct point *p2)
{
    int x, y;

    y = mod(p2->y - p1->y, p);

    x = p2->x - p1->x;
    while (x < 0) /* 确保求 inverse 时始终是非负数，否则失败 */
    {
        x += p;
    }
    x = int_inv(x, p);

    return mod(y * x, p);
}

int ecc_point_add(int p, int a, const struct point *p1, const struct point *p2, struct point *p3)
{
    int s;
    int x3, y3;

    if (p1 == p2) /* 相同点 */
    {
        s = get_slope_by_tangent(p, a, p1);
    }
    else /* 不同点 */
    {
        s = get_slope_by_points(p, p1, p2);
    }

    x3 = mod(s * s - p1->x - p2->x, p);
    y3 = mod(s * (p1->x - x3) - p1->y, p);

    p3->x = x3;
    p3->y = y3;

    return 0;
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

int ecc_point_mul(int p, int a, unsigned long x, const struct point *p1, struct point *p2)
{
    int i, pos;
    struct point p3;

    pos = get_msb1_pos(x);
    p2->x = p1->x;
    p2->y = p1->y;

    for (i=pos-1; i>0; i--)
    {
        ecc_point_add(p, a, p2, p2, &p3);    /* p3 = p2 * 2 */
        if ((x >> i) & 0x01)
        {
            ecc_point_add(p, a, &p3, p1, &p3); /* p3 = p3 + p1 = p2 * 2 + p1 */
        }

        p2->x = p3.x;
        p2->y = p3.y;
    }

    return 0;
}

int ecc_point_is_valid(int p, int a, int b, struct point *p1)
{
    int l, r;

    l = mod(p1->y * p1->y, p);
    r = mod(p1->x * p1->x * p1->x + a * p1->x + b, p);

    if (l == r)
    {
        return 1;
    }

    return 0;
}

int main(int argc, char *argv)
{
    int p, a, b;
    struct point p1, p2, p3;
    int i;

    /*
     * 深入浅出密码学, p232
     * Elliptic Curve: y^2 = x^3 + 2x + 2 mod 17
     * Base Point (5, 1)
     */
    printf("Elliptic Curve: y^2 = x^3 + 2x + 2 mod 17, Base Point (5, 1)\n");
    p = 17; a = 2; b = 2;
    p1.x = 5; p1.y = 1;

    i = 1;
    printf("%4dP(%4d, %4d)\n", i, p1.x, p1.y);

    i++;
    ecc_point_add(p, a, &p1, &p1, &p2);
    printf("%4dP(%4d, %4d)\n", i, p2.x, p2.y);

    while (p2.x != p1.x)
    {
        i++;
        ecc_point_add(p, a, &p1, &p2, &p3);
        printf("%4dP(%4d, %4d)\n", i, p3.x, p3.y);
        p2.x = p3.x;
        p2.y = p3.y;
    }

    /*
     * 深入浅出密码学, p242, Q9.5
     * Elliptic Curve: y^2 = x^3 + 3x + 2 mod 7
     * Base Point (2, 4)
     */
    printf("Elliptic Curve: y^2 = x^3 + 3x + 2 mod 7, Base Point (2, 4)\n");
    p = 7; a = 3; b = 2;
    p1.x = 0;
    p1.y = 3;

    i = 1;
    printf("%4dP(%4d, %4d)\n", i, p1.x, p1.y);

    i++;
    ecc_point_add(p, a, &p1, &p1, &p2);
    printf("%4dP(%4d, %4d)\n", i, p2.x, p2.y);

    while (p2.x != p1.x)
    {
        i++;
        ecc_point_add(p, a, &p1, &p2, &p3);
        printf("%4dP(%4d, %4d)\n", i, p3.x, p3.y);
        p2.x = p3.x;
        p2.y = p3.y;
    }

    /*
     * 深入浅出密码学, p242, Q9.7
     * Elliptic Curve: y^2 = x^3 + 4x + 20 mod 29
     * Base Point (8, 10)
     */
    printf("Elliptic Curve: y^2 = x^3 + 4x + 20 mod 29, Base Point (8, 10)\n");
    p = 29; a = 4; b = 20;
    p1.x = 8;
    p1.y = 10;

    i = 1;
    printf("%4dP(%4d, %4d)\n", i, p1.x, p1.y);

    i++;
    ecc_point_add(p, a, &p1, &p1, &p2);
    printf("%4dP(%4d, %4d)\n", i, p2.x, p2.y);

    while (p2.x != p1.x)
    {
        i++;
        ecc_point_add(p, a, &p1, &p2, &p3);
        printf("%4dP(%4d, %4d)\n", i, p3.x, p3.y);
        p2.x = p3.x;
        p2.y = p3.y;
    }

    /*
     * 深入浅出密码学, p243, Q9.9
     * Elliptic Curve: y^2 = x^3 + x + 6 mod 11
     * Base Point (5, 9)
     */
    printf("Elliptic Curve: y^2 = x^3 + x + 6 mod 11, Base Point (5, 9)\n");
    p = 11; a = 1; b = 6;
    p1.x = 5;
    p1.y = 9;

    i = 1;
    printf("%4dP(%4d, %4d)\n", i, p1.x, p1.y);

    i++;
    ecc_point_add(p, a, &p1, &p1, &p2);
    printf("%4dP(%4d, %4d)\n", i, p2.x, p2.y);

    while (p2.x != p1.x)
    {
        i++;
        ecc_point_add(p, a, &p1, &p2, &p3);
        printf("%4dP(%4d, %4d)\n", i, p3.x, p3.y);
        p2.x = p3.x;
        p2.y = p3.y;
    }

    /*
     * 密码编码学与网络安全, 7th, section 10.4, p226
     * Elliptic Curve: y^2 = x^3 + 9x + 17 mod 23
     * Base Point (9, 17)
     */
    printf("Elliptic Curve: y^2 = x^3 + 9x + 17 mod 23, Base Point (16, 5)\n");
    p = 23; a = 9; b = 17;
    p1.x = 16;
    p1.y = 5;

    i = 1;
    printf("%4dP(%4d, %4d)\n", i, p1.x, p1.y);

    i++;
    ecc_point_add(p, a, &p1, &p1, &p2);
    printf("%4dP(%4d, %4d)\n", i, p2.x, p2.y);

    while (p2.x != p1.x)
    {
        i++;
        ecc_point_add(p, a, &p1, &p2, &p3);
        printf("%4dP(%4d, %4d)\n", i, p3.x, p3.y);
        p2.x = p3.x;
        p2.y = p3.y;
    }

    /*
     * 密码编码学与网络安全, 7th, section 10.4.1, p227
     * Elliptic Curve: y^2 = x^3 - 4 mod 211
     * Base Point (2, 2)
     */
    printf("Elliptic Curve: Elliptic Curve: y^2 = x^3 - 4 mod 211, Base Point (2, 2)\n");
    p = 211; a = 0; b = -4;
    p1.x = 2;
    p1.y = 2;

    i = 1;
    printf("%4dP(%4d, %4d)\n", i, p1.x, p1.y);

    i++;
    ecc_point_add(p, a, &p1, &p1, &p2);
    printf("%4dP(%4d, %4d)\n", i, p2.x, p2.y);

    while (p2.x != p1.x)
    {
        i++;
        ecc_point_add(p, a, &p1, &p2, &p3);
        printf("%4dP(%4d, %4d)\n", i, p3.x, p3.y);
        p2.x = p3.x;
        p2.y = p3.y;
    }

    return 0;
}