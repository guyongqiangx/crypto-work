#include <stdio.h>
#include "int-ecc.h"

/* a = b * q + r, 0 < r < |b| */
static int int_mod(int a, int b)
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

    r = int_gcd_ex(b, int_mod(a, b), &x, &y);

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

static int get_slope_by_tangent(int p, int a, const struct point *p1)
{
    int x, y;

    x = int_mod(3 * p1->x * p1->x + a, p);
    y = int_inv(2 * p1->y, p);

    return int_mod(x * y, p);
}

static int get_slope_by_points(int p, const struct point *p1, const struct point *p2)
{
    int x, y;

    y = int_mod(p2->y - p1->y, p);

    x = p2->x - p1->x;
    while (x < 0) /* 确保求 inverse 时始终是非负数，否则失败 */
    {
        x += p;
    }
    x = int_inv(x, p);

    return int_mod(y * x, p);
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

    x3 = int_mod(s * s - p1->x - p2->x, p);
    y3 = int_mod(s * (p1->x - x3) - p1->y, p);

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

int ecc_point_mul(int p, int a, int x, const struct point *p1, struct point *p2)
{
    int i, pos;
    struct point p3;

    pos = get_msb1_pos(x);
    p2->x = p1->x;
    p2->y = p1->y;

    for (i=pos-1; i>=0; i--)
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

int ecc_point_on_curve(int p, int a, int b, const struct point *p1)
{
    int l, r;

    l = int_mod(p1->y * p1->y, p);
    r = int_mod(p1->x * p1->x * p1->x + a * p1->x + b, p);

    if (l == r)
    {
        return 1;
    }

    return 0;
}

int ecc_point_order(int p, int a, int b, const struct point *p1)
{
    int i;
    struct point p2;

    if (!ecc_point_on_curve(p, a, b, p1))
    {
        return 0;
    }

    i = 2;
    ecc_point_add(p, a, p1, p1, &p2);
    while (p2.x != p1->x)
    {
        i++;
        ecc_point_add(p, a, p1, &p2, &p2);
    }

    return i + 1; /* + Identity Element */
}

void ecc_point_show_group(int p, int a, int b, const struct point *p1)
{
    int i;
    struct point p2;

    if (!ecc_point_on_curve(p, a, b, p1))
    {
        return;
    }

    i = 1;
    printf("%4dP(%4d, %4d)\n", i, p1->x, p1->y);

    i++;
    ecc_point_add(p, a, p1, p1, &p2);
    printf("%4dP(%4d, %4d)\n", i, p2.x, p2.y);
    while (p2.x != p1->x)
    {
        i++;
        ecc_point_add(p, a, p1, &p2, &p2);
        printf("%4dP(%4d, %4d)\n", i, p2.x, p2.y);
    }

    printf("%4dP = O\n", i+1);

    return;
}