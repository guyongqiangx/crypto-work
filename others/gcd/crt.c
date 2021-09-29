#include <stdio.h>
// #include "gcd.h"

/**
 * @description: 基于扩展欧几里得算法计算整数 a 关于 整数 b 的乘法逆元(展开 int_gcd_ex 后的优化版本)
 * @param {int} a 整数 a
 * @param {int} b 整数 b
 * @return {*} 返回整数 a 关于整数 b 的最小正整数乘法逆元, 乘法逆元不存在(gcd(a, b) != 1)则返回 0;
 */
int int_inv(int a, int b)
{
    int x, x0, x1;
    int q, r, t;

    /* 消除警告: "warning: ‘x’ may be used uninitialized in this function" */
    x = 0;

    /* 初始化最初两项系数 */
    x0 = 1;
    x1 = 0;

    /* 临时保存 b */
    t = b;

    q = a / b;
    r = a % b;

    while (r != 0)
    {
        /* 计算当前项 x */
        x = x0 - q * x1;

        /* 依次保存前两项到 x0, x1 */
        x0 = x1; x1 = x;

        a = b;
        b = r; /* 前一次的余数 */

        q = a / b;
        r = a % b;
    }

    /* gcd(a, b) != 1, 没有乘法逆元 */
    if (b != 1)
    {
        return 0;
    }

    /* 调整小于 0 的情况 */
    if (x < 0)
    {
        x += t;
    }

    return x;
}

/**
 * @description: 中国剩余定理(CRT: Chinese Reminder Theorem)求同余方程解
 * @param {int} 指针 m, 指向整型数组, 包含每一组除数
 * @param {int} 指针 r, 指向整型数组, 包含每一组余数
 * @param {int} 整数 n, 指定传入指针 m 和 r 指向数组的大小
 * @return {*} 中国剩余定理的同余方程解
 */
int crt(int *m, int *r, int n)
{
    int i;
    int M, Mi, yi;
    int sum;

    // 计算同于方程组的模 M
    M = 1;
    for (i=0; i<n; i++)
    {
        M *= m[i];
    }

    sum = 0;
    for (i=0; i<n; i++)
    {
        // 计算每一个 Mi
        Mi = M / m[i];

        // 计算每一个 yi
        yi = int_inv(Mi, m[i]) % m[i];

        // 累积求和
        sum += r[i] * Mi * yi;
    }

    return sum % M;
}

int main(int argc, char *argv[])
{
    int m1[3] = { 3,  5,  7}, r1[3] = { 2,  3,  2}; // 示例1: 孙子算经
    int m2[3] = { 7, 11, 13}, r2[3] = { 5,  3, 10}; // 示例2: 《密码学原理与实践》第三版, p133, 例 5.3
    int m3[3] = {25, 26, 27}, r3[3] = {12,  9, 23}; // 示例3: 《密码学原理与实践》第三版, p178, 题 5.6
    int m4[2] = {37, 49},     r4[2] = {11, 42};     // 示例4: 《密码编码学与网络安全》第七版, p37, 示例
    int res;

    res = crt(m1, r1, 3);
    printf("同余方程组: 除数{ 7, 11, 13}, 余数{ 5,  3, 10}的解为 %d\n", res);

    res = crt(m2, r2, 3);
    printf("同余方程组: 除数{ 3,  5,  7}, 余数{ 2,  3,  2}的解为 %d\n", res);

    res = crt(m3, r3, 3);
    printf("同余方程组: 除数{25, 26, 27}, 余数{12,  9, 23}的解为 %d\n", res);

    res = crt(m4, r4, 2);
    printf("同余方程组: 除数{37, 49},     余数{11, 42}    的解为 %d\n", res);

    //printf("inverse(49, 37)=%d\n", int_inv(49, 37));
    //printf("inverse(37, 49)=%d\n", int_inv(37, 49));
    //printf("inverse(35, 3)=%d\n", int_inv(35, 3));
    //printf("inverse(21, 5)=%d\n", int_inv(21, 5));
    //printf("inverse(15, 7)=%d\n", int_inv(15, 7));
    return 0;
}