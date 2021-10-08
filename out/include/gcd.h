/*
 * @        file: gcd.h
 * @ description: 整数和扩展域上多项式的最大公约数(gcd), 乘法逆元(multiple reverse)的计算
 * @      author: Yongqiang Gu
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#ifndef __GCD_H__
#define __GCD_H__
#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @description: 使用欧几里得算法(辗转相除)求最大公约数
 * @param {int} a 整数a
 * @param {int} b 整数b
 * @return {*} 返回整数 (a, b) 的最大公约数
 */
int int_gcd(int a, int b);

/**
 * @description: 使用扩展欧几里得算法: Extend Euclidean Algorithm (EEA) 计算等式 a x ia + b x ib = gcd(a, b) 中的 ia, ib 和 gcd(a, b)
 * @param {int} a 整数 a
 * @param {int} b 整数 b
 * @param {int} *ia 整数 a 的系数 ia
 * @param {int} *ib 整数 b 的系数 ib
 * @return {*} 返回整数 (a, b) 的最大公约数 gcd(a, b)
 */
int int_gcd_ex(int a, int b, int *ia, int *ib);

/**
 * @description: 基于扩展欧几里得算法计算整数 a 关于 整数 b 的乘法逆元
 * @param {int} a 整数 a
 * @param {int} b 整数 b
 * @return {*} 返回整数 a 关于整数 b 的最小正整数乘法逆元, 乘法逆元不存在(gcd(a, b) != 1)则返回 0;
 */
int int_inv(int a, int b);

/* 扩展域上的多项式 GF(2^n), 系数位于 GF(2) 上的欧几里得算法/扩展欧几里得算法/乘法逆元 */
int poly_gcd(int p1, int p2);
int poly_gcd_ex(int a, int b, int *ia, int *ib);
int poly_inv(int a, int b);

#ifdef __cplusplus
}
#endif
#endif