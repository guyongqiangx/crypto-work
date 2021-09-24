#ifndef __GCD_H__
#define __GCD_H__
#ifdef __cplusplus
extern "C"
{
#endif

/*
 * 欧几里得算法
 */
int int_gcd(int a, int b);

/*
 * 扩展欧几里得算法: Extend Euclidean Algorithm (EEA)
 * ax + by = 1 = gcd(a, b)
 * 使用扩展欧几里得算法计算 a 和 b 的 x 和 y, 似的 ax + by = gcd(a, b)
 * 返回 a 和 b 的最大公约数 gcd(a, b)
 */
int int_gcd_ex(int a, int b, int *ia, int *ib);

/*
 * 计算 a 关于 b 的乘法逆元
 * 返回 a 关于 b 的最小正整数乘法逆元
 * 如果逆元不存在 gcd(a, b) != 1, 则返回 0
 */
int int_inv(int a, int b);

#ifdef __cplusplus
}
#endif
#endif