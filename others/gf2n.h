/*
 * GF(2^8) 内的多项式乘法
 * 0x13 x 0xcc = 0xd94
 */
unsigned int gf2n_mul(unsigned int p1, unsigned int p2);

/*
 * GF(2^n) 内的多项式求余
 * p1 = 0x0d94: x^11 + x^10 + x^8  + x^7  + x^4  + x^2
 * p2 = 0x011b: x^8  + x^4  + x^3  + x^1  + 1
 * p1 mod p2 = 0xd98 mod 0x11b = 0x3d: x^5  + x^4  + x^3  + x^1  + 1
 */
unsigned int gf2n_mod(unsigned int p1, unsigned int p2);

/*
 * GF(2^n) 内的多项式求商
 * p1 = 0x007f: x^6  + x^5  + x^4  + x^3  + x^2  + x^1  + 1
 * p2 = 0x0017: x^4  + x^2  + x^1  + 1
 * p1 mod p2 = 0x007f mod 0x0017 = 0x0006: x^2  + x^1
 */
unsigned int gf2n_div(unsigned int p1, unsigned int p2);

/*
 * GF(2^n) 内的多项式最大公约数
 * p1 = 0x007f: x^6  + x^5  + x^4  + x^3  + x^2  + x^1  + 1
 * p2 = 0x0017: x^4  + x^2  + x^1  + 1
 * p1 mod p2 = 0x007f mod 0x0017 = 0x0006: x^2  + x^1
 */
unsigned int gf2n_gcd(unsigned int p1, unsigned int p2);

/*
 * 扩展欧几里得算法求多项式 a 和 b 互相的逆元
 * ax + by = 1 = gcd(a, b)
 * --> ax mod b + by mod b = 1 mod b
 * --> ax mod b = 1 mod b
 */
unsigned int gf2n_gcd(unsigned int p1, unsigned int p2);

/*
 * 扩展欧几里得算法求多项式 p1 和 p2 互相的逆元
 * ax + by = 1 = gcd(a, b)
 * --> ax mod b + by mod b = 1 mod b
 * --> ax mod b = 1 mod b
 */
unsigned int gf2n_ext_euclidean(unsigned int p1, unsigned int p2, unsigned int *ip1, unsigned int *ip2);

/*
 * 返回多项式 p1 对于多项式 p2 的逆元
 * ax + by = 1 mod b
 */
unsigned int gf2n_inv(unsigned int p1, unsigned int p2);