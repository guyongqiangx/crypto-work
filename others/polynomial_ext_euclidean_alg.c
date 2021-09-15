#include <stdio.h>

static void show_polynomial(unsigned int x);
static void show_sbox(unsigned int arr[256]);

/*
 * GF(2^8) 内的多项式乘法
 * 0x13 x 0xcc = 0xd94
 */
unsigned int gf2n_multi(unsigned int p1, unsigned int p2)
{
    unsigned int i, x;

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
static int get_msb1_pos(unsigned int x)
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
unsigned int gf2n_mod(unsigned int p1, unsigned int p2)
{
    unsigned int i, j;

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
unsigned int gf2n_div(unsigned int p1, unsigned int p2)
{
    unsigned int i, j;

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

unsigned int gcd(unsigned int p1, unsigned int p2)
{
    if (p2 == 0)
    {
        return p1;
    }
    else
    {
        return gcd(p2, gf2n_mod(p1, p2));
    }
}

/*
 * 扩展欧几里得算法求多项式 a 和 b 互相的逆元
 * ax + by = 1 = gcd(a, b)
 * --> ax mod b + by mod b = 1 mod b
 * --> ax mod b = 1 mod b
 */
int ext_euclidean(int a, int b, int *ia, int *ib)
{
    int x, y, x0, y0, x1, y1;
    int q, r;

    x0 = 1; y0 = 0;
    x1 = 0; y1 = 1;

    q = gf2n_div(a, b); // q = a / b;
    r = gf2n_mod(a, b); // r = a % b;

    while (r != 0)
    {
        /* 计算当前项 x/y */
        x = x0 ^ gf2n_multi(q, x1); // x = x0 - q * x1;
        y = y0 ^ gf2n_multi(q, y1); // y = y0 - q * y1;

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

    return x;
}

/*
 * 返回多项式 a 对于多项式 b 的逆元
 * ax + by = 1 mod b
 */
int gf2n_inverse(int a, int b)
{
    int ia, ib;

    ext_euclidean(a, b, &ia, &ib);

    return ia;
}

int main(int argc, char *argv[])
{
    int i, sbox[256];
    unsigned int p, p1, p2, t;

    p1 = 0x7f;
    p2 = 0x17;

    show_polynomial(p1);
    show_polynomial(p2);
    
    p = gf2n_mod(p1, p2);
    show_polynomial(p);

    p = gf2n_div(p1, p2);
    show_polynomial(p);

    p = gcd(p1, p2);
    show_polynomial(p);

    p1 = 0x83;  // x^7 + x + 1
    p2 = 0x11b; // x^8 + x^4 + x^3 + x + 1

    show_polynomial(p1);
    show_polynomial(p2);
    ext_euclidean(p1, p2, &p, &t);
    show_polynomial(p);

    p1 = 0x57;  // x^6 + x^4 + x^2 + x + 1
    p2 = 0x83;  // x^7 + x + 1
    p  = 0x11b; // x^8 + x^4 + x^3 + x + 1

    show_polynomial(p1);
    show_polynomial(p2);
    t = gf2n_multi(p1, p2);
    show_polynomial(t);
    t = gf2n_mod(t, p);
    show_polynomial(t);

    for (i=0; i<256; i++)
    {
        sbox[i] = gf2n_inverse(i, 0x11b);
    }
    show_sbox(sbox);

    return 0;
}

/*
 * 格式化打印值 p 代表的多项式:
 * 0x0000: 0
 * 0x0001: 1
 * 0x0002: x^1
 * 0x0003: x^1  + 1
 * 0x0004: x^2
 * 0x0013: x^4  + x^1  + 1
 * 0x00cc: x^7  + x^6  + x^3  + x^2
 * 0x0d94: x^11 + x^10 + x^8  + x^7  + x^4  + x^2
 */
static void show_polynomial(unsigned int p)
{
    int z[32], i;

    // 从最高位开始, 逐位检查多项式系数
    for (i=0; i<32; i++)
    {
        if (p & (1<<(31-i)))
        {
            z[i] = 1;
        }
        else
        {
            z[i] = 0;
        }
    }

    printf("0x%04x: ", p);

    // 找到最高次项
    i = 0;
    while (z[i] == 0)
    {
        i++;
    }

    if (i < 31)
    {
        printf("x^%-2d", 31-i);

        // 打印中间次项
        while (++i < 31)
        {
            if (z[i])
            {
                printf(" + x^%-2d", 31-i);
            }
        }

        // 打印最后一项 "+ 1"
        if (z[i])
        {
            printf(" + 1");
        }
    }
    else if (i == 31)
    {
        printf("1");
    }
    else /* i == 32, p = 0 */
    {
        printf("0");
    }

    printf("\n");
}

static void show_sbox(unsigned int arr[256])
{
    unsigned int x, y;

    printf("  ");
    for (x=0; x<16; x++)
    {
        printf(" %2X", x);
    }
    printf("\n");

    for (x=0; x<16; x++)
    {
        printf("%2X ", x);
        for (y=0; y<16; y++)
        {
            printf(" %02X", arr[16 * x + y]);
        }
        printf("\n");
    }
}