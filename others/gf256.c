#include <stdio.h>

void show_polynomial(unsigned int x);

/*
 * GF(2^8) 内的多项式乘法
 * 0x13 x 0xcc = 0xd94
 */
unsigned int gf256_multi(unsigned int a, unsigned int b)
{
    unsigned int i, x;

    //show_polynomial(a);
    //show_polynomial(b);
    
    x = 0;
    i = 0;
    while (b != 0)
    {
        if (b & 0x01)
        {
            x ^= a << i;
        }
        i ++;
        b >>= 1;
    }

    //show_polynomial(x);

    return x;
}

/*
 * GF(2^8) 内的多项式求余
 * a = 0x0d94: x^11 + x^10 + x^8  + x^7  + x^4  + x^2
 * b = 0x011b: x^8  + x^4  + x^3  + x^1  + 1
 * a mod b = 0xd98 mod 0x11b = 0x3d: x^5  + x^4  + x^3  + x^1  + 1
 */
unsigned int gf256_mod(unsigned int a, unsigned int b)
{
    unsigned int i, j, t, x;
    
    if (a < 0x100)
    {
        //show_polynomial(a);
        return a;
    }

    // 找到 a 的最高位
    t = a;
    i = 0;
    while (t != 0)
    {
        i ++;
        t >>= 1;
    }

    // 找到 b 的最高位
    t = b;
    j = 0;
    while (t != 0)
    {
        j ++;
        t >>= 1;
    }

    return gf256_mod(a ^ (b << (i-j)), b);
}

/*
 * 格式化打印值 x 代表的多项式:
 * 0x0013: x^4  + x^1  + 1
 * 0x00cc: x^7  + x^6  + x^3  + x^2 
 * 0x0d94: x^11 + x^10 + x^8  + x^7  + x^4  + x^2
 */
void show_polynomial(unsigned int x)
{
    int z[32], i;

    // 从最高位开始, 逐位检查多项式系数
    for (i=0; i<32; i++)
    {
        if (x & (1<<(31-i)))
        {
            z[i] = 1;
        }
        else
        {
            z[i] = 0;
        }
    }

    printf("0x%04x: ", x);

    // 找到最高次项
    i = 0;
    while (z[i] == 0)
    {
        i++;
    }
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
    printf("\n");
}

unsigned int get_gf256_reverse(unsigned int a, unsigned int p)
{
    unsigned int i, x;

    if (a == 0)
    {
        return 0;
    }

    x = 0;
    for (i=0; i<256; i++)
    {
        x = gf256_mod(gf256_multi(a, i), p);
        if (x == 1)
        {
            return i;
        }
    }
}

void generate_gf256_reverse_matrix(void)
{
    unsigned int x, y;
    unsigned int arr[256];

    for (x=0; x<256; x++)
    {
        arr[x] = get_gf256_reverse(x, 0x11b);
    }

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

int main(int argc, char *argv)
{
    unsigned int x;

    x = gf256_multi(0x13, 0xcc);
    printf("res: 0x%02x\n", x);

    x = gf256_multi(0xcc, 0x13);
    printf("res: 0x%02x\n", x);

    x = gf256_mod(0xd94, 0x11b);
    printf("res: 0x%02x\n", x);

    generate_gf256_reverse_matrix();
    return 0;
}