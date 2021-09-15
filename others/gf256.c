#include <stdio.h>
#include <string.h>

void show_polynomial(unsigned int x);

/*
 * GF(2^8) 内的多项式乘法
 * 0x13 x 0xcc = 0xd94
 */
unsigned int gf256_multi(unsigned int p1, unsigned int p2)
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
int get_msb1_pos(unsigned int x)
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
 * GF(2^8) 内的多项式求余
 * p1 = 0x0d94: x^11 + x^10 + x^8  + x^7  + x^4  + x^2
 * p2 = 0x011b: x^8  + x^4  + x^3  + x^1  + 1
 * p1 mod p2 = 0xd98 mod 0x11b = 0x3d: x^5  + x^4  + x^3  + x^1  + 1
 */
unsigned int gf256_mod(unsigned int p1, unsigned int p2)
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

    return gf256_mod(p1 ^ (p2 << (i-j)), p2);
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

static char *get_polynomial(unsigned int p)
{
    int z[32], i, pos;
    /* buf = "x^31+x^30+x^29+...+x^2+x+1" */
    static unsigned char buf[256];

    if (x == 0)
    {
        buf[0] = '0';
        buf[1] = '\0';
        return buf;
    }

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

    pos = 0;

    // 找到最高次项
    i = 0;
    while (z[i] == 0)
    {
        i++;
    }

    if (i<30)
    {
        pos += sprintf(buf+pos, "x^%d", 31-i);

        // 打印中间次项(除 x 和 1)
        while (++i < 30)
        {
            if (z[i])
            {
                pos += sprintf(buf+pos, "+x^%d", 31-i);
            }
        }

        // 打印倒数第二项 "x"
        if (z[30])
        {
            pos += sprintf(buf+pos, "+x");
        }

        // 打印最后一项 "1"
        if (z[31])
        {
            pos += sprintf(buf+pos, "+1");
        }
    }
    else if (i==30) /* p=x, p=x+1 */
    {
        if (z[30])
        {
            pos += sprintf(buf+pos, "x");
        }

        // 打印最后一项 "1"
        if (z[31])
        {
            pos += sprintf(buf+pos, "+1");
        }
    }
    else if (i==31) /* p=1 */
    {
        // 打印最后一项 "1"
        if (z[31])
        {
            pos += sprintf(buf+pos, "1");
        }
    }
    else /* i==32, p=0 */
    {
        pos += sprintf(buf+pos, "0");
    }

    buf[pos] = '\0';

    return buf;
}

/*
 * 查表法, 在GF(2^8)内求 a 的逆元素
 * AES不可约多项式: p(x) = x^8 + x^4 + x^3 + x + 1
 *
 *    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
 * 0  00 01 8D F6 CB 52 7B D1 E8 4F 29 C0 B0 E1 E5 C7
 * 1  74 B4 AA 4B 99 2B 60 5F 58 3F FD CC FF 40 EE B2
 * 2  3A 6E 5A F1 55 4D A8 C9 C1 0A 98 15 30 44 A2 C2
 * 3  2C 45 92 6C F3 39 66 42 F2 35 20 6F 77 BB 59 19
 * 4  1D FE 37 67 2D 31 F5 69 A7 64 AB 13 54 25 E9 09
 * 5  ED 5C 05 CA 4C 24 87 BF 18 3E 22 F0 51 EC 61 17
 * 6  16 5E AF D3 49 A6 36 43 F4 47 91 DF 33 93 21 3B
 * 7  79 B7 97 85 10 B5 BA 3C B6 70 D0 06 A1 FA 81 82
 * 8  83 7E 7F 80 96 73 BE 56 9B 9E 95 D9 F7 02 B9 A4
 * 9  DE 6A 32 6D D8 8A 84 72 2A 14 9F 88 F9 DC 89 9A
 * A  FB 7C 2E C3 8F B8 65 48 26 C8 12 4A CE E7 D2 62
 * B  0C E0 1F EF 11 75 78 71 A5 8E 76 3D BD BC 86 57
 * C  0B 28 2F A3 DA D4 E4 0F A9 27 53 04 1B FC AC E6
 * D  7A 07 AE 63 C5 DB E2 EA 94 8B C4 D5 9D F8 90 6B
 * E  B1 0D D6 EB C6 0E CF AD 08 4E D7 E3 5D 50 1E B3
 * F  5B 23 38 34 68 46 03 8C DD 9C 7D A0 CD 1A 41 1C
 */
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

static unsigned char SBOX_PATTERN[8] =
{
    0xF1, /* 1111 0001 */
    0xE3, /* 1110 0011 */
    0xC7, /* 1100 0111 */
    0x8F, /* 1000 1111 */
    0x1F, /* 0001 1111 */
    0x3E, /* 0011 1110 */
    0x7C, /* 0111 1100 */
    0xF8, /* 1111 1000 */
};

#define SBOX_CONST 0x63

static unsigned char SBOX_INV_PATTERN[8] =
{
    0xA4, /* 1010 0100 */
    0x49, /* 0100 1001 */
    0x92, /* 1001 0010 */
    0x25, /* 0010 0101 */
    0x4A, /* 0100 1010 */
    0x94, /* 1001 0100 */
    0x29, /* 0010 1001 */
    0x52, /* 0101 0010 */
};

#define SBOX_INV_CONST 0x05

#define GET_BIT(data,i) (((data) >> (i)) & 0x01)

static unsigned char affine_transformation(unsigned char pat[8], unsigned char data, unsigned char C)
{
    int i, j;
    unsigned char x, y;

    x = 0;
    for (i=0; i<8; i++)
    {
        y = 0;
        for (j=0; j<8; j++)
        {
            // 1. get inner bit j and xor with previous inner bit
            y ^= GET_BIT(pat[i], j) & GET_BIT(data, j);
        }
        // 2. save outer bit i
        x |= y << i;
    }

    x ^= C;

    return x;
}

void show_sbox(unsigned int arr[256])
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

/*
 * 生成 AES S 盒
 */
void generate_aes_sbox(unsigned int *sbox)
{
    unsigned int i;

    /* 顺序填入 0~255 */
    for (i=0; i<256; i++)
    {
        sbox[i] = i;
    }

    /* 对 0~255 代表的多项式计算 GF(2^8) 的逆多项式 */
    for (i=0; i<256; i++)
    {
        sbox[i] = get_gf256_reverse(sbox[i], 0x11b);
    }

    /* 依次对所有逆元素执行仿射变换 */
    for (i=0; i<256; i++)
    {
        sbox[i] = affine_transformation(SBOX_PATTERN, sbox[i], SBOX_CONST);
    }
}

/*
 * 生成 AES 逆 S 盒
 */
void generate_aes_inv_sbox(unsigned int *inv_sbox)
{
    unsigned int i;

    /* 顺序填入 0~255 */
    for (i=0; i<256; i++)
    {
        inv_sbox[i] = i;
    }

    /* 依次对 0~255 执行逆仿射变换 */
    for (i=0; i<256; i++)
    {
        inv_sbox[i] = affine_transformation(SBOX_INV_PATTERN, inv_sbox[i], SBOX_INV_CONST);
    }

    /* 对逆仿射结果代表的多项式计算 GF(2^8) 的逆多项式 */
    for (i=0; i<256; i++)
    {
        inv_sbox[i] = get_gf256_reverse(inv_sbox[i], 0x11b);
    }
}

#if 1
void generate_gf256_reverse_matrix(void)
{
    unsigned int sbox[256];

    generate_aes_sbox(sbox);
    printf("SBox:\n");
    show_sbox(sbox);

    generate_aes_inv_sbox(sbox);
    printf("Inverse SBox:\n");
    show_sbox(sbox);
}
#else
void generate_gf256_reverse_matrix(void)
{
    unsigned int x, y;
    unsigned int arr[256], out[256], inv[256];

    /*
     * 生成 S 盒
     */
    for (x=0; x<256; x++)
    {
        arr[x] = x;
    }
    printf("Origin Table:\n");
    show_sbox(arr);

    // 生成 0~255 逆元
    for (x=0; x<256; x++)
    {
        arr[x] = get_gf256_reverse(x, 0x11b);
    }

    printf("GF(2^8) Inverse Table:\n");
    show_sbox(arr);

    // 对 0~255 逆元进行仿射变换
    for (x=0; x<256; x++)
    {
        out[x] = affine_transformation(SBOX_PATTERN, arr[x], SBOX_CONST);
    }

    printf("SBox:\n");
    show_sbox(out);

    /*
     * S 盒逆操作
     */
    // 对 S 盒进行逆仿射变换
    for (x=0; x<256; x++)
    {
        arr[x] = affine_transformation(SBOX_INV_PATTERN, out[x], SBOX_INV_CONST);
    }

    printf("After Inverse Transform:\n");
    show_sbox(arr);

    // 生成 0~255 逆元
    for (x=0; x<256; x++)
    {
        inv[x] = get_gf256_reverse(arr[x], 0x11b);
    }

    printf("GF(2^8) Origin Table:\n");
    show_sbox(inv);

    /*
     * 生成逆 S 盒
     */
    for (x=0; x<256; x++)
    {
        arr[x] = x;
    }

    // 对 S 盒进行逆仿射变换
    for (x=0; x<256; x++)
    {
        arr[x] = affine_transformation(SBOX_INV_PATTERN, arr[x], SBOX_INV_CONST);
    }

    // 生成 0~255 逆元
    for (x=0; x<256; x++)
    {
        arr[x] = get_gf256_reverse(arr[x], 0x11b);
    }

    printf("Inverse SBox:\n");
    show_sbox(arr);
}
#endif

void generate_gf8_table(void)
{
    int i, j;
    unsigned int arr[64];

    printf("  ");
    for (i=0; i<8; i++)
    {
        printf(" %d", i);
    }
    printf("\n");

    for (i=0; i<8; i++)
    {
        printf(" %d", i);
        for (j=0; j<8; j++)
        {
            arr[8*i + j] = gf256_mod(gf256_multi(i, j), 0x0b);
            printf(" %d", arr[8*i+j]);
        }
        printf("\n");
    }
}

void generate_gf8_polynomial_table(void)
{
    int i, j;
    unsigned int arr[64];

    printf("  ");
    for (i=0; i<8; i++)
    {
        printf(" %8d", i);
    }
    printf("\n");

    for (i=0; i<8; i++)
    {
        printf(" %d", i);
        for (j=0; j<8; j++)
        {
            arr[8*i + j] = gf256_mod(gf256_multi(i, j), 0x0b);
            printf(" %8s", get_polynomial(arr[8*i+j]));
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

    show_polynomial(0x57);
    show_polynomial(0x83);
    x = gf256_mod(gf256_multi(0x57, 0x83), 0x11b);
    show_polynomial(x);

    x = get_gf256_reverse(0x83, 0x11b);
    show_polynomial(x);

    x = get_msb1_pos(0x11);
    printf("highest bit: %d\n", x);

    x = get_msb1_pos(0x03);
    printf("highest bit: %d\n", x);

    x = get_msb1_pos(0xff);
    printf("highest bit: %d\n", x);

    x = get_msb1_pos(0xffffffff);
    printf("highest bit: %d\n", x);

    printf("GF(2^3): \n");
    generate_gf8_table();

    printf("GF(2^3) polynomial: \n");
    generate_gf8_polynomial_table();

    printf("%s\n", get_polynomial(0xff));

    return 0;
}