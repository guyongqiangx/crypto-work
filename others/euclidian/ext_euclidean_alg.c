/*
 * @        file: 
 * @ description: 
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <stdint.h>

int gcd(int a, int b)
{
    if (b == 0)
    {
        return a;
    }
    else
    {
        return gcd(b, a%b);
    }
}

int inverse(int a, int b)
{
    int q, r;
    int x2, y2, x1, y1, x, y;
    int temp;

    x2 = 1; y2 = 0;
    x1 = 0; y1 = 1;

    q = a / b;
    r = a % b;

    while (r != 0)
    {
        x = x2 - x1 * q;
        y = y2 - y1 * q;

        x2 = x1; y2 = y1;
        x1 = x;  y1 = y;

        a = b;
        b = r;

        q = a / b;
        r = a % b;
    }

    return y;
}

/* a x b mod m(x) */
uint8_t polonomial_xtime(uint8_t a, uint8_t b)
{
    uint8_t m, res;

    m = a;
    res = 0;
    while (b != 0)
    {
        if (b & 0x01)
        {
            if (0 == res)
            {
                res = m;
            }
            else
            {
                res ^= m;
            }
        }
        if (m & 0x80)   /* b7=1 */
        {
            m = (m << 1) ^ 0x1B; /* 0x1B = b00011011, m(x) = x4 + x3 + x + 1 */
        }
        else            /* b7=0 */
        {
            m <<= 1;
        }
        b >>= 1;
    }

    return res;
}

int main(int argc, char *argv)
{
    printf("gcd(%d, %d) = %d\n", 52, 76, gcd(52, 76));
    printf("gcd(%d, %d) = %d\n", 243, 77, gcd(243, 77));
    printf("invers(%d, %d) = %d\n", 243, 77, inverse(243, 77));
    printf("invers(%d, %d) = %d\n", 1759, 550, inverse(1759, 550));

    printf("xtime(0x%02x, 0x%02x) = 0x%02x\n", 0x57, 0x83, polonomial_xtime(0x57, 0x83));

    return 0;
}