/*
 * @        file: 
 * @ description: 
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>

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

int main(int argc, char *argv)
{
    printf("gcd(%d, %d) = %d\n", 52, 76, gcd(52, 76));
    printf("gcd(%d, %d) = %d\n", 243, 77, gcd(243, 77));
    printf("invers(%d, %d) = %d\n", 243, 77, inverse(243, 77));
    printf("invers(%d, %d) = %d\n", 1759, 550, inverse(1759, 550));

    return 0;
}