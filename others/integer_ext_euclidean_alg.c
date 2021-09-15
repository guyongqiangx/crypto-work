#include <stdio.h>

/*
 * 示例:
 * gcd(3, 0) = 3
 * gcd(0, 3) = gcd(3, 0) = 3
 * gcd(50, 30) = gcd(30, 20) = gcd(20, 10) = gcd(10, 0) = 10
 * gcd(30, 50) = gcd(50, 30) = ...
 */
int gcd(int a, int b)
{
    if (b == 0)
    {
        return a;
    }
    else
    {
        return gcd(b, a % b);
    }
}

int gcdx(int a, int b)
{
    int t;

    while (b != 0)
    {
        t = a % b;
        a = b;
        b = t;
    }

    return a;
}

/*
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

    q = a / b;
    r = a % b;

    while (r != 0)
    {
        /* 计算当前项 x/y */
        x = x0 - q * x1;
        y = y0 - q * y1;

        /* 依次保存前两项到 x0/y0, x1/y1 */
        x0 = x1; x1 = x;
        y0 = y1; y1 = y;

        a = b;
        b = r;

        q = a / b;
        r = a % b;
    }

    *ia = x;
    *ib = y;

    return x;
}

/* ax + by = 1 mod b */
int multi_inverse(int a, int b)
{
    int ia, ib;

    ext_euclidean(a, b, &ia, &ib);
    if (ia < 0)
    {
        ia += b;
    }

    return ia;
}

int main(int argc, char *argv[])
{
    int x;
    int ia, ib;

    x = gcd(33, 18);
    printf("gcd(33,18)=%d\n", x);

    x = gcd(100, 29);
    printf("gcd(100,29)=%d\n", x);

    x = gcdx(33, 18);
    printf("gcdx(33,18)=%d\n", x);

    x = gcdx(18, 33);
    printf("gcdx(18,33)=%d\n", x);

    x = gcdx(100, 29);
    printf("gcdx(100,29)=%d\n", x);

    x = gcdx(29, 100);
    printf("gcdx(29,100)=%d\n", x);

    x = gcdx(50, 30);
    printf("gcdx(50,30)=%d\n", x);

    x = gcdx(1759, 550);
    printf("gcdx(1759,550)=%d\n", x);

    ext_euclidean(1759, 550, &ia, &ib);
    printf("ext_euclidian(1759, 550) = (%d, %d)\n", ia, ib);
    printf("%d x (%d) + %d x (%d) = %d\n", 1759,  ia, 550, ib, 1759 * ia + 550 * ib);

    x = multi_inverse(1759, 550);
    printf("multi_inverse(1759, 550) = %d\n", x);

    x = multi_inverse(550, 1759);
    printf("multi_inverse(550, 1759) = %d\n", x);

    return 0;
}