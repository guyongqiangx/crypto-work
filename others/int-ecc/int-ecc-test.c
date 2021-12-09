#include <stdio.h>
#include "int-ecc.h"

int main(int argc, char *argv)
{
    int p, a, b;
    struct point p1, p2, p3, p4;
    int i, order;
    unsigned long n;

    /*
     * 深入浅出密码学, p232
     * Elliptic Curve: y^2 = x^3 + 2x + 2 mod 17
     * Base Point (5, 1)
     */
    printf("Elliptic Curve: y^2 = x^3 + 2x + 2 mod 17, Base Point (5, 1)\n");
    p = 17; a = 2; b = 2;
    p1.x = 5; p1.y = 1;

    order = ecc_point_order(p, a, b, &p1);
    printf("Order P(%d, %d) = %d\n", p1.x, p1.y, order);

    ecc_point_show_group(p, a, b, &p1);

    /*
     * 深入浅出密码学, p242, Q9.5
     * Elliptic Curve: y^2 = x^3 + 3x + 2 mod 7
     * Base Point (2, 4)
     */
    printf("Elliptic Curve: y^2 = x^3 + 3x + 2 mod 7, Base Point (2, 4)\n");
    p = 7; a = 3; b = 2;
    p1.x = 0;
    p1.y = 3;

    order = ecc_point_order(p, a, b, &p1);
    printf("Order P(%d, %d) = %d\n", p1.x, p1.y, order);

    ecc_point_show_group(p, a, b, &p1);

    /*
     * 深入浅出密码学, p242, Q9.7
     * Elliptic Curve: y^2 = x^3 + 4x + 20 mod 29
     * Base Point (8, 10)
     */
    printf("Elliptic Curve: y^2 = x^3 + 4x + 20 mod 29, Base Point (8, 10)\n");
    p = 29; a = 4; b = 20;
    p1.x = 8;
    p1.y = 10;

    order = ecc_point_order(p, a, b, &p1);
    printf("Order P(%d, %d) = %d\n", p1.x, p1.y, order);

    ecc_point_show_group(p, a, b, &p1);

    /*
     * 深入浅出密码学, p243, Q9.9
     * Elliptic Curve: y^2 = x^3 + x + 6 mod 11
     * Base Point (5, 9)
     */
    printf("Elliptic Curve: y^2 = x^3 + x + 6 mod 11, Base Point (5, 9)\n");
    p = 11; a = 1; b = 6;
    p1.x = 5;
    p1.y = 9;

    order = ecc_point_order(p, a, b, &p1);
    printf("Order P(%d, %d) = %d\n", p1.x, p1.y, order);

    ecc_point_show_group(p, a, b, &p1);

    /*
     * 密码编码学与网络安全, 7th, section 10.4, p226
     * Elliptic Curve: y^2 = x^3 + 9x + 17 mod 23
     * Base Point (9, 17)
     */
    printf("Elliptic Curve: y^2 = x^3 + 9x + 17 mod 23, Base Point (16, 5)\n");
    p = 23; a = 9; b = 17;
    p1.x = 16;
    p1.y = 5;

    order = ecc_point_order(p, a, b, &p1);
    printf("Order P(%d, %d) = %d\n", p1.x, p1.y, order);

    ecc_point_show_group(p, a, b, &p1);

    /*
     * 密码编码学与网络安全, 7th, section 10.4.1, p227
     * Elliptic Curve: y^2 = x^3 - 4 mod 211
     * Base Point (2, 2)
     */
    printf("Elliptic Curve: Elliptic Curve: y^2 = x^3 - 4 mod 211, Base Point (2, 2)\n");
    p = 211; a = 0; b = -4;
    p1.x = 2;
    p1.y = 2;

    order = ecc_point_order(p, a, b, &p1);
    printf("Order P(%d, %d) = %d\n", p1.x, p1.y, order);

    ecc_point_show_group(p, a, b, &p1);

    printf("Point Multiple Test:\n");
    n = 20;
    ecc_point_mul(p, a, n, &p1, &p4);
    printf("%4luP(%4d, %4d)\n", n, p4.x, p4.y);

    n = 200;
    ecc_point_mul(p, a, n, &p1, &p4);
    printf("%4luP(%4d, %4d)\n", n, p4.x, p4.y);

    n = 240;
    ecc_point_mul(p, a, n, &p1, &p4);
    printf("%4luP(%4d, %4d)\n", n, p4.x, p4.y);
    return 0;
}