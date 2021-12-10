#include <stdio.h>
#include "int-ecc.h"

/*
 * gcc int-ecc.c int-ecc-test.c -o int-ecc
 */
int main(int argc, char *argv)
{
    struct ec_param param;
    struct point p1, p2, p3, p4;
    int i, n, order;

    /*
     * 深入浅出密码学, p232
     * Elliptic Curve: y^2 = x^3 + 2x + 2 mod 17
     * Base Point (5, 1)
     */
    printf("Elliptic Curve: y^2 = x^3 + 2x + 2 mod 17, Base Point (5, 1)\n");
    param.p = 17; param.a = 2; param.b = 2;
    p1.x = 5; p1.y = 1;

    order = ec_point_order(&param, &p1);
    printf("Order P(%d, %d) = %d\n", p1.x, p1.y, order);

    ec_point_show_group(&param, &p1);

    /*
     * 深入浅出密码学, p242, Q9.5
     * Elliptic Curve: y^2 = x^3 + 3x + 2 mod 7
     * Base Point (2, 4)
     */
    printf("Elliptic Curve: y^2 = x^3 + 3x + 2 mod 7, Base Point (2, 4)\n");
    param.p = 7; param.a = 3; param.b = 2;
    p1.x = 0; p1.y = 3;

    order = ec_point_order(&param, &p1);
    printf("Order P(%d, %d) = %d\n", p1.x, p1.y, order);

    ec_point_show_group(&param, &p1);

    /*
     * 深入浅出密码学, p242, Q9.7
     * Elliptic Curve: y^2 = x^3 + 4x + 20 mod 29
     * Base Point (8, 10)
     */
    printf("Elliptic Curve: y^2 = x^3 + 4x + 20 mod 29, Base Point (8, 10)\n");
    param.p = 29; param.a = 24; param.b = 20;
    p1.x = 8; p1.y = 10;

    order = ec_point_order(&param, &p1);
    printf("Order P(%d, %d) = %d\n", p1.x, p1.y, order);

    ec_point_show_group(&param, &p1);

    /*
     * 深入浅出密码学, p243, Q9.9
     * Elliptic Curve: y^2 = x^3 + x + 6 mod 11
     * Base Point (5, 9)
     */
    printf("Elliptic Curve: y^2 = x^3 + x + 6 mod 11, Base Point (5, 9)\n");
    param.p = 11; param.a = 1; param.b = 6;
    p1.x = 5; p1.y = 9;

    order = ec_point_order(&param, &p1);
    printf("Order P(%d, %d) = %d\n", p1.x, p1.y, order);

    ec_point_show_group(&param, &p1);

    /*
     * 密码编码学与网络安全, 7th, section 10.4, p226
     * Elliptic Curve: y^2 = x^3 + 9x + 17 mod 23
     * Base Point (9, 17)
     */
    printf("Elliptic Curve: y^2 = x^3 + 9x + 17 mod 23, Base Point (16, 5)\n");
    param.p = 23; param.a = 9; param.b = 17;
    p1.x = 16; p1.y = 5;

    order = ec_point_order(&param, &p1);
    printf("Order P(%d, %d) = %d\n", p1.x, p1.y, order);

    ec_point_show_group(&param, &p1);

    /*
     * 密码编码学与网络安全, 7th, section 10.4.1, p227
     * Elliptic Curve: y^2 = x^3 - 4 mod 211
     * Base Point (2, 2)
     */
    printf("Elliptic Curve: Elliptic Curve: y^2 = x^3 - 4 mod 211, Base Point (2, 2)\n");
    param.p = 211; param.a = 0; param.b = -4;
    p1.x = 2; p1.y = 2;

    order = ec_point_order(&param, &p1);
    printf("Order P(%d, %d) = %d\n", p1.x, p1.y, order);

    ec_point_show_group(&param, &p1);

    printf("Point Multiple Test:\n");
    n = 20;
    ec_point_mul(&param, n, &p1, &p4);
    printf("%4dP(%4d, %4d)\n", n, p4.x, p4.y);

    n = 200;
    ec_point_mul(&param, n, &p1, &p4);
    printf("%4dP(%4d, %4d)\n", n, p4.x, p4.y);

    n = 240;
    ec_point_mul(&param, n, &p1, &p4);
    printf("%4dP(%4d, %4d)\n", n, p4.x, p4.y);
    return 0;
}