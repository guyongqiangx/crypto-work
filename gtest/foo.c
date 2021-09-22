#include "foo.h"

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

int Factorial(int n)
{
    int i, res;

    res = 1;
    for (i=n; i>0; i--)
    {
        res *= i;
    }

    return res;
}