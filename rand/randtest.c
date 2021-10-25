#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "rand.h"

/*
 * cc randtest.c rand.c -o randtest -I/public/ygu/cryptography/crypto-work.git/out/include
 */
int main(int argc, char *argv[])
{
    int i, j, count;
    char buf[1024];
    time_t t;

    /* 初始化随机数发生器 */
    srand((unsigned) time(&t));

    memset(buf, 0, 1024);

    for (j=0; j<10; j++)
    {
        count = rand() % 32;

        Get_Random_Bytes(buf, count);

        printf("%d: %3d bytes ", j, count);
        for (i=0; i<count; i++)
        {
            printf("%02x", ((unsigned char *)buf)[i]);
        }
        printf("\n");

        system("sleep 1");
    }

    return 0;
}