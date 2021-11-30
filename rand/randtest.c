#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "rand.h"

/*
 * cc randtest.c rand.c -o randtest -I../out/include
 */
int main(int argc, char *argv[])
{
    int i, j, count;
    char buf[1024];
    time_t t;

    /* 初始化随机数发生器 */
    srand((unsigned) time(&t));

    memset(buf, 0, 1024);

    printf("Random bytes test: \n");
    for (j=0; j<10; j++)
    {
        count = rand() % 32;
        while (count == 0)
        {
            count = rand() % 32;
        }

        Get_Random_Bytes(buf, count);

        printf("\n%2d: %3d bytes\n", j, count);
        for (i=0; i<count; i++)
        {
            printf("%02x ", ((unsigned char *)buf)[i]);
            if (i % 16 == 15)
            {
                printf("\n");
            }
        }
        printf("\n");

        system("sleep 1");
    }

    printf("Random nonzero bytes test: \n");
    for (j=0; j<30; j++)
    {
        count = rand() % 32;
        while (count == 0)
        {
            count = rand() % 32;
        }

        Get_Random_NonZero_Bytes(buf, count);

        printf("\n%2d: %3d bytes\n", j, count);
        for (i=0; i<count; i++)
        {
            printf("%02x ", ((unsigned char *)buf)[i]);
            if (i % 16 == 15)
            {
                printf("\n");
            }
        }
        printf("\n");

        system("sleep 1");
    }

    return 0;
}