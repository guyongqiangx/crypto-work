#include <stdio.h>
#include "utils.h"

void dumphex(const void *data, int data_size, const char *tips, const char *indent, int line_size)
{
    int i;

    printf("%s%s", tips==NULL?"":(indent==NULL?"":indent), tips==NULL?"":tips);
    for (i=0; i<data_size; i++)
    {
        if (i%line_size == 0)
        {
            printf("\n%s", indent==NULL?"":indent);
        }

        printf("%02x ", ((unsigned char *)data)[i]);
    }
    printf("\n");
}

void dump(const void *data, int size, const char *tips)
{
    dumphex(data, size, tips, NULL, 16);
}