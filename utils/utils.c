#include <stdio.h>
#include "string.h"
#include "utils.h"

void dumphex(const char *tips, const void *data, int data_size, const char *indent, int line_size)
{
    int i;

    /* tips line */
    if ((NULL != tips) && (0 != strlen(tips)))
    {
        printf("%s%s\n", indent==NULL?"":indent, tips);
    }

    for (i=0; i<data_size; i++)
    {
        /* new line */
        if (i%line_size == 0)
        {
            printf("%s%s", i==0?"":"\n", indent==NULL?"":indent);
        }

        printf("%02x ", ((unsigned char *)data)[i]);
    }
    printf("\n");
}

void dump(const char *tips, const void *data, int size)
{
    dumphex(tips, data, size, NULL, 16);
}