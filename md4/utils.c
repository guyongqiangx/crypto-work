#include <stdio.h>
#include "utils.h"

/* LE: unsigned long to 4 bytes unsigned char */
int htole32c(unsigned char *data, unsigned long x)
{
    *data ++ = (unsigned char)( x     &0xff);
    *data ++ = (unsigned char)((x>> 8)&0xff);
    *data ++ = (unsigned char)((x>>16)&0xff);
    *data    = (unsigned char)((x>>24)&0xff);

    return 0;
}

/* LE: 4 bytes unsigned char to unsigned long */
unsigned long le32ctoh(const unsigned char *data)
{
    unsigned long x;

    x =  (unsigned long)data[0]
      | ((unsigned long)data[1] <<  8)
      | ((unsigned long)data[2] << 16)
      | ((unsigned long)data[3] << 24);

    return x;
}

/* LE: unsigned long long to 8 bytes unsigned char */
int htole64c(unsigned char *data, unsigned long long x)
{
    *data    = (unsigned char)( x	  &0xff);
    *data ++ = (unsigned char)((x>> 8)&0xff);
    *data ++ = (unsigned char)((x>>16)&0xff);
    *data ++ = (unsigned char)((x>>24)&0xff);
    *data ++ = (unsigned char)((x>>32)&0xff);
    *data ++ = (unsigned char)((x>>40)&0xff);
    *data ++ = (unsigned char)((x>>48)&0xff);
    *data    = (unsigned char)((x>>56)&0xff);

    return 0;
}

/* BE: unsigned long to 4 bytes unsigned char */
int htobe32c(unsigned char *data, unsigned long x)
{
    *data ++ = (unsigned char)((x>>24)&0xff);
    *data ++ = (unsigned char)((x>>16)&0xff);
    *data ++ = (unsigned char)((x>> 8)&0xff);
    *data    = (unsigned char)( x     &0xff);

    return 0;
}

/* BE: unsigned long long to 8 bytes unsigned char */
int htobe64c(unsigned char *data, unsigned long long x)
{
    *data ++ = (unsigned char)((x>>56)&0xff);
    *data ++ = (unsigned char)((x>>48)&0xff);
    *data ++ = (unsigned char)((x>>40)&0xff);
    *data ++ = (unsigned char)((x>>32)&0xff);
    *data ++ = (unsigned char)((x>>24)&0xff);
    *data ++ = (unsigned char)((x>>16)&0xff);
    *data ++ = (unsigned char)((x>> 8)&0xff);
    *data    = (unsigned char)( x	  &0xff);

    return 0;
}

/* BE: 8 bytes unsigned char to unsigned long long */
unsigned long long be64ctoh(const unsigned char *data)
{
    unsigned long long x;

    x = ((unsigned long long)data[0] << 56)
      | ((unsigned long long)data[1] << 48)
      | ((unsigned long long)data[2] << 40)
      | ((unsigned long long)data[3] << 32)
      | ((unsigned long long)data[4] << 24)
      | ((unsigned long long)data[5] << 16)
      | ((unsigned long long)data[6] <<  8)
      |  (unsigned long long)data[7];

    return x;
}

#define DUMP_LINE_SIZE 16
int print_buffer(const void *buf, unsigned long len, const char *indent)
{
    unsigned long i = 0;
    for (i=0; i<len; i++)
    {
        if (i%DUMP_LINE_SIZE == 0)
        {
            printf("%s%04lX:", indent, i);
        }

        printf(" %02x", ((unsigned char *)buf)[i]);

        if (i%DUMP_LINE_SIZE == (DUMP_LINE_SIZE-1)) /* end of line */
        {
            printf("\n");
        }
        else if (i==(len-1)) /* last one */
        {
            printf("\n");
        }
    }

    return 0;
}
