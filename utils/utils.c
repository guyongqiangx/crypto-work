#include <stdio.h>
#include "string.h"
#include "utils.h"

/**
 * @description: Dump hex data from an array
 * @param {char}    *tips, tips at the first line of output
 * @param {void}    *data, binary data to be dump out
 * @param {int} data_size, binary data size to be dump out
 * @param {char}  *indent, indent size for each line
 * @param {int} line_size, line size for each line
 * @return {*}           , no return
 */
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

/**
 * @description: Dump hex data from an array, same as dumphex with no indent and line size 16
 * @param {char}    *tips, tips at the first line of output
 * @param {void}    *data, binary data to be dump out
 * @param {int} data_size, binary data size to be dump out
 * @return {*}           , no return
 */
void dump(const char *tips, const void *data, int data_size)
{
    dumphex(tips, data, data_size, NULL, 16);
}

static int char2oct(char ch)
{
    if (('a' <= ch) && (ch <= 'f'))
    {
        return 10 + ch - 'a';
    }

    if (('A' <= ch) && (ch <= 'F'))
    {
        return 10 + ch - 'A';
    }

    if (('0' <= ch) && (ch <= '9'))
    {
        return ch - '0';
    }

    return -1;
}

/**
 * @description: Convert hexdecimal string to bytes array
 * @param {char}           *str, hexdecimal string, like: "1234567890"
 * @param {unsigned char} *data, data array to store the out put
 * @param {int}            size, output data array size
 * @param {int}         padding, if padding=1, then fill 0x00 before the output data to get the total size bytes
 * @return {*}
 */
int str2bytes(const char *str, unsigned char *data, int size, int padding)
{
    size_t len, padding_len;
    int count;
    unsigned char *p;

    /* check parameters */
    if ((NULL == str) || (NULL == data) || (0 == size))
    {
        return -1;
    }

    len = strlen(str);
    /* string is too long */
    if ((len + 1) / 2 > size)
    {
        return -1;
    }

    count = 0;
    p = data;
    if (padding)
    {
        padding_len = size - (len + 1) / 2;
        while (padding_len--)
        {
            *p ++ = 0x00;
            count ++;
        }
    }

    /* odd chars, need to add one 0-prefix, like: '123'->'0123'->0x0123 */
    if (len%2)
    {
        *p ++ = char2oct(*str++);
        count ++;
    }

    while (*str)
    {
        *p++ = (char2oct(*str) << 4) | char2oct(*(str+1));
        str += 2;
        count ++;
    }

    return count;
}