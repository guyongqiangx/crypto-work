#include <stdio.h>
#include <string.h>
#include "utils.h"
#include "base64.h"

/*
 * The Base64 index table: https://en.wikipedia.org/wiki/Base64
 *
 * Index   Binary      Char    Index   Binary      Char    Index   Binary      Char    Index   Binary      Char
 * 0       000000      A       16      010000      Q       32      100000      g       48      110000      w
 * 1       000001      B       17      010001      R       33      100001      h       49      110001      x
 * 2       000010      C       18      010010      S       34      100010      i       50      110010      y
 * 3       000011      D       19      010011      T       35      100011      j       51      110011      z
 * 4       000100      E       20      010100      U       36      100100      k       52      110100      0
 * 5       000101      F       21      010101      V       37      100101      l       53      110101      1
 * 6       000110      G       22      010110      W       38      100110      m       54      110110      2
 * 7       000111      H       23      010111      X       39      100111      n       55      110111      3
 * 8       001000      I       24      011000      Y       40      101000      o       56      111000      4
 * 9       001001      J       25      011001      Z       41      101001      p       57      111001      5
 * 10      001010      K       26      011010      a       42      101010      q       58      111010      6
 * 11      001011      L       27      011011      b       43      101011      r       59      111011      7
 * 12      001100      M       28      011100      c       44      101100      s       60      111100      8
 * 13      001101      N       29      011101      d       45      101101      t       61      111101      9
 * 14      001110      O       30      011110      e       46      101110      u       62      111110      +
 * 15      001111      P       31      011111      f       47      101111      v       63      111111      /
 * Padding =
 */

static char CharCode[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
};

static unsigned char Padding = '=';

/*
 * Setup Look Up Table for Base64 chars:
 * static void Fill_HexCode(void)
 * {
 *     int i;
 *
 *     for (i=0; i<64; i++)
 *     {
 *         HexCode[CharCode[i]] = i;
 *     }
 * }
 */
static unsigned char HexCode[128] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/*
 * Encoding: 3 bytes (24 bits) to 4 chars (24 bits)
 * 1. "Man" --> "TWFu";
 * 2. "Ma"  --> "TWE=";
 * 3. "M"   --> "TQ==";
 */
static void h2s(const unsigned char *hex, int len, char *out)
{
    switch(len)
    {
    case 3:
        out[0] = CharCode[(hex[0] >> 2) & 0x3f];
        out[1] = CharCode[((hex[0] & 0x03) << 4) | ((hex[1] & 0xf0) >> 4) ];
        out[2] = CharCode[((hex[1] & 0x0f) << 2) | ((hex[2] >> 6) & 0x03)];
        out[3] = CharCode[hex[2] & 0x3f];
        break;
    case 2:
        out[0] = CharCode[(hex[0] >> 2) & 0x3f];
        out[1] = CharCode[((hex[0] & 0x03) << 4) | ((hex[1] & 0xf0) >> 4) ];
        out[2] = CharCode[((hex[1] & 0x0f) << 2)];
        out[3] = Padding;
        break;
    case 1:
        out[0] = CharCode[(hex[0] >> 2) & 0x3f];
        out[1] = CharCode[((hex[0] & 0x03) << 4)];
        out[2] = Padding;
        out[3] = Padding;
        break;
    }
}

#define H(i) HexCode[str[i]]

/*
 * Decoding: 4 chars (24 bits) --> 3 bytes (24 bits)
 * 1. "TWFu" --> "Man";
 * 2. "TWE=" --> "Ma" ;
 * 3. "TQ==" --> "M"  ;
 */
static void s2h(const unsigned char *str, unsigned char *out, int *len)
{
    int count;

    count = 3;
    if (str[3] == '=')
    {
        count --;
    }
    if (str[2] == '=')
    {
        count --;
    }

    switch (count)
    {
    case 3:
        out[0] = ( H(0) << 2)         | ((H(1) >> 4) & 0x03);
        out[1] = ((H(1) & 0x0f) << 4) | ((H(2) & 0x3c) >> 2);
        out[2] = ((H(2) & 0x03) << 6) |   H(3);
        break;
    case 2:
        out[0] = ( H(0) << 2)         | ((H(1) >> 4) & 0x03);
        out[1] = ((H(1) & 0x0f) << 4) | ((H(2) & 0x3c) >> 2);
        break;
    case 1:
        out[0] = ( H(0) << 2)         | ((H(1) >> 4) & 0x03);
        break;
    }

    *len = count;
}

/*
 * 3 bytes (3 x 8 bits = 24 bits) --> 4 chars (4 x 6 bits)
 */
int Base64Encode(const unsigned char *data, int data_len, char *out, int *out_len)
{
    *out_len = 0;

    while (data_len >= 3)
    {
        h2s(data, 3, out);
        out += 4;
        *out_len += 4;

        data += 3;
        data_len -= 3;
    }

    if (data_len != 0)
    {
        h2s(data, data_len, out);
        *out_len += 4;
    }

    return *out_len;
}

int Base64Decode(const char *str, int str_len, unsigned char *out, int *out_len)
{
    int count;

    *out_len = 0;

    /*
     * 理论上，正常的 Base64 解码字符串长度应该为 4 字符的整数倍
     * 如果不是 4 字符整数倍，则只处理 4 字符整数倍的部分，其余丢弃
     */

    /*
     * 按照 4 字符一个单元进行处理
     */
    while (str_len >= 4)
    {
        s2h(str, out, &count);
        out += count;
        *out_len += count;

        str += 4;
        str_len -= 4;
    }

    return *out_len;
}

/*
 * $ gcc base64.c -I../out/include -L../out/lib -lutils -o base64
 */
int main(int argc, char *argv[])
{
    //unsigned char data[] = {
    //    0x62, 0x61, 0x73, 0x65, 0x36, 0x34, 0x2e, 0x63
    //};
    unsigned char data[27] = "Many hands make light work.";
    unsigned char result[] = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu";

    char buf[128], dec[128];
    int len, count;

    printf("Origin: %s\n", data);

    memset(buf, 0, sizeof(buf));
    Base64Encode(data, sizeof(data), buf, &len);

    printf("Expect: %s\n", result);
    printf("Encode: %s\n", buf);

    Base64Decode(result, strlen(result), dec, &count);
    dump("Decode: ", dec, count);

    {
        int i;
        unsigned char *temp[] = {
            "light work.",
            "light work",
            "light wor",
            "light wo",
            "light w"
        };
        unsigned char *expect[] = {
            "bGlnaHQgd29yay4=",
            "bGlnaHQgd29yaw==",
            "bGlnaHQgd29y",
            "bGlnaHQgd28=",
            "bGlnaHQgdw==",
        };
        printf("\n");
        for (i=0; i<sizeof(temp)/sizeof(temp[0]); i++)
        {
            printf("Origin: %s\n", temp[i]);

            memset(buf, 0, sizeof(buf));
            Base64Encode(temp[i], strlen(temp[i]), buf, &len);

            printf("Expect: %s\n", expect[i]);   
            printf("Encode: %s\n", buf);

            Base64Decode(buf, len, dec, &count);
            dump("Decode: ", dec, count);
        }
    }

    return 0;
}