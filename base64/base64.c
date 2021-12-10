#include <stdio.h>
#include <string.h>
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

static unsigned char HexCode[] = {

};

static void h2s(const unsigned char *hex, int len, char *out)
{
    //printf("[%02x-%02x-%02x-%02x]->", hex[0], hex[1], hex[2], hex[3]);
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
    //printf("%c%c%c%c[%02x-%02x-%02x-%02x]\n", out[0], out[1], out[2], out[3], out[0], out[1], out[2], out[3]);
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

int main(int argc, char *argv[])
{
    //unsigned char data[] = {
    //    0x62, 0x61, 0x73, 0x65, 0x36, 0x34, 0x2e, 0x63
    //};
    unsigned char data[27] = "Many hands make light work.";
    unsigned char result[] = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu";

    char buf[512];
    int len;

    memset(buf, 0, sizeof(buf));

    Base64Encode(data, sizeof(data), buf, &len);

    printf("Expect: %s\n", result);
    printf("Encode: %s\n", buf);

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
            memset(buf, 0, sizeof(buf));
            Base64Encode(temp[i], strlen(temp[i]), buf, &len);
            printf("Expect: %s\n", expect[i]);   
            printf("Encode: %s\n", buf);
        }

    }

    return 0;
}