#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Initial Permutation Table */
static uint8_t IP[64] =
{
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
};

/* Reverse of Initial Permutation Table */
/* // offset of array IP and RIP starts from 0 to 63,
 * // but value in IP and RIP starts from 1 to 64,
 * // so need to convert value and offset
 *  for (i=0; i<64; i++)
 *  {
 *      j = IP[i]-1;    // convert value to offset
 *      RIP[j] = i+1;   // convert offset to value
 *  }
 */
static uint8_t RIP[64] =
{
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
};

static int data_to_bits(uint8_t data[8], uint8_t bits[64])
{
    uint64_t x;
    int i;

    x = *(uint64_t *)data;
    for (i=0; i<64; i++)
    {
        bits[i] = (uint8_t)(x >> i & 0x01);
    }
    return 0;
}

static int data_permutation(uint8_t data[64], uint8_t p[64])
{
    int i, j;
    uint8_t temp[64];

    memcpy(temp, data, sizeof(temp));
    for (i=0; i<64; i++)
    {
        data[i] = temp[p[i]-1];
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int i;
    uint8_t data[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    uint8_t bits[64];

    printf("data: ");
    for (i=0; i<sizeof(data); i++)
    {
        printf("0x%02x ", data[i]);
    }
    printf("\n");

    data_to_bits(data, bits);
    printf("bits: ");
    for (i=0; i<64; i++)
    {
        printf("%d", bits[i]);
        if (i%8 == 7)
            printf(" ");
    }
    return 0;
}