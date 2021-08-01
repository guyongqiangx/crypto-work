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

static int bytes_to_msb_bits(uint8_t *data, int size, uint8_t *bits)
{
    int i, j;

    for (i=0; i<size; i++)
    {
        for (j=7; j>=0; j--)
        {
            *bits ++ = (data[i] >> j) & 0x01;
        }
    }

    return 0;
}

static int msb_bits_to_bytes(uint8_t *bits, int size, uint8_t *data)
{
    int i, j;
    uint8_t x;

    for (i=0; i<size; i+=8)
    {
        x = 0;
        for (j=0; j<8; j++)
        {
            x |= (bits[i+j] & 0x01) << (7-j);
        }
        *data ++ = x;
    }

    return 0;
}

static int data_permutation(uint8_t *bits, uint8_t bits_size, uint8_t *p, uint8_t p_size)
{
    int i;
    uint8_t temp[64];

    memcpy(temp, bits, bits_size);
    for (i=0; i<bits_size; i++)
    {
        bits[i] = temp[p[i]-1];
    }

    return 0;
}

static void show_msb_bits(uint8_t *bits, int size, char *tips)
{
    int i;
    uint8_t buf[16];

    printf("[raw]%20s", tips);
    for (i=0; i<size; i++)
    {
        printf("%d", bits[i]);
        if (i%8 == 7)
            printf(" ");
    }
    printf("\n");

    msb_bits_to_bytes(bits, size, buf);
    printf("[hex]%20s", tips);
    for (i = 0; i < size/8; i++)
    {
        printf ("%02x", buf[i]);
    }
    printf("\n");

    printf("\n");
}

int main(int argc, char *argv[])
{
    int i;
    uint8_t  data[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    uint8_t data2[8] = {0x75, 0xe8, 0xfd, 0x8f, 0x25, 0x89, 0x64, 0x90};
    uint8_t bits[64];
    uint8_t temp[8];

    printf("data: ");
    for (i=0; i<sizeof(data); i++)
    {
        printf("0x%02x ", data[i]);
    }
    printf("\n");

    bytes_to_msb_bits(data, 8, bits);
    show_msb_bits(bits, 64, "1: ");

    data_permutation(bits, 64, IP, 64);
    show_msb_bits(bits, 64, "after permute: ");

    data_permutation(bits, 64, RIP, 64);
    show_msb_bits(bits, 64, "reverse permute: ");

    msb_bits_to_bytes(bits, 64, temp);
    printf("[hex]%10s: ", "bytes");
    for (i=0; i<8; i++)
    {
        printf("0x%02x ", temp[i]);
    }
    printf("\n");

    bytes_to_msb_bits(data2, 8, bits);
    show_msb_bits(bits, 64, "origin: ");
    data_permutation(bits, 64, RIP, 64);
    show_msb_bits(bits, 64, "permute: ");

    return 0;
}