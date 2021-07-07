/*
 * @        file: des.c
 * @ description: implementation for the Data Encryption Standard
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "des.h"

//#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#define DUMP_BLOCK_DATA 1
#define DUMP_BLOCK_HASH 1
#define DUMP_ROUND_DATA 1
#else
#define DBG(...)
#define DUMP_BLOCK_DATA 0
#define DUMP_BLOCK_HASH 0
#define DUMP_ROUND_DATA 0
#endif

#define DES_KEY_SIZE            8
#define DES_BLOCK_SIZE          8

#define DES_ROUND_NUM           16

#if 0
static void swap_bytes(uint8_t *data, int size)
{
    uint8_t x;
    int i;
    for (i=0; i<size/2; i++)
    {
        x = data[i];
        data[i] = data[size-1-i];
        data[size-1-i] = x;
    }

    return;
}
#endif

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

    return ERR_OK;
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

    return ERR_OK;
}

static int print_hex(unsigned char *data, uint32_t len, const char *tips)
{
    uint32_t i;

    printf("%15s[hex]", tips);
    for (i = 0; i < len; i++)
    {
        printf ("%02x", data[i]);
    }
    printf("\n");

    return 0;
}

static void show_bits_group(uint8_t *bits, int size, int group, char *tips)
{
    int i;

    printf("%15s[bin]", tips);
    for (i=0; i<size; i++)
    {
        printf("%d", bits[i]);
        if ((i%group == (group-1)) && (i != size-1))
            printf(" ");
    }
    printf("\n");
}

static void show_msb_bits(uint8_t *bits, int size, char *tips)
{
    int i;
    uint8_t buf[16];

    show_bits_group(bits, size, 8, tips);

    msb_bits_to_bytes(bits, size, buf);
    print_hex(buf, size/8, tips);

    printf("\n");
}

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

/* E BIT-SELECTION TABLE */
static uint8_t E[48] =
{
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
};

static uint8_t S1[64] =
{
    14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
     0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
     4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
};

static uint8_t S2[64] =
{
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
     3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
     0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
};

static uint8_t S3[64] =
{
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
     1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
};

static uint8_t S4[64] =
{
     7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
     3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
};

static uint8_t S5[64] =
{
     2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
     4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
};

static uint8_t S6[64] =
{
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
     9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
     4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
};

static uint8_t S7[64] =
{
     4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
     1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
     6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
};

static uint8_t S8[64] =
{
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
     1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
     7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
     2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11,
};

static uint8_t *SBox[8] =
{
    S1, S2, S3, S4, S5, S6, S7, S8
};

static uint8_t P[32] =
{
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25,
};

/* Key Permute Choice 1 */
static uint8_t PC1[56] =
{
    57, 49, 41, 33, 25, 17,  9,  1,
    58, 50, 42, 34, 26, 18, 10,  2,
    59, 51, 43, 35, 27, 19, 11,  3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15,  7, 62, 54, 46, 38,
    30, 22, 14,  6, 61, 53, 45, 37,
    29, 21, 13,  5, 28, 20, 12,  4,
};

/* Key Permute Choice 2 */
static uint8_t PC2[48] =
{
    14, 17, 11, 24,  1,  5,  3, 28,
    15,  6, 21, 10, 23, 19, 12,  4,
    26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32,
};

/*
 * |--------------------------------------------------------------------------------------------|
 * | round      | 1  | 2  | 3  | 4  | 5  | 6  | 7  | 8  | 9  | 10 | 11 | 12 | 13 | 14 | 15 | 16 |
 * |--------------------------------------------------------------------------------------------|
 * |    single  | 1  | 1  | 2  | 2  | 2  | 2  | 2  | 2  | 1  | 2  | 2  | 2  | 2  | 2  | 2  | 1  |
 * | enc(left)  |-------------------------------------------------------------------------------|
 * |    total   | 1  | 2  | 4  | 6  | 8  | 10 | 12 | 14 | 15 | 17 | 19 | 21 | 23 | 25 | 27 | 28 |
 * |--------------------------------------------------------------------------------------------|
 * |    single  | 0  | 1  | 2  | 2  | 2  | 2  | 2  | 2  | 1  | 2  | 2  | 2  | 2  | 2  | 2  | 1  |
 * | enc(right) |-------------------------------------------------------------------------------|
 * |    total   | 0  | 1  | 3  | 5  | 7  | 9  | 11 | 13 | 14 | 16 | 18 | 20 | 22 | 24 | 26 | 27 |
 * |--------------------------------------------------------------------------------------------|
 */
/* shift left: 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 */
static uint8_t shift_enc[16] =
{
    1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
};

/* shift right: 0, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 */
static uint8_t shift_dec[16] =
{
    0, 1, 3, 5, 7, 9, 11, 13, 14, 16, 18, 20, 22, 24, 26, 27
};

static int key_permutation(uint8_t *in, uint8_t *out, uint8_t *p, uint8_t p_size)
{
    int i;

    for (i=0; i<p_size; i++)
    {
        out[i] = in[p[i]-1];
    }

    return ERR_OK;
}

static int key_shift(const uint8_t in[56], uint8_t out[56], uint8_t enc, uint8_t round)
{
    uint8_t i;
    uint8_t shift;

    if (enc == 1)
    {
        shift = shift_enc[round];
        for (i=0; i<28; i++)
        {
            out[(i+28-shift)%28] = in[i];
            out[28+(i+28-shift)%28] = in[28+i];
        }
    }
    else
    {
        shift = shift_dec[round];
        for (i=0; i<28; i++)
        {
            out[(i+shift)%56] = in[i];
            out[28+(i+shift)%56] = in[28+i];
        }
    }
    return 0;
}

static int key_schedule(uint8_t in[56], uint8_t out[56], uint8_t enc, uint8_t round)
{
    uint8_t temp[56];

    memset(temp, 0, 56);
    //show_msb_bits(in, 56, "key before shift: ");
    key_shift(in, temp, enc, round);
    //show_msb_bits(temp, 56, "key after shift: ");

    key_permutation(temp, out, PC2, 48);
    //show_msb_bits(out, 48, "key after PC2: ");

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

    return ERR_OK;
}

static int s_box_operation(uint8_t in[6], uint8_t out[4], uint8_t index)
{
    uint8_t *sbox;
    uint8_t row, col;
    uint8_t temp;

    sbox = SBox[index];

    row = (in[0] << 1) | in[5];
    col = (in[1] << 3) | (in[2] << 2) | (in[3] << 1) | in[4];

    temp = sbox[16 * row + col];

    printf("%15sS%d(%d,%2d)=%02d\n", "SBox: ", index+1, row, col, temp);

    out[0] = (temp >> 3) & 0x01;
    out[1] = (temp >> 2) & 0x01;
    out[2] = (temp >> 1) & 0x01;
    out[3] = temp & 0x01;

    return ERR_OK;
}

static int f(uint8_t in[32], uint8_t out[32], uint8_t key[48])
{
    int i;
    uint8_t expand[48];

    show_msb_bits(in, 32, "processing: ");
    for (i=0; i<48; i++)
    {
        expand[i] = in[E[i]-1];
    }
    show_bits_group(expand, 48, 6, "after expand: ");

    show_bits_group(key, 48, 6, "input key: ");
    for (i=0; i<48; i++)
    {
        expand[i] ^= key[i];
    }
    show_bits_group(expand, 48, 6, "after key: ");

    for (i=0; i<48; i+=6)
    {
        s_box_operation(&expand[i], &out[i/6*4], i/6);
    }
    show_bits_group(out, 32, 4, "after sbox: ");

    data_permutation(out, 32, P, 32);
    show_msb_bits(out, 32, "after P: ");

    return ERR_OK;
}

static void show_48bits_key(uint8_t *bits, int size, char *tips)
{
    int i, j;
    uint8_t x;
    uint8_t buf[16];

    show_bits_group(bits, size, 6, tips);

    for (i=0; i<size; i+=6)
    {
        x = 0;
        for (j=0; j<6; j++)
        {
            x |= (bits[i+j] & 0x01) << (5-j);
        }
        buf[i/6] = x;
    }
    print_hex(buf, size/6, tips);

    printf("\n");
}

static int DES_ProcessBlock(uint8_t in[8], uint8_t out[8], uint8_t key[8], uint8_t enc)
{
    uint8_t data_bits[64];
    uint8_t key_bits[56];
    uint8_t round_key[48];

    uint8_t temp[64];
    uint8_t i, t;

    uint8_t L, R;

    L =  0;
    R = 32;

    print_hex(in, 8, "in: ");

    bytes_to_msb_bits(in, 8, data_bits);
    show_msb_bits(data_bits, 64, "before IP: ");

    data_permutation(data_bits, 64, IP, 64);
    show_msb_bits(data_bits, 64, "after IP: ");

    show_msb_bits(&data_bits[L], 32, "L: ");
    show_msb_bits(&data_bits[R], 32, "R: ");

    print_hex(key, 8, "key: ");

    bytes_to_msb_bits(key, 8, temp);
    show_msb_bits(temp, 64, "raw key: ");

    key_permutation(temp, key_bits, PC1, 56);
    show_msb_bits(key_bits, 56, "key after PC1: ");

    for (t=0; t<16; t++)
    {
        printf("%13d:\n", t);

        /* copy Rn to Ln+1 */
        memcpy(&temp[L], &data_bits[R], 32);

        show_msb_bits(&data_bits[L], 32, "L: ");
        show_msb_bits(&data_bits[R], 32, "R: ");

        key_schedule(key_bits, round_key, enc, t);
        show_48bits_key(round_key, 48, "key: ");

        f(&data_bits[R], &temp[R], round_key);
        show_msb_bits(&temp[R], 32, "out: ");
        for (i=0; i<32; i++)
        {
            /* Rn+1 = Ln ^ f(Rn) */
            temp[R+i] ^= data_bits[L+i];
        }

        memcpy(data_bits, temp, 64);
        show_msb_bits(data_bits, 64, "out data: ");
        printf("-------------------------------------------------------------------------------------\n");
    }

    show_msb_bits(data_bits, 64, "swap L16/R16: ");
    memcpy(temp, data_bits, 64);
    /* Swap L16 and R16 */
    memcpy(&data_bits[R], &temp[L], 32);
    memcpy(&data_bits[L], &temp[R], 32);

    show_msb_bits(data_bits, 64, "before RIP: ");
    data_permutation(data_bits, 64, RIP, 64);
    show_msb_bits(data_bits, 64, "final: ");
    msb_bits_to_bytes(data_bits, 64, out);

    return 0;
}

#define TEST

#ifdef TEST

/*
 *  Plaintext: 0x02468aceeca86420
 *        Key: 0x0f1571c947d9e859
 * Ciphertext: 0xda02ce3a89ecac3b
 *
 *      |         Ki         |     Li     |     Ri
 * -----|--------------------|------------|-----------
 *   IP |                    | 0x5a005a00 | 0x3cf03c0f
 *    1 | 0x1e030f03080d2930 | 0x3cf03c0f | 0xbad22845
 *    2 | 0x0a31293432242318 | 0xbad22845 | 0x99e9b723
 *    3 | 0x23072318201d0c1d | 0x99e9b723 | 0x0bae3b9e
 *    4 | 0x05261d3824311a20 | 0x0bae3b9e | 0x42415649
 *    5 | 0x3325340136002c25 | 0x42415649 | 0x18b3fa41
 *    6 | 0x123a2d0d04262a1c | 0x18b3fa41 | 0x9616fe23
 *    7 | 0x021f120b1c130611 | 0x9616fe23 | 0x67117cf2
 *    8 | 0x1c10372a2832002b | 0x67117cf2 | 0xc11bfc09
 *    9 | 0x04292a380c341f03 | 0xc11bfc09 | 0x887fbc6c
 *   10 | 0x2703212607280403 | 0x887fbc6c | 0x600f7e8b
 *   11 | 0x2826390c31261504 | 0x600f7e8b | 0xf596506e
 *   12 | 0x12071c241a0a0f08 | 0xf596506e | 0x738538b8
 *   13 | 0x300935393c0d100b | 0x738538b8 | 0xc6a62c4e
 *   14 | 0x311e09231321182a | 0xc6a62c4e | 0x56b0bd75
 *   15 | 0x283d3e0227072528 | 0x56b0bd75 | 0x75e8fd8f
 *   16 | 0x2921080b13143025 | 0x75e8fd8f | 0x25896490
 * IP−1 |                    | 0xda02ce3a | 0x89ecac3b
 */

int main(int argc, char *argv[])
{
    uint8_t enc[8] = {0x02, 0x46, 0x8a, 0xce, 0xec, 0xa8, 0x64, 0x20};
    uint8_t key[8] = {0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59};
    uint8_t dec[8] = {0xda, 0x02, 0xce, 0x3a, 0x89, 0xec, 0xac, 0x3b};
    uint8_t temp[8];

    //uint8_t enc2[8] = {0x12, 0x46, 0x8a, 0xce, 0xec, 0xa8, 0x64, 0x20};

    memset(temp, 0, 8);

    print_hex(enc, 8, "input: ");
    DES_ProcessBlock(enc, temp, key, 1);
    print_hex(temp, 8, "enc: ");

    //print_hex(dec, 8, "input: ");
    //DES_ProcessBlock(dec, temp, key, 0);
    //print_hex(temp, 8, "dec: ");

    //print_hex(enc2, 8, "input: ");
    //DES_ProcessBlock(enc2, temp, key, 1);
    //print_hex(temp, 8, "enc2: ");

    return 0;
}
#endif