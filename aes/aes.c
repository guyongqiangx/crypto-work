/*
 * @        file: aes.c
 * @ description: implementation for the Advanced Encryption Standard
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "aes.h"

#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#define DUMP_KEY_SCHED  1
#define DUMP_BLOCK_DATA 1
#define DUMP_BLOCK_HASH 1
#define DUMP_ROUND_DATA 1
#else
#define DBG(...)
#define DUMP_KEY_SCHED  0
#define DUMP_BLOCK_DATA 0
#define DUMP_BLOCK_HASH 0
#define DUMP_ROUND_DATA 0
#endif

#if (DUMP_KEY_SCHED == 1)
#define key_sched_print(...) printf(__VA_ARGS__)
#else
#define key_sched_print(...)
#endif

#if (DUMP_BLOCK_DATA == 1)
#define block_data_print(...) printf(__VA_ARGS__)
#else
#define block_data_print(...)
#endif

#define AES_BLOCK_SIZE  16
#define AES_ROW_COUNT   4
#define AES_COL_COUNT   4 /* ((AES_BLOCK_SIZE)/(AES_LINE_SIZE) */

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

static void show_state(uint8_t state[4][4], const char *indent)
{
    int i, j;
    for (i=0; i<4; i++)
    {
        printf("%s", indent);
        for (j=0; j<4; j++)
        {
            printf(j==3?"%02x\n":"%02x ", state[i][j]);
        }
    }
}

static int to_state(uint8_t in[16], uint8_t out[4][4])
{
    int i;
    int row, col;

    for (i=0; i<16; i++)
    {
        row = i%4;
        col = i/4;

        out[row][col] = in[i];
    }

    return 0;
}

static int from_state(uint8_t in[4][4], uint8_t out[16])
{
    int i;
    int row, col;

    show_state(in, "");

    i = 0;
    for (col=0; col<4; col++)
    {
        for (row=0; row<4; row++)
        {
            out[i++] = in[row][col];
        }
    }

    return 0;
}

static const uint8_t SBox[256] =
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

/* Circular left shift 8 bits */
static uint32_t RotWord(uint32_t x)
{
    return (x << 8) | (x >> (32 - 8));
}

#define SKeyByte(x,i) (SBox[((x)>>(i))&0xff]<<(i))

static uint32_t SubWord(uint32_t x)
{
    return SKeyByte(x, 0) | SKeyByte(x, 8) | SKeyByte(x, 16) | SKeyByte(x, 24);
}

/* Key round constant word array */
static uint32_t Rcon[] =
{
    0x01000000, /* {01}, {00}, {00}, {00} */
    0x02000000, /* {02}, {00}, {00}, {00} */
    0x04000000, /* {04}, {00}, {00}, {00} */
    0x08000000, /* {08}, {00}, {00}, {00} */
    0x10000000, /* {10}, {00}, {00}, {00} */
    0x20000000, /* {20}, {00}, {00}, {00} */
    0x40000000, /* {40}, {00}, {00}, {00} */
    0x80000000, /* {80}, {00}, {00}, {00} */
    0x1B000000, /* {1B}, {00}, {00}, {00} */
    0x36000000, /* {36}, {00}, {00}, {00} */
};

/*
 * FIPS-197: Figure 11. Pseudo Code for Key Expansion.
 *
 * KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
 * begin
 *     word temp
 *
 *     i = 0
 *
 *     while (i < Nk)
 *         w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
 *         i = i+1
 *     end while
 *
 *     i = Nk
 *
 *     while (i < Nb * (Nr+1)]
 *         temp = w[i-1]
 *         if (i mod Nk = 0)
 *             temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
 *         else if (Nk > 6 and i mod Nk = 4)
 *             temp = SubWord(temp)
 *         end if
 *         w[i] = w[i-Nk] xor temp
 *         i = i + 1
 *     end while
 * end
 */
static int KeyExpansion(uint8_t *key, uint32_t *w, uint32_t Nk, uint32_t Nr)
{
    uint32_t *pKey, temp;
    uint32_t i;

    pKey = (uint32_t *)key;
    for (i=0; i<Nk; i++)
    {
        /* convert big endian bytes to word(32bit) */
        w[i] = be32toh(pKey[i]);
        key_sched_print("w[%2d]=0x%08x\n", i, w[i]);
    }

    for (i=Nk; i<4*(Nr+1); i++)
    {
        temp = w[i-1];

        if (i%Nk == 0)
        {
            temp = SubWord(RotWord(temp)) ^ Rcon[i/Nk-1];
        }
        else if ((Nk>6) && (i%Nk==4))
        {
            temp = SubWord(temp);
        }
        w[i] = w[i-Nk] ^ temp;
        key_sched_print("w[%2d]=0x%08x\n", i, w[i]);
    }

    /* convert word(32bit) back to big endian bytes */
    for (i=0; i<4*(Nr+1); i++)
    {
        w[i] = htobe32(w[i]);
    }

    return ERR_OK;
}

static int SubBytes(uint8_t state[4][4])
{
    int i, j;

    for (i=0; i<4; i++)
    {
        for (j=0; j<4; j++)
        {
            state[i][j] = SBox[state[i][j]];
        }
    }

    return 0;
}

static int ShiftRows(uint8_t state[4][4])
{
    uint8_t temp[3];

    temp[0] = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp[0];

    temp[0] = state[2][0]; temp[1] = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = temp[0];
    state[2][3] = temp[1];

    temp[0] = state[3][0]; temp[1] = state[3][1]; temp[2] = state[3][2];
    state[3][0] = state[3][3];
    state[3][1] = temp[0];
    state[3][2] = temp[1];
    state[3][3] = temp[2];

    return 0;
}

/* Polynomial multiplication in GF(2^8)
 * {57} * {02} = {fe}
 */
static uint8_t multiple(uint8_t a, uint8_t b)
{
    uint8_t m, res;

    m = a;
    res = 0;
    while (b != 0)
    {
        if (b & 0x01)
        {
            if (0 == res)
            {
                res = m;
            }
            else
            {
                res ^= m;
            }
        }
        if (m & 0x80)   /* b7=1 */
        {
            m = (m << 1) ^ 0x1B; /* 0x1B = b00011011, m(x) = x4 + x3 + x + 1 */
        }
        else            /* b7=0 */
        {
            m <<= 1;
        }
        b >>= 1;
    }

    return res;
}

static int MixColumns(uint8_t state[4][4])
{
    int row, col;
    uint8_t temp[4][4];
    static uint8_t mix[4][4] =
    {
        { 0x02, 0x03, 0x01, 0x01},
        { 0x01, 0x02, 0x03, 0x01},
        { 0x01, 0x01, 0x02, 0x03},
        { 0x03, 0x01, 0x01, 0x02}
    };

    memcpy(temp, state, AES_BLOCK_SIZE);
    for (col=0; col<4; col++)
    {
        for (row=0; row<4; row++)
        {
            state[row][col] = multiple(mix[row][0], temp[0][col]) ^ multiple(mix[row][1], temp[1][col]) ^ multiple(mix[row][2], temp[2][col]) ^ multiple(mix[row][3], temp[3][col]);
        }
    }

    return 0;
}

static int AddRoundKey(uint8_t state[4][4], uint32_t *key)
{
    int i, j;
    uint8_t temp[4][4];

    to_state((uint8_t *)key, temp);
    printf(" key: \n");
    show_state(temp, "    ");

    for (i=0; i<4; i++)
    {
        for (j=0; j<4; j++)
        {
            state[i][j] ^= temp[i][j];
        }
    }

    return 0;
}

/*
 * FIPS-197: Figure 5. Pseudo Code for the Cipher
 *
 * Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
 * begin
 *     byte state[4,Nb]
 *
 *     state = in
 *
 *     AddRoundKey(state, w[0, Nb-1])   // See Sec. 5.1.4
 * 
 *     for round = 1 step 1 to Nr–1
 *         SubBytes(state)              // See Sec. 5.1.1
 *         ShiftRows(state)             // See Sec. 5.1.2
 *         MixColumns(state)            // See Sec. 5.1.3
 *         AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
 *     end for
 *
 *     SubBytes(state)
 *     ShiftRows(state)
 *     AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
 * 
 *     out = state
 * end
 */

static int Cipher(uint8_t *in, uint8_t *out, uint32_t *w, uint32_t Nr)
{
    uint32_t round;
    uint8_t state[4][4];

    to_state(in, state);
    printf("  in: \n");
    show_state(state, "    ");

    AddRoundKey(state, w);

    for (round=1; round<=Nr-1; round++)
    {
        printf("%d: \n", round);

        printf("   Start of Round: \n");
        show_state(state, "    ");

        SubBytes(state);
        printf("   after SubBytes: \n");
        show_state(state, "    ");

        ShiftRows(state);
        printf("  after ShiftRows: \n");
        show_state(state, "    ");

        MixColumns(state);
        printf("after MixColumns: \n");
        show_state(state, "    ");

        AddRoundKey(state, w+round*4);
    }

    printf("final:\n");
    printf("   Start of Round: \n");
    show_state(state, "    ");

    SubBytes(state);
    printf("   after SubBytes: \n");
    show_state(state, "    ");

    ShiftRows(state);
    printf("  after ShiftRows: \n");
    show_state(state, "    ");

    AddRoundKey(state, w+Nr*4);
    printf("after AddRoundKey: \n");
    show_state(state, "    ");

    from_state(state, out);

    return 0;
}

static const uint8_t InvSBox[256] =
{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

static int InvSubBytes(uint8_t state[4][4])
{
    int i, j;

    for (i=0; i<4; i++)
    {
        for (j=0; j<4; j++)
        {
            state[i][j] = InvSBox[state[i][j]];
        }
    }

    return 0;
}

static int InvShiftRows(uint8_t state[4][4])
{
    uint8_t temp[3];

    temp[0] = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp[0];

    temp[0] = state[2][3]; temp[1] = state[2][2];
    state[2][3] = state[2][1];
    state[2][2] = state[2][0];
    state[2][1] = temp[0];
    state[2][0] = temp[1];

    temp[0] = state[3][3]; temp[1] = state[3][2]; temp[2] = state[3][1];
    state[3][3] = state[3][0];
    state[3][2] = temp[0];
    state[3][1] = temp[1];
    state[3][0] = temp[2];

    return 0;
}

static int InvMixColumns(uint8_t state[4][4])
{
    int row, col;
    uint8_t temp[4][4];
    static uint8_t mix[4][4] =
    {
        { 0x0E, 0x0B, 0x0D, 0x09},
        { 0x09, 0x0E, 0x0B, 0x0D},
        { 0x0D, 0x09, 0x0E, 0x0B},
        { 0x0B, 0x0D, 0x09, 0x0E}
    };

    memcpy(temp, state, AES_BLOCK_SIZE);
    for (col=0; col<4; col++)
    {
        for (row=0; row<4; row++)
        {
            state[row][col] = multiple(mix[row][0], temp[0][col]) ^ multiple(mix[row][1], temp[1][col]) ^ multiple(mix[row][2], temp[2][col]) ^ multiple(mix[row][3], temp[3][col]);
        }
    }

    return 0;
}

/*
 * FIPS-197: Figure 12. Pseudo Code for the Inverse Cipher.
 *
 * InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
 * begin
 *     byte state[4,Nb]
 *
 *     state = in
 *
 *     AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4
 *
 *     for round = Nr-1 step -1 downto 1
 *         InvShiftRows(state)             // See Sec. 5.3.1
 *         InvSubBytes(state)              // See Sec. 5.3.2
 *         AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
 *         InvMixColumns(state)            // See Sec. 5.3.3
 *     end for
 *
 *     InvShiftRows(state)
 *     InvSubBytes(state)
 *     AddRoundKey(state, w[0, Nb-1])
 *
 *     out = state
 * end
 */
static int InvCipher(uint8_t *in, uint8_t *out, uint32_t *w, uint32_t Nr)
{
    uint32_t round;
    uint8_t state[4][4];

    to_state(in, state);
    printf("  in: \n");
    show_state(state, "    ");

    AddRoundKey(state, w+Nr*4);
    printf("after AddRoundKey: \n");
    show_state(state, "    ");

    for (round=Nr-1; round>=1; round--)
    {
        printf("%d: \n", round);

        printf("   Start of Round: \n");
        show_state(state, "    ");

        InvShiftRows(state);
        printf("  after ShiftRows: \n");
        show_state(state, "    ");

        InvSubBytes(state);
        printf("   after SubBytes: \n");
        show_state(state, "    ");

        AddRoundKey(state, w+round*4);
        printf("after AddRoundKey: \n");
        show_state(state, "    ");

        InvMixColumns(state);
        //printf("after MixColumns: \n");
        //show_state(state, "    ");
    }

    printf("final:\n");
    printf("   Start of Round: \n");
    show_state(state, "    ");

    InvShiftRows(state);
    printf("  after ShiftRows: \n");
    show_state(state, "    ");

    InvSubBytes(state);
    printf("   after SubBytes: \n");
    show_state(state, "    ");

    AddRoundKey(state, w);
    printf("after AddRoundKey: \n");
    show_state(state, "    ");

    from_state(state, out);

    return 0;
}


#define TEST
#ifdef TEST
static int test_KeyExpansion_128(void)
{
    /*
     * FIPS-197: A.1 Expansion of a 128-bit Cipher Key
     * Cipher Key = 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
     */
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    // /*
    //  * key = "0f1571c947d9e8590cb7add6af7f6798"
    //  */
    // uint8_t key[16] =
    // {
    //     0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59,
    //     0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98
    // };

    uint32_t W[44];

    show_state((uint8_t (*)[4])key, " ");
    KeyExpansion(key, W, 4, 10);

    return 0;
}

static int test_KeyExpansion_192(void)
{
    /*
     * FIPS-197: A.2 Expansion of a 192-bit Cipher Key
     * Cipher Key = 8e 73 b0 f7 da 0e 64 52 c8 10 f3 2b
     *              80 90 79 e5 62 f8 ea d2 52 2c 6b 7b
     */
    uint8_t key[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    uint32_t W[52];

    print_buffer(key, 24, "");
    KeyExpansion(key, W, 6, 12);

    return 0;
}

static int test_KeyExpansion_256(void)
{
    /*
     * FIPS-197: A.3 Expansion of a 256-bit Cipher Key
     * Cipher Key = 60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81
     *              1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4
     */
    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    uint32_t W[60];

    print_buffer(key, 32, "");
    KeyExpansion(key, W, 8, 14);

    return 0;
}

static int test_Cipher_128(void)
{
#if 0
    /* PlainText: 0123456789abcdeffedcba9876543210 */
    uint8_t data[16] =
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    /* Key: 0f1571c947d9e8590cb7add6af7f6798 */
    uint8_t key[16] =
    {
        0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59,
        0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98
    };
#elif 0
    /*
     * FIPS-197: Appendix B – Cipher Example
     *      Input = 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
     * Cipher Key = 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
     */
    uint8_t data[16] =
    {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    uint8_t key[16] =
    {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
#else
    /*
     * FIPS-197: Appendix C – Example Vectors
     * C.1 AES-128 (Nk=4, Nr=10)
     * PLAINTEXT: 00112233445566778899aabbccddeeff
     *       KEY: 000102030405060708090a0b0c0d0e0f
     */
    uint8_t data[16] =
    {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    uint8_t key[16] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
#endif

    uint8_t enc[16], dec[16];
    uint32_t W[44];

    printf("AES-128 Encryption: \n");

    memset(enc, 0, sizeof(enc));
    memset(W, 0, sizeof(W));

    print_buffer(data, 16, "");

    KeyExpansion(key, W, 4, 10);
    Cipher(data, enc, W, 10);

    print_buffer(enc, 16, "   ");

    printf("AES-128 Decryption: \n");

    memset(dec, 0, sizeof(dec));
    memset(W, 0, sizeof(W));

    KeyExpansion(key, W, 4, 10);
    InvCipher(enc, dec, W, 10);

    print_buffer(dec, 16, "   ");

    return 0;
}

static int test_Cipher_192(void)
{
    /*
     * FIPS-197: Appendix C – Example Vectors
     * C.2 AES-192 (Nk=6, Nr=12)
     * PLAINTEXT: 00112233445566778899aabbccddeeff
     *       KEY: 000102030405060708090a0b0c0d0e0f1011121314151617
     */
    uint8_t data[16] =
    {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    uint8_t key[24] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };

    uint8_t enc[16], dec[16];
    uint32_t W[52];

    printf("AES-192 Encryption: \n");

    memset(enc, 0, sizeof(enc));
    memset(W, 0, sizeof(W));

    print_buffer(data, 16, "");

    KeyExpansion(key, W, 6, 12);
    Cipher(data, enc, W, 12);

    print_buffer(enc, 16, "   ");

    printf("AES-192 Decryption: \n");

    memset(dec, 0, sizeof(dec));
    memset(W, 0, sizeof(W));

    KeyExpansion(key, W, 6, 12);
    InvCipher(enc, dec, W, 12);

    print_buffer(dec, 16, "   ");

    return 0;
}

static int test_Cipher_256(void)
{
    /*
     * FIPS-197: Appendix C – Example Vectors
     * C.3 AES-256 (Nk=8, Nr=14)
     * PLAINTEXT: 00112233445566778899aabbccddeeff
     *       KEY: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
     */
    uint8_t data[16] =
    {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    uint8_t key[32] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    uint8_t enc[16], dec[16];
    uint32_t W[60];

    printf("AES-256 Encryption: \n");

    memset(enc, 0, sizeof(enc));
    memset(W, 0, sizeof(W));

    print_buffer(data, 16, "");

    KeyExpansion(key, W, 8, 14);
    Cipher(data, enc, W, 14);

    print_buffer(enc, 16, "   ");

    printf("AES-256 Decryption: \n");

    memset(dec, 0, sizeof(dec));
    memset(W, 0, sizeof(W));

    KeyExpansion(key, W, 8, 14);
    InvCipher(enc, dec, W, 14);

    print_buffer(dec, 16, "   ");

    return 0;
}

int main(int argc, char *argv[])
{
    //test_KeyExpansion_128();
    //test_KeyExpansion_192();
    //test_KeyExpansion_256();

    //test_Cipher_128();
    //test_Cipher_192();
    test_Cipher_256();
    return 0;
}
#endif