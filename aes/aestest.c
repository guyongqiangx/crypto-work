/*
 * @        file: aestest.c
 * @ description: test tool for aes
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>  /* printf, fopen, fread, fclose... */
#include <stdlib.h> /* exit */
#include <string.h> /* strlen */
#include <unistd.h> /* getopt */

#include "aes.h"
#include "utils.h"

#define BLOCK_SIZE      16      /* aes block size */
#define AES128_KEY_SIZE 16
#define AES192_KEY_SIZE 24
#define AES256_KEY_SIZE 32

#define FILE_BLOCK_SIZE     1024

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
    uint8_t key[AES128_KEY_SIZE] =
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
    uint8_t key[AES128_KEY_SIZE] =
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

    uint8_t key[AES128_KEY_SIZE] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
#endif

    uint8_t enc[16], dec[16];

    print_buffer(data, 16, "   ");

    printf("AES-128 Encryption: \n");

    memset(enc, 0, sizeof(enc));
    AES_Encrypt(AES128, data, key, enc);
    print_buffer(enc, 16, "   ");

    printf("AES-128 Decryption: \n");

    memset(dec, 0, sizeof(dec));
    AES_Decrypt(AES128, enc, key, dec);
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

    uint8_t key[AES192_KEY_SIZE] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };

    uint8_t enc[16], dec[16];

    print_buffer(data, 16, "   ");

    printf("AES-192 Encryption: \n");

    memset(enc, 0, sizeof(enc));
    AES_Encrypt(AES192, data, key, enc);
    print_buffer(enc, 16, "   ");

    printf("AES-192 Decryption: \n");

    memset(dec, 0, sizeof(dec));
    AES_Decrypt(AES192, enc, key, dec);
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

    uint8_t key[AES256_KEY_SIZE] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    uint8_t enc[16], dec[16];

    print_buffer(data, 16, "   ");

    printf("AES-256 Encryption: \n");

    memset(enc, 0, sizeof(enc));
    AES_Encrypt(AES256, data, key, enc);
    print_buffer(enc, 16, "   ");

    printf("AES-256 Decryption: \n");
    AES_Decrypt(AES256, enc, key, dec);
    print_buffer(dec, 16, "   ");

    return 0;
}

#define DATA_SIZE 64
static int test_AES128_CBC(void)
{
    uint8_t data[DATA_SIZE] =
    {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

    uint8_t key[AES128_KEY_SIZE] =
    {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t iv[16] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    uint8_t enc[DATA_SIZE], dec[DATA_SIZE];

    printf("     input: \n");
    print_buffer(data, DATA_SIZE, "      ");

    memset(enc, 0, DATA_SIZE);
    AES_CBC_Encrypt(AES128, data, DATA_SIZE, key, iv, enc);
    printf("encryption: \n");
    print_buffer(enc, DATA_SIZE, "      ");

    memset(dec, 0, DATA_SIZE);
    AES_CBC_Decrypt(AES128, enc, DATA_SIZE, key, iv, dec);
    printf("decryption: \n");
    print_buffer(dec, DATA_SIZE, "      ");

    return 0;
}

static int test_AES192_CBC(void)
{
    uint8_t data[DATA_SIZE] =
    {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

    uint8_t key[AES192_KEY_SIZE] =
    {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    uint8_t iv[16] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    uint8_t enc[DATA_SIZE], dec[DATA_SIZE];

    printf("     input: \n");
    print_buffer(data, DATA_SIZE, "      ");

    memset(enc, 0, DATA_SIZE);
    AES_CBC_Encrypt(AES192, data, DATA_SIZE, key, iv, enc);
    printf("encryption: \n");
    print_buffer(enc, DATA_SIZE, "      ");

    memset(dec, 0, DATA_SIZE);
    AES_CBC_Decrypt(AES192, enc, DATA_SIZE, key, iv, dec);
    printf("decryption: \n");
    print_buffer(dec, DATA_SIZE, "      ");

    return 0;
}

static int test_AES256_CBC(void)
{
    uint8_t data[DATA_SIZE] =
    {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

    uint8_t key[AES256_KEY_SIZE] =
    {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    uint8_t iv[16] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    uint8_t enc[DATA_SIZE], dec[DATA_SIZE];

    printf("     input: \n");
    print_buffer(data, DATA_SIZE, "      ");

    memset(enc, 0, DATA_SIZE);
    AES_CBC_Encrypt(AES256, data, DATA_SIZE, key, iv, enc);
    printf("encryption: \n");
    print_buffer(enc, DATA_SIZE, "      ");

    memset(dec, 0, DATA_SIZE);
    AES_CBC_Decrypt(AES256, enc, DATA_SIZE, key, iv, dec);
    printf("decryption: \n");
    print_buffer(dec, DATA_SIZE, "      ");

    return 0;
}


int main(int argc, char *argv[])
{
    printf("AES-128 Encryption/Decryption Test:\n");
    test_Cipher_128();
    printf("\n");

    printf("AES-192 Encryption/Decryption Test:\n");
    test_Cipher_192();
    printf("\n");

    printf("AES-256 Encryption/Decryption Test:\n");
    test_Cipher_256();
    printf("\n");

    printf("AES-128 CBC Encryption/Decryption Test:\n");
    test_AES128_CBC();
    printf("\n");

    printf("AES-192 CBC Encryption/Decryption Test:\n");
    test_AES192_CBC();
    printf("\n");

    printf("AES-256 CBC Encryption/Decryption Test:\n");
    test_AES256_CBC();
    printf("\n");
    return 0;
}