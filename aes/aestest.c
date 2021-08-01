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

#define AES_BLOCK_SIZE      20      /* aes block size */
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

    uint8_t key[24] =
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

    uint8_t key[32] =
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

int main(int argc, char *argv[])
{
    printf("AES 128 Encryption/Decryption Test:\n");
    test_Cipher_128();
    printf("\n");

    printf("AES 192 Encryption/Decryption Test:\n");
    test_Cipher_192();
    printf("\n");

    printf("AES 256 Encryption/Decryption Test:\n");
    test_Cipher_256();
    printf("\n");

    return 0;
}