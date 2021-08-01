/*
 * @        file: destest.c
 * @ description: test tool for des
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>  /* printf, fopen, fread, fclose... */
#include <stdlib.h> /* exit */
#include <string.h> /* strlen */
#include <unistd.h> /* getopt */

#include "des.h"
#include "utils.h"

#define DES_BLOCK_SIZE      20      /* des block size */
#define FILE_BLOCK_SIZE     1024

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
    uint8_t temp[8], temp2[8];

    uint8_t enc2[8] = {0x12, 0x46, 0x8a, 0xce, 0xec, 0xa8, 0x64, 0x20};

    memset(temp, 0, 8);
    print_buffer(enc, 8, "     input: ");
    DES_Encryption(enc, key, temp);
    print_buffer(temp, 8, "encryption: ");

    memset(temp, 0, 8);
    print_buffer(dec, 8, "     input: ");
    DES_Decryption(dec, key, temp);
    print_buffer(temp, 8, "decryption: ");

    memset(temp, 0, 8);
    print_buffer(enc2, 8, "     input: ");
    DES_Encryption(enc2, key, temp);
    print_buffer(temp, 8, "encryption: ");

    memset(temp2, 0, 8);
    DES_Decryption(temp, key, temp2);
    print_buffer(temp2, 8, "decryption: ");

    return 0;
}