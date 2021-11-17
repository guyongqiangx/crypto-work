/*
 * @        file: hmactest.c
 * @ description: hmac test tool for below hash algorithms:
 *                1. MD(md2/md4/md5)
 *                2. SHA1(sha1)
 *                3. SHA2(sha224/sha256/sha384/sha512/sha512-224/sha512-256/sha512t)
 *                4. SHA3(sha3-224/sha3-256/sha3-384/sha3-512/shake128/shake256)
 *                5. SM3(sm3)
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>  /* printf, fopen, fread, fclose... */
#include <stdlib.h> /* exit */
#include <string.h> /* strlen */
#include <unistd.h> /* getopt */

#include "hash.h"
#include "hmac.h"
#include "utils.h"

/*
 * 使用 openssl dgst 命令行工具手工计算数据的 HMAC
 *
 * $ echo -n "0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0xbb, 0xaa, 0x00, 0x99, 0xff, 0xee, 0xdd, 0xcc" | xxd -r -ps | openssl dgst -mac HMAC -macopt hexkey:56c9d97c3846f7a425569e352a4fe7d9db4c9bc82f2f5d12530bb3127ccf46cb | awk '{print $2}' | xxd -r -ps | xxd -g 1
 * 0000000: 13 27 05 70 9e a2 12 24 14 0e 61 17 00 57 63 c5  .'.p...$..a..Wc.
 * 0000010: 00 e9 7e 6a 72 45 26 1c 4f 46 ea d5 bb 9e 0e ff  ..~jrE&.OF......
 * $
 * $ echo -n "0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0xbb, 0xaa, 0x00, 0x99, 0xff, 0xee, 0xdd, 0xcc" | xxd -r -ps | openssl dgst -mac HMAC -macopt hexkey:56c9d97c3846f7a425569e352a4fe7d9db4c9bc82f2f5d12530bb3127ccf46cb
 * (stdin)= 132705709ea21224140e6117005763c500e97e6a7245261c4f46ead5bb9e0eff
 */
// gcc utils.c md2.c md4.c md5.c sha1.c sha256.c sha512.c sha3.c sha3ex.c sm3.c hash_tables.c hash.c hmac.c hmactest2.c -o hmactest2
int main(int argc, char *argv[])
{
#if 1
    unsigned char data[] = {
      //0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0xbb, 0xaa, 0x00, 0x99, 0xff, 0xee, 0xdd, 0xcc, 
    };

    unsigned char key[] = {
        0x56, 0xc9, 0xd9, 0x7c, 0x38, 0x46, 0xf7, 0xa4, 0x25, 0x56, 0x9e, 0x35, 0x2a, 0x4f, 0xe7, 0xd9,
        0xdb, 0x4c, 0x9b, 0xc8, 0x2f, 0x2f, 0x5d, 0x12, 0x53, 0x0b, 0xb3, 0x12, 0x7c, 0xcf, 0x46, 0xcb
    };
#else
    unsigned char data[] = {
        0x49, 0x20, 0x4c, 0x6f, 0x76, 0x65, 0x20, 0x43, 0x68, 0x69, 0x6e, 0x61, 0x21
    };

    unsigned char key[] = {
        0x49, 0x20, 0x4c, 0x6f, 0x76, 0x65, 0x20, 0x43, 0x68, 0x69, 0x6e, 0x61, 0x21
    };

    /*
     * $ echo -n "I Love China!" | openssl dgst -hmac "I Love China!"
     * (stdin)= a1858d82d31d44625cb6218626bc63897f5c5e599b8aa0e06d23c36e9115715f
     */
#endif
    unsigned char buf[256];

    // unsigned char *HMAC(HASH_ALG alg, const void *key, unsigned int key_len, const unsigned char *data, size_t n, unsigned char *md);
    HMAC(HASH_ALG_SHA256, key, sizeof(key)/sizeof(key[0]), data, sizeof(data)/sizeof(data[0]), buf);

    printf("data:\n");
    print_buffer(data, sizeof(data)/sizeof(data[0]), "");

    printf(" key:\n");
    print_buffer(key, sizeof(key)/sizeof(key[0]), "");

    printf("HMAC:\n");
    print_buffer(buf, 32, "");

    return 0;
}