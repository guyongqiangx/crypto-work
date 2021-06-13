#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha3.h"

unsigned char test[200] = 
{
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
    0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3
};

#define HASH_SIZE 64
int main(int argc, char * argv[])
{
	char data[]="abc";
	//char data[]="abcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
	uint8_t hash[HASH_SIZE];
	uint32_t i, len = 0;

	SHA3_CTX ctx;

#if 1
	len = strlen(data);
	printf("length: %d\n", len);

	memset(hash, 0, sizeof(hash));

	SHA3_Init(&ctx, SHA3_256);
	SHA3_Update(&ctx, test, sizeof(test)/sizeof(unsigned char));
	SHA3_Final(hash, &ctx);

	printf("sha3 result:\n");

	//print_buffer(hash, 32);
	for (i=0; i<32; i++)
		printf("%02x", hash[i]);
	printf("\n");
#endif

#if 0
	sha3_init();
	sha3_update("abc", 3);
	sha3_update("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 55);
	//sha3_update("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 55);
	//sha3_update("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 55);
	sha3_final(hash);

	printf("sha3 result:\n");

	//print_buffer(hash, 20);
	for (i=0; i<HASH_SIZE; i++)
		printf("%02x", hash[i]);
	printf("\n");
#endif

#if 1
    //sleep(2);
	//printf("openssl dgst -sha3-256 SHA3-256_1600.bin\n");
	//system("openssl dgst -sha3-256 SHA3-256_1600.bin");
#else
	//system("stat 58.txt");
	printf("openssl dgst -sha3 58.txt\n");
	system("openssl dgst -sha3 58.txt");
#endif

#if 0
	len = strlen(data);
	printf("length: %d\n", len);

	memset(hash, 0, sizeof(hash));

	SHA384_Init(&ctx);
	SHA384_Update(&ctx, data, len);
	SHA384_Final(hash, &ctx);

	printf("sha384 result:\n");

	//print_buffer(hash, 20);
	for (i=0; i<48; i++)
		printf("%02x", hash[i]);
	printf("\n");

	printf("openssl dgst -sha384 abc.txt\n");
	system("openssl dgst -sha384 abc.txt");
#endif

#if 0
    len = strlen(data);
    printf("length: %d\n", len);

    memset(hash, 0, sizeof(hash));

    SHA3_224_Init(&ctx);
    SHA3_224_Update(&ctx, data, len);
    SHA3_224_Final(hash, &ctx);

    printf("sha384 result:\n");

    //print_buffer(hash, 20);
    for (i=0; i<28; i++)
        printf("%02x", hash[i]);
    printf("\n");

    //printf("openssl dgst -sha384 abc.txt\n");
    //system("openssl dgst -sha384 abc.txt");
#endif

/* SHA3t("abc", 224) */
#if 0
	len = strlen(data);
	printf("length: %d\n", len);

	memset(hash, 0, sizeof(hash));

	SHA3t_Init(&ctx, 224);
	SHA3t_Update(&ctx, data, len);
	SHA3t_Final(hash, &ctx);

	printf("sha3/256 result:\n");

	//print_buffer(hash, 20);
	for (i=0; i<224/8; i++)
		printf("%02x", hash[i]);
	printf("\n");

    printf("openssl dgst -sha3-224 abc.txt\n");
    system("openssl dgst -sha3-224 abc.txt");
#endif

#if 1
    /*
     * $ echo -n "" | openssl dgst -sha3-224
     * (stdin)= 6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7
     * $ echo -n "" | openssl dgst -sha3-256
     * (stdin)= a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
     * $ echo -n "" | openssl dgst -sha3-384
     * (stdin)= 0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004
     * $ echo -n "" | openssl dgst -sha3-512
     * (stdin)= a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
     */

    printf("sha3_224(""):\n");
    SHA3(SHA3_224, "", 0, hash);
    for (i=0; i<28; i++)
        printf("%02x", hash[i]);
    printf("\n");

    printf("sha3_256(""):\n");
    SHA3(SHA3_256, "", 0, hash);
    for (i=0; i<32; i++)
        printf("%02x", hash[i]);
    printf("\n");

    printf("sha3_384(""):\n");
    SHA3(SHA3_384, "", 0, hash);
    for (i=0; i<48; i++)
        printf("%02x", hash[i]);
    printf("\n");

    printf("sha3_512(""):\n");
    SHA3(SHA3_512, "", 0, hash);
    for (i=0; i<64; i++)
        printf("%02x", hash[i]);
    printf("\n");
#endif

	//printf("press any key to exit...\n");
	//getchar();

	return 0;
}


