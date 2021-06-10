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

#define HASH_SIZE 32
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
	for (i=0; i<HASH_SIZE; i++)
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
	//printf("openssl dgst -sha3 abc.txt\n");
	//system("openssl dgst -sha3 abc.txt");
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

	printf("press any key to exit...\n");
	getchar();

	return 0;
}


