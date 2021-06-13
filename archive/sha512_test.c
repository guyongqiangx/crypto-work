#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha512.h"

#define HASH_SIZE 64
int main(int argc, char * argv[])
{
	char data[]="abc";
	//char data[]="abcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
	uint8_t hash[HASH_SIZE];
	uint32_t i, len = 0;

	SHA512_CTX ctx;

#if 0
	len = strlen(data);
	printf("length: %d\n", len);

	memset(hash, 0, sizeof(hash));

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, data, len);
	SHA512_Final(hash, &ctx);

	printf("sha512 result:\n");

	//print_buffer(hash, 20);
	for (i=0; i<HASH_SIZE; i++)
		printf("%02x", hash[i]);
	printf("\n");
#endif

#if 0
	sha512_init();
	sha512_update("abc", 3);
	sha512_update("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 55);
	//sha512_update("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 55);
	//sha512_update("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 55);
	sha512_final(hash);

	printf("sha512 result:\n");

	//print_buffer(hash, 20);
	for (i=0; i<HASH_SIZE; i++)
		printf("%02x", hash[i]);
	printf("\n");
#endif

#if 1
	//printf("openssl dgst -sha512 abc.txt\n");
	//system("openssl dgst -sha512 abc.txt");
#else
	//system("stat 58.txt");
	printf("openssl dgst -sha512 58.txt\n");
	system("openssl dgst -sha512 58.txt");
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

#if 1
    len = strlen(data);
    printf("length: %d\n", len);

    memset(hash, 0, sizeof(hash));

    SHA512_224_Init(&ctx);
    SHA512_224_Update(&ctx, data, len);
    SHA512_224_Final(hash, &ctx);

    printf("sha384 result:\n");

    //print_buffer(hash, 20);
    for (i=0; i<28; i++)
        printf("%02x", hash[i]);
    printf("\n");

    //printf("openssl dgst -sha384 abc.txt\n");
    //system("openssl dgst -sha384 abc.txt");
#endif

/* SHA512t("abc", 224) */
#if 1
	len = strlen(data);
	printf("length: %d\n", len);

	memset(hash, 0, sizeof(hash));

	SHA512t_Init(&ctx, 224);
	SHA512t_Update(&ctx, data, len);
	SHA512t_Final(hash, &ctx);

	printf("sha512/256 result:\n");

	//print_buffer(hash, 20);
	for (i=0; i<224/8; i++)
		printf("%02x", hash[i]);
	printf("\n");

    printf("openssl dgst -sha512-224 abc.txt\n");
    system("openssl dgst -sha512-224 abc.txt");
#endif

	printf("press any key to exit...\n");
	getchar();

	return 0;
}


