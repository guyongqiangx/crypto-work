#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

int main(int argc, char * argv[])
{
	char data[]="abc";
	//char data[]="abcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
	//uint8_t buf[SHA1_BLOCK_SIZE];
	uint8_t hash[32];
	uint32_t i, len = 0;

	SHA256_CTX ctx;

	len = strlen(data);
	printf("length: %d\n", len);

	memset(hash, 0, sizeof(hash));

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data, len);
	SHA256_Final(hash, &ctx);

	printf("sha256 result:\n");

	//print_buffer(hash, 20);
	for (i=0; i<32; i++)
		printf("%02x", hash[i]);
	printf("\n");

#if 0
	sha1_init();
	sha1_update("abc", 3);
	sha1_update("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 55);
	sha1_final(hash);

	printf("sha1 result:\n");

	//print_buffer(hash, 20);
	for (i=0; i<20; i++)
		printf("%02x", hash[i]);
	printf("\n");
#endif

#if 1
	printf("openssl dgst -sha256 abc.txt\n");
	system("openssl dgst -sha256 abc.txt");
#else
	//system("stat 58.txt");
	printf("openssl dgst -sha1 58.txt\n");
	system("openssl dgst -sha1 58.txt");
#endif

#if 1
	len = strlen(data);
	printf("length: %d\n", len);

	memset(hash, 0, sizeof(hash));

	SHA224_Init(&ctx);
	SHA224_Update(&ctx, data, len);
	SHA224_Final(hash, &ctx);

	printf("sha224 result:\n");

	//print_buffer(hash, 20);
	for (i=0; i<28; i++)
		printf("%02x", hash[i]);
	printf("\n");

	printf("openssl dgst -sha224 abc.txt\n");
	system("openssl dgst -sha224 abc.txt");

#endif
	printf("press any key to exit...\n");
	getchar();

	return 0;
}

