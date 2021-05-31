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
	printf("openssl dgst -sha512 abc.txt\n");
	system("openssl dgst -sha512 abc.txt");
#else
	//system("stat 58.txt");
	printf("openssl dgst -sha512 58.txt\n");
	system("openssl dgst -sha512 58.txt");
#endif
	printf("press any key to exit...\n");
	getchar();

	return 0;
}


