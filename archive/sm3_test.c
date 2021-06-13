#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sm3.h"

int main(int argc, char * argv[])
{
	char data[]="abc";
	//char data[]="abcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
	//uint8_t buf[SHA1_BLOCK_SIZE];
	uint8_t hash[32];
	uint32_t i, len = 0;

	SM3_CTX ctx;

	len = strlen(data);
	printf("length: %d\n", len);

	memset(hash, 0, sizeof(hash));

	SM3_Init(&ctx);
	SM3_Update(&ctx, data, len);
	SM3_Final(hash, &ctx);

	printf("sm3 result:\n");

	//print_buffer(hash, 32);
	for (i=0; i<32; i++)
		printf("%02x", hash[i]);
	printf("\n");

#if 0

	SM3_Init(&ctx);
	SM3_Update(&ctx, "abcdabcdabcdabcdabcdabcdabcdabcd", 32);
	SM3_Update(&ctx, "abcdabcdabcdabcdabcdabcdabcdabcd", 32);
	SM3_Final(hash, &ctx);

	printf("sm3 result:\n");

	//print_buffer(hash, 32);
	for (i=0; i<32; i++)
		printf("%02x", hash[i]);
	printf("\n");
#endif

#if 1
	printf("openssl dgst -sm3 abc.txt\n");
	system("openssl dgst -sm3 abc.txt");
#else
	//system("stat 58.txt");
	printf("openssl dgst -sm3 58.txt\n");
	system("openssl dgst -sm3 58.txt");
#endif

	printf("press any key to exit...\n");
	getchar();

	return 0;
}

