#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md2.h"

int main(int argc, char * argv[])
{
	char data[]="abc";
	//char data[]="abcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
	//uint8_t buf[SHA1_BLOCK_SIZE];
	uint8_t hash[16];
	uint32_t i, len = 0;
    MD2_CTX ctx;

	memset(hash, 0, sizeof(hash));
	len = strlen(data);
	printf("length: %d\n", len);

    MD2_Init(&ctx);
    MD2_Update(&ctx, data, len);
	MD2_Final(hash, &ctx);

	printf("md2 result:\n");

	//print_buffer(hash, 20);
	for (i=0; i<16; i++)
		printf("%02x", hash[i]);
	printf("\n");

#if 0
	md5_init();
	md5_update("abc", 3);
	md5_update("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 55);
	md5_final(hash);

	printf("md5 result:\n");

	//print_buffer(hash, 20);
	for (i=0; i<16; i++)
		printf("%02x", hash[i]);
	printf("\n");
#endif

#if 1
	printf("openssl dgst -md2 abc.txt\n");
	system("openssl dgst -md2 abc.txt");
#else
	//system("stat 58.txt");
	printf("openssl dgst -md2 58.txt\n");
	system("openssl dgst -md2 58.txt");
#endif
	printf("press any key to exit...\n");
	getchar();

	return 0;
}

