#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha3.h"

int main(int argc, char * argv[])
{
	char data[]="abc";
	//char data[]="abcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
	//uint8_t buf[SHA1_BLOCK_SIZE];
	uint8_t hash[20];
	uint32_t i, len = 0;

	memset(hash, 0, sizeof(hash));

	sha3_init();

	len = strlen(data);
	printf("length: %d\n", len);

	sha3_update(data, len);

	sha3_final(hash);

	printf("sha3 result:\n");

	//print_buffer(hash, 20);
	for (i=0; i<20; i++)
		printf("%02x", hash[i]);
	printf("\n");

#if 0
	sha3_init();
	sha3_update("abc", 3);
	sha3_update("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 55);
	sha3_final(hash);

	printf("sha3 result:\n");

	//print_buffer(hash, 20);
	for (i=0; i<20; i++)
		printf("%02x", hash[i]);
	printf("\n");
#endif

#if 1
	printf("openssl dgst -sha3 abc.txt\n");
	system("openssl dgst -sha3 abc.txt");
#else
	//system("stat 58.txt");
	printf("openssl dgst -sha3 58.txt\n");
	system("openssl dgst -sha3 58.txt");
#endif
	printf("press any key to exit...\n");
	getchar();

	return 0;
}

