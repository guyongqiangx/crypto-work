#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mysha1.h"

int main(int argc, char * argv[])
{
	uint8_t data[]="abc";
	//uint8_t data[]="abcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
	//uint8_t buf[SHA1_BLOCK_SIZE];
	uint8_t hash[160];
	uint32_t len = 0;

	sha1_init();

	len = strlen(data);
	printf("length: %d\n", len);

	sha1_update(data, len);

	sha1_final(&hash);

	printf("sha1 result:\n");

	printf("%20s\n", hash);

#if 1
	printf("openssl dgst -sha1 abc.txt\n");
	system("openssl dgst -sha1 abc.txt");
#else
	//system("stat 58.txt");
	printf("openssl dgst -sha1 58.txt\n");
	system("openssl dgst -sha1 58.txt");
#endif
	printf("press any key to exit...\n");
	getchar();

	return 0;
}

