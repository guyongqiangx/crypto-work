#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "hmac.h"

int main(int argc, char * argv[])
{
	char data[]="abc";
    char key[]="I Love China!";
	//char data[]="abcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
	//uint8_t buf[HMAC_BLOCK_SIZE];
	uint8_t hash[32];
	uint32_t i, len = 0;

    HMAC_CTX ctx;
    
	memset(hash, 0, sizeof(hash));

	HMAC_Init_ex(&ctx, key, strlen(key), NULL, NULL);
    HMAC_Update(&ctx, data, strlen(data));
    HMAC_Final(&ctx, hash, &len);

    printf("hmac result:\n");
    print_buffer(hash, 32, " ");

	//print_buffer(hash, 20);
	for (i=0; i<32; i++)
		printf("%02x", hash[i]);
	printf("\n");

#if 0
	hmac_init();
	hmac_update("abc", 3);
	hmac_update("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 55);
	hmac_final(hash);

	printf("hmac result:\n");

	//print_buffer(hash, 20);
	for (i=0; i<20; i++)
		printf("%02x", hash[i]);
	printf("\n");
#endif

#if 1
	printf("openssl dgst -sha256 -hmac \"I Love China!\" abc.txt\n");
	system("openssl dgst -sha256 -hmac \"I Love China!\" abc.txt\n");
#else
	//system("stat 58.txt");
	printf("openssl dgst -hmac \"I Love China!\" 58.txt\n");
	system("openssl dgst -hmac \"I Love China!\" 58.txt");
#endif
	printf("press any key to exit...\n");
	getchar();

	return 0;
}


