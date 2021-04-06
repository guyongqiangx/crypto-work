 
/*
* sha1test.c
*
* Description:
* This file will exercise the SHA-1 code performing the three
* tests documented in FIPS PUB 180-1 plus one which calls
* SHA1Input with an exact multiple of 512 bits, plus a few
* error test checks.
*
* Portability Issues:
* None.
*
*/
 
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "SHA1.h"
/*
* Define patterns for testing
*/
//#define TEST1 "abc"
#define TEST1 "abcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
#define TEST2a "abcdbcdecdefdefgefghfghighijhi"
 
#define TEST2b "jkijkljklmklmnlmnomnopnopq"
#define TEST2 TEST2a TEST2b
#define TEST3 "a"
#define TEST4a "01234567012345670123456701234567"
#define TEST4b "01234567012345670123456701234567"
/* an exact multiple of 512 bits */
#define TEST4 TEST4a TEST4b
char *testarray[4] =
{
	TEST1,
	TEST2,
	TEST3,
	TEST4
};
 
long int repeatcount[4] = { 1, 1, 1000000, 10 };
char *resultarray[4] =
{
	"A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D",
	"84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1",
	"34 AA 97 3C D4 C4 DA A4 F6 1E EB 2B DB AD 27 31 65 34 01 6F",
	"DE A3 56 A2 CD DD 90 C7 A7 EC ED C5 EB B5 63 93 4F 46 04 52"
};
 
int main1()
{
	SHA1Context sha;
	int i, j, err;
	uint8_t Message_Digest[20];
	/*
	* Perform SHA-1 tests
	*/
	for(j = 0; j < 4; ++j)
	{
		//printf( "\nTest %d: %ld, ’%s’\n",j+1,repeatcount[j],testarray[j]);
		err = SHA1Reset(&sha);
		//if (err)
		//{
			//fprintf(stderr, "SHA1Reset Error %d.\n", err );
			//break; /* out of for j loop */
		//}
		for(i = 0; i < repeatcount[j]; ++i)
		{
			err = SHA1Input(&sha,
				(const unsigned char *) testarray[j],
				strlen(testarray[j]));
			if (err)
			{
				fprintf(stderr, "SHA1Input Error %d.\n", err );
				break; /* out of for i loop */
			}
		}
		err = SHA1Result(&sha, Message_Digest);
		if (err)
		{
			fprintf(stderr,
				"SHA1Result Error %d, could not compute message digest.\n",
				err );
		}
		else
		{
			printf("\t");
			for(i = 0; i < 20 ; ++i)
			{
				printf("%02X ", Message_Digest[i]);
			}
			printf("\n");
		}
		printf("Should match:\n");
		printf("\t%s\n", resultarray[j]);
	}
 
	/* Test some error returns */
	err = SHA1Input(&sha,(const unsigned char *) testarray[1], 1);
	printf ("\nError %d. Should be %d.\n", err, shaStateError );
	err = SHA1Reset(0);
	printf ("\nError %d. Should be %d.\n", err, shaNull );
	return 0;
}

int main(int argc, char * argv[])
{
	SHA1Context sha;
	int i, j, err;
	uint8_t Message_Digest[20];

	uint8_t data[]="abc";
	//uint8_t data[]="abcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
	//uint8_t buf[SHA1_BLOCK_SIZE];
	uint8_t hash[20];
	uint32_t len = 0;

	//sha1_init();

	len = strlen(data);
	printf("length: %d\n", len);

	//sha1_update(data, len);

	//sha1_final(&hash);
	SHA1Reset(&sha);
	err = SHA1Input(&sha,
				(const unsigned char *) data,
				strlen(data));
	if (err)
		printf("SHA1Input Error %d.\n", err );

	SHA1Result(&sha, Message_Digest);
	printf("sha1 result:\n");

	//printf("%20s\n", Message_Digest);
	for(i = 0; i < 20 ; ++i)
	{
		printf("%02x", Message_Digest[i]);
	}
	printf("\n");

#if 1
	printf("openssl dgst -sha1 abc.txt\n");
	system("openssl dgst -sha1 abc.txt");
#else
	printf("openssl dgst -sha1 58.txt\n");
	system("openssl dgst -sha1 58.txt");
#endif
	printf("press any key to exit...\n");
	getchar();

	return 0;
}

