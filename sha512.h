#ifndef __MY_SHA512__
#define __MY_SHA512__

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

int sha512_init(void);
int sha512_update(const void *data, uint64_t size);
int sha512_final(uint8_t *hash);

#endif

