#ifndef __MY_SHA1__
#define __MY_SHA1__

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

int md5_init(void);
int md5_update(const void *data, uint64_t size);
int md5_final(uint8_t *hash);

#endif
