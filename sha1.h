#ifndef __MY_SHA1__
#define __MY_SHA1__

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

int sha1_init(void);
int sha1_update(const void *data, uint64_t size);
int sha1_final(uint8_t *hash);

int print_buffer(const void *buf, uint32_t len);

#endif
