#ifndef __ROCKY_MD2__H
#define __ROCKY_MD2__H
#include "type.h"

typedef struct md2_context {
    /* message total length in bytes */
    uint64_t total;

    /* 48 bytes buffer */
    uint8_t X[48];

    /* last block */
    struct {
        uint32_t used;     /* used bytes */
        uint8_t  buf[16];  /* block data buffer */
    }last;

    uint8_t checksum[16]; /* checksum */
}MD2_CTX;

/* https://www.openssl.org/docs/man1.1.0/man3/MD5_Init.html */
int MD2_Init(MD2_CTX *c);
int MD2_Update(MD2_CTX *c, const void *data, unsigned long len);
/* int MD2_Update(MD2_CTX *c, const unsigned char *data, unsigned long len); */
int MD2_Final(unsigned char *md, MD2_CTX *c);
unsigned char *MD2(const unsigned char *d, unsigned long n, unsigned char *md);
#endif
