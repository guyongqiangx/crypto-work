#ifndef __ROCKY_SHA3__H
#define __ROCKY_SHA3__H

#define ERR_OK           0
#define ERR_ERR         -1	/* generic error */
#define ERR_INV_PARAM   -2  /* invalid parameter */
#define ERR_TOO_LONG    -3  /* too long */
#define ERR_STATE_ERR   -4  /* state error */

typedef unsigned char       uint8_t;
typedef unsigned short      uint16_t;
typedef unsigned int        uint32_t;
typedef unsigned long long  uint64_t;
typedef struct {
	uint64_t high; /* high 64 bits */
	uint64_t low;  /*  low 64 bits */
} uint128_t;

typedef struct sha3_context {
    /* message total length in bytes */
    uint128_t total;

    /* intermedia hash value for each block */
    struct {
        uint64_t a;
        uint64_t b;
        uint64_t c;
        uint64_t d;
        uint64_t e;
        uint64_t f;
        uint64_t g;
        uint64_t h;
    }hash;

    /* last block */
    struct {
        uint32_t used;      /* used bytes */
        uint8_t  buf[128];  /* block data buffer */
    }last;

    uint32_t ext;           /* t value of SHA3/t */
}SHA3_CTX;

/* https://www.openssl.org/docs/man1.1.1/man3/SHA256_Final.html */

int SHA3_Init(SHA3_CTX *c);
int SHA3_Update(SHA3_CTX *c, const void *data, size_t len);
int SHA3_Final(unsigned char *md, SHA3_CTX *c);
unsigned char *SHA3(const unsigned char *d, size_t n,
					  unsigned char *md);
#endif
