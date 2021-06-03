#ifndef __ROCKY_MD5__H
#define __ROCKY_MD5__H

#define ERR_OK			 0
#define ERR_ERR         -1	/* generic error */
#define ERR_INV_PARAM	-2  /* invalid parameter */
#define ERR_TOO_LONG	-3  /* too long */
#define ERR_STATE_ERR   -4  /* state error */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef struct md5_context {
    /* message total length in bytes */
    uint64_t total;

    /* intermedia hash value for each block */
    struct {
        uint32_t a;
        uint32_t b;
        uint32_t c;
        uint32_t d;
        uint32_t e;
    }hash;

    /* last block */
    struct {
        uint32_t used;     /* used bytes */
        uint8_t  buf[64];  /* block data buffer */
    }last;
}MD5_CTX;

/* https://www.openssl.org/docs/man1.1.0/man3/MD5_Init.html */

int MD5_Init(MD5_CTX *c);
int MD5_Update(MD5_CTX *c, const void *data, unsigned long len);
int MD5_Final(unsigned char *md, MD5_CTX *c);
unsigned char *MD5(const unsigned char *d, unsigned long n, unsigned char *md);

int md5_init(void);
int md5_update(const void *data, uint64_t size);
int md5_final(uint8_t *hash);

#if 0
 int MD2_Init(MD2_CTX *c);
 int MD2_Update(MD2_CTX *c, const unsigned char *data,
                  unsigned long len);
 int MD2_Final(unsigned char *md, MD2_CTX *c);


 #include <openssl/md4.h>

 unsigned char *MD4(const unsigned char *d, unsigned long n,
                  unsigned char *md);

 int MD4_Init(MD4_CTX *c);
 int MD4_Update(MD4_CTX *c, const void *data,
                  unsigned long len);
 int MD4_Final(unsigned char *md, MD4_CTX *c);
 #endif
#endif
