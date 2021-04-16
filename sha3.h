#ifndef __MY_SHA3__
#define __MY_SHA3__

#define ERR_OK			 0
#define ERR_ERR         -1	/* generic error */
#define ERR_INV_PARAM	-2  /* invalid parameter */
#define ERR_TOO_LONG	-3  /* too long */
#define ERR_STATE_ERR   -4  /* state error */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

int sha3_init(void);
int sha3_update(const void *data, uint64_t size);
int sha3_final(uint8_t *hash);

int print_buffer(const void *buf, uint32_t len);

#endif
