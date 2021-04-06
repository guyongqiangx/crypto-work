#include <stdio.h>
#include <string.h>

#include "sha512.h"

#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#else
#define DBG(...)
#endif

#define SHA512_BLOCK_SIZE			128	/* 1024 bits = 128 bytes */
#define SHA512_LEN_SIZE	 			 16	/*  128 bits =  16 bytes */
#define SHA512_LEN_OFFSET 			(SHA512_BLOCK_SIZE - SHA512_LEN_SIZE)
#define SHA512_DIGEST_SIZE			512 /* 512 bits =  64 bytes */

#define SHA512_PADDING_PATTERN 	   0x80
#define SHA512_ROUND_NUM			 80

#define U64(x)	x##ULL

typedef union {
	struct
	{
		uint64_t l;
		uint64_t h;
	}i;				/* integer: low, high */
	uint8_t d[16];	/*    data: bytes */
} uint128_t;

/* SHA512 Constants */
static const uint64_t K512[80] = 
{
    U64(0x428a2f98d728ae22), U64(0x7137449123ef65cd), U64(0xb5c0fbcfec4d3b2f), U64(0xe9b5dba58189dbbc),
    U64(0x3956c25bf348b538), U64(0x59f111f1b605d019), U64(0x923f82a4af194f9b), U64(0xab1c5ed5da6d8118),
    U64(0xd807aa98a3030242), U64(0x12835b0145706fbe), U64(0x243185be4ee4b28c), U64(0x550c7dc3d5ffb4e2),
    U64(0x72be5d74f27b896f), U64(0x80deb1fe3b1696b1), U64(0x9bdc06a725c71235), U64(0xc19bf174cf692694),
    U64(0xe49b69c19ef14ad2), U64(0xefbe4786384f25e3), U64(0x0fc19dc68b8cd5b5), U64(0x240ca1cc77ac9c65),
    U64(0x2de92c6f592b0275), U64(0x4a7484aa6ea6e483), U64(0x5cb0a9dcbd41fbd4), U64(0x76f988da831153b5),
    U64(0x983e5152ee66dfab), U64(0xa831c66d2db43210), U64(0xb00327c898fb213f), U64(0xbf597fc7beef0ee4),
    U64(0xc6e00bf33da88fc2), U64(0xd5a79147930aa725), U64(0x06ca6351e003826f), U64(0x142929670a0e6e70),
    U64(0x27b70a8546d22ffc), U64(0x2e1b21385c26c926), U64(0x4d2c6dfc5ac42aed), U64(0x53380d139d95b3df),
    U64(0x650a73548baf63de), U64(0x766a0abb3c77b2a8), U64(0x81c2c92e47edaee6), U64(0x92722c851482353b),
    U64(0xa2bfe8a14cf10364), U64(0xa81a664bbc423001), U64(0xc24b8b70d0f89791), U64(0xc76c51a30654be30),
    U64(0xd192e819d6ef5218), U64(0xd69906245565a910), U64(0xf40e35855771202a), U64(0x106aa07032bbd1b8),
    U64(0x19a4c116b8d2d0c8), U64(0x1e376c085141ab53), U64(0x2748774cdf8eeb99), U64(0x34b0bcb5e19b48a8),
    U64(0x391c0cb3c5c95a63), U64(0x4ed8aa4ae3418acb), U64(0x5b9cca4f7763e373), U64(0x682e6ff3d6b2b8a3),
    U64(0x748f82ee5defb2fc), U64(0x78a5636f43172f60), U64(0x84c87814a1f0ab72), U64(0x8cc702081a6439ec),
    U64(0x90befffa23631e28), U64(0xa4506cebde82bde9), U64(0xbef9a3f7b2c67915), U64(0xc67178f2e372532b),
    U64(0xca273eceea26619c), U64(0xd186b8c721c0c207), U64(0xeada7dd6cde0eb1e), U64(0xf57d4f7fee6ed178),
    U64(0x06f067aa72176fba), U64(0x0a637dc5a2c898a6), U64(0x113f9804bef90dae), U64(0x1b710b35131c471b),
    U64(0x28db77f523047d84), U64(0x32caab7b40c72493), U64(0x3c9ebe0a15c9bebc), U64(0x431d67c49c100d4c),
    U64(0x4cc5d4becb3e42b6), U64(0x597f299cfc657e2a), U64(0x5fcb6fab3ad6faec), U64(0x6c44198c4a475817)
};

#if 0
/* ROTate Left (circular left shift) */
static uint64_t ROTL(uint64_t x, uint8_t shift)
{
	return (x << shift) | (x >> (64 - shift));
}
#endif

/* ROTate Right (cirular right shift) */
static uint64_t ROTR(uint64_t x, uint8_t shift)
{
	return (x >> shift) | (x << (64 - shift));
}

/* Right SHift */
static uint64_t SHR(uint64_t x, uint8_t shift)
{
	return (x >> shift);
}

/* Ch ... choose */
static uint64_t Ch(uint64_t x, uint64_t y, uint64_t z)
{
	//DBG("    Ch(0x%016llx, 0x%016llx, 0x%016llx);\n", x, y, z);
	return (x & y) ^ (~x & z) ;
}

/* Maj ... majority */
static uint64_t Maj(uint64_t x, uint64_t y, uint64_t z)
{
	//DBG("   Maj(0x%016llx, 0x%016llx, 0x%016llx);\n", x, y, z);
	return (x & y) ^ (x & z) ^ (y & z);
}

/* Sigma0 */
static uint64_t Sigma0(uint64_t x)
{
	return ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39);
}

/* Sigma1 */
static uint64_t Sigma1(uint64_t x)
{
	return ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41);
}

/* sigma0, different from Sigma0 */
static uint64_t sigma0(uint64_t x)
{
	return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7);
}

/* sigma1, different from Sigma1 */
static uint64_t sigma1(uint64_t x)
{
	return ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6);
}

#if 0
/* swap 16 bytes */
static void *swap128(void *data)
{
	uint8_t *buf, temp, i;

	buf = (uint8_t *)data;
	for (i=0; i<8; i++)
	{
		temp = buf[i];
		buf[i] = buf[15-i];
		buf[15-i] = temp;
	}

	return (void *)buf;
}
#endif

static uint64_t swap64(uint64_t a)
{
  return ((a & 0x00000000000000FFULL) << 56) |
         ((a & 0x000000000000FF00ULL) << 40) |
         ((a & 0x0000000000FF0000ULL) << 24) |
         ((a & 0x00000000FF000000ULL) <<  8) |
         ((a & 0x000000FF00000000ULL) >>  8) |
         ((a & 0x0000FF0000000000ULL) >> 24) |
         ((a & 0x00FF000000000000ULL) >> 40) |
         ((a & 0xFF00000000000000ULL) >> 56);
}

#define DUMP_LINE_SIZE 16
int print_buffer(const void *buf, uint32_t len)
{
	uint32_t i;
	for (i=0; i<len; i++)
	{
		if (i%DUMP_LINE_SIZE == 0)
			printf("%04X:", i);

		printf(" %02x", ((uint8_t *)buf)[i]);

		if (i%DUMP_LINE_SIZE == (DUMP_LINE_SIZE-1))
			printf("\n");
	}
	printf("\n");

	return 0;
}

/*
 * "abc" -->   0x61,     0x62,     0x63
 *   Origin: 0b0110 0001 0110 0010 0110 0011
 *  Padding: 0b0110 0001 0110 0010 0110 0011 1000 0000 .... 0000 0000  0000 0000 .... 0001 1000
 *                                          (|<-------------------->|)(|<------- 0x18 ------->|)
 *   Format: "abc" + 1 + 0 x 423 + 0x18
 */

struct sha512_context {
	uint64_t a;
	uint64_t b;
	uint64_t c;
	uint64_t d;
	uint64_t e;
	uint64_t f;
	uint64_t g;
	uint64_t h;

	uint128_t processed_bits;

	uint32_t rest; /* rest size in last block */
	uint8_t last_block[SHA512_BLOCK_SIZE];

};

static struct sha512_context *get_sha512_context(void)
{
	static struct sha512_context _sha512;

	return &_sha512;
}

int sha512_init(void)
{
	struct sha512_context *context;

	context = get_sha512_context();

	memset(context, 0, sizeof(struct sha512_context));
	context->a = U64(0x6a09e667f3bcc908);
	context->b = U64(0xbb67ae8584caa73b);
	context->c = U64(0x3c6ef372fe94f82b);
	context->d = U64(0xa54ff53a5f1d36f1);
	context->e = U64(0x510e527fade682d1);
	context->f = U64(0x9b05688c2b3e6c1f);
	context->g = U64(0x1f83d9abfb41bd6b);
	context->h = U64(0x5be0cd19137e2179);

	context->processed_bits.i.l = 0;
	context->processed_bits.i.h = 0;
	context->rest = 0;

	return 0;
}

#define WORD(b,i) (((uint64_t *)b)[i])
static uint32_t prepare_schedule_word(const void *block, uint64_t *w)
{
	uint32_t t;
	for (t=0; t<SHA512_ROUND_NUM; t++)
	{
		if (t<=15) /*  0 <= t <= 15 */
			w[t] = swap64(WORD(block, t));
		else	   /* 16 <= t <= 79 */
			w[t] = sigma1(w[t-2]) + w[t-7] + sigma0(w[t-15]) + w[t-16];
	}

	return 0;
}

static int update_processed_bits(uint128_t *x, uint64_t len)
{
	uint64_t l;

	l = (x->i.l + (((uint64_t)len)<<3)) & U64(0xffffffffffffffff);
	if (l < x->i.l)
		x->i.h++;

	//if (sizeof(len) >= 8)
	//	x->i.h += ((uint64_t)len)>> 61)

    x->i.l = l;

	return 0;
}

static int update_length_field(uint8_t *buffer, uint128_t *length)
{
	int i;

	for (i=0; i<SHA512_LEN_SIZE; i++)
	{
		buffer[i] = length->d[SHA512_LEN_SIZE-1-i];
	}

	return 0;
}

static uint32_t sha512_process_block(const void *block)
{
	uint32_t t;
	uint64_t W[SHA512_ROUND_NUM];
	uint64_t T1, T2;
	uint64_t a, b, c, d, e, f, g, h;
	struct sha512_context *context;

	context = get_sha512_context();

#ifdef DEBUG
	//printf("block: %d\n", context->processed_bits >> 10);  /* block size: 2^10 = 1024 */
	print_buffer(block, SHA512_BLOCK_SIZE);
#endif

	/* prepare schedule word */
	prepare_schedule_word(block, W);

	a = context->a;
	b = context->b;
	c = context->c;
	d = context->d;
	e = context->e;
	f = context->f;
	g = context->g;
	h = context->h;

	//DBG("block: \n");
	//DBG("a=0x%016llx, b=0x%016llx, c=0x%016llx, d=0x%016llx, e=0x%016llx, f=0x%016llx, g=0x%016llx, h=0x%016llx\n", 
	//	a, b, c, d, e, f, g, h);

	for (t=0; t<SHA512_ROUND_NUM; t++)
	{
		T1 = h + Sigma1(e) + Ch(e, f, g) + K512[t] + W[t];
		T2 = Sigma0(a) + Maj(a, b, c);
		 h = g;
		 g = f;
		 f = e;
		 e = d + T1;
		 d = c;
		 c = b;
		 b = a;
		 a = T1 + T2;

#ifdef DEBUG
		DBG("%02d:\n", t);
		DBG("T1=0x%016llx, T2=0x%016llx, W=0x%016llx\n", T1, T2, W[t]);
		DBG(" a=0x%016llx,  b=0x%016llx, c=0x%016llx, d=0x%016llx,\n e=0x%016llx,  f=0x%016llx, g=0x%016llx, h=0x%016llx\n", 
			a, b, c, d, e, f, g, h);
#endif
	}

	context->a += a;
	context->b += b;
	context->c += c;
	context->d += d;
	context->e += e;
	context->f += f;
	context->g += g;
	context->h += h;

#ifdef DEBUG
	DBG("block hash:\n");
	DBG("   %016llx %016llx %016llx %016llx\n   %016llx %016llx %016llx %016llx\n", 
		context->a, context->b, context->c, context->d, context->e, context->f, context->g, context->h);
#endif

	return 0;
}

int sha512_update(const void *data, uint64_t size)
{
	uint64_t len = 0;

	struct sha512_context *context;

	context = get_sha512_context();

	/* has rest data */
	if (context->rest != 0)
	{
		/* less than 1 block in total, combine data */
		if (context->rest + size < SHA512_BLOCK_SIZE)
		{
			memcpy(&context->last_block[context->rest], data, size);
			context->rest += size;

			return 0;
		}
		else /* more than 1 block */
		{
			/* process the block in context buffer */
			len = SHA512_BLOCK_SIZE - context->rest;
			memcpy(&context->last_block[context->rest], data, len);
			sha512_process_block(&context->last_block);
			update_processed_bits(&context->processed_bits, SHA512_BLOCK_SIZE);

			data = (uint8_t *)data + len;
			size -= len;

			/* reset context buffer */
			memset(&context->last_block[0], 0, SHA512_BLOCK_SIZE);
			context->rest = 0;
		}
	}

	/* less than 1 block, copy to context buffer */
	if (size < SHA512_BLOCK_SIZE)
	{
		memcpy(&context->last_block[context->rest], data, size);
		context->rest += size;

		return 0;
	}
	else
	{
		/* process data blocks */
		while (size > SHA512_BLOCK_SIZE)
		{
			sha512_process_block(data);
			update_processed_bits(&context->processed_bits, SHA512_BLOCK_SIZE);

			data = (uint8_t *)data + SHA512_BLOCK_SIZE;
			size -= SHA512_BLOCK_SIZE;
		}

		/* copy the reset to context buffer */
		memcpy(&context->last_block[0], data, size);
		context->rest = size;
	}

	return 0;
}

int sha512_final(uint8_t *hash)
{
	uint64_t *buf;

	struct sha512_context *context;

	context = get_sha512_context();

	/* Last block should be less thant SHA512_BLOCK_SIZE - SHA512_LEN_SIZE */
	if (context->rest >= (SHA512_BLOCK_SIZE - SHA512_LEN_SIZE))
	{
		/* update processed bits */
		update_processed_bits(&context->processed_bits, context->rest);

		/* one more block */
		context->last_block[context->rest] = SHA512_PADDING_PATTERN;
		context->rest++;

		memset(&context->last_block[context->rest], 0, SHA512_BLOCK_SIZE - context->rest);
		sha512_process_block(&context->last_block);

		context->rest = 0;

		memset(&context->last_block[0], 0, SHA512_BLOCK_SIZE - SHA512_LEN_SIZE);
		update_length_field(&context->last_block[SHA512_LEN_OFFSET], &context->processed_bits);
		sha512_process_block(&context->last_block);
	}
	else /* 0 <= rest < SHA512_BLOCK_SIZE - SHA512_LEN_SIZE */
	{
		/* update processed bits */
		update_processed_bits(&context->processed_bits, context->rest);

		/* one more block */
		context->last_block[context->rest] = SHA512_PADDING_PATTERN;
		context->rest++;

		memset(&context->last_block[context->rest], 0, SHA512_BLOCK_SIZE - SHA512_LEN_SIZE - context->rest);
		update_length_field(&context->last_block[SHA512_LEN_OFFSET], &context->processed_bits);
	
		sha512_process_block(&context->last_block);
	}

	DBG("%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n", 
		context->a, context->b, context->c, context->d, context->e, context->f, context->g, context->h);

	buf = (uint64_t *)hash;
	buf[0] = swap64(context->a);
	buf[1] = swap64(context->b);
	buf[2] = swap64(context->c);
	buf[3] = swap64(context->d);
	buf[4] = swap64(context->e);
	buf[5] = swap64(context->f);
	buf[6] = swap64(context->g);
	buf[7] = swap64(context->h);

	return 0;
}
