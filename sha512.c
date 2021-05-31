#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "sha512.h"

#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#define DUMP_BLOCK_DATA 1
#define DUMP_BLOCK_HASH 1
#define DUMP_ROUND_DATA 1
#else
#define DBG(...)
#define DUMP_BLOCK_DATA 0
#define DUMP_BLOCK_HASH 0
#define DUMP_ROUND_DATA 0
#endif

#define SHA512_BLOCK_SIZE			128	/* 1024 bits = 128 bytes */
#define SHA512_LEN_SIZE	 			 16	/*  128 bits =  16 bytes */
#define SHA512_LEN_OFFSET 			(SHA512_BLOCK_SIZE - SHA512_LEN_SIZE)
#define SHA512_DIGEST_SIZE			 64 /*  512 bits =  64 bytes */

#define SHA512_PADDING_PATTERN 	   0x80
#define SHA512_ROUND_NUM			 80

#define HASH_BLOCK_SIZE		SHA512_BLOCK_SIZE
#define HASH_LEN_SIZE		SHA512_LEN_SIZE
#define HASH_LEN_OFFSET		SHA512_LEN_OFFSET
#define HASH_DIGEST_SIZE	SHA512_DIGEST_SIZE

#define HASH_PADDING_PATTERN	SHA512_PADDING_PATTERN
#define HASH_ROUND_NUM			SHA512_ROUND_NUM

/* SHA512 Constants */
static const uint64_t K512[HASH_ROUND_NUM] =
{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
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

/* SIGMA0 */
static uint64_t SIGMA0(uint64_t x)
{
	return ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39);
}

/* SIGMA1 */
static uint64_t SIGMA1(uint64_t x)
{
	return ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41);
}

/* sigma0, different from SIGMA0 */
static uint64_t sigma0(uint64_t x)
{
	return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7);
}

/* sigma1, different from SIGMA1 */
static uint64_t sigma1(uint64_t x)
{
	return ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6);
}

/*
 * "abc" -->   0x61,     0x62,     0x63
 *   Origin: 0b0110 0001 0110 0010 0110 0011
 *  Padding: 0b0110 0001 0110 0010 0110 0011 1000 0000 .... 0000 0000  0000 0000 .... 0001 1000
 *                                          (|<-------------------->|)(|<------- 0x18 ------->|)
 *   Format: "abc" + 1 + 0 x 423 + 0x18
 */

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
	context->hash.a = 0x6a09e667f3bcc908;
	context->hash.b = 0xbb67ae8584caa73b;
	context->hash.c = 0x3c6ef372fe94f82b;
	context->hash.d = 0xa54ff53a5f1d36f1;
	context->hash.e = 0x510e527fade682d1;
	context->hash.f = 0x9b05688c2b3e6c1f;
	context->hash.g = 0x1f83d9abfb41bd6b;
	context->hash.h = 0x5be0cd19137e2179;

	context->total.i.l = 0;
	context->total.i.h = 0;
	context->last.used = 0;

	return 0;
}

//#define WORD(b,i) (((uint64_t *)b)[i])
static uint32_t prepare_schedule_word(const void *block, uint64_t *w)
{
	uint32_t t;
	for (t=0; t<HASH_ROUND_NUM; t++)
	{
		if (t<=15) /*  0 <= t <= 15 */
			w[t] = be64toh(QWORD(block, t));
		else	   /* 16 <= t <= 79 */
			w[t] = sigma1(w[t-2]) + w[t-7] + sigma0(w[t-15]) + w[t-16];
	}

	return 0;
}

static int update_processed_bits(uint128_t *x, uint64_t len)
{
	uint64_t l;

	/* l = (x->i.l + len) & U64(0xffffffffffffffff); */
	l = (x->i.l + (((uint64_t)len)<<3)) & 0xffffffffffffffff;
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

	for (i=0; i<HASH_LEN_SIZE; i++)
	{
		buffer[i] = length->d[HASH_LEN_SIZE-1-i];
	}

	return 0;
}

static uint32_t sha512_process_block(const void *block)
{
	uint32_t t;
	uint64_t W[HASH_ROUND_NUM];
	uint64_t T1, T2;
	uint64_t a, b, c, d, e, f, g, h;
	struct sha512_context *context;

	context = get_sha512_context();

#ifdef DEBUG
	//printf("block: %d\n", context->total >> 10);  /* block size: 2^10 = 1024 */
	print_buffer(block, HASH_BLOCK_SIZE, " ");
#endif

	/* prepare schedule word */
	prepare_schedule_word(block, W);

	a = context->hash.a;
	b = context->hash.b;
	c = context->hash.c;
	d = context->hash.d;
	e = context->hash.e;
	f = context->hash.f;
	g = context->hash.g;
	h = context->hash.h;

	//DBG("block: \n");
	//DBG("a=0x%016llx, b=0x%016llx, c=0x%016llx, d=0x%016llx, e=0x%016llx, f=0x%016llx, g=0x%016llx, h=0x%016llx\n", 
	//	a, b, c, d, e, f, g, h);

	for (t=0; t<HASH_ROUND_NUM; t++)
	{
		T1 = h + SIGMA1(e) + Ch(e, f, g) + K512[t] + W[t];
		T2 = SIGMA0(a) + Maj(a, b, c);
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

	context->hash.a += a;
	context->hash.b += b;
	context->hash.c += c;
	context->hash.d += d;
	context->hash.e += e;
	context->hash.f += f;
	context->hash.g += g;
	context->hash.h += h;

#ifdef DEBUG
	DBG("block hash:\n");
	DBG("   %016llx %016llx %016llx %016llx\n   %016llx %016llx %016llx %016llx\n", 
		context->hash.a, context->hash.b, context->hash.c, context->hash.d, context->hash.e, context->hash.f, context->hash.g, context->hash.h);
#endif

	return 0;
}

int sha512_update(const void *data, uint64_t size)
{
	uint64_t len = 0;

	struct sha512_context *context;

	context = get_sha512_context();

	/* has used data */
	if (context->last.used != 0)
	{
		/* less than 1 block in total, combine data */
		if (context->last.used + size < HASH_BLOCK_SIZE)
		{
			memcpy(&context->last.buf[context->last.used], data, size);
			context->last.used += size;

			return 0;
		}
		else /* more than 1 block */
		{
			/* process the block in context buffer */
			len = HASH_BLOCK_SIZE - context->last.used;
			memcpy(&context->last.buf[context->last.used], data, len);
			sha512_process_block(&context->last.buf);
			update_processed_bits(&context->total, HASH_BLOCK_SIZE);

			data = (uint8_t *)data + len;
			size -= len;

			/* reset context buffer */
			memset(&context->last.buf[0], 0, HASH_BLOCK_SIZE);
			context->last.used = 0;
		}
	}

	/* less than 1 block, copy to context buffer */
	if (size < HASH_BLOCK_SIZE)
	{
		memcpy(&context->last.buf[context->last.used], data, size);
		context->last.used += size;

		return 0;
	}
	else
	{
		/* process data blocks */
		while (size > HASH_BLOCK_SIZE)
		{
			sha512_process_block(data);
			update_processed_bits(&context->total, HASH_BLOCK_SIZE);

			data = (uint8_t *)data + HASH_BLOCK_SIZE;
			size -= HASH_BLOCK_SIZE;
		}

		/* copy the reset to context buffer */
		memcpy(&context->last.buf[0], data, size);
		context->last.used = size;
	}

	return 0;
}

int sha512_final(uint8_t *hash)
{
	uint64_t *buf;

	struct sha512_context *context;

	context = get_sha512_context();

	/* Last block should be less thant HASH_BLOCK_SIZE - HASH_LEN_SIZE */
	if (context->last.used >= (HASH_BLOCK_SIZE - HASH_LEN_SIZE))
	{
		/* update processed bits */
		update_processed_bits(&context->total, context->last.used);

		/* one more block */
		context->last.buf[context->last.used] = HASH_PADDING_PATTERN;
		context->last.used++;

		memset(&context->last.buf[context->last.used], 0, HASH_BLOCK_SIZE - context->last.used);
		sha512_process_block(&context->last.buf);

		context->last.used = 0;

		memset(&context->last.buf[0], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE);
		update_length_field(&context->last.buf[HASH_LEN_OFFSET], &context->total);
		sha512_process_block(&context->last.buf);
	}
	else /* 0 <= last.used < HASH_BLOCK_SIZE - HASH_LEN_SIZE */
	{
		/* update processed bits */
		update_processed_bits(&context->total, context->last.used);

		/* one more block */
		context->last.buf[context->last.used] = HASH_PADDING_PATTERN;
		context->last.used++;

		memset(&context->last.buf[context->last.used], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE - context->last.used);
		update_length_field(&context->last.buf[HASH_LEN_OFFSET], &context->total);
	
		sha512_process_block(&context->last.buf);
	}

	DBG("%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n", 
		context->hash.a, context->hash.b, context->hash.c, context->hash.d, context->hash.e, context->hash.f, context->hash.g, context->hash.h);

	buf = (uint64_t *)hash;
	buf[0] = htobe64(context->hash.a);
	buf[1] = htobe64(context->hash.b);
	buf[2] = htobe64(context->hash.c);
	buf[3] = htobe64(context->hash.d);
	buf[4] = htobe64(context->hash.e);
	buf[5] = htobe64(context->hash.f);
	buf[6] = htobe64(context->hash.g);
	buf[7] = htobe64(context->hash.h);

	return 0;
}
