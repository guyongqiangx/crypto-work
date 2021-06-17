#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "hmac.h"
#include "sha256.h"

#if 0
typedef struct {
    const char *name;
    uint32_t block_size;
    uint32_t digest_size;
    int init(void *ctx);
    int update(void *ctx, const void *data, size_t len);
    int final(unsigned char *md, void *ctx);
    unsigned char *hash(const unsigned char *d, unsigned long n, unsigned char *md);
}HASH_CTX;

static HASH_CTX ctxs[] =
{
    {
        "sha256", 64, 32,
        SHA256_Init,
        SHA256_Update,
        SHA256_Final,
        SHA256,
    },
}
#endif

// extern int print_buffer(const void *buf, unsigned long len, const char *indent);

int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,
                 const EVP_MD *md, ENGINE *impl)
{
    int i;
    SHA256_CTX *hash;
 
    memset(ctx, 0, sizeof(HMAC_CTX));
    ctx->alg = HMAC_SHA256;
    ctx->block_size = 64;
    ctx->digest_size = 32;

    hash = (SHA256_CTX *)malloc(sizeof(SHA256_CTX));
    ctx->impl = hash;

    printf("Key0 is:\n");
    print_buffer(key, key_len, " ");
    if (key_len <= ctx->block_size)
    {
        memset(ctx->padding, 0, ctx->block_size - key_len);
        memcpy(&ctx->padding[0], key, key_len);
    }
    else /* key_len > block_size, do hash first to convert key */
    {
        unsigned char temp[32];
        SHA256(key, key_len, temp);
        memset(ctx->padding, 0, ctx->block_size - ctx->digest_size);
        memcpy(&ctx->padding[0], temp, ctx->digest_size);
    }

    printf("Key 0 again:\n");
    print_buffer(ctx->padding, ctx->block_size, " ");

    for (i=0; i<ctx->block_size; i++)
    {
        ctx->inner[i] = ctx->padding[i] ^ 0x36;
        ctx->outer[i] = ctx->padding[i] ^ 0x5c;
    }

    printf("Key0 ^ ipad:\n");
    print_buffer(ctx->inner, ctx->block_size, " ");
    printf("K0 xor opad:\n");
    print_buffer(ctx->outer, ctx->block_size, " ");

    SHA256_Init(ctx->impl);

    /* H(Si) */
    SHA256_Update(ctx->impl, ctx->inner, ctx->block_size);

    return 0;
}
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len)
{
    /* H(Y0Y1...Yn-1) */
    SHA256_Update(ctx->impl, data, len);

    return 0;
}
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len)
{
    unsigned char sha256_hash[32];

    memset(sha256_hash, 0, sizeof(sha256_hash));

    /* S = H(K^ipad || text) */
    SHA256_Final(sha256_hash, ctx->impl);

    printf("Hash((Key^ipad)||text)\n");
    print_buffer(sha256_hash, ctx->digest_size, " ");

    SHA256_Init(ctx->impl);

    /* H(So) */
    SHA256_Update(ctx->impl, ctx->outer, ctx->block_size);
    /* H() */
    SHA256_Update(ctx->impl, sha256_hash, ctx->digest_size);

    memset(sha256_hash, 0, sizeof(sha256_hash));

    /* H() */
    SHA256_Final(sha256_hash, ctx->impl);
    printf("Hash((K0^opad)||Hash((K0^ipad)||text))\n");
    print_buffer(sha256_hash, ctx->digest_size, " ");

    memcpy(md, sha256_hash, 32);
    *len = ctx->digest_size;

    free(ctx->impl);
    ctx->impl = NULL;

    return 0;
}

