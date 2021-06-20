#include <stdio.h>  /* printf, fopen, fread, fclose... */
#include <stdlib.h> /* exit */
#include <string.h> /* strlen */
#include <unistd.h> /* getopt */

#include "sha512.h"

#define SHA512_224_DIGEST_SIZE  	28
#define SHA512_256_DIGEST_SIZE  	32
#define SHA384_DIGEST_SIZE  		48
#define SHA512_DIGEST_SIZE  		64

#define HASH_DIGEST_SIZE    		SHA512_DIGEST_SIZE  /* sha512 digest size */
#define HASH_NAME_SIZE              10                  /* hash name size, like "sha512-224" is 10 bytes */
#define FILE_BLOCK_SIZE             1024

/* Hash Algorithm List */
typedef enum {
    HASH_MD2,
    HASH_MD4,
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA224,
    HASH_SHA256,
    HASH_SHA384,
    HASH_SHA512,
    HASH_SHA512_224,
    HASH_SHA512_256,
    HASH_SHA3_224,
    HASH_SHA3_256,
    HASH_SHA3_384,
    HASH_SHA3_512,
} HASH_ALG;

typedef struct {
    SHA512_CTX impl;
    HASH_ALG alg;
    unsigned char md[HASH_DIGEST_SIZE];
    uint32_t md_size;
    int (* init)(SHA512_CTX *c);
    int (* update)(SHA512_CTX *c, const void *data, size_t len);
    int (* final)(unsigned char *md, SHA512_CTX *c);
    unsigned char * (* hash)(const unsigned char *d, size_t n, unsigned char *md);
} HASH_CTX;

/*
 * Print a usage message
 */
void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage:\n"
        "Common options: [-x|-f file|-s string| -a sha384|sha512|sha512-224|sha512-256 | -h]\n"
        "Hash a string:\n"
            "\t%s -a sha384|sha512|sha512-224|sha512-256 -s string\n"
        "Hash a file:\n"
            "\t%s -a sha384|sha512|sha512-224|sha512-256 -f file [-k key]\n"
        "-a\tSecure hash algorithm: \"sha384\", \"sha512\", \"sha512-224\", \"sha512-256\"\n"
        "-x\tInternal string hash test\n"
        "-h\tDisplay this message\n"
        , argv0, argv0);
    exit(1);
}

/*
 * Print a message digest in hexadecimal
 */
static int print_digest(unsigned char *digest, uint32_t len)
{
    uint32_t i;

    for (i = 0; i < len; i++)
    {
        printf ("%02x", digest[i]);
    }

    return 0;
}

struct HASH_ITEM {
    char        *str;
    uint32_t    len;
    unsigned char md[HASH_DIGEST_SIZE*2];
    // unsigned char *md;
};

/*
 * $ for alg in "sha384" "sha512" "sha512-224" "sha512-256"; \
 *   do \
 *     echo "Algorithm: $alg"; \
 *     for str in "" "a" "abc" "message digest" "abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" "12345678901234567890123456789012345678901234567890123456789012345678901234567890"; \
 *     do \
 *       echo "echo -n \"$str\" | openssl dgst -$alg"; \
 *       echo -n $str | openssl dgst -$alg; \
 *     done; \
 *     echo; \
 * done;
 *
 */

struct HASH_ITEM sha384_hashes[] =
{
    { /* 0 */
        "",
        0,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    },
    { /* 1 */
        "a",
        1,
        "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31"
    },
    { /* 2 */
        "abc",
        3,
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    },
    { /* 3 */
        "message digest",
        14,
        "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026"
    },
    {   /* End */
        NULL, 0, ""
    }
};

struct HASH_ITEM sha512_hashes[] =
{
    { /* 0 */
        "",
        0,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    },
    { /* 1 */
        "a",
        1,
        "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"
    },
    { /* 2 */
        "abc",
        3,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    },
    { /* 3 */
        "message digest",
        14,
        "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843"
    },
    {   /* End */
        NULL, 0, ""
    }
};

struct HASH_ITEM sha512_224_hashes[] =
{
    { /* 0 */
        "",
        0,
        "a8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3"
    },
    { /* 1 */
        "a",
        1,
        "a8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3"
    },
    { /* 2 */
        "abc",
        3,
        "a8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3"
    },
    { /* 3 */
        "message digest",
        14,
        "a8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "a8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "a8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "a8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3"
    },
    {   /* End */
        NULL, 0, ""
    }
};

struct HASH_ITEM sha512_256_hashes[] =
{
    { /* 0 */
        "",
        0,
        "cdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8"
    },
    { /* 1 */
        "a",
        1,
        "cdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8"
    },
    { /* 2 */
        "abc",
        3,
        "cdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8"
    },
    { /* 3 */
        "message digest",
        14,
        "cdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "cdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "cdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "cdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8"
    },
    {   /* End */
        NULL, 0, ""
    }
};

/*
 * Internal digest tests
 */
static int internal_digest_tests(const char *argv0, HASH_CTX *ctx)
{
    struct HASH_ITEM *tests, *item;

    switch (ctx->alg)
    {
        case HASH_SHA384:
            printf("Internal hash tests for %s(SHA384):\n", argv0);
            tests = sha384_hashes;
            break;

        case HASH_SHA512_224:
            printf("Internal hash tests for %s(SHA512/224):\n", argv0);
            tests = sha512_224_hashes;
            break;
        case HASH_SHA512_256:
            printf("Internal hash tests for %s(SHA512/256):\n", argv0);
            tests = sha512_256_hashes;
            break;

        case HASH_SHA512:
        default:
            printf("Internal hash tests for %s(SHA512):\n", argv0);
            tests = sha512_hashes;
            break;
    }

    for (item=tests; item->str != NULL; item++)
    {
        printf("%s(\"%s\")\n", argv0, item->str);
        ctx->hash((unsigned char*)item->str, item->len, ctx->md);
        printf("  Expect: %s\n", item->md);
        printf("  Result: ");
        print_digest(ctx->md, ctx->md_size);
        printf("\n\n");
    }

    return 0;
}

/*
 * Hash a string and print the digest
 */
static int digest_string(const char *argv0, HASH_CTX *ctx, const unsigned char *string, uint32_t len)
{
    printf("%s(\"%s\") = ", argv0, string);

    ctx->hash(string, len, ctx->md);

    print_digest(ctx->md, ctx->md_size);
    printf("\n");

    return 0;
}

/*
 * Hash a file and print the digest
 */
static int digest_file(const char *argv0, HASH_CTX *ctx, const char *filename)
{
    FILE *f;

    unsigned char buf[FILE_BLOCK_SIZE];

    int len = 0;
    int rc = 0;

    f = fopen(filename, "rb");
    if (NULL == f)
    {
        printf("Can't open file %s\n", filename);
        rc = -1;
    }
    else
    {
        printf("%s(%s) = ", argv0, filename);
        ctx->init(&ctx->impl);
        while ((len = fread(buf, 1, FILE_BLOCK_SIZE, f)))
        {
            ctx->update(&ctx->impl, buf, len);
        }
        ctx->final(ctx->md, &ctx->impl);

        fclose(f);

        print_digest(ctx->md, ctx->md_size);
        printf("\n");

        rc = 0;
    }

    return rc;
}

/*
 * Hash the standard input and prints the digest
 */
static void digest_stdin(const char *argv0, HASH_CTX *ctx)
{
    int len;
    unsigned char buf[HASH_DIGEST_SIZE];

    ctx->init(&ctx->impl);
    while ((len = fread(buf, 1, HASH_DIGEST_SIZE, stdin)))
    {
        ctx->update(&ctx->impl, buf, len);
    }
    ctx->final(ctx->md, &ctx->impl);

    printf("%s(stdin) = ", argv0);
    print_digest(ctx->md, ctx->md_size);
    printf("\n");
}

/*
 * $ sha512 -h
 * Usage:
 * Common options: [-x|-f file|-s string| -a sha384|sha512|sha512-224|sha512-256 | -h]
 * Hash a string:
 *         sha512 -a sha384|sha512|sha512-224|sha512-256 -s string
 * Hash a file:
 *         sha512 -a sha384|sha512|sha512-224|sha512-256 -f file [-k key]
 * -a      Secure hash algorithm: "sha384", "sha512", "sha512-224", "sha512-256"
 * -x      Internal string hash test
 * -h      Display this message
 */
int main(int argc, char *argv[])
{
    int ch;
    int hash_internal = 0;
    int hash_str = 0;
    int hash_file = 0;
    int hash_stdin = 0;

    char alg[HASH_NAME_SIZE];
    uint32_t alg_len;

    char *str = NULL;
    uint32_t len = 0;

    char *filename = NULL;

    HASH_CTX ctx;
    memset(&ctx, 0, sizeof(HASH_CTX));

    while ((ch = getopt(argc, argv, "a:s:f:xh")) != -1)
    {
        switch(ch)
        {
            case 'a':
                alg_len = strlen(optarg);
                alg_len = alg_len < HASH_NAME_SIZE ? alg_len : HASH_NAME_SIZE;
                memset(alg, 0, sizeof(alg));
                strncpy(alg, optarg, alg_len);
                break;
            case 'x':
                hash_internal = 1;
                break;
            case 's':
                hash_str = 1;
                str = optarg;
                len = strlen(str);
                break;
            case 'f':
                hash_file = 1;
                filename = optarg;
                break;
            case 'h':
            default: /* '?' */
                usage(argv[0]);
                break;
        }
    }

    if (argc == 1)
    {
        hash_stdin = 1;
    }

    /*
     * Setup ctx according to algorithm
     */
    if ((NULL == alg) || (strncmp(alg, "sha512", alg_len) == 0))
    {
        ctx.alg = HASH_SHA512;
        ctx.md_size = SHA512_DIGEST_SIZE;
        ctx.init = SHA512_Init;
        ctx.update = SHA512_Update;
        ctx.final = SHA512_Final;
        ctx.hash = SHA512;
    }
    else if (strncmp(alg, "sha384", alg_len) == 0)
    {
        ctx.alg = HASH_SHA384;
        ctx.md_size = SHA384_DIGEST_SIZE;
        ctx.init = SHA384_Init;
        ctx.update = SHA384_Update;
        ctx.final = SHA384_Final;
        ctx.hash = SHA384;
    }
    else if (strncmp(alg, "sha512-224", alg_len) == 0)
    {
        ctx.alg = HASH_SHA512_224;
        ctx.md_size = SHA512_224_DIGEST_SIZE;
        ctx.init = SHA512_224_Init;
        ctx.update = SHA512_224_Update;
        ctx.final = SHA512_224_Final;
        ctx.hash = SHA512_224;
    }
    else if (strncmp(alg, "sha512-256", alg_len) == 0)
    {
        ctx.alg = HASH_SHA512_256;
        ctx.md_size = SHA512_256_DIGEST_SIZE;
        ctx.init = SHA512_256_Init;
        ctx.update = SHA512_256_Update;
        ctx.final = SHA512_256_Final;
        ctx.hash = SHA512_256;
    }
    else
    {
        usage(argv[0]);
    }

    if (hash_internal)
    {
        internal_digest_tests(argv[0], &ctx);
    }

    if (hash_str)
    {
        digest_string(argv[0], &ctx, (unsigned char *)str, len);
    }

    if (hash_file)
    {
        digest_file(argv[0], &ctx, filename);
    }

    if (hash_stdin)
    {
        digest_stdin(argv[0], &ctx);
    }

    return 0;
}
