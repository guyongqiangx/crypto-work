#include <stdio.h>  /* printf, fopen, fread, fclose... */
#include <stdlib.h> /* exit */
#include <string.h> /* strlen */
#include <unistd.h> /* getopt */

#include "hash.h"
#include "utils.h"

#define HASH_NAME_SIZE              10                  /* hash name size, like "sha512-224" is 10 bytes */
#define FILE_BLOCK_SIZE             1024

#include "sha3.h"

typedef struct {
    HASH_CTX impl;
    HASH_ALG alg;
    unsigned char *md;
    unsigned int md_str_size;       /* 1 byte converts to 2 chars */

    int (* init)(HASH_CTX *c, HASH_ALG alg);
    int (* update)(HASH_CTX *c, const void *data, size_t len);
    int (* final)(unsigned char *md, HASH_CTX *c);
    unsigned char * (* hash)(HASH_ALG alg, const unsigned char *d, size_t n, unsigned char *md);

    int (* init_ex)(HASH_CTX *c, HASH_ALG alg, unsigned int md_size);
    unsigned char * (* hash_ex)(HASH_ALG alg, const unsigned char *d, size_t n, unsigned char *md, unsigned int md_size);

    int (* uninit)(HASH_CTX *ctx);

    unsigned int ext;
} TEST_CTX;

struct string2hash {
    char name[HASH_NAME_SIZE];
    HASH_ALG alg;
    unsigned int md_size;
    unsigned int flag;
} hash_lists[HASH_ALG_MAX] =
{
  /* "name",       alg,                 md_size */
    {"md2",        HASH_ALG_MD2,        16, 0},
    {"md4",        HASH_ALG_MD4,        16, 0},
    {"md5",        HASH_ALG_MD5,        16, 0},
    {"sha1",       HASH_ALG_SHA1,       20, 0},
    {"sha224",     HASH_ALG_SHA224,     28, 0},
    {"sha256",     HASH_ALG_SHA256,     32, 0},
    {"sha384",     HASH_ALG_SHA384,     48, 0},
    {"sha512",     HASH_ALG_SHA512,     64, 0},
    {"sha512-224", HASH_ALG_SHA512_224, 28, 0},
    {"sha512-256", HASH_ALG_SHA512_256, 32, 0},
    {"sha512t",    HASH_ALG_SHA512_T,   0,  1},
    {"sha3-224",   HASH_ALG_SHA3_224,   28, 0},
    {"sha3-256",   HASH_ALG_SHA3_256,   32, 0},
    {"sha3-384",   HASH_ALG_SHA3_384,   48, 0},
    {"sha3-512",   HASH_ALG_SHA3_512,   64, 0},
    {"shake128",   HASH_ALG_SHAKE128,   0,  1},
    {"shake256",   HASH_ALG_SHAKE256,   0,  1},
};

static int setup_ctx(const char *name, unsigned int len, TEST_CTX *ctx)
{
    struct string2hash *item = NULL;

    for (item=&hash_lists[0]; item<=&hash_lists[HASH_ALG_MAX-1]; item++)
    {
        if (strncmp(name, item->name, len) ==  0)
        {
            ctx->alg = item->alg;
            ctx->md_str_size = item->md_size * 2;
            if (item->flag)
            {
                ctx->init_ex = Hash_Init_Ex;
                ctx->hash_ex = Hash_Ex;

                ctx->init = NULL;
                ctx->hash = NULL;
            }
            else
            {
                ctx->init = Hash_Init;
                ctx->hash = Hash;

                ctx->init_ex = NULL;
                ctx->hash_ex = NULL;
            }

            ctx->update = Hash_Update;
            ctx->final = Hash_Final;
            ctx->uninit = Hash_UnInit;

            return ERR_OK;
        }
    }

    ctx->alg = HASH_ALG_INVALID;

    return ERR_ERR;
}

/*
 * Print a usage message
 */
void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage:\n"
        "Common options: [-a sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256 [-t ext] [-d num]] [-x|-f file|-s string|-h]\n"
        "Hash a string:\n"
            "\t%s -a [sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256] [-t ext] [-d num] -s string\n"
        "Hash a file:\n"
            "\t%s -a [sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256] [-t ext] [-d num] -f file\n"
        "-a\tSecure hash algorithm: \"sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256\". Default: sha3-256\n"
        "-d\tDigest length for shake128/shake256, required. Default: num=128[shake128], num=256[shake256]\n"
        "-t\tT value for SHA-512/t algorithm\n"
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

/*
 * Hash a string and print the digest
 */
static int digest_string(const char *argv0, TEST_CTX *ctx, const unsigned char *string, uint32_t len)
{
    printf("%s(\"%s\") = ", argv0, string);

    if (ctx->hash_ex)
    {
        ctx->hash_ex(ctx->alg, string, len, ctx->md, ctx->ext);
    }
    else
    {
        ctx->hash(ctx->alg, string, len, ctx->md);
    }

    print_digest(ctx->md, ctx->md_str_size);
    printf("\n");

    return 0;
}

/*
 * Hash a file and print the digest
 */
static int digest_file(const char *argv0, TEST_CTX *ctx, const char *filename)
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

        if (ctx->init_ex)
        {
            ctx->init_ex(&ctx->impl, ctx->alg, ctx->ext);
        }
        else
        {
            ctx->init(&ctx->impl, ctx->alg);
        }

        while ((len = fread(buf, 1, FILE_BLOCK_SIZE, f)))
        {
            ctx->update(&ctx->impl, buf, len);
        }

        ctx->final(ctx->md, &ctx->impl);

        fclose(f);

        print_digest(ctx->md, ctx->md_str_size);
        printf("\n");

        rc = 0;
    }

    return rc;
}

/*
 * Hash the standard input and prints the digest
 */
static void digest_stdin(const char *argv0, TEST_CTX *ctx)
{
    int len;
    unsigned char buf[FILE_BLOCK_SIZE];

    if (ctx->init_ex)
    {
        ctx->init_ex(&ctx->impl, ctx->alg, ctx->ext);
    }
    else
    {
        ctx->init(&ctx->impl, ctx->alg);
    }

    while ((len = fread(buf, 1, FILE_BLOCK_SIZE, stdin)))
    {
        ctx->update(&ctx->impl, buf, len);
    }
    ctx->final(ctx->md, &ctx->impl);

    printf("%s(stdin) = ", argv0);
    print_digest(ctx->md, ctx->md_str_size);
    printf("\n");
}

/*
 * $ sha3 -h
 * Usage:
 * Common options: [-a sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256 [-d num]] [-x|-f file|-s string|-h]
 * Hash a string:
 *         sha3 -a [sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256] [-d num] -s string
 * Hash a file:
 *         sha3 -a [sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256] [-d num] -f file
 * -a      Secure hash algorithm: "sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256". Default: sha3-256
 * -d      Digest length for shake128/shake256, required. Default: num=128[shake128], num=256[shake256]
 * -x      Internal string hash test
 * -h      Display this message
 */
int main(int argc, char *argv[])
{
    int rc = ERR_OK;
    int ch;
    int hash_internal = 0;
    int hash_str = 0;
    int hash_file = 0;
    int hash_stdin = 0;

    /* digest size in bytes for SHAKE128/SHAKE256 */
    uint32_t md_size = 0;

    /* t value for SHA512/t */
    uint32_t ext = 0;

    char alg[HASH_NAME_SIZE];
    uint32_t alg_len = 0;

    char *str = NULL;
    uint32_t len = 0;

    char *filename = NULL;

    TEST_CTX ctx;
    memset(&ctx, 0, sizeof(TEST_CTX));

    while ((ch = getopt(argc, argv, "a:s:f:d:xh")) != -1)
    {
        switch(ch)
        {
            case 'a':
                alg_len = strlen(optarg);
                alg_len = alg_len < HASH_NAME_SIZE ? alg_len : HASH_NAME_SIZE;
                memset(alg, 0, sizeof(alg));
                strncpy(alg, optarg, alg_len);
                alg[alg_len] = '\0';
                break;
            case 'x':
                hash_internal = 1;
                break;
            case 's':
                hash_str = 1;
                str = optarg;
                len = strlen(str);
                break;
            case 'd':
                md_size = atoi(optarg);
                if (md_size%8)
                {
                    usage(argv[0]);
                }
                else /* convert to bytes */
                {
                    md_size /= 8;
                }
                break;
            case 't':
                ext = atoi(optarg);
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
     * Setup ctx.alg and ctx.md_str_size;
     */
    rc = setup_ctx(alg, sizeof(alg), &ctx);
    if (rc != ERR_OK)
    {
        usage(argv[0]);
    }

    /* setup ext for SHA-512/t */
    if (ctx.alg == HASH_ALG_SHA512_T)
    {
        if ((ext==0) || (ext%8!=0) || (ext>=512))
        {
            usage(argv[0]);
        }
        else
        {
            md_size = ext / 8;
            ctx.md_str_size = md_size * 2;
            ctx.ext = ext;
        }
    }

    /* setup ext for SHAKE128/SHAKE256 */
    if (ctx.alg == HASH_ALG_SHAKE128)
    {
        if (md_size == 0)  /* 't' is not set, set to 128 bits, same as 'openssl dgst -shake128' */
            md_size = 128 / 8;
        ctx.md_str_size = md_size * 2;
        ctx.ext = md_size * 8;
    }
    else if (ctx.alg == HASH_ALG_SHAKE256)
    {
        if (md_size == 0)  /* 't' is not set, set to 256 bits, same as 'openssl dgst -shake256' */
            md_size = 256 / 8;
        ctx.md_str_size = md_size * 2;
        ctx.ext = md_size * 8;
    }

    /* allocate buffer for message digest */
    ctx.md = (unsigned char *)malloc(ctx.md_str_size);
    memset(ctx.md, 0, ctx.md_str_size);

    if (hash_internal)
    {
        //internal_digest_tests(alg, &ctx);
        printf("No internal tests availble!\n");
    }

    if (hash_str)
    {
        digest_string(alg, &ctx, (unsigned char *)str, len);
    }

    if (hash_file)
    {
        digest_file(alg, &ctx, filename);
    }

    if (hash_stdin)
    {
        digest_stdin(alg, &ctx);
    }

    free(ctx.md);
    ctx.md = NULL;

    return 0;
}
