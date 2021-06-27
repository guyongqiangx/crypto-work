/*
 * @        file: hashtest.c
 * @ description: hash test tool for:
 *                1. MD(md2/md4/md5)
 *                2. SHA1(sha1)
 *                3. SHA2(sha224/sha256/sha384/sha512/sha512-224/sha512-256/sha512t)
 *                4. SHA3(sha3-224/sha3-256/sha3-384/sha3-512/shake128/shake256)
 *                5. SM3(sm3)
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>  /* printf, fopen, fread, fclose... */
#include <stdlib.h> /* exit */
#include <string.h> /* strlen */
#include <unistd.h> /* getopt */

#include "hmac.h"
#include "utils.h"

#define HASH_NAME_SIZE              10      /* hash name size, like "sha512-224" is 10 bytes */
#define FILE_BLOCK_SIZE             1024

typedef struct {
    HMAC_ALG alg;
    HMAC_CTX impl;

    unsigned char *md;
    unsigned int md_size;

    unsigned int ext;       /* t value for SHA-512/t or d value for SHAKE128/SHAKE256 */
} TEST_CTX;

static struct string2hash {
    char name[HASH_NAME_SIZE];
    HMAC_ALG alg;
    unsigned int md_size;
    unsigned int flag;
} hash_lists[HMAC_ALG_MAX] =
{
  /* "name",       alg,                 md_size */
    {"md2",        HMAC_ALG_MD2,        16, 0},
    {"md4",        HMAC_ALG_MD4,        16, 0},
    {"md5",        HMAC_ALG_MD5,        16, 0},
    {"sha1",       HMAC_ALG_SHA1,       20, 0},
    {"sha224",     HMAC_ALG_SHA224,     28, 0},
    {"sha256",     HMAC_ALG_SHA256,     32, 0},
    {"sha384",     HMAC_ALG_SHA384,     48, 0},
    {"sha512",     HMAC_ALG_SHA512,     64, 0},
    {"sha512-224", HMAC_ALG_SHA512_224, 28, 0},
    {"sha512-256", HMAC_ALG_SHA512_256, 32, 0},
    {"sha512t",    HMAC_ALG_SHA512_T,   0,  1},
    {"sha3-224",   HMAC_ALG_SHA3_224,   28, 0},
    {"sha3-256",   HMAC_ALG_SHA3_256,   32, 0},
    {"sha3-384",   HMAC_ALG_SHA3_384,   48, 0},
    {"sha3-512",   HMAC_ALG_SHA3_512,   64, 0},
    {"shake128",   HMAC_ALG_SHAKE128,   0,  1},
    {"shake256",   HMAC_ALG_SHAKE256,   0,  1},
    {"sm3",        HMAC_ALG_SM3,        32, 0},
};

static int setup_ctx(const char *name, unsigned int len, TEST_CTX *ctx)
{
    struct string2hash *item = NULL;

    for (item=&hash_lists[0]; item<=&hash_lists[HMAC_ALG_MAX-1]; item++)
    {
        if (strncmp(name, item->name, len) ==  0)
        {
            ctx->alg = item->alg;
            ctx->md_size = item->md_size;

            return ERR_OK;
        }
    }

    ctx->alg = HMAC_ALG_INVALID;

    return ERR_ERR;
}

/*
 * Print a usage message
 */
void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage:\n"
        "Common options: [-a alg] [-t num1] [-d num2] [-k key] [-x|-f file|-s string|-h]\n"
        "Hash a string:\n"
            "\t%s -a alg [-t ext] [-t num1] [-d num2] -s string\n"
        "Hash a file:\n"
            "\t%s -a alg [-t ext] [-t num1] [-d num2] -f file\n"
        "-a\tHash algorithm: \"md2|md4|md5|sha1|sha224|sha256|sha484|sha512|sha512-224|sha512-256|sha512t|sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256|sm3\", default: sha512\n"
        "-d\td value for shake128/shake256, default: shake128(num2=128), shake256(num=256)\n"
        "-t\tt value for sha512t algorithm\n"
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
static int hmac_string(const char *argv0, TEST_CTX *ctx, const char *key, uint32_t key_len, const unsigned char *string, uint32_t len)
{
    printf("%s(\"%s\") = ", argv0, string);

    if (ctx->ext)
    {
        HMAC_Ex(ctx->alg, key, key_len, string, len, ctx->md, ctx->ext);
    }
    else
    {
        HMAC(ctx->alg, key, key_len, string, len, ctx->md);
    }

    print_digest(ctx->md, ctx->md_size);
    printf("\n");

    return 0;
}

/*
 * Hash a file and print the digest
 */
static int hmac_file(const char *argv0, TEST_CTX *ctx, const char *key, uint32_t key_len, const char *filename)
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

        if (ctx->ext)
        {
            HMAC_Init_Ex(&ctx->impl, ctx->alg, key, key_len, ctx->ext);
        }
        else
        {
            HMAC_Init(&ctx->impl, ctx->alg, key, key_len);
        }

        while ((len = fread(buf, 1, FILE_BLOCK_SIZE, f)))
        {
            HMAC_Update(&ctx->impl, buf, len);
        }

        HMAC_Final(ctx->md, &ctx->impl);
        HMAC_UnInit(&ctx->impl);

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
static void hmac_stdin(const char *argv0, TEST_CTX *ctx,  const char *key, uint32_t key_len)
{
    int len;
    unsigned char buf[FILE_BLOCK_SIZE];

    if (ctx->ext)
    {
        HMAC_Init_Ex(&ctx->impl, ctx->alg, key, key_len, ctx->ext);
    }
    else
    {
        HMAC_Init(&ctx->impl, ctx->alg, key, key_len);
    }

    while ((len = fread(buf, 1, FILE_BLOCK_SIZE, stdin)))
    {
        HMAC_Update(&ctx->impl, buf, len);
    }
    HMAC_Final(ctx->md, &ctx->impl);
    HMAC_UnInit(&ctx->impl);

    printf("%s(stdin) = ", argv0);
    print_digest(ctx->md, ctx->md_size);
    printf("\n");
}

/*
 * $ ./hash -h
 * Usage:
 * Common options: [-a alg] [-t num1] [-d num2] [-x|-f file|-s string|-h]
 * Hash a string:
 *         ./hash -a alg [-t ext] [-t num1] [-d num2] -s string
 * Hash a file:
 *         ./hash -a alg [-t ext] [-t num1] [-d num2] -f file
 * -a      Hash algorithm: "md2|md4|md5|sha1|sha224|sha256|sha484|sha512|sha512-224|sha512-256|sha512t|sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256", default: sha512
 * -d      d value for shake128/shake256, default: shake128(num2=128), shake256(num=256)
 * -t      t value for sha512t algorithm
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

    /* d value for SHAKE128/SHAKE256 */
    uint32_t d = 0;

    /* t value for SHA512/t */
    uint32_t t = 0;

    char alg[HASH_NAME_SIZE];
    uint32_t alg_len = 0;

    char *key = NULL;
    uint32_t key_len = 0;

    char *str = NULL;
    uint32_t len = 0;

    char *filename = NULL;

    TEST_CTX ctx;
    memset(&ctx, 0, sizeof(TEST_CTX));

    while ((ch = getopt(argc, argv, "a:s:f:t:d:k:xh")) != -1)
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
            case 'k':
                key = optarg;
                key_len = strlen(key);
                if (( NULL == key) || (0 == key_len))
                {
                    usage(argv[0]);
                }
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
            case 'd':
                d = atoi(optarg);
                if ((d == 0) || (d%8))
                {
                    usage(argv[0]);
                }
                break;
            case 't':
                t = atoi(optarg);
                if ((t>=512) || (t==384) || (t%8!=0))
                {
                    usage(argv[0]);
                }
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
     * Setup ctx
     */
    rc = setup_ctx(alg, alg_len, &ctx);
    if (rc != ERR_OK)
    {
        usage(argv[0]);
    }

    /* setup ext for SHA-512/t */
    if (ctx.alg == HMAC_ALG_SHA512_T)
    {
        if ((t==0) || (t%8!=0) || (t>=512))
        {
            usage(argv[0]);
        }
        else
        {
            ctx.ext = t;
            ctx.md_size = t / 8;
        }
    }

    /* setup ext for SHAKE128/SHAKE256 */
    if (ctx.alg == HMAC_ALG_SHAKE128)
    {
        if (d == 0)  /* 't' is not set, set to 128 bits, same as 'openssl dgst -shake128' */
            d = 128;
        ctx.ext = d;
        ctx.md_size = d / 8;
    }
    else if (ctx.alg == HMAC_ALG_SHAKE256)
    {
        if (d == 0)  /* 't' is not set, set to 256 bits, same as 'openssl dgst -shake256' */
            d = 256;
        ctx.ext = d;
        ctx.md_size = d / 8;
    }

    /* allocate buffer for message digest */
    ctx.md = (unsigned char *)malloc(ctx.md_size);
    if (NULL == ctx.md)
    {
        printf("Out Of Memory in %s\n", __FUNCTION__);
        return 0;
    }
    memset(ctx.md, 0, ctx.md_size);

    if (hash_internal)
    {
        //internal_digest_tests(alg, &ctx);
        printf("No internal tests availble!\n");
    }

    if (hash_str)
    {
        hmac_string(alg, &ctx, key, key_len, (unsigned char *)str, len);
    }

    if (hash_file)
    {
        hmac_file(alg, &ctx, key, key_len, filename);
    }

    if (hash_stdin)
    {
        hmac_stdin(alg, &ctx, key, key_len);
    }

    free(ctx.md);
    ctx.md = NULL;

    return 0;
}