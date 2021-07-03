/*
 * @        file: 
 * @ description: 
 * @      author: Yongqiang Gu
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

void usage(const char *argv0)
{
    #if 0
    fprintf(stderr,
        "Usage:\n"
        "Common options: -alg [-t num|-d num] [-k key] [-x|-f file|-s string|-h]\n"
        "HMAC a string:\n"
            "\t%s -alg [-t num|-d num] [-k key] -s string\n"
        "HMAC a file:\n"
            "\t%s -alg [-t num|-d num] [-k key] -f file\n"
        "HMAC standard input:\n"
            "\t%s -alg [-t num|-d num] [-k key] -\n"
        " -md2           MD2 hash algorithm\n"
        " -md4           MD4 hash algorithm\n"
        " -md5           MD5 hash algorithm\n"
        " -sha1          SHA1 hash algorithm\n"
        " -sha224        SHA224 hash algorithm\n"
        " -sha256        SHA256 hash algorithm\n"
        " -sha384        SHA384 hash algorithm\n"
        " -sha512        SHA512 hash algorithm\n"
        " -sha512-224    SHA512-224 hash algorithm\n"
        " -sha512-256    SHA512-256 hash algorithm\n"
        " -sha512t       SHA512/t hash algorithm\n"
        " -sha3-224      SHA3-224 hash algorithm\n"
        " -sha3-256      SHA3-256 hash algorithm\n"
        " -sha3-384      SHA3-384 hash algorithm\n"
        " -sha3-512      SHA3-512 hash algorithm\n"
        " -shake128      SHAKE128 hash algorithm\n"
        " -shake256      SHAKE256 hash algorithm\n"
        " -sm3           SM3 hash algorithm\n"
        , argv0, argv0, argv0);
    #else
    fprintf(stderr, "Usage: %s -alg [-t num|-d num] [-k key] [-x|-f file|-s string|-h]\n", argv0);
    #endif
    exit(1);
}

void show_algorithm(const char *argv0)
{
    fprintf(stderr, "Support hash algorithm list:\n"
        "        -md2  MD2 hash algorithm\n"
        "        -md4  MD4 hash algorithm\n"
        "        -md5  MD5 hash algorithm\n"
        "       -sha1  SHA1 hash algorithm\n"
        "     -sha224  SHA224 hash algorithm\n"
        "     -sha256  SHA256 hash algorithm\n"
        "     -sha384  SHA384 hash algorithm\n"
        "     -sha512  SHA512 hash algorithm\n"
        " -sha512-224  SHA512-224 hash algorithm\n"
        " -sha512-256  SHA512-256 hash algorithm\n"
        "    -sha512t  SHA512/t hash algorithm\n"
        "   -sha3-224  SHA3-224 hash algorithm\n"
        "   -sha3-256  SHA3-256 hash algorithm\n"
        "   -sha3-384  SHA3-384 hash algorithm\n"
        "   -sha3-512  SHA3-512 hash algorithm\n"
        "   -shake128  SHAKE128 hash algorithm\n"
        "   -shake256  SHAKE256 hash algorithm\n"
        "        -sm3  SM3 hash algorithm\n"
    );
    exit(1);
}

static struct option long_options[] =
{
    /* name,        has_arg,            flag,   val */
    {"md2",         no_argument,        0,      0},
    {"md4",         no_argument,        0,      0},
    {"md5",         no_argument,        0,      0},
    {"sha1",        no_argument,        0,      0},
    {"sha224",      no_argument,        0,      0},
    {"sha256",      no_argument,        0,      0},
    {"sha384",      no_argument,        0,      0},
    {"sha512",      no_argument,        0,      0},
    {"sha512-224",  no_argument,        0,      0},
    {"sha512-256",  no_argument,        0,      0},
    {"sha512t",     required_argument,  0,      't'},   /* Can be '-sha512t=t' or '-sha512t t' */
    {"sha3-224",    no_argument,        0,      0},
    {"sha3-256",    no_argument,        0,      0},
    {"sha3-384",    no_argument,        0,      0},
    {"sha3-512",    no_argument,        0,      0},
    {"shake128",    optional_argument,  0,      'd'},   /* MUST BE: -shake128=d */
    {"shake256",    optional_argument,  0,      'd'},   /* MUST BE: -shake256=d */
    {"sm3",         no_argument,        0,      0},
    {"s",           required_argument,  0,      's'},
    {"file",        required_argument,  0,      'f'},
    {"l",           no_argument,        0,      'l'},
    {"list",        no_argument,        0,      'l'},
    {"h",           no_argument,        0,      'h'},
    {"help",        no_argument,        0,      'h'},
    {0,             0,                  0,      0}
};

int main(int argc, char *argv[])
{
    unsigned int d, t;
    int ch;

    char *cur_arg = NULL;

    int option_idx; /* option index */

    while ((ch=getopt_long_only(argc, argv, "", long_options, &option_idx)) != -1)
    {
        cur_arg = argv[optind-1];
        if (cur_arg != NULL)
            printf("cur_arg=%s\n", cur_arg);
        else
            printf("cur_arg=NULL\n");

        if ((cur_arg != NULL) && (cur_arg[0] == '-') && (cur_arg[1] == '-'))
        {
            printf("I don't like '--option'\n");
            usage(argv[0]);
        }

        /* only accept options like '-sha1' */
        if ((strlen(long_options[option_idx].name) != strlen(argv[optind-1])-1))
        {
            printf("invalid params!\n");
            usage(argv[0]);
        }
        if (option_idx < sizeof(long_options)/sizeof(struct option))
        {
            printf("option %s", long_options[option_idx].name);
        }
        
        switch(ch)
        {
        case 0:
            //printf("option %s", long_options[option_idx].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");
            break;
        case 'd':
            if (optarg)
            {
                printf("d=%s\n", optarg);
            }
            break;
        case 'f':
            if (optarg)
            {
                printf("f=%s\n", optarg);
            }
            break;
        case 's':
            if (optarg)
            {
                printf("s=%s\n", optarg);
            }
            break;
        case 't':
            if (optarg)
            {
                printf("t=%s\n", optarg);
            }
            break;
        case 'l':
            show_algorithm(argv[0]);
            break;
        case 'h':
            usage(argv[0]);
            break;
        case '?':
            printf("Here!\n");
            usage(argv[0]);
            break;
        default:
            printf("?? getopt returned character code 0%o ??\n", ch);
            break;
        }
    }

    if (optind < argc)
    {
        printf("Files:");
        while (optind < argc)
            printf(" %s", argv[optind++]);
        printf("\n");
    }

    return EXIT_SUCCESS;
}