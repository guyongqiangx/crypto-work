#include <stdio.h>
#include <string.h>
#include "gmp.h"
#include "hash.h"
#include "pkcs1-v1_5.h"

// test vector: 186-2rsatestvectors\SigGen15_186-2.rsp
static char *str_n = "c8a2069182394a2ab7c3f4190c15589c56a2d4bc42dca675b34cc950e24663048441e8aa593b2bc59e198b8c257e882120c62336e5cc745012c7ffb063eebe53f3c6504cba6cfe51baa3b6d1074b2f398171f4b1982f4d65caf882ea4d56f32ab57d0c44e6ad4e9cf57a4339eb6962406e350c1b15397183fbf1f0353c9fc991";
static char *str_e = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";

//SHAAlg = SHA1
static char *str_m1 = "e8312742ae23c456ef28a23142c4490895832765dadce02afe5be5d31b0048fbeee2cf218b1747ad4fd81a2e17e124e6af17c3888e6d2d40c00807f423a233cad62ce9eaefb709856c94af166dba08e7a06965d7fc0d8e5cb26559c460e47bc088589d2242c9b3e62da4896fab199e144ec136db8d84ab84bcba04ca3b90c8e5";
static char *str_s1 = "28928e19eb86f9c00070a59edf6bf8433a45df495cd1c73613c2129840f48c4a2c24f11df79bc5c0782bcedde97dbbb2acc6e512d19f085027cd575038453d04905413e947e6e1dddbeb3535cdb3d8971fe0200506941056f21243503c83eadde053ed866c0e0250beddd927a08212aa8ac0efd61631ef89d8d049efb36bb35f";
static char arr_m1[] = {
    0xe8, 0x31, 0x27, 0x42, 0xae, 0x23, 0xc4, 0x56, 0xef, 0x28, 0xa2, 0x31, 0x42, 0xc4, 0x49, 0x08,
    0x95, 0x83, 0x27, 0x65, 0xda, 0xdc, 0xe0, 0x2a, 0xfe, 0x5b, 0xe5, 0xd3, 0x1b, 0x00, 0x48, 0xfb,
    0xee, 0xe2, 0xcf, 0x21, 0x8b, 0x17, 0x47, 0xad, 0x4f, 0xd8, 0x1a, 0x2e, 0x17, 0xe1, 0x24, 0xe6,
    0xaf, 0x17, 0xc3, 0x88, 0x8e, 0x6d, 0x2d, 0x40, 0xc0, 0x08, 0x07, 0xf4, 0x23, 0xa2, 0x33, 0xca,
    0xd6, 0x2c, 0xe9, 0xea, 0xef, 0xb7, 0x09, 0x85, 0x6c, 0x94, 0xaf, 0x16, 0x6d, 0xba, 0x08, 0xe7,
    0xa0, 0x69, 0x65, 0xd7, 0xfc, 0x0d, 0x8e, 0x5c, 0xb2, 0x65, 0x59, 0xc4, 0x60, 0xe4, 0x7b, 0xc0,
    0x88, 0x58, 0x9d, 0x22, 0x42, 0xc9, 0xb3, 0xe6, 0x2d, 0xa4, 0x89, 0x6f, 0xab, 0x19, 0x9e, 0x14,
    0x4e, 0xc1, 0x36, 0xdb, 0x8d, 0x84, 0xab, 0x84, 0xbc, 0xba, 0x04, 0xca, 0x3b, 0x90, 0xc8, 0xe5
};
static char arr_s1[] = {
    0x28, 0x92, 0x8e, 0x19, 0xeb, 0x86, 0xf9, 0xc0, 0x00, 0x70, 0xa5, 0x9e, 0xdf, 0x6b, 0xf8, 0x43,
    0x3a, 0x45, 0xdf, 0x49, 0x5c, 0xd1, 0xc7, 0x36, 0x13, 0xc2, 0x12, 0x98, 0x40, 0xf4, 0x8c, 0x4a,
    0x2c, 0x24, 0xf1, 0x1d, 0xf7, 0x9b, 0xc5, 0xc0, 0x78, 0x2b, 0xce, 0xdd, 0xe9, 0x7d, 0xbb, 0xb2,
    0xac, 0xc6, 0xe5, 0x12, 0xd1, 0x9f, 0x08, 0x50, 0x27, 0xcd, 0x57, 0x50, 0x38, 0x45, 0x3d, 0x04,
    0x90, 0x54, 0x13, 0xe9, 0x47, 0xe6, 0xe1, 0xdd, 0xdb, 0xeb, 0x35, 0x35, 0xcd, 0xb3, 0xd8, 0x97,
    0x1f, 0xe0, 0x20, 0x05, 0x06, 0x94, 0x10, 0x56, 0xf2, 0x12, 0x43, 0x50, 0x3c, 0x83, 0xea, 0xdd,
    0xe0, 0x53, 0xed, 0x86, 0x6c, 0x0e, 0x02, 0x50, 0xbe, 0xdd, 0xd9, 0x27, 0xa0, 0x82, 0x12, 0xaa,
    0x8a, 0xc0, 0xef, 0xd6, 0x16, 0x31, 0xef, 0x89, 0xd8, 0xd0, 0x49, 0xef, 0xb3, 0x6b, 0xb3, 0x5f
};

//SHAAlg = SHA1
static char *str_m2 = "4c95073dac19d0256eaadff3505910e431dd50018136afeaf690b7d18069fcc980f6f54135c30acb769bee23a7a72f6ce6d90cbc858c86dbbd64ba48a07c6d7d50c0e9746f97086ad6c68ee38a91bbeeeb2221aa2f2fb4090fd820d4c0ce5ff025ba8adf43ddef89f5f3653de15edcf3aa8038d4686960fc55b2917ec8a8f9a8";
static char *str_s2 = "53ab600a41c71393a271b0f32f521963087e56ebd7ad040e4ee8aa7c450ad18ac3c6a05d4ae8913e763cfe9623bd9cb1eb4bed1a38200500fa7df3d95dea485f032a0ab0c6589678f9e8391b5c2b1392997ac9f82f1d168878916aace9ac7455808056af8155231a29f42904b7ab87a5d71ed6395ee0a9d024b0ca3d01fd7150";

// $ gcc pkcs1-v1_5_test.c pkcs1-v1_5.c -o pkcs-v1_5-test -I../out/gmp/include -L../out/gmp/lib -lgmp -I../out/include -L../out/lib -lhash -lrand
int main(int argc, char *argv[])
{
    int i;
    size_t count;
    mpz_t n, e;
    mpz_t m1, s1, em1, res;
    //mpz_t m2, s2, em2;
    char buf[512];

    //mpz_inits(n, e);
    //mpz_inits(m1, s1, em1);
    mpz_init(em1);
    mpz_init(res);

    mpz_init_set_str(n, str_n, 16);
    mpz_init_set_str(e, str_e, 16);

    mpz_init_set_str(m1, str_m1, 16);
    mpz_init_set_str(s1, str_s1, 16);

    gmp_printf("  n: %Zx\n", n);
    gmp_printf("  e: %Zx\n", e);
    gmp_printf(" m1: %Zx\n", m1);
    gmp_printf(" s1: %Zx\n", s1);

    EMSA_PKCS1_v1_5_Encode(HASH_ALG_SHA1, arr_m1, sizeof(arr_m1)/sizeof(arr_m1[0]), 128, buf);

    printf("origin m1:\n");
    for (i=0; i<128; i++)
    {
        printf("%02x ", ((unsigned char *)arr_m1)[i]);
        if (i % 16 == 15)
        {
            printf("\n");
        }
    }
    printf("\n");

    printf("encoding m1:\n");
    for (i=0; i<128; i++)
    {
        printf("%02x ", ((unsigned char *)buf)[i]);
        if (i % 16 == 15)
        {
            printf("\n");
        }
    }
    printf("\n");

    // 从 buf 中加载到 em1
    mpz_import(em1, 128, 1, 1, 0, 0, buf);
    gmp_printf("em1: %Zx\n", em1);

    mpz_powm(res, em1, e, n); /* res = em1 ^ e mod n */
    gmp_printf("res: %Zx\n", res);

    memset(buf, 0, sizeof(buf));
    // 从 res 中导出到 buf
    mpz_export(buf, &count, 1, 1, 0, 0, res);
    printf("res(%ld):\n", count);
    for (i=0; i<count; i++)
    {
        printf("%02x ", ((unsigned char *)buf)[i]);
        if (i % 16 == 15)
        {
            printf("\n");
        }
    }
    printf("\n");

    mpz_clear(m1);
    mpz_clear(s1);
    mpz_clear(em1);
    mpz_clear(res);
    mpz_clear(n);
    mpz_clear(e);

    printf("done!\n");

    return 0;
}

/*
 * 1. 生成 1024 bit RSA 私钥
 * openssl genrsa -out rsa_priv.pem -f4 1024
 *
 * 2. 将 PEM 格式的私钥存储为 text 格式
 * openssl rsa -inform PEM -in rsa_priv.pem -text -out rsa_priv.txt
 *
 * 3. 从私钥导出公钥
 * openssl rsa -inform PEM -in rsa_priv.pem -pubout -out rsa_pub.pem
 *
 * 4. 以 txt 格式显示公钥
 * openssl rsa -inform PEM -in rsa_pub.pem -pubin -text
 */

/*
 * SHA1 填充的 DER 结构解析
 * $ echo -n "30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 c8 91 9f 90 87 28 2f 20 59 f1 12 b5 5f aa e3 c6 46 2f 44 69" | xxd -r -ps | openssl asn1parse -inform DER
 *     0:d=0  hl=2 l=  33 cons: SEQUENCE                                                          --> 30  21 [30  09  06  05  2b  0e  03  02  1a  05  00  04  14  c8  91  9f  90  87  28  2f  20  59  f1  12  b5  5f  aa  e3  c6  46  2f  44  69]
 *     2:d=1  hl=2 l=   9 cons: SEQUENCE                                                          -->         30  09 [06  05  2b  0e  03  02  1a  05  00]
 *     4:d=2  hl=2 l=   5 prim: OBJECT        :sha1                                               -->                 06  05 [2b  0e  03  02  1a]
 *    11:d=2  hl=2 l=   0 prim: NULL                                                              -->                                             05  00[]
 *    13:d=1  hl=2 l=  20 prim: OCTET STRING  [HEX DUMP]:C8919F9087282F2059F112B55FAAE3C6462F4469 -->                                                     04  14 [c8  91  9f  90  87  28  2f  20  59  f1  12  b5  5f  aa  e3  c6  46  2f  44  69]
 *
 * 30  21 [30  09  06  05  2b  0e  03  02  1a  05  00  04  14  c8  91  9f  90  87  28  2f  20  59  f1  12  b5  5f  aa  e3  c6  46  2f  44  69]
 *         30  09 [06  05  2b  0e  03  02  1a  05  00] 04  14 [c8  91  9f  90  87  28  2f  20  59  f1  12  b5  5f  aa  e3  c6  46  2f  44  69]
 *                 06  05 [2b  0e  03  02  1a] 05  00[]
 */