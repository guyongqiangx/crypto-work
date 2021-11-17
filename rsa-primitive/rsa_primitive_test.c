#include <stdio.h>
#include <string.h>
#include "gmp.h"
#include "hash.h"
#include "pkcs1-v1_5.h"

// Test Vector: FIPS 186-4 RSA PKCS1-v1_5 RSASP1 Signature Primitive Component Test Vectors
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/RSA2SP1testvectors.zip
// RSA2SP1testvectors\RSASP1.fax
static char   *str_n = "bad47a84c1782e4dbdd913f2a261fc8b65838412c6e45a2068ed6d7f16e9cdf4462b39119563cafb74b9cbf25cfd544bdae23bff0ebe7f6441042b7e109b9a8afaa056821ef8efaab219d21d6763484785622d918d395a2a31f2ece8385a8131e5ff143314a82e21afd713bae817cc0ee3514d4839007ccb55d68409c97a18ab62fa6f9f89b3f94a2777c47d6136775a56a9a0127f682470bef831fbec4bcd7b5095a7823fd70745d37d1bf72b63c4b1b4a3d0581e74bf9ade93cc46148617553931a79d92e9e488ef47223ee6f6c061884b13c9065b591139de13c1ea2927491ed00fb793cd68f463f5f64baa53916b46c818ab99706557a1c2d50d232577d1";
static char   *str_p = "e7c9e4b3e5d7ac9e83be08328105356dfeefe222f26c95378effd2150fadf7ba23f5b4705d82e4f1bc45057067c7def73e2100f756ee6d547965fa4f24b85d68867f03d7c886d1dbcca4c589745701b362a1f1417f471d8475b6b7a16a4c48ef1f556edc3f0ff6ba13d365d6e82751f207d91101c8eea1013ccdd9e1de4c387f";
static char   *str_q = "ce58602e051f0f4647c4ec57f682e5737fc482a8a1ffac9043bba4fba3387d7dd2154507af1e28bd81b61fcdfe35f9734e0d9b53682ec785f1f6e6224f63d10bf78484b83a4254f333d0fb3f3e9e1834bede52e3078ac279a862fb90af266d7591c81f20b718d07d51bfc221b66a25403b4ac1a68d673fdd959b01ecf3d0a7af";
static char   *str_e = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
static char   *str_d = "40d60f24b61d76783d3bb1dc00b55f96a2a686f59b3750fdb15c40251c370c65cada222673811bc6b305ed7c90ffcb3abdddc8336612ff13b42a75cb7c88fb936291b523d80acce5a0842c724ed85a1393faf3d470bda8083fa84dc5f31499844f0c7c1e93fb1f734a5a29fb31a35c8a0822455f1c850a49e8629714ec6a2657efe75ec1ca6e62f9a3756c9b20b4855bdc9a3ab58c43d8af85b837a7fd15aa1149c119cfe960c05a9d4cea69c9fb6a897145674882bf57241d77c054dc4c94e8349d376296137eb421686159cb878d15d171eda8692834afc871988f203fc822c5dcee7f6c48df663ea3dc755e7dc06aebd41d05f1ca2891e2679783244d068f";

static char *str_em1 = "70992c9d95a4908d2a94b3ab9fa1cd643f120e326f9d7808af50cac42c4b0b4eeb7f0d4df303a568fbfb82b0f58300d25357645721bb71861caf81b27a56082c80a146499fb4eab5bde4493f5d00f1a437bbc360dfcd8056fe6be10e608adb30b6c2f7652428b8d32d362945982a46585d2102ef7995a8ba6e8ad8fd16bd7ae8f53c3d7fcfba290b57ce7f8f09c828d6f2d3ce56f131bd9461e5667e5b73edac77f504dac4f202a9570eb4515b2bf516407db831518db8a2083ec701e8fd387c430bb1a72deca5b49d429cf9deb09cc4518dc5f57c089aa2d3420e567e732102c2c92b88a07c69d70917140ab3823c63f312d3f11fa87ba29da3c7224b4fb4bc";
static char  *str_s1 = "7e65b998a05f626b028c75dc3fbf98963dce66d0f4c3ae4237cff304d84d8836cb6bad9ac86f9d1b8a28dd70404788b869d2429f1ec0663e51b753f7451c6b4645d99126e457c1dac49551d86a8a974a3131e9b371d5c214cc9ff240c299bd0e62dbc7a9a2dad9fa5404adb00632d36332d5be6106e9e6ec81cac45cd339cc87abbe7f89430800e16e032a66210b25e926eda243d9f09955496ddbc77ef74f17fee41c4435e78b46965b713d72ce8a31af641538add387fedfd88bb22a42eb3bda40f72ecad941dbffdd47b3e77737da741553a45b630d070bcc5205804bf80ee2d51612875dbc4796960052f1687e0074007e6a33ab8b2085c033f9892b6f74";

#if 1
// $ gcc pkcs1-v1_5_test.c pkcs1-v1_5.c -o pkcs-v1_5-test -I../out/gmp/include -L../out/gmp/lib -lgmp -I../out/include -L../out/lib -lhash -lrand
int main(int argc, char *argv[])
{
    int i;
    size_t count;
    mpz_t n, e, d;
    mpz_t m1, s1, em1, res;
    char buf[512];

    mpz_init_set_str(n, str_n, 16);
    mpz_init_set_str(e, str_e, 16);
    mpz_init_set_str(d, str_d, 16);

    mpz_init_set_str(em1, str_em1, 16);
    mpz_init_set_str(s1, str_s1, 16);

    mpz_init(m1);
    mpz_init(res);

    gmp_printf("  n: %Zx\n", n);
    gmp_printf("  e: %Zx\n", e);
    gmp_printf("em1: %Zx\n", em1);
    gmp_printf(" s1: %Zx\n", s1);

    // signature primitive, s = m ^ d mod n
    printf("RSASP1:\n");
    mpz_powm(res, em1, d, n); /* s = res = em1 ^ d mod n */
    gmp_printf("res: %Zx\n", res);

    // 从 res 中导出到 buf
    mpz_export(buf, &count, 1, 1, 0, 0, res);
    for (i=0; i<count; i++)
    {
        printf("%02x ", ((unsigned char *)buf)[i]);
        if (i % 16 == 15)
        {
            printf("\n");
        }
    }

    // verification primitive, m = s ^ e mode n
    printf("RSAVP1:\n");
    mpz_powm(res, s1, e, n); /* em1 = res = s ^ e mod n */
    gmp_printf("res: %Zx\n", res);

    mpz_export(buf, &count, 1, 1, 0, 0, res);
    for (i=0; i<count; i++)
    {
        printf("%02x ", ((unsigned char *)buf)[i]);
        if (i % 16 == 15)
        {
            printf("\n");
        }
    }
#if 0
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
#endif
    mpz_clear(m1);
    mpz_clear(s1);
    mpz_clear(em1);
    mpz_clear(res);

    mpz_clear(d);
    mpz_clear(e);
    mpz_clear(n);

    printf("done!\n");

    return 0;
}
#else
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
#endif

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