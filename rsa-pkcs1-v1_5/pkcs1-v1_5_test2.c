#include <stdio.h>
#include <string.h>
#include "gmp.h"
#include "hash.h"
#include "pkcs1-v1_5.h"
#include "utils.h"

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

// $ gcc pkcs1-v1_5_test2.c pkcs1-v1_5.c -o pkcs-v1_5-test -I../out/gmp/include -L../out/gmp/lib -lgmp -I../out/include -L../out/lib -lutils -lhash -lrand
int main(int argc, char *argv[])
{
    size_t count;
    mpz_t n, e, d;
    mpz_t m1, s1, em1, res;
    unsigned char buf[512];

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
    dump(NULL, buf, count);

    // verification primitive, m = s ^ e mode n
    printf("RSAVP1:\n");
    mpz_powm(res, s1, e, n); /* em1 = res = s ^ e mod n */
    gmp_printf("res: %Zx\n", res);

    mpz_export(buf, &count, 1, 1, 0, 0, res);
    dump(NULL, buf, count);

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