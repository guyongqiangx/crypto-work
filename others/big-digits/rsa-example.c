/*
 * $ gcc rsa-example.c -o rsatest -I/public/ygu/cryptography/crypto-work.git/out/gmp/include -L/public/ygu/cryptography/crypto-work.git/out/gmp/lib -lgmp
 */

/*
 * A format specification is of the form
 * % [flags] [width] [.[precision]] [type] conv
 * GMP adds types ‘Z’, ‘Q’ and ‘F’ for mpz_t, mpq_t and mpf_t respectively,
 * ‘M’ for mp_limb_t, and ‘N’ for an mp_limb_t array.
 *
 * ‘Z’, ‘Q’, ‘M’ and ‘N’ behave like integers.
 * ‘Q’ will print a ‘/’ and a denominator, if needed.
 * ‘F’ behaves like a float.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <gmp.h>

/*
 * 1. 选择两个素数 p, q;
 * 2. 计算 n = p x q;
 * 3. 计算 Φ(n) = Φ(p) x Φ(q) = (p-1) x (q-1);
 * 4. 选择 e, 是的 e ∈ {0, 1, ..., Φ(n)-1}, 且 gcd(e, Φ(n)) = 1;
 * 5. 计算 d, 是的 ed ≡ 1 mod Φ(n);
 * Kpub(e, n), Kpr(d, n)
 * Y = X^e mod n, X = Y^d mod n
 *
 * ASN.1 key structures in DER:
 *
 * RSAPublicKey ::= SEQUENCE {
 *     modulus           INTEGER,  -- n
 *     publicExponent    INTEGER   -- e
 * }
 *
 * RSAPrivateKey ::= SEQUENCE {
 *   version           Version,
 *   modulus           INTEGER,  -- n
 *   publicExponent    INTEGER,  -- e
 *   privateExponent   INTEGER,  -- d
 *   prime1            INTEGER,  -- p
 *   prime2            INTEGER,  -- q
 *   exponent1         INTEGER,  -- d mod (p-1)
 *   exponent2         INTEGER,  -- d mod (q-1)
 *   coefficient       INTEGER,  -- (inverse of q) mod p
 *   otherPrimeInfos   OtherPrimeInfos OPTIONAL
 * }
 */

/*
 * Export private key file to public key file:
 * $ openssl rsa -in rsa_private_key.txt -pubout | openssl rsa -pubin -text -out rsa_public_key.txt
 */

#include <stdio.h>
#include <stdarg.h>
#include <gmp.h>

// mpz_mod(mpz_t r, const mpz_t n, const mpz_t d)
// mpz_powm_ui(mpz_t rop, const mpz_t base, unsigned long int exp, const mpz_t mod)

static int generate_prime_integer(unsigned long int bits, gmp_randstate_t state, mpz_t big_int);

// Fast Exponentiation, rop = n ^ exp
void fast_exp(mpz_t rop, mpz_t x, unsigned long int exp, const mpz_t n)
{
    int i;
    unsigned long int temp;
    mpz_t m;

    mpz_init(m);

    // 1. 找到最高为 1 的位
    temp = exp;
    i = -1;
    while (temp)
    {
        temp >>= 1;
        i ++;
    }

    // rop = x;
    mpz_set(rop, x);
    i --;

    while (i > 0)
    {
        // square
        mpz_mul(m, rop, rop); // m = rop ^ 2;
        mpz_mod(m, m, n);     // m = m mod n;

        // multiple
        if (exp & (0x1 << i))
        {
            mpz_mul(m, m, x);  // m = m * x;
            mpz_mod(m, m, n);  // m = m mod n;
        }

        mpz_set(rop, m);

        i --;
    }

    mpz_clear(m);
}

#if 0
int main(int argc, char *argv[])
{
    int i, len;
    gmp_randstate_t state;
    mpz_t p, q, n, fn, e, d;

    mpz_t plain, cipher;

    len = 1024;

    gmp_randinit_default(state);

    mpz_inits(p, q, n, fn, e, d, plain, cipher, NULL);

    generate_prime_integer(len, state, p);
    gmp_printf("P: %Zx\n", p);

    generate_prime_integer(len, state, q);
    gmp_printf("Q: %Zx\n", q);

    mpz_mul(n, p, q);     // n = p x q
    gmp_printf("N: %Zx\n", fn);

    mpz_sub_ui(p, p, 1);  // p = p - 1
    mpz_sub_ui(q, q, 1);  // q = q - 1
    mpz_mul(fn, p, q);    // Φ(N) = Φ(p) x Φ(q) = (p-1) x (q-1)
    gmp_printf("Φ(N): %Zx\n", fn);

    // void mpz_gcd (mpz_t rop, const mpz_t op1, const mpz_t op2)
    // void mpz_gcd_ui (mpz_t rop, const mpz_t op1, unsigned long int op2)
    mpz_gcd_ui(e, fn, 65537);
    gmp_printf("gcd(e, Φ(N))= %Zd\n", e);

    mpz_set_ui(e, 65537);
    gmp_printf("e: %Zd\n", e);

    mpz_invert(d, e, fn);
    gmp_printf("d: %Zx\n", d);

    char *msg = "54f7edd9153c3b3ac14ac664e254e50a42556933713c086574e2d82aa76"
                "50ebe03534beb607f4027734eb27cb7dc44c8cc792054dffc148dbd8fa6"
                "a6b2c655bf424e697a71b29efad04b053e3dff253bb10436fb33a9dd1d9"
                "6adecfdea0dbd5327f44f0a718159f68b576357965c7c5b06995589d886"
                "0bd4f945a11a3a2a265c5be0910d0458539740b3807ee87bf688ceb3c8b"
                "81a1272253525b3f66203b1304068d7977ebcbec9e709bb0b5ec764f91e"
                "1daa135e8c8a1640f48027658410947bc389a638b5c92dda0676a7064b5"
                "6b07843e84ae26872d30fee06dddd8e9";
    mpz_init_set_str(plain, msg, 16);
    gmp_printf("plain: %Zx\n", plain);

    //fast_exp(cipher, plain, 65537, n);
    mpz_powm(cipher, plain, e, n);
    gmp_printf("cipher: %Zx\n", cipher);

    mpz_powm(plain, cipher, d, n);
    gmp_printf("plain: %Zx\n", plain);

    mpz_inits(p, q, n, fn, e, d, plain, cipher, NULL);

    gmp_randclear(state);

    return 0;
}
#endif

static int generate_prime_integer(unsigned long int bits, gmp_randstate_t state, mpz_t big_int)
{
    int i;

    mpz_urandomb(big_int, state, bits); /* mp_bitcnt_t is unsigned long int */
    //gmp_printf("%d bits: %Zx\n", bits, big_int);

    // 检查随机数是否为素数
    i = mpz_probab_prime_p (big_int, 25);
    if (0 == i) // 如果不是素数，则生成一个紧挨着的素数
    {
        mpz_nextprime(big_int, big_int);
        //gmp_printf("%d bits: %Zx\n", bits, big_int);

        // 检查随机数是否为素数
        i = mpz_probab_prime_p(big_int, 25);
    }

    return i;
}

/*
 * @description: I2OSP, Integer-to-Octet-String Primitive
 * @param {mpz_t} x, nonnegative integer to be converted
 * @param {unsigned long} xLen, intended length of the resulting octet string
 * @param {unsigned char} *X, corresponding octet string of length xLen
 * @return {*} 0, OK; -1 Fail;
 */
int I2OSP(mpz_t x, unsigned long xLen, char *X)
{
    mpz_t max;
    char format[12]; // unsigned long: 0～4294967295. format="%04294967296Zx"
    int i, res;

    if (X == NULL)
    {
        return -1;
    }

    res = 0;

    mpz_init(max);
    mpz_ui_pow_ui(max, 256, xLen);
    if (mpz_cmp(x, max) > 0)
    {
        printf("integer too large\n");
        res = -1;
    }
    else
    {
        sprintf(format, "%%0%luZx", 2 * xLen);
        gmp_sprintf(X, format, x);
    }
    mpz_clear(max);

    return res;
}

/**
 * @description: OS2IP, Octet-String-to-Integer Primitive
 * @param {char} *X, octet string to be converted
 * @param {mpz_t} x, corresponding onnegative integer
 * @return {*} 0, OK; -1 Fail;
 */
int OS2IP(const char *X, mpz_t x)
{
    if (X == NULL)
    {
        return -1;
    }

    mpz_set_str(x, X, 16);

    return 0;
}

typedef struct {
    mpz_t n;
    unsigned long e;
} *RSAPublicKey;

typedef struct {
    // 0: (n, d); 1: (p, q, dP, dQ, qInv)
    int type;

    // (n, d)
    mpz_t n;
    mpz_t d;

    // (p, q, dP, dQ, qInv)
    mpz_t p;
    mpz_t q;
    mpz_t dP;
    mpz_t dQ;
    mpz_t qInv;
} *RSAPrivateKey;

/**
 * @description: RSAEP, RSA Encryption Primitive
 * @param {RSAPublicKey} key, RSA public key
 * @param {mpz_t} m, message representative, an integer between 0 and n-1
 * @param {mpz_t} c, ciphertext representative, an integer between 0 and n-1
 * @return {*}, 0, OK; -1 Fail;
 */
int RSAEP(RSAPublicKey key, mpz_t m, mpz_t c)
{
    int res = 0;

    res = mpz_cmp(m, key->n);
    if (res > 0)
    {
        printf("message representative out of range\n");
        res = -1;
    }

    mpz_powm_ui(c, m, key->e, key->n);

    gmp_printf("message: %Zx\n", m);
    gmp_printf(" cipher: %Zx\n", c);

    return 0;
}

/**
 * @description: RSADP, RSA Decryption Primitive
 * @param {RSAPrivateKey} key, RSA private key
 * @param {mpz_t} c, ciphertext representative, an integer between 0 and n-1
 * @param {mpz_t} m, message representative, an integer between 0 and n-1
 * @return {*}, 0, OK; -1, Fail;
 */
int RSADP(RSAPrivateKey key, mpz_t c, mpz_t m)
{
    int res = 0;

    if (key->type == 1) // (p, q, dP, dQ, qInv)
    {
        mpz_mul(key->n, key->p, key->q); // n = p x q
    }

    res = mpz_cmp(c, key->n);
    if (res > 0)
    {
        printf("ciphertext representative out of range\n");
        return -1;
    }

    switch (key->type)
    {
    case 0: // (n, d)
        mpz_powm(m, c, key->d, key->n);
        break;
    case 1: // (p, q, dP, dQ, qInv)
    default:
        gmp_printf("Not Implemented Yet!\n");
        break;
    }

    gmp_printf("message: %Zx\n", m);
    gmp_printf(" cipher: %Zx\n", c);

    return 0;
}

/**
 * @description: RSASP1, RSA Signature Primitive, version 1 
 * @param {RSAPrivateKey} key, RSA private key
 * @param {mpz_t} m, message representative, an integer between 0 and n-1
 * @param {mpz_t} s, signature representative, an integer between 0 and n-1
 * @return {*}, 0, OK; -1, Fail;
 */
int RSASP1(RSAPrivateKey key, mpz_t m, mpz_t s)
{
    int res = 0;

    if (key->type == 1) // (p, q, dP, dQ, qInv)
    {
        mpz_mul(key->n, key->p, key->q);
    }

    res = mpz_cmp(m, key->n);
    {
        printf("message representative out of range\n");
        return -1;
    }

    switch (key->type)
    {
    case 0: // (n, d)
        mpz_powm(m, s, key->d, key->n);
        break;
    case 1: // (p, q, dP, dQ, qInv)
    default:
        gmp_printf("Not Implemented Yet!\n");
        break;
    }

    gmp_printf("  message: %Zx\n", m);
    gmp_printf("signature: %Zx\n", s);

    return 0;
}

/**
 * @description: RSAVP1, RSA Verification Primitive, version 1
 * @param {RSAPublicKey} key, RSA public key
 * @param {mpz_t} s, signature representative, an integer between 0 and n-1
 * @param {mpz_t} m, message representative, an integer between 0 and n-1
 * @return {*}, 0, OK; -1, Fail;
 */
int RSAVP1(RSAPublicKey key, mpz_t s, mpz_t m)
{
    int res = 0;

    res = mpz_cmp(s, key->n);
    if (res > 0)
    {
        printf("signature representative out of range\n");
        res = -1;
    }

    mpz_powm_ui(m, s, key->e, key->n);

    gmp_printf(" cipher: %Zx\n", s);
    gmp_printf("message: %Zx\n", m);

    return 0;
}

#include "gtest/gtest.h"

// g++ rsa-example.c -o rsa-example -I/public/ygu/cryptography/crypto-work.git/out/gmp/include -L/public/ygu/cryptography/crypto-work.git/out/gmp/lib -lgmp -I/public/ygu/cryptography/crypto-work.git/out/gtest/include -L/public/ygu/cryptography/crypto-work.git/out/gtest/lib -lgtest_main -lgtest -lpthread
TEST(RSAPrimitive, I2OSPTest)
{
    char buf[256];
    int res;
    mpz_t x;

    mpz_init(x);

    /*
     * Test 1, 10 octets
     */
    const char *str1 = "54f7edd9153c3b3ac14a";
    mpz_set_str(x, str1, 16);

    memset(buf, 0, sizeof(buf));
    res = I2OSP(x, 10, buf);
    EXPECT_EQ(0, res);

    res = strncmp(str1, buf, 10 * 2);
    EXPECT_EQ(0, res);

    /*
     * Test 2, 11 octets, and only 10 octets buffer, error: large integer
     */
    const char *str2 = "54f7edd9153c3b3ac14ace";
    mpz_set_str(x, str2, 16);

    memset(buf, 0, sizeof(buf));
    res = I2OSP(x, 10, buf);
    EXPECT_EQ(-1, res);

    /*
     * Test 3, 30 octets
     */
    const char *str3 = "54f7edd9153c3b3ac14ac664e254e50a42556933713c086574e2d82aa7cd";
    mpz_set_str(x, str3, 16);

    memset(buf, 0, sizeof(buf));
    res = I2OSP(x, 30, buf);
    EXPECT_EQ(0, res);

    res = strncmp(str3, buf, 30 * 2);
    EXPECT_EQ(0, res);

    /*
     * Test 4, 40 octets, prefix '0's
     */
    const char *str4 = "54f7edd9153c3b3ac14ac664e254e50a42556933713c086574e2d82aa7cd";
    mpz_set_str(x, str4, 16);

    memset(buf, 0, sizeof(buf));
    res = I2OSP(x, 40, buf);
    EXPECT_EQ(0, res);

    const char *str5 = "0000000000000000000054f7edd9153c3b3ac14ac664e254e50a42556933713c086574e2d82aa7cd";
    res = strncmp(str5, buf, 40 * 2);
    EXPECT_EQ(0, res);

    mpz_clear(x);
}

TEST(RSAPrimitive, OS2IPTest)
{
    mpz_t x;
    int res;

    mpz_init(x);

    /*
     * Test 1
     */
    const char *str1 = "54f7edd9153c3b3ac14a";
    res = OS2IP(str1, x);
    gmp_printf("%Zx\n", x);
    EXPECT_EQ(res, 0);

    /*
     * Test 2
     */
    const char *str2 = "54f7edd9153c3b3ac14ac664e254e50a42556933713c086574e2d82aa7cd";
    res = OS2IP(str2, x);
    gmp_printf("%Zx\n", x);
    EXPECT_EQ(res, 0);

    /*
     * Test 3
     */
    const char *str3 = "000000000000000000ac54f7edd9153c3b3ac14ac664e254e50a42556933713c086574e2d82aa7cd";
    res = OS2IP(str3, x);
    gmp_printf("%Zx\n", x);
    gmp_printf("%050Zx\n", x);
    EXPECT_EQ(res, 0);

    mpz_clear(x);
}