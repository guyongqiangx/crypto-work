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

int main(int argc, char *argv[])
{
    int i, len;
    gmp_randstate_t state;
    mpz_t p, q, n, fn, e, d, x, y;

    mpz_t plain, cipher;

    len = 1024;

    gmp_randinit_default(state);

    mpz_inits(p, q, n, fn, e, d, x, y, plain, cipher, NULL);

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

    mpz_inits(p, q, n, fn, e, d, x, y, plain, cipher, NULL);

    gmp_randclear(state);

    return 0;
}

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