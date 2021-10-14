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

// mpz_mod(mpz_t r, const mpz_t n, const mpz_t d)
// mpz_powm_ui(mpz_t rop, const mpz_t base, unsigned long int exp, const mpz_t mod)

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
    while (!temp)
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
    }

    mpz_clear(m);
}

int main(int argc, char *argv[])
{
    int i, len;
    gmp_randstate_t state;
    mpz_t p, q, n, x, y;

    len = 1024;

    gmp_randinit_default(state);
    //gmp_randinit_mt(state);
    //gmp_randseed_ui(state, time(NULL));

    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init(x);
    mpz_init(y);

    generate_prime_integer(len, state, p);
    gmp_printf("P: %Zx\n", p);

    generate_prime_integer(len, state, q);
    gmp_printf("Q: %Zx\n", q);

    mpz_mul(n, p, q);
    gmp_printf("N: %Zx\n", n);

    fast_exp(x, p, 65537, n);
    gmp_printf("x: %Zx\n", x);

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(x);
    mpz_clear(y);

    gmp_randclear(state);

    return 0;
}

int generate_prime_integer(int bits, gmp_randstate_t state, mpz_t big_int)
{
    int i;
    mp_bitcnt_t n;

    n = bits;

    mpz_urandomb(big_int, state, n);
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