/*
 * $ gcc gmp-example.c -o gmptest -I/public/ygu/cryptography/crypto-work.git/out/gmp/include -L/public/ygu/cryptography/crypto-work.git/out/gmp/lib -lgmp
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
#include <gmp.h>

// Random Number Functions
static int random_number_function_examples(void)
{
    mpz_t rop;
    gmp_randstate_t state;
    mp_bitcnt_t n;

    mpz_init(rop);

    // void gmp_randinit_default (gmp_randstate_t state);
    gmp_randinit_default (state);

    // 生成 1024 bits 随机数
    n = 1024;

    // void mpz_urandomb (mpz_t rop, gmp_randstate_t state, mp_bitcnt_t n);
    mpz_urandomb(rop, state, n);

    gmp_printf("1024 bits: %Zx\n", rop);

    // 生成 2048 bits 随机数
    n = 2048;

    // void mpz_urandomb (mpz_t rop, gmp_randstate_t state, mp_bitcnt_t n);
    mpz_urandomb(rop, state, n);

    gmp_printf("2048 bits: %Zx\n", rop);

    mpz_clear(rop);

    return 0;
}

// Number Theoretic Functions
static int number_theoretic_function_examples(void)
{
    int i;

    // int mpz_probab_prime_p (const mpz_t n, int reps);
    // void mpz_nextprime (mpz_t rop, const mpz_t op);
    // void mpz_gcd (mpz_t rop, const mpz_t op1, const mpz_t op2);
    // void mpz_gcdext (mpz_t g, mpz_t s, mpz_t t, const mpz_t a, const mpz_t b);

    mpz_t a, b, c, d, e, f, z;
    gmp_randstate_t state;
    mp_bitcnt_t n;

    mpz_init(a);
    mpz_init(z);

    // void gmp_randinit_default (gmp_randstate_t state);
    gmp_randinit_default (state);

    // 生成 1024 bits 随机数
    n = 1024;

    // void mpz_urandomb (mpz_t rop, gmp_randstate_t state, mp_bitcnt_t n);
    mpz_urandomb(z, state, n);

    gmp_printf("1024 bits: %Zx\n", z);

    // 检查随机数是否为素数
    i = mpz_probab_prime_p (z, 25);
    switch(i)
    {
    case 0:
        printf("definitely non-prime\n");
        break;
    case 1:
        printf("probably prime (without being certain)\n");
        break;
    case 2:
        printf("definitely prime\n");
        break;
    }

    // 如果不是素数，则生成一个紧挨着的素数
    if (i == 0)
    {
        mpz_nextprime (a, z);
        gmp_printf("1024 bits: %Zx\n", a);
        i = mpz_probab_prime_p (a, 25);
        switch(i)
        {
        case 0:
            printf("definitely non-prime\n");
            break;
        case 1:
            printf("probably prime (without being certain)\n");
            break;
        case 2:
            printf("definitely prime\n");
            break;
        }
    }

    mpz_clear(a);
    mpz_clear(z);

    return 0;
}

static int bit_integer_from_string(void)
{
    mpz_t modulus;

    char *n = "00c90b62a6ef543d2204a72caca617aec5a76e01485f96235312d3eaff854f7edd9153c3b3ac14ac664e254e50a42556933713c086574e2d82aa7650ebe03534beb607f4027734eb27cb7dc44c8cc792054dffc148dbd8fa6a6b2c655bf424e697a71b29efad04b053e3dff253bb10436fb33a9dd1d96adecfdea0dbd5327f44f0a718159f68b576357965c7c5b06995589d8860bd4f945a11a3a2a265c5be0910d0458539740b3807ee87bf688ceb3c8b81a1272253525b3f66203b1304068d7977ebcbec9e709bb0b5ec764f91e1daa135e8c8a1640f48027658410947bc389a638b5c92dda0676a7064b56b07843e84ae26872d30fee06dddd8e930b542b05f";
    mpz_init_set_str(modulus, n, 16);

    gmp_printf("2048 bits integer: %Zx\n", modulus);

    mpz_clear(modulus);

    return 0;
}

int main(int argc, const char *argv[])
{
#if 1
    // random_number_function_examples();
    // number_theoretic_function_examples();
    bit_integer_from_string();
#else
    mpz_t z_i, z_s, z_o;

    mpz_init_set_str(z_i, "1", 10);
    mpz_init_set_str(z_s, "1", 10);
    mpz_init_set_str(z_o, "1", 10);

    int i;
    for (i = 0; i < 10000; i++)
    {
        mpz_mul(z_s, z_s, z_i);
        mpz_add(z_i, z_i, z_o);
    }

    gmp_printf("%Zd\n", z_s);

    mpz_clear(z_i);
    mpz_clear(z_s);
    mpz_clear(z_o);
    getchar();
#endif
    printf("Done!\n");
  return 0;
}