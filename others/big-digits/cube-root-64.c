#include <stdio.h>
#include <stdarg.h>

#include <gmp.h>
#include <mpfr.h>

int main (void)
{
  //unsigned int i;
  mpfr_t s, t, u;

  mpfr_init2 (s, 200);
  //mpfr_set_d (s, 2, MPFR_RNDD);
  //Function: int mpfr_pow_ui (mpfr_t rop, mpfr_t op1, unsigned long int op2, mpfr_rnd_t rnd)
  //mpfr_pow_ui(s, s, 63, MPFR_RNDD);

  //Function: int mpfr_ui_pow_ui (mpfr_t rop, unsigned long int op1, unsigned long int op2, mpfr_rnd_t rnd)
  mpfr_ui_pow_ui(s, 2, 63, MPFR_RNDD);

  printf("s: ");
  mpfr_out_str (stdout, 10, 0, s, MPFR_RNDD);
  printf("\n");

  mpfr_init2 (t, 200);
  //mpfr_set_d (t, 2, MPFR_RNDD);
  //Function: int mpfr_set_ui (mpfr_t rop, unsigned long int op, mpfr_rnd_t rnd)
  mpfr_set_ui(t, 2, MPFR_RNDD);

  printf("t: ");
  mpfr_out_str (stdout, 10, 0, t, MPFR_RNDD);
  printf("\n");

  mpfr_init2 (u, 200);
  mpfr_set_d (u, 0, MPFR_RNDD);

  printf("u: ");
  mpfr_out_str (stdout, 10, 0, u, MPFR_RNDD);
  printf("\n");

  /*
   * Function: int mpfr_rootn_ui (mpfr_t rop, mpfr_t op, unsigned long int n, mpfr_rnd_t rnd)
   *   Set rop to the nth root (with n = 3, the cubic root, for mpfr_cbrt) of op rounded in the direction rnd. 
   */
  //mpfr_rootn_ui(t, t, 3, MPFR_RNDD);

  // Function: int mpfr_cbrt (mpfr_t rop, mpfr_t op, mpfr_rnd_t rnd)
  // Set rop to the cubic root (resp. the kth root) of op rounded in the direction rnd. 
  mpfr_cbrt(t, t, MPFR_RNDD);

  printf("cube root of t: ");
  mpfr_out_str (stdout, 10, 0, t, MPFR_RNDD);
  printf("\n");

  /*
   * Function: int mpfr_frac (mpfr_t rop, mpfr_t op, mpfr_rnd_t rnd)
   *   Set rop to the fractional part of op, having the same sign as op, rounded in the direction rnd
   */
  mpfr_frac(t, t, MPFR_RNDD);

  printf("fact part     : ");
  mpfr_out_str (stdout, 10, 0, t, MPFR_RNDD);
  printf("\n");

  // Function: int mpfr_mul (mpfr_t rop, mpfr_t op1, mpfr_t op2, mpfr_rnd_t rnd)
  mpfr_mul(t, t, s, MPFR_RNDD);
  printf("mul           : ");
  mpfr_out_str (stdout, 10, 0, t, MPFR_RNDD);
  printf("\n");

  // Function: int mpfr_modf (mpfr_t iop, mpfr_t fop, mpfr_t op, mpfr_rnd_t rnd)
  // Set simultaneously iop to the integral part of op and fop to the fractional part of op, 
  // rounded in the direction rnd with the corresponding precision of iop and fop
  mpfr_modf(u, t, t, MPFR_RNDD);

  printf("Cube root is: ");
  /*
   * Function: size_t mpfr_out_str (FILE *stream, int base, size_t n, mpfr_t op, mpfr_rnd_t rnd)
   *   Output op on stream stream as a text string in base abs(base), rounded in the direction rnd.
   */

  //mpfr_out_str (stdout, 16, 64, u, MPFR_RNDD);
  mpfr_out_str (stdout, 10, 0, u, MPFR_RNDD);
  printf("\n");
  mpfr_out_str (stdout, 16, 0, u, MPFR_RNDD);
  printf("\n");

  mpfr_printf ("u = %.64P\n", u);

  //Function: int mpfr_printf (const char *template, ...)

  mpfr_clear (s);
  mpfr_clear (t);
  mpfr_clear (u);
  mpfr_free_cache ();
  return 0;
}