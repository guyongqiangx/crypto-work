#include <stdio.h>

#include <gmp.h>
#include <mpfr.h>

int main (void)
{
  unsigned int i;
  mpfr_t s, t, u;

  /*
   * An mpfr_t object must be initialized before storing the first value in it
   * Function: void mpfr_init2 (mpfr_t x, mpfr_prec_t prec)
   *   Initialize x, set its precision to be exactly prec bits and its value to NaN.
   */
  mpfr_init2 (t, 200);
  /*
   * Assign new values to already initialized floats
   * Function: int mpfr_set_d (mpfr_t rop, double op, mpfr_rnd_t rnd)
   *   Set the value of rop from op, rounded toward the given direction rnd.
   */
  mpfr_set_d (t, 1.0, MPFR_RNDD);
  mpfr_init2 (s, 200);
  mpfr_set_d (s, 1.0, MPFR_RNDD);
  mpfr_init2 (u, 200);
  for (i = 1; i <= 100; i++)
  {
      /*
       * Arithmetic Functions
       * Function: int mpfr_mul_ui (mpfr_t rop, mpfr_t op1, unsigned long int op2, mpfr_rnd_t rnd)
       *   Set rop to op1 times op2 rounded in the direction rnd. 
       */
      mpfr_mul_ui (t, t, i, MPFR_RNDU);
      mpfr_set_d (u, 1.0, MPFR_RNDD);
      /*
       * Function: int mpfr_div (mpfr_t rop, mpfr_t op1, mpfr_t op2, mpfr_rnd_t rnd)
       *   Set rop to op1/op2 rounded in the direction rnd.
       */
      mpfr_div (u, u, t, MPFR_RNDD);
      /*
       * Function: int mpfr_add (mpfr_t rop, mpfr_t op1, mpfr_t op2, mpfr_rnd_t rnd)
       *   Set rop to op1 + op2 rounded in the direction rnd.
       */
      mpfr_add (s, s, u, MPFR_RNDD);
  }
  printf ("Sum is ");
  /*
   * Function: size_t mpfr_out_str (FILE *stream, int base, size_t n, mpfr_t op, mpfr_rnd_t rnd)
   *   Output op on stream stream as a text string in base abs(base), rounded in the direction rnd.
   */
  mpfr_out_str (stdout, 10, 0, s, MPFR_RNDD);
  putchar ('\n');
  mpfr_clear (s);
  mpfr_clear (t);
  mpfr_clear (u);
  mpfr_free_cache ();
  return 0;
}
