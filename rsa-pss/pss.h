#ifndef __ROCKY_PSS__H
#define __ROCKY_PSS__H
#ifdef __cplusplus
extern "C"
{
#endif

#include "hash.h"

int PSS_Encoding(HASH_ALG alg, unsigned long k, char *M, unsigned long mLen, unsigned long sLen, char *EM, unsigned long emLen, unsigned long emBits);
int PSS_Decoding(HASH_ALG alg, unsigned long k, const char *L, unsigned long lLen, char *EM, unsigned long emLen, char *M, unsigned long *mLen unsigned long emBits);

#ifdef __cplusplus
}
#endif
#endif