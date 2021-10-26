#ifndef __ROCKY_OAEP__H
#define __ROCKY_OAEP__H
#ifdef __cplusplus
extern "C"
{
#endif

#include "hash.h"

int OAEP_Encoding(HASH_ALG alg, unsigned long k, char *M, unsigned long mLen, const char *L, unsigned long lLen, char *EM, unsigned long emLen);
int OAEP_Decoding(HASH_ALG alg, unsigned long k, const char *L, unsigned long lLen, char *EM, unsigned long emLen, char *M, unsigned long *mLen);

#ifdef __cplusplus
}
#endif
#endif