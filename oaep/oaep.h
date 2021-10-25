#ifndef __ROCKY_OAEP__H
#define __ROCKY_OAEP__H
#ifdef __cplusplus
extern "C"
{
#endif

#include "hash.h"

int OAEP_Encoding(char *M, unsigned long msgLen, const char *L, unsigned long lLen, HASH_ALG alg, char *EM, unsigned long emLen);
int OAEP_Decoding(const char *L, unsigned long lLen, char *em, unsigned long emLen, HASH_ALG alg, char *M, unsigned long mLen);

#ifdef __cplusplus
}
#endif
#endif