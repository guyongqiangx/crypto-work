#ifndef __ROCKY_PSS__H
#define __ROCKY_PSS__H
#ifdef __cplusplus
extern "C"
{
#endif

#include "hash.h"

int PSS_Encode(HASH_ALG alg, unsigned char *M, unsigned long mLen, unsigned long sLen, unsigned char *EM, unsigned long emLen, unsigned long emBits);
int PSS_Verify(HASH_ALG alg, unsigned char *M, unsigned long mLen, unsigned long sLen, unsigned char *EM, unsigned long emLen, unsigned long emBits);

#ifdef __cplusplus
}
#endif
#endif