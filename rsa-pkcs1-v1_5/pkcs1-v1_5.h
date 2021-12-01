#ifndef __ROCKY_OAEP__H
#define __ROCKY_OAEP__H
#ifdef __cplusplus
extern "C"
{
#endif

int EME_PKCS1_v1_5_Encode(unsigned long k, unsigned char *M, unsigned long mLen, unsigned char *EM);
int EME_PKCS1_v1_5_Decode(unsigned long k, unsigned char *EM, unsigned char *M, unsigned long *mLen);

int EMSA_PKCS1_v1_5_Encode(HASH_ALG alg, unsigned char *M, unsigned long mLen, unsigned long emLen, unsigned char *EM);

#ifdef __cplusplus
}
#endif
#endif