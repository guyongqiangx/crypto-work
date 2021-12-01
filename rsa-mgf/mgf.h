#ifndef __ROCKY_MGF__H
#define __ROCKY_MGF__H
#ifdef __cplusplus
extern "C"
{
#endif

int MGF1(const unsigned char *mgfSeed, unsigned int mgfSeedLen, HASH_ALG alg, unsigned int maskLen, unsigned char *mask);

typedef int (* MGF)(const unsigned char *mgfSeed, unsigned int mgfSeedLen, HASH_ALG alg, unsigned int maskLen, unsigned char *mask);

#ifdef __cplusplus
}
#endif
#endif