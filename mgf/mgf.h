#ifndef __ROCKY_MGF__H
#define __ROCKY_MGF__H

int MGF1(const char *mgfSeed, unsigned int mgfSeedLen, HASH_ALG alg, unsigned int maskLen, char *mask);

#endif