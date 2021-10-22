#ifndef __ROCKY_MGF__H
#define __ROCKY_MGF__H

int MGF1(const char *mgfSeed, HASH_ALG alg, unsigned int maskLen, char *mask);

#endif