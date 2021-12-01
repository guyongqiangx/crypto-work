#ifndef __ROCKY_FAKERAND__H
#define __ROCKY_FAKERAND__H
#ifdef __cplusplus
extern "C"
{
#endif

#include "rand.h"

/* Entry for set fake data */
void Set_Random_Data(unsigned char *buf, unsigned long len);

#ifdef __cplusplus
}
#endif
#endif