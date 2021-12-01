#ifndef __ROCKY_RAND__H
#define __ROCKY_RAND__H
#ifdef __cplusplus
extern "C"
{
#endif

int Get_Random_Bytes(unsigned char *buf, unsigned long len);
int Get_Random_NonZero_Bytes(unsigned char *buf, unsigned long len);

#ifdef __cplusplus
}
#endif
#endif