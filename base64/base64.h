#ifndef __ROCKY_BASE64__H
#define __ROCKY_BASE64__H
#ifdef __cplusplus
extern "C"
{
#endif

int Base64Encode(const unsigned char *data, int data_len, char *out, int *out_len);
int Base64Decode(const char *str, int str_len, unsigned char *out, int *out_len);

#ifdef __cplusplus
}
#endif
#endif

