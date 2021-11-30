#ifndef __ROCKY_UTILS__H
#define __ROCKY_UTILS__H
#ifdef __cplusplus
extern "C"
{
#endif

void dumphex(const void *data, int data_size, const char *tips, const char *indent, int line_size);
void dump(const void *data, int size, const char *tips);

#ifdef DISABLE_DUMP_FUNCTIONS
#define dumphex(...)
#define dump(...)
#endif

#ifdef __cplusplus
}
#endif
#endif