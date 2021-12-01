#ifndef __ROCKY_UTILS__H
#define __ROCKY_UTILS__H
#ifdef __cplusplus
extern "C"
{
#endif

void dumphex(const char *tips, const void *data, int data_size, const char *indent, int line_size);
void dump(const char *tips, const void *data, int size);

#ifdef DISABLE_DUMP_FUNCTIONS
#define dumphex(...)
#define dump(...)
#endif

#ifdef __cplusplus
}
#endif
#endif