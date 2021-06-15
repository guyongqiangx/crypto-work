#ifndef __UTILS__H
#define __UTILS__H

int htole32c(unsigned char *data, unsigned long x);
unsigned long le32ctoh(const unsigned char *data);

int htobe64c(unsigned char *data, unsigned long long x);
unsigned long long be64ctoh(const unsigned char *data);

int print_buffer(const void *buf, size_t len, const char *indent);

#endif
