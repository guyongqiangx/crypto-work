.PHONY: all install clean

CROSS_COMPILE=

CC      = $(CROSS_COMPILE)gcc
CXX     = $(CROSS_COMPILE)g++

LD      = $(CROSS_COMPILE)ld
LDFLAGS =

STRIP   = $(CROSS_COMPILE)strip
AR      = $(CROSS_COMPILE)ar
ARFLAGS = crs

RM      = rm
RMFLAGS = -rf

CFLAGS  = -Wall -g -O2
INCLUDE =

INSTALL ?= .

SRCS    = md2.c md4.c md5.c sha1.c sha256.c sha512.c sha3.c sha3ex.c sm3.c hash_tables.c hash.c
OBJS    = $(SRCS:.c=.o)
HDRS	= hash.h

LIB     = libhash.a

all: $(LIB)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

install: $(LIB)
	mkdir -p $(INSTALL)/include $(INSTALL)/lib
	cp -f $(LIB) $(INSTALL)/lib/$(LIB)
	cp -f $(HDRS) $(INSTALL)/include/$(HDRS)
	cp -f type.h $(INSTALL)/include/type.h

clean:
	$(RM) $(RMFLAGS) $(OBJS) $(LIB)
