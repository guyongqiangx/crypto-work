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
INCLUDE = -I../out/gmp/include -I../out/include

INSTALL ?= .

SRCS    = rsa_primitive.c rsa_key.c
OBJS    = $(SRCS:.c=.o)
HDRS	= rsa.h

LIB     = librsa_primitive.a

all: $(LIB)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

install: $(LIB)
	mkdir -p $(INSTALL)/include $(INSTALL)/lib
	cp -f $(LIB) $(INSTALL)/lib/$(LIB)
	cp -f $(HDRS) $(INSTALL)/include/$(HDRS)

clean:
	$(RM) $(RMFLAGS) $(OBJS) $(LIB)
