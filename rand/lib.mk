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
INCLUDE = -I../out/include

INSTALL ?= .

SRCS    = rand.c
OBJS    = $(SRCS:.c=.o)
HDRS	= $(SRCS:.c=.h)

FAKE_SRCS = fakerand.c
FAKE_OBJS = $(FAKE_SRCS:.c=.o)
FAKE_HDRS = $(FAKE_SRCS:.c=.h)

LIB     = librand.a
FAKELIB = libfakerand.a

all: $(LIB) $(FAKELIB)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(FAKELIB): $(FAKE_OBJS)
	$(AR) $(ARFLAGS) $@ $^

install: all
	mkdir -p $(INSTALL)/include $(INSTALL)/lib
	cp -f $(LIB)  $(FAKELIB)   $(INSTALL)/lib
	cp -f $(HDRS) $(FAKE_HDRS) $(INSTALL)/include

clean:
	$(RM) $(RMFLAGS) $(OBJS) $(LIB) $(FAKE_OBJS) $(FAKELIB)
