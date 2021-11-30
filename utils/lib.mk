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

SRCS    = utils.c
OBJS    = $(SRCS:.c=.o)
HDRS	= $(SRCS:.c=.h)

LIB     = libutils.a

all: $(LIB)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(FAKELIB): $(FAKE_OBJS)
	$(AR) $(ARFLAGS) $@ $^

install: all
	mkdir -p $(INSTALL)/include $(INSTALL)/lib
	cp -f $(LIB)  $(INSTALL)/lib
	cp -f $(HDRS) $(INSTALL)/include

clean:
	$(RM) $(RMFLAGS) $(OBJS) $(LIB)
