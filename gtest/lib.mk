.PHONY: all clean

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

SRC     = foo.c
OBJS    = $(SRC:.c=.o)

LIB     = libfoo.a

all: $(LIB)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

clean:
	$(RM) $(RMFLAGS) $(OBJS) $(LIB)
