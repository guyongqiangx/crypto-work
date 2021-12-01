.PHONY: all test clean

CROSS_COMPILE=

CC      = $(CROSS_COMPILE)gcc
CXX     = $(CROSS_COMPILE)g++

LD      = $(CROSS_COMPILE)ld
LDFLAGS =

RM      = rm
RMFLAGS = -rf

CFLAGS  = -Wall -g -O2 -Wno-narrowing
INCLUDE = -I../out/gtest/include -I../out/gmp/include -I../out/include

LDLIBS  = -L../out/gtest/lib -lgtest_main -lgtest -lpthread -L../out/lib -lutils -lpkcs1-v1_5 -lrand -lhash -L../out/gmp/lib -lgmp

LIB     = libpkcs1-v1_5.a

SRCS    = pkcs1-v1_5_unittest.cc
OBJS    = $(SRCS:.cc=.o)

TARGET  = pkcs1-v1_5_unittest

all: .prepare $(TARGET) test

.prepare:
	# make -f gtest.mk
	touch .prepare

$(LIB):
	make -f lib.mk

%.o: %.cc
	$(CXX) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(TARGET): $(OBJS) $(LIB)
	$(CXX) $(LDFLAGS) $(OBJS) -o $@ $(LDLIBS)

test: $(TARGET)
	@echo "Run Test..."
	./$(TARGET)

clean:
#	make -f gtest.mk clean
	make -f lib.mk clean
	$(RM) $(RMFLAGS) $(TARGET) $(OBJS) .prepare
