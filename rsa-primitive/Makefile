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

LDLIBS  = -L../out/gtest/lib -lgtest_main -lgtest -lpthread -L../out/lib -lrsa_primitive -lpkcs1-v1_5 -loaep -lmgf -lhash -L../out/gmp/lib -lgmp

LIB     = librsa_primitive.a

SRCS    = rsa_key_unittest.cc rsa_primitive_unittest.cc rsa_encryption_unittest.cc
OBJS    = $(SRCS:.cc=.o)

TARGET  = rsa_unittest

all: .prepare $(TARGET) test

.prepare:
	# make -f gtest.mk
	touch .prepare

$(LIB):
	make -f lib.mk install INSTALL=../out

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
