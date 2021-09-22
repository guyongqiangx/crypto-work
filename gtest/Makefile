.PHONY: all test clean

CROSS_COMPILE=

CC      = $(CROSS_COMPILE)gcc
CXX     = $(CROSS_COMPILE)g++

LD      = $(CROSS_COMPILE)ld
LDFLAGS =

RM      = rm
RMFLAGS = -rf

CFLAGS  = -Wall -g -O2
INCLUDE = -Igtest/include

LDLIBS  = -Lgtest/lib -lgtest_main -lgtest -lpthread

LIB     = libfoo.a

SRCS    = foo_unittest.cc
OBJS    = $(SRCS:.cc=.o)

TARGET  = footest

all: .prepare $(TARGET) test

.prepare:
	make -f gtest.mk
	touch .prepare

$(LIB):
	make -f lib.mk

%.o: %.cc
	$(CXX) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(TARGET): $(OBJS) $(LIB)
	$(CXX) $(LDFLAGS) $(OBJS) -o $@ $(LDLIBS) $(LIB)

test: $(TARGET)
	@echo "Run Test..."
	./$(TARGET)

clean:
	make -f gtest.mk clean
	make -f lib.mk clean
	$(RM) $(RMFLAGS) $(TARGET) $(OBJS) .prepare
