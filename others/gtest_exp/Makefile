.PHONY: all clean sm4 test

CROSS_COMPILE=

CC      = $(CROSS_COMPILE)gcc
CXX     = $(CROSS_COMPILE)g++
STRIP   = $(CROSS_COMPILE)strip
AR      = $(CROSS_COMPILE)ar
ARFLAGS = crs

RM      = rm
RMFLAGS = -rf

LIBS    =
INCLUDE =
CFLAGS  = -Wall -g -O2

GTEST   = ../../gtest

CFLAGS  += -I$(GTEST)/_deps/googletest-src/googletest/include/gtest

SRCS    = main_unittest.cpp
TARGET  = sm4

OBJS 	= $(SRCS:.cpp=.o)

all: $(TARGET) test

# customer.o: customer.c
# 	$(CC) $(CFLAGS) -c $< -o $@
# 
# widget.o: widget.c
# 	$(CC) $(CFLAGS) -c $< -o $@

main_unittest

$(LIBS): $(OBJS)
	$(AR) $(ARFLAGS) $@ $(filter %.o, $^)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS) $(INCLUDE)
#	$(STRIP) --strip-all $(TARGET)

test: 

clean:
	$(RM) $(RMFLAGS) $(TARGET) $(OBJS)
