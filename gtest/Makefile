.PHONY: all clean gtestfoo test

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

LIBS    = -Lgtest/lib  -libgtest_main -libgtest -lpthread
INCLUDE = -Igtest/include

SRCS    = foo.c foo_unittest.cc
TARGET  = gtestfoo

OBJS 	= $(SRCS:.c=.o) $(SRCS:.cc=.o)

all: gtestfoo test

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDE)

%.o: %.cc
	$(CXX) $(CFLAGS) -c $< -o $@ $(INCLUDE)

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)
#	$(STRIP) --strip-unneeded $(TARGET)

test: $(TARGET)
	@echo
	@echo "Run Test..."
	./$(TARGET) -x

clean:
	$(RM) $(RMFLAGS) $(TARGET) $(OBJS)
