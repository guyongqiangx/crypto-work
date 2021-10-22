.PHONY: all clean hash test

CROSS_COMPILE=

CC      = $(CROSS_COMPILE)gcc
CXX     = $(CROSS_COMPILE)g++
STRIP   = $(CROSS_COMPILE)strip
AR      = $(CROSS_COMPILE)ar
ARFLAGS = crs
LD      = $(CROSS_COMPILE)ld
LDFLAGS =

RM      = rm
RMFLAGS = -rf

CFLAGS  = -Wall -g -O2
# INCLUDE = -Igtest/include
INCLUDE =

# LDLIBS  = -Lgtest/lib -lgtest_main -lgtest -lpthread
LDLIBS  =
LIB     = libhash.a

SRCS    = utils.c hashtest.c
OBJS    = $(SRCS:.c=.o)

TARGET  = hash

OBJS 	= $(SRCS:.c=.o)

all: hash test


$(LIB):
	make -f lib.mk

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
	# $(CXX) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(TARGET): $(OBJS) $(LIB)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(INCLUDE) $(LDLIBS) $(LIB)
	# $(CXX) $(LDFLAGS) $(OBJS) -o $@ $(LDLIBS) $(LIB)
#	$(STRIP) --strip-all $(TARGET)

test: $(TARGET)
	@echo
	@echo "Run Test..."
	./$(TARGET) -a sha1 -s "abc"
	./$(TARGET) -a sha512t -t 320 -s "abc"
	./$(TARGET) -a shake128 -d 128 -s "abc"
	./$(TARGET) -a shake128 -d 256 -s "abc"
	./hashtest.sh

clean:
	$(RM) $(RMFLAGS) $(TARGET) $(OBJS)
