.PHONY: all clean hmac test

CROSS_COMPILE=

CC      = $(CROSS_COMPILE)gcc
STRIP   = $(CROSS_COMPILE)strip
AR      = $(CROSS_COMPILE)ar
ARFLAGS = crs

RM      = rm
RMFLAGS = -rf

LIBS    =
INCLUDE =
CFLAGS  = -Wall -g -O2

SRCS    = utils.c md2.c md4.c md5.c sha1.c sha256.c sha512.c sha3.c sha3ex.c sm3.c hash_tables.c hash.c hmac.c hmactest.c
# use sha1test.c for test
# SRCS    = utils.c md2.c md4.c md5.c sha1.c sha256.c sha512.c sha3.c sha3ex.c sm3.c hash_tables.c hash.c sha1test.c
TARGET  = hmac

OBJS 	= $(SRCS:.c=.o)

all: hmac test

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS) $(INCLUDE)
#	$(STRIP) --strip-all $(TARGET)

test: $(TARGET)
	@echo
	@echo "Run Test..."
#	./$(TARGET) -a sha1 -s "abc"
#	./$(TARGET) -a sha512t -t 320 -s "abc"
#	./$(TARGET) -a shake128 -d 128 -s "abc"
#	./$(TARGET) -a shake128 -d 256 -s "abc"
#	./hashtest.sh

clean:
	$(RM) $(RMFLAGS) $(TARGET) $(OBJS)
