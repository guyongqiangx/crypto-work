.PHONY: all clean hash hmac test

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

HASH_SRCS = utils.c md2.c md4.c md5.c sha1.c sha256.c sha512.c sha3.c sha3ex.c sm3.c hash_tables.c hash.c hashtest.c
# HASH_SRCS    = utils.c md2.c md4.c md5.c sha1.c sha256.c sha512.c sha3.c sha3ex.c sm3.c hash_tables.c hash.c sha1test.c

HMAC_SRCS = utils.c md2.c md4.c md5.c sha1.c sha256.c sha512.c sha3.c sha3ex.c sm3.c hash_tables.c hash.c hmac.c hmactest.c

HASH  = hash
HMAC  = hmac
TARGET       = $(HASH_TARGET) $(HMAC_TARGET)

HASH_OBJS    = $(HASH_SRCS:.c=.o)
HMAC_OBJS    = $(HMAC_SRCS:.c=.o)

OBJS = $(HASH_OBJS) $(HMAC_OBJS)

all: hash hmac test

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(HASH): $(HASH_OBJS)
	$(CC) $(CFLAGS) $(HASH_OBJS) -o $@ $(LIBS) $(INCLUDE)
#	$(STRIP) --strip-all $@

$(HMAC): $(HMAC_OBJS)
	$(CC) $(CFLAGS) $(HMAC_OBJS) -o $@ $(LIBS) $(INCLUDE)
#	$(STRIP) --strip-all $@

test: $(TARGET)
	@echo
	@echo "Run Test..."
#	./$(HASH) -a sha1 -s "abc"
#	./$(HASH) -a sha512t -t 320 -s "abc"
#	./$(HASH) -a shake128 -d 128 -s "abc"
#	./$(HASH) -a shake128 -d 256 -s "abc"
#	./hashtest.sh

clean:
	$(RM) $(RMFLAGS) $(TARGET) $(OBJS)
