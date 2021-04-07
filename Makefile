# -fPIC : position-independent code,suitable for dynamic linking and avoiding any limit on the size of the global offset table.

#arm-hisiv100nptl-linux-

CROSS_COMPILE=
CC = $(CROSS_COMPILE)gcc
STRIP = $(CROSS_COMPILE)strip
#LIBS = -L. -lstdc++  #移植到开发板上需要主动链接libstdc++.so 这个动态库，暂时没有更好的解决方法，只能手动链接
CFLAGS = -Wall -g -Os
INCLUDE = -I ./

.PHONY: all SHA1 SHA512 MD5

all: SHA1 SHA512

#
# rules for sha1
#
SHA1_OBJ := sha1.o
SHA1_OBJ += sha1_test.o

SHA1_TARGET = sha1_test

SHA1: $(SHA1_OBJ)
	$(CC) $(CFLAGS) $(SHA1_OBJ) -o $(SHA1_TARGET) $(LIBS) $(INCLUDE)
	$(STRIP) --strip-unneeded $(SHA1_TARGET)
 
# --strip-unneeded 
 
SHA1.o : sha1.c
	$(CC) $(CFLAGS) -c $< -o $@

sha1_test.o : sha1_test.c
	$(CC) $(CFLAGS) -c $< -o $@

#
# rules for sha512
#
SHA512_OBJ := sha512.o
SHA512_OBJ += sha512_test.o

SHA512_TARGET = sha512_test

SHA512: $(SHA512_OBJ)
	$(CC) $(CFLAGS) $(SHA512_OBJ) -o $(SHA512_TARGET) $(LIBS) $(INCLUDE)
	$(STRIP) --strip-unneeded $(SHA512_TARGET)

SHA512.o : sha512.c
	$(CC) $(CFLAGS) -c $< -o $@

sha512_test.o : sha512_test.c
	$(CC) $(CFLAGS) -c $< -o $@

#
# rules for md5
#
MD5_OBJ := md5.o
MD5_OBJ += md5_test.o

MD5_TARGET = md5_test

MD5: $(MD5_OBJ)
	$(CC) $(CFLAGS) $(MD5_OBJ) -o $(MD5_TARGET) $(LIBS) $(INCLUDE)
	$(STRIP) --strip-unneeded $(MD5_TARGET)

md5.o : md5.c
	$(CC) $(CFLAGS) -c $< -o $@

md5_test.o : md5_test.c
	$(CC) $(CFLAGS) -c $< -o $@

OBJ = $(SHA1_OBJ) $(SHA1_TARGET) $(SHA512_OBJ) $(SHA512_TARGET) $(MD5_OBJ) $(MD5_TARGET)

clean:
	rm -rf $(OBJ) $(TARGET)
