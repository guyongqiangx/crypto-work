# -fPIC : position-independent code,suitable for dynamic linking and avoiding any limit on the size of the global offset table.

#arm-hisiv100nptl-linux-

CROSS_COMPILE=
CC = $(CROSS_COMPILE)gcc
STRIP = $(CROSS_COMPILE)strip
#LIBS = -L. -lstdc++  #移植到开发板上需要主动链接libstdc++.so 这个动态库，暂时没有更好的解决方法，只能手动链接
CFLAGS = -Wall -g -Os
INCLUDE = -I ./

.PHONY: all SHA1 SHA256 SHA512 SHA3 MD5 SM3 HMAC help common

all: MD2 MD4 MD5 SHA1 SHA256 SHA512 SHA3 SM3 HMAC

help:
	@echo "Support Targets: MD5 SHA1 SHA512 SHA3 SM3 HMAC"
	@echo "make MD5 SHA1 SHA512 SHA3 SM3 HMAC"

COMM_OBJ := utils.o
COMMON : $(COMM_OBJ)
utils.o: utils.c
	$(CC) $(CFLAGS) -c $< -o $@

#
# rules for sha1
#
SHA1_OBJ := sha1.o
SHA1_OBJ += sha1_test.o
SHA1_OBJ += $(COMM_OBJ)

SHA1_TARGET = sha1_test

SHA1: $(SHA1_OBJ) common
	$(CC) $(CFLAGS) $(SHA1_OBJ) -o $(SHA1_TARGET) $(LIBS) $(INCLUDE)
	$(STRIP) --strip-unneeded $(SHA1_TARGET)
 
# --strip-unneeded 
 
sha1.o : sha1.c
	$(CC) $(CFLAGS) -c $< -o $@

sha1_test.o : sha1_test.c
	$(CC) $(CFLAGS) -c $< -o $@

#
# rules for sha256
#
SHA256_OBJ := sha256.o
SHA256_OBJ += sha256_test.o
SHA256_OBJ += $(COMM_OBJ)

SHA256_TARGET = sha256_test

SHA256: $(SHA256_OBJ) common
	$(CC) $(CFLAGS) $(SHA256_OBJ) -o $(SHA256_TARGET) $(LIBS) $(INCLUDE)
	$(STRIP) --strip-unneeded $(SHA256_TARGET)

# --strip-unneeded

sha256.o : sha256.c
	$(CC) $(CFLAGS) -c $< -o $@

sha256_test.o : sha256_test.c
	$(CC) $(CFLAGS) -c $< -o $@

#
# rules for sha512
#
SHA512_OBJ := sha512.o
SHA512_OBJ += sha512_test.o
SHA512_OBJ += $(COMM_OBJ)

SHA512_TARGET = sha512_test

SHA512: $(SHA512_OBJ)
	$(CC) $(CFLAGS) $(SHA512_OBJ) -o $(SHA512_TARGET) $(LIBS) $(INCLUDE)
	$(STRIP) --strip-unneeded $(SHA512_TARGET)

SHA512.o : sha512.c
	$(CC) $(CFLAGS) -c $< -o $@

sha512_test.o : sha512_test.c
	$(CC) $(CFLAGS) -c $< -o $@

#
# rules for md2
#
MD2_OBJ := md2.o
MD2_OBJ += md2_test.o
MD2_OBJ += $(COMM_OBJ)

MD2_TARGET = md2_test

MD2: $(MD2_OBJ)
	$(CC) $(CFLAGS) $(MD2_OBJ) -o $(MD2_TARGET) $(LIBS) $(INCLUDE)
	$(STRIP) --strip-unneeded $(MD2_TARGET)

md2.o : md2.c
	$(CC) $(CFLAGS) -c $< -o $@

md2_test.o : md2_test.c
	$(CC) $(CFLAGS) -c $< -o $@

#
# rules for md4
#
MD4_OBJ := md4.o
MD4_OBJ += md4_test.o
MD4_OBJ += $(COMM_OBJ)

MD4_TARGET = md4_test

MD4: $(MD4_OBJ)
	$(CC) $(CFLAGS) $(MD4_OBJ) -o $(MD4_TARGET) $(LIBS) $(INCLUDE)
	$(STRIP) --strip-unneeded $(MD4_TARGET)

md4.o : md4.c
	$(CC) $(CFLAGS) -c $< -o $@

md4_test.o : md4_test.c
	$(CC) $(CFLAGS) -c $< -o $@

#
# rules for md5
#
MD5_OBJ := md5.o
MD5_OBJ += md5_test.o
MD5_OBJ += $(COMM_OBJ)

MD5_TARGET = md5_test

MD5: $(MD5_OBJ)
	$(CC) $(CFLAGS) $(MD5_OBJ) -o $(MD5_TARGET) $(LIBS) $(INCLUDE)
	$(STRIP) --strip-unneeded $(MD5_TARGET)

md5.o : md5.c
	$(CC) $(CFLAGS) -c $< -o $@

md5_test.o : md5_test.c
	$(CC) $(CFLAGS) -c $< -o $@

#
# rules for sm3
#
SM3_OBJ := sm3.o
SM3_OBJ += sm3_test.o
SM3_OBJ += $(COMM_OBJ)

SM3_TARGET = sm3_test

SM3: $(SM3_OBJ)
	$(CC) $(CFLAGS) $(SM3_OBJ) -o $(SM3_TARGET) $(LIBS) $(INCLUDE)
	$(STRIP) --strip-unneeded $(SM3_TARGET)

sm3.o : sm3.c
	$(CC) $(CFLAGS) -c $< -o $@

sm3_test.o : sm3_test.c
	$(CC) $(CFLAGS) -c $< -o $@

#
# rules for sha3
#
SHA3_OBJ := sha3.o
SHA3_OBJ += sha3_test.o
SHA3_OBJ += $(COMM_OBJ)

SHA3_TARGET = sha3_test

SHA3: $(SHA3_OBJ)
	$(CC) $(CFLAGS) $(SHA3_OBJ) -o $(SHA3_TARGET) $(LIBS) $(INCLUDE)
	$(STRIP) --strip-unneeded $(SHA3_TARGET)

SHA3.o : sha3.c
	$(CC) $(CFLAGS) -c $< -o $@

sha3_test.o : sha3_test.c
	$(CC) $(CFLAGS) -c $< -o $@

#
# rules for HMAC
#
HMAC_OBJ := hmac.o
HMAC_OBJ += hmac_test.o
HMAC_OBJ += $(COMM_OBJ)

HMAC_TARGET = hmac_test

HMAC: $(HMAC_OBJ)
	$(CC) $(CFLAGS) $(HMAC_OBJ) -o $(HMAC_TARGET) $(LIBS) $(INCLUDE)
	$(STRIP) --strip-unneeded $(HMAC_TARGET)

HMAC.o : hmac.c
	$(CC) $(CFLAGS) -c $< -o $@

hmac_test.o : hmac_test.c
	$(CC) $(CFLAGS) -c $< -o $@

OBJ = $(SHA1_OBJ) $(SHA1_TARGET)
OBJ += $(SHA256_OBJ) $(SHA256_TARGET)
OBJ += $(SHA512_OBJ) $(SHA512_TARGET)
OBJ += $(SHA3_OBJ) $(SHA3_TARGET)
OBJ += $(MD2_OBJ) $(MD2_TARGET)
OBJ += $(MD4_OBJ) $(MD4_TARGET)
OBJ += $(MD5_OBJ) $(MD5_TARGET)
OBJ += $(SM3_OBJ) $(SM3_TARGET)
OBJ += $(HMAC_OBJ) $(HMAC_TARGET)

clean:
	rm -rf $(OBJ) $(TARGET)
