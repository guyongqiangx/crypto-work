# -fPIC : position-independent code,suitable for dynamic linking and avoiding any limit on the size of the global offset table.
 
#arm-hisiv100nptl-linux-
 
CROSS_COMPILE=
CC = $(CROSS_COMPILE)gcc
STRIP = $(CROSS_COMPILE)strip
#LIBS = -L. -lstdc++  #移植到开发板上需要主动链接libstdc++.so 这个动态库，暂时没有更好的解决方法，只能手动链接
CFLAGS = -Wall -g -Os
INCLUDE = -I ./
 
 
OBJ := SHA1.o 
OBJ += test.o 
 
TARGET = sha 
 
all: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET) $(LIBS) $(INCLUDE)
	$(STRIP) --strip-unneeded $(TARGET)
 
# --strip-unneeded 
 
SHA1.o : SHA1.c 
	$(CC) $(CFLAGS) -c $< -o $@ 
 
test.o : test.c 
	$(CC) $(CFLAGS) -c $< -o $@ 
 
clean:
	rm -rf $(OBJ)
