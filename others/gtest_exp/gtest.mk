.PHONY: all clean

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

CMAKE   = cmake
MAKE    = make

GTEST           = ../../gtest
GTEST_CMAKELIST = $(GTEST)/CMakeLists.txt
GTEST_MAKEFILE  = $(GTEST)/Makefile
GTEST_LIB       = $(GTEST)/libgtest.a
GTEST_LIBMAIN   = $(GTEST)/libgtest_main.a

TARGET  = gtestlib

all: $(TARGET)

$(TARGET):
	if [ ! -e $(GTEST_LIB) ] || [ ! -e $(GTEST_LIBMAIN) ]; then \
		$(CMAKE) -S $(GTEST) -B $(GTEST) -DBUILD_GMOCK=OFF && $(MAKE) -C $(GTEST); \
	fi;

clean:
	if [ -e $(GTEST_MAKEFILE) ]; then \
		$(MAKE) -C $(GTEST) clean; \
	fi;
