.PHONY: all clean

CROSS_COMPILE=

CC      = $(CROSS_COMPILE)gcc
STRIP   = $(CROSS_COMPILE)strip
AR      = $(CROSS_COMPILE)ar
ARFLAGS = crs

LIBS    =
INCLUDE =
CFLAGS  = -Wall -g -O2

CMAKE   = cmake
MAKE    = make

# GTEST           = ../gtest
GTEST             = .
GTEST_BUILD_DIR   = $(GTEST)/build
GTEST_INSTALL_DIR = $(GTEST)/gtest
GTEST_CMAKELIST   = $(GTEST)/CMakeLists.txt
GTEST_LIB         = $(GTEST_INSTALL_DIR)/lib/libgtest.a
GTEST_LIBMAIN     = $(GTEST_INSTALL_DIR)/lib/libgtest_main.a

TARGET  = gtestlib

all: $(TARGET)

# $ cmake --help
# Usage
#
#   cmake [options] <path-to-source>
#   cmake [options] <path-to-existing-build>
#   cmake [options] -S <path-to-source> -B <path-to-build>
#
# Specify a source directory to (re-)generate a build system for it in the
# current working directory.  Specify an existing build directory to
# re-generate its build system.
#
# Options
#   -S <path-to-source>          = Explicitly specify a source directory.
#   -B <path-to-build>           = Explicitly specify a build directory.
#   -C <initial-cache>           = Pre-load a script to populate the cache.
#   -D <var>[:<type>]=<value>    = Create or update a cmake cache entry.
#   -U <globbing_expr>           = Remove matching entries from CMake cache.
#   -G <generator-name>          = Specify a build system generator.
#   -T <toolset-name>            = Specify toolset name if supported by
#                                  generator.
#   -A <platform-name>           = Specify platform name if supported by
#                                  generator.

# If you want to build only GoogleTest, you should replace the last command with
# cmake .. -DBUILD_GMOCK=OFF

$(TARGET):
	if [ ! -e $(GTEST_LIB) ] || [ ! -e $(GTEST_LIBMAIN) ]; then \
		mkdir -p $(GTEST_BUILD_DIR); \
		$(CMAKE) -S $(GTEST) -B $(GTEST_BUILD_DIR) -DBUILD_GMOCK=OFF -DCMAKE_INSTALL_PREFIX=$(GTEST_INSTALL_DIR) && \
		$(MAKE) -C $(GTEST_BUILD_DIR) && \
		$(MAKE) -C $(GTEST_BUILD_DIR) install; \
	fi;

clean:
	if [ -e $(GTEST_BUILD_DIR) ]; then \
		$(MAKE) -C $(GTEST_BUILD_DIR) clean; \
	fi;
	rm -rf $(GTEST_BUILD_DIR);
	rm -rf $(GTEST_INSTALL_DIR);
