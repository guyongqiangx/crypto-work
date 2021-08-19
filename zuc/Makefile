.PHONY: all clean zuc test

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

SRCS    = utils.c zuc.c zuctest.c
TARGET  = zuc

OBJS 	= $(SRCS:.c=.o)

all: $(TARGET) test

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS) $(INCLUDE)
#	$(STRIP) --strip-all $(TARGET)

test: $(TARGET)
	@echo
	@echo "Run Test..."
	./$(TARGET) -x

clean:
	$(RM) $(RMFLAGS) $(TARGET) $(OBJS)
