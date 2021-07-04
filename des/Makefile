.PHONY: all clean des test mydes

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

SRCS    = utils.c des.c destest.c
TARGET  = des

OBJS 	= $(SRCS:.c=.o)

# all: des test
all: mydes

mydes: desv2.o utils.o
	$(RM) $(RMFLAGS) $@
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS) $(INCLUDE)
	./$@

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
