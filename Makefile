# Toolchain
CC      ?= cc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -O2
LDFLAGS ?=

# Target
TARGET  = ta152

# Sources
SRCS    = main.c ta152.c
OBJS    = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Link
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Compile
%.o: %.c ta152.h
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets
.PHONY: all clean
