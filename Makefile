# C
CC ?= gcc
CFLAGS ?= -Wall -Wextra -g3
LIBS ?= -lssl -lcrypto
TARGET_EXEC ?= ssl-tls-proxy

# Path
OBJ_DIR ?= ./obj
SRC_DIRS ?= ./src
SRCS := $(shell find $(SRC_DIRS) -name *.c)
OBJS := $(SRCS:%=$(OBJ_DIR)/%.o)
DEPS := $(OBJS:.o=.h)

# Build target
$(OBJ_DIR)/$(TARGET_EXEC): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET_EXEC) $(LIBS)

# Build all the binary files
$(OBJ_DIR)/%.c.o: %.c
	$(MKDIR_P) $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean

clean:
	rm -r $(OBJ_DIR)
	rm $(TARGET_EXEC)

-include $(DEPS)
MKDIR_P ?= mkdir -p
