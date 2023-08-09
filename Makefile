# C
CC ?= gcc
CFLAGS ?= -Wall -Wextra -g3
LIBS ?= -lssl -lcrypto
TARGET_EXEC ?= sni-changer-using-mitm-proxy

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

# CA information
CERT_NAME := rootCA
CERT_DIR := ./cert
COMMON_NAME := SNI-Changer
COUNTRY := BR
ORGANIZATION := SNI-Changer

cert:
	@ $(MKDIR_P) $(CERT_DIR)
	@ bash -c 'read -s -p "Enter DES3 password: " PASSWORD && echo && \
	openssl genrsa -des3 -out $(CERT_DIR)/$(CERT_NAME).key -passout pass:$$PASSWORD 2048 && \
	openssl req -x509 -new -nodes -key $(CERT_DIR)/$(CERT_NAME).key -sha256 -days 1825 -subj "/CN=$(COMMON_NAME)/C=$(COUNTRY)/O=$(ORGANIZATION)" -passin pass:$$PASSWORD -out $(CERT_DIR)/$(CERT_NAME).pem && \
	openssl pkcs12 -export -in $(CERT_DIR)/$(CERT_NAME).pem -inkey $(CERT_DIR)/$(CERT_NAME).key -passin pass:$$PASSWORD -passout pass:$$PASSWORD -out $(CERT_DIR)/$(CERT_NAME).p12'

clean:
	rm -rf $(OBJ_DIR) $(CERT_DIR)
	rm -f $(TARGET_EXEC)

-include $(DEPS)
MKDIR_P ?= mkdir -p

.PHONY: clean cert

