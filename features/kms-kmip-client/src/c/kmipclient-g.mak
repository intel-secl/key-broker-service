# /*
# Copyright (C) 2020 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
# */

# the compiler: gcc for C program
CC = gcc

ifeq ($(debug),1)
    DEBUG_CFLAGS     := -Wall  -Wno-format -g -DDEBUG
else
    DEBUG_CFLAGS     := -Wall -Wno-unknown-pragmas -Wno-format -O3 -Wformat -Wformat-security
endif

KC_ROOT=.
BIN=$(KC_ROOT)/bin
LIB=$(KC_ROOT)/lib
OBJ=$(KC_ROOT)/build/kcobjects
LIBKMIP=/usr/local/lib/
LIBKMIP_INCLUDE=/usr/local/include/kmip/

# compiler flags:
LDFLAGS  = -z noexecstack -z relro -z now
CFLAGS  = -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fPIC -fstack-protector-strong -O2 -D FORTIFY_SOURCE=2 $(DEBUG_CFLAGS)

LIBS  = -lssl -lcrypto -lkmip
CURR_DIR  = `pwd`

INCLUDES  = -I$(CURR_DIR) -I$(LIBKMIP_INCLUDE)
OBJS  = $(OBJ)/create.o $(OBJ)/get.o \
		$(OBJ)/destroy.o $(OBJ)/logging.o \
		$(OBJ)/init.o $(OBJ)/util.o $(OBJ)/log.o

# the build target executable:
TARGET  = libkmipclient.so

all: $(LIB)/$(TARGET)

$(LIB)/$(TARGET): $(OBJS)
	$(CC) -shared $(CFLAGS) $(LDFLAGS) $(OBJS) -L$(LIBKMIP) $(LIBS) -o $(LIB)/$(TARGET)
ifneq "$(debug)" "1"
	strip -s $(LIB)/$(TARGET)
endif

$(OBJ)/create.o: create.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(OBJ)/create.o $(CURR_DIR)/create.c

$(OBJ)/get.o: get.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(OBJ)/get.o $(CURR_DIR)/get.c

$(OBJ)/destroy.o: destroy.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(OBJ)/destroy.o $(CURR_DIR)/destroy.c

$(OBJ)/logging.o: logging.c logging.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(OBJ)/logging.o $(CURR_DIR)/logging.c

$(OBJ)/init.o: init.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(OBJ)/init.o $(CURR_DIR)/init.c

$(OBJ)/util.o: util.c util.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(OBJ)/util.o $(CURR_DIR)/util.c

$(OBJ)/log.o: log.c log.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(OBJ)/log.o $(CURR_DIR)/log.c
