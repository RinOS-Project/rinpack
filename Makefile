# SPDX-License-Identifier: Apache-2.0
CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
LDLIBS ?= -lcrypto -lz

ifeq ($(OS),Windows_NT)
MKDIR_P = if not exist "$(1)" mkdir "$(1)"
RM_RF = if exist "$(1)" rmdir /s /q "$(1)"
RM_F = if exist "$(1)" del /q "$(1)"
else
MKDIR_P = mkdir -p "$(1)"
RM_RF = rm -rf "$(1)"
RM_F = rm -f "$(1)"
endif

all: rinpack

obj:
	$(call MKDIR_P,obj)

obj/rinpack.o: src/rinpack.c | obj
	$(CC) $(CFLAGS) -c $< -o $@

rinpack: obj/rinpack.o
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	$(call RM_RF,obj)
	$(call RM_F,rinpack)
	$(call RM_F,rinpack.exe)

.PHONY: all clean
