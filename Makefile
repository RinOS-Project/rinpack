# SPDX-License-Identifier: MIT
CC = gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
LDLIBS ?= -lcrypto -lz

all: rinpack

obj:
	@if not exist obj mkdir obj

obj/rinpack.o: src/rinpack.c | obj
	$(CC) $(CFLAGS) -c $< -o $@

rinpack: obj/rinpack.o
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	@if exist obj rmdir /s /q obj
	@if exist rinpack del /q rinpack
	@if exist rinpack.exe del /q rinpack.exe

.PHONY: all clean
