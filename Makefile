# SPDX-License-Identifier: Apache-2.0
CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
LDLIBS ?= -lcrypto -lz
TEST_BUILD_DIR ?= ../../../build/rinpack-source-toctou

# GNU make supplies a built-in `CC=cc`.  On Windows that command is often not
# installed even when the selected GCC toolchain is available, so use gcc for
# the built-in default while still honoring an explicit CC override.
ifeq ($(origin CC),default)
CC = gcc
endif

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

ifeq ($(OS),Windows_NT)
check-source-toctou: src/rinpack.c | $(TEST_BUILD_DIR)
	$(CC) $(CFLAGS) -o $(TEST_BUILD_DIR)/rinpack-source-toctou.exe $< $(LDLIBS)
	python tests/source_toctou_test.py --binary $(TEST_BUILD_DIR)/rinpack-source-toctou.exe
else
check-source-toctou: src/rinpack.c tests/source_root_swap_interposer.c | $(TEST_BUILD_DIR)
	$(CC) $(CFLAGS) -o $(TEST_BUILD_DIR)/rinpack-source-toctou $< $(LDLIBS)
	$(CC) -std=c11 -Wall -Wextra -O2 -fPIC -shared tests/source_root_swap_interposer.c -o $(TEST_BUILD_DIR)/source_root_swap.so -ldl
	python3 tests/source_toctou_test.py --binary $(TEST_BUILD_DIR)/rinpack-source-toctou --interposer $(TEST_BUILD_DIR)/source_root_swap.so
endif

$(TEST_BUILD_DIR):
	$(call MKDIR_P,$@)

.PHONY: all clean check-source-toctou
