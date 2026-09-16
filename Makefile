CC      ?= gcc
CFLAGS  ?= -O2 -g
STD      = -std=gnu99
WARNINGS = -Wall -Wextra
PREFIX  ?= /usr/local
INSTALL ?= install

ARCH := $(shell uname -m)
ifneq (,$(filter aarch64 arm64 armv8b armv8l,$(ARCH)))
	ARCH_DIR = arm64
else ifneq (,$(findstring arm,$(ARCH)))
	ARCH_DIR = arm32
else ifneq (,$(filter i386 i486 i586 i686,$(ARCH)))
	ARCH_DIR = x86
else ifneq (,$(filter x86_64 amd64,$(ARCH)))
	ARCH_DIR = x86_64
else
	$(error unsupported architecture '$(ARCH)'. whatfiles supports x86_64, x86, arm32 and arm64)
endif

SOURCES = $(addprefix src/, whatfiles.c trace.c attach.c utilities.c hashmap.c wfstring.c syscalls.c) \
          src/$(ARCH_DIR)/registers.c
HEADERS = $(addprefix src/, whatfiles.h hashmap.h wfstring.h syscalls.h arch.h)

all: bin/whatfiles

# Headers and the architecture file are prerequisites, so editing them rebuilds.
bin/whatfiles: $(SOURCES) $(HEADERS)
	@mkdir -p bin
	$(CC) $(STD) $(WARNINGS) $(CFLAGS) -o $@ $(SOURCES)

# --- Android ----------------------------------------------------------------
# Cross-compile with the NDK, then push the result to a device:
#   make android NDK=~/Android/Sdk/ndk/<version>
#   adb push bin/whatfiles-android /data/local/tmp/whatfiles
# ANDROID_ABI is arm64, arm32, x86_64 or x86. ANDROID_API is the minimum API level.

ANDROID_ABI ?= arm64
ANDROID_API ?= 21
NDK_HOST    ?= linux-x86_64

ifeq ($(ANDROID_ABI),arm64)
	ANDROID_TRIPLE   = aarch64-linux-android
	ANDROID_ARCH_DIR = arm64
else ifeq ($(ANDROID_ABI),arm32)
	ANDROID_TRIPLE   = armv7a-linux-androideabi
	ANDROID_ARCH_DIR = arm32
else ifeq ($(ANDROID_ABI),x86_64)
	ANDROID_TRIPLE   = x86_64-linux-android
	ANDROID_ARCH_DIR = x86_64
else ifeq ($(ANDROID_ABI),x86)
	ANDROID_TRIPLE   = i686-linux-android
	ANDROID_ARCH_DIR = x86
endif

ANDROID_CC = $(NDK)/toolchains/llvm/prebuilt/$(NDK_HOST)/bin/$(ANDROID_TRIPLE)$(ANDROID_API)-clang

android:
	@test -n "$(NDK)" || { echo "usage: make android NDK=/path/to/android-ndk [ANDROID_ABI=arm64|arm32|x86_64|x86] [ANDROID_API=21]" >&2; exit 1; }
	@test -n "$(ANDROID_TRIPLE)" || { echo "unknown ANDROID_ABI '$(ANDROID_ABI)'" >&2; exit 1; }
	@test -x "$(ANDROID_CC)" || { echo "no NDK compiler at $(ANDROID_CC)" >&2; exit 1; }
	@rm -f bin/whatfiles-android   # always rebuild: the ABI may have changed
	$(MAKE) bin/whatfiles-android CC="$(ANDROID_CC)" ARCH_DIR="$(ANDROID_ARCH_DIR)"

bin/whatfiles-android: $(SOURCES) $(HEADERS)
	@mkdir -p bin
	$(CC) $(STD) $(WARNINGS) $(CFLAGS) -o $@ $(SOURCES)

# utils

install: bin/whatfiles
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -m 755 bin/whatfiles $(DESTDIR)$(PREFIX)/bin/whatfiles

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/whatfiles

clean:
	rm -f bin/whatfiles bin/whatfiles-android bin/hashmap bin/forktest bin/grandchild bin/threads bin/random bin/syscall_test

test: bin/whatfiles
	tests/run_tests.sh

# Runs the same checks on a connected device: make test-android NDK=~/Android/Sdk/ndk/<version>
# The ABI comes from the device; run the script directly to force a different one.
test-android:
	NDK="$(NDK)" ANDROID_API="$(ANDROID_API)" tests/run_tests_android.sh

check: bin/whatfiles bin/hashmap
	valgrind --leak-check=full --error-exitcode=1 bin/whatfiles -s ls -lah . > /dev/null
	valgrind --leak-check=full --error-exitcode=1 bin/hashmap

# ignore these, just tests used during development

scraps: bin/forktest bin/grandchild bin/threads bin/hashmap bin/random bin/syscall_test

bin/forktest: scraps/forktest.c
	@mkdir -p bin
	$(CC) $(STD) $(WARNINGS) $(CFLAGS) -o $@ $^

bin/grandchild: scraps/grandchild.c
	@mkdir -p bin
	$(CC) $(STD) $(WARNINGS) $(CFLAGS) -o $@ $^

bin/threads: scraps/threads.c
	@mkdir -p bin
	$(CC) $(STD) $(WARNINGS) $(CFLAGS) -pthread -o $@ $^

bin/hashmap: scraps/hashdriver.c src/hashmap.c src/wfstring.c $(HEADERS)
	@mkdir -p bin
	$(CC) $(STD) $(WARNINGS) $(CFLAGS) -o $@ scraps/hashdriver.c src/hashmap.c src/wfstring.c

bin/random: scraps/random.c
	@mkdir -p bin
	$(CC) $(STD) $(WARNINGS) $(CFLAGS) -o $@ $^

bin/syscall_test: scraps/syscall_test.c
	@mkdir -p bin
	$(CC) $(STD) $(WARNINGS) $(CFLAGS) -o $@ $^

.PHONY: all android install uninstall clean test test-android check scraps
