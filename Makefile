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

# utils

install: bin/whatfiles
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -m 755 bin/whatfiles $(DESTDIR)$(PREFIX)/bin/whatfiles

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/whatfiles

clean:
	rm -f bin/whatfiles bin/hashmap bin/forktest bin/grandchild bin/threads bin/random bin/syscall_test

test: bin/whatfiles
	tests/run_tests.sh

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

.PHONY: all install uninstall clean test check scraps
