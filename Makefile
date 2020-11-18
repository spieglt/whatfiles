CC = gcc
CFLAGS = -Wall -std=gnu99
SOURCES = $(addprefix src/, whatfiles.c attach.c utilities.c hashmap.c strings.c)

ARCH = $(shell uname -m)
ifeq ($(findstring arm,$(ARCH)), arm)
	ARCH_DIR = arm32
else ifeq ($(findstring aarch64,$(ARCH)), aarch64)
	ARCH_DIR = arm64
else ifeq ($(findstring i386,$(ARCH)), i386)
	ARCH_DIR = x86
else ifeq ($(findstring i686,$(ARCH)), i686)
	ARCH_DIR = x86
else
	ARCH_DIR = x86_64
endif

all: bin/whatfiles

bin/whatfiles: $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) src/$(ARCH_DIR)/registers.c

# utils

install:
	cp ./bin/whatfiles /usr/local/bin/whatfiles

clean:
	rm -rf bin/*

check: bin/whatfiles bin/hashmap
	valgrind --leak-check=full bin/whatfiles cal
	valgrind --leak-check=full bin/hashmap

# ignore these, just tests used during development

scraps: bin/forktest bin/grandchild bin/threads bin/hashmap bin/random

bin/forktest: scraps/forktest.c
	$(CC) $(CFLAGS) -o $@ $^

bin/grandchild: scraps/grandchild.c
	$(CC) $(CFLAGS) -o $@ $^

bin/threads: scraps/threads.c
	$(CC) $(CFLAGS) -pthread -o $@ $^

bin/hashmap: scraps/hashdriver.c src/hashmap.c src/strings.c
	$(CC) $(CFLAGS) -o $@ $^

bin/random: scraps/random.c
	$(CC) $(CFLAGS) -o $@ $^

bin/syscall_test: scraps/syscall_test.c
	$(CC) $(CFLAGS) -o $@ $^


chain: bin/whatfiles bin/forktest bin/grandchild
	bin/whatfiles bin/forktest

redo: bin/whatfiles bin/threads
	bin/whatfiles bin/threads a s d f
	cat whatfiles*

syscall_test: bin/whatfiles bin/syscall_test
	bin/whatfiles -ds bin/syscall_test
