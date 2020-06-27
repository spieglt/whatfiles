CC = gcc
CFLAGS = -Wall
SOURCES = $(addprefix src/, whatfiles.c attach.c utilities.c hashmap.c strings.c)
ARCH_DIR = $(shell uname -m)

all: bin/whatfiles

bin/whatfiles: $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) src/$(ARCH_DIR)/registers.c

# utils

install:
	cp ./bin/whatfiles /usr/local/bin/whatfiles

clean:
	-rm whatfiles15*
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


chain: bin/whatfiles bin/forktest bin/grandchild
	bin/whatfiles bin/forktest

redo: bin/whatfiles bin/threads
	-rm whatfiles15*
	bin/whatfiles bin/threads a s d f
	cat whatfiles*
