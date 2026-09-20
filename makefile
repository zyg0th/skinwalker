# skinwalker - userland execve()-like ELF loader
# Copyright (C) 2025  zygoth <core.zyg0th@gmail.com>
#
# Licensed under GPLv3, see LICENSE. Provided AS IS, WITHOUT WARRANTY
# OF ANY KIND. Built for exploratory/educational purposes — no
# responsibility is taken for misuse of this software or any damage
# resulting from it.

CC       = gcc
TESTS    = test/sample test/sample_pie test/dynsample test/threadsample test/dynthreadsample test/forksample

.PHONY: build test clean

build: skinwalker $(TESTS)

skinwalker: main.c skinwalker.o
	$(CC) main.c skinwalker.o -o skinwalker -lcurl

skinwalker.o: skinwalker.c skinwalker.h
	$(CC) -c skinwalker.c -o skinwalker.o

test/sample: test/sample.c
	$(CC) test/sample.c -o test/sample -static

test/sample_pie: test/sample.c
	$(CC) test/sample.c -o test/sample_pie -static-pie

test/dynsample: test/sample.c
	$(CC) test/sample.c -o test/dynsample

test/threadsample: test/threadsample.c
	$(CC) test/threadsample.c -o test/threadsample -static -lpthread

test/dynthreadsample: test/threadsample.c
	$(CC) test/threadsample.c -o test/dynthreadsample -lpthread

test/forksample: test/forksample.c
	$(CC) test/forksample.c -o test/forksample -static

# just builds the loader + the test binaries. doesn't run anything —
# each test binary loops printing "hello world! pid=<pid>" once a
# second, so to try one by hand:
#   ./skinwalker test/sample
#   ./skinwalker test/sample_pie
#   ./skinwalker test/dynsample
#   ./skinwalker test/threadsample
#   ./skinwalker test/dynthreadsample
#   ./skinwalker test/forksample
test: build

clean:
	rm -f skinwalker.o skinwalker $(TESTS)
