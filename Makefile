SHELL   := /usr/bin/env bash
VERSION := "0.8.3"
ARCH    := amd64
BUILD   ?= 1
OS		:= $(shell uname -s | tr '[:upper:]' '[:lower:]')

TARGET_LIB ?= /usr/local/lib
TARGET_INCLUDE ?= /usr/local/include

ifeq ($(OS), darwin)
LIB_TYPE := dylib
LIB_PATH := DYLD_LIBRARY_PATH
else
LIB_TYPE := so
LIB_PATH := LD_LIBRARY_PATH
endif

all: compile

clean:
	cargo clean
	rm -rf test/target
	rm -f deb/usr/include/*.h
	rm -f deb/usr/lib/*.so

compile:
	cargo build

compile-release:
	cargo build --release

testgo: compile test-compilego

test-compilego:
	cp target/debug/libcryptoboxdb.$(LIB_TYPE) /usr/lib/
	cd go
	go run main.go
	
test: compile test-compile
	$(LIB_PATH)=test/target valgrind --leak-check=full --error-exitcode=1 --track-origins=yes test/target/main

test-compile:
	mkdir -p test/target
	cp target/debug/libcryptoboxdb.$(LIB_TYPE) test/target/libcryptoboxdb.$(LIB_TYPE)
	rm -f test/target/main
	$(CC) -std=c99 -Wall -Wextra -Werror -g test/main.c -o test/target/main -Isrc -Ltest/target -lcryptoboxdb

bench: bench-compile
	$(LIB_PATH)=test/target test/target/bench

bench-compile: compile-release
	mkdir -p test/target
	cp target/release/libcryptoboxdb.$(LIB_TYPE) test/target/libcryptoboxdb.$(LIB_TYPE)
	rm -f test/target/bench
	$(CC) -std=c99 -Wall -Wextra -Werror -g test/bench.c -o test/target/bench -Isrc -Ltest/target -lcryptoboxdb

install: compile-release
	cp src/cbox.h $(TARGET_INCLUDE)
	cp target/release/libcryptoboxdb.$(LIB_TYPE) $(TARGET_LIB)

uninstall:
	rm -f $(TARGET_INCLUDE)/cbox.h
	rm -f $(TARGET_LIB)/libcryptoboxdb.$(LIB_TYPE)

dist: compile-release
	mkdir -p deb/usr/include
	mkdir -p deb/usr/lib
	cp src/cbox.h deb/usr/include
	cp target/release/libcryptoboxdb.$(LIB_TYPE) deb/usr/lib
ifeq ($(OS), linux)
	makedeb --name=cryptobox       \
			--version=$(VERSION)   \
			--debian-dir=deb       \
			--build=$(BUILD)       \
			--architecture=$(ARCH) \
			--output-dir=target/release
endif
