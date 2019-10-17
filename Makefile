SHELL   := /usr/bin/env bash
VERSION := "0.8.3"
ARCH    := $(shell if [ -f "`which dpkg-architecture`" ]; then dpkg-architecture -qDEB_HOST_ARCH; else [ -f "`which dpkg`" ] && dpkg --print-architecture; fi )
BUILD   ?= 1
OS      := $(shell uname -s | tr '[:upper:]' '[:lower:]')

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

audit:
	type -P cargo-audit || cargo install cargo-audit
	cargo audit

compile:
	cargo build

compile-release:
	cargo build --release

test: compile test-compile
	$(LIB_PATH)=test/target valgrind --leak-check=full --error-exitcode=1 --track-origins=yes test/target/main

test-compile:
	mkdir -p test/target
	cp target/debug/libcryptobox.$(LIB_TYPE) test/target/libcryptobox.$(LIB_TYPE)
	rm -f test/target/main
	$(CC) -std=c99 -Wall -Wextra -Werror -g test/main.c -o test/target/main -Isrc -Ltest/target -lcryptobox

bench: bench-compile
	$(LIB_PATH)=test/target test/target/bench

bench-compile: compile-release
	mkdir -p test/target
	cp target/release/libcryptobox.$(LIB_TYPE) test/target/libcryptobox.$(LIB_TYPE)
	rm -f test/target/bench
	$(CC) -std=c99 -Wall -Wextra -Werror -g test/bench.c -o test/target/bench -Isrc -Ltest/target -lcryptobox

install: compile-release
	cp src/cbox.h $(TARGET_INCLUDE)
	cp target/release/libcryptobox.$(LIB_TYPE) $(TARGET_LIB)

uninstall:
	rm -f $(TARGET_INCLUDE)/cbox.h
	rm -f $(TARGET_LIB)/libcryptobox.$(LIB_TYPE)

dist: compile-release
	mkdir -p deb/usr/include
	mkdir -p deb/usr/lib
	cp src/cbox.h deb/usr/include
	cp target/release/libcryptobox.$(LIB_TYPE) deb/usr/lib
ifeq ($(OS), linux)
	makedeb --name=cryptobox       \
			--version=$(VERSION)   \
			--debian-dir=deb       \
			--build=$(BUILD)       \
			--architecture=$(ARCH) \
			--output-dir=target/release
endif
