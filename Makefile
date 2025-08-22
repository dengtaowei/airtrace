export VERSION	= 1.2.11

ARCH=arm
CROSS_COMPILE=arm-linux-gnueabi-
export CROSS_COMPILE
CC=arm-linux-gnueabi-gcc
export CC
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
export ARCH

ROOT		:= $(abspath .)
export ROOT
PREFIX		?= ./output/$(ARCH)
PREFIX		:= $(abspath $(PREFIX))
MAN_DIR		:= $(PREFIX)/usr/share/man
BCOMP		:= ${PREFIX}/usr/share/bash-completion/completions/
export PREFIX
SCRIPT		= $(ROOT)/script
export SCRIPT

all clean:
	make -C src $@

direct:
	make -C src $@

3rdparty/compile:
	make -C 3rdparty compile

3rdparty/clean:
	make -C 3rdparty clean

install:
	@mkdir -p $(PREFIX)
	make -C src install
