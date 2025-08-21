ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')

PREFIX = ../install/$(ARCH)
CC		:= $(CROSS_COMPILE)gcc
AR 		:= $(CROSS_COMPILE)ar

INCDIR = $(PREFIX)/include
LIBDIR = $(PREFIX)/lib

CFLAGS = -O2 -Wall
LDFLAGS = -L../install/$(ARCH)/lib
LDLIBS = -lz

MAJOR = 1
MINOR = 0.193

HEADERS = $(wildcard include/*.h src/*.h)
SOURCES = $(wildcard src/*.c)
LIBOBJS = $(patsubst %.c,%.o,$(SOURCES))
PICOBJS = $(patsubst %.c,%.os,$(SOURCES))

override CFLAGS += -DHAVE_CONFIG_H -Iinclude -Isrc

all: libelf.a libelf.so

clean:
	rm -f src/*.o src/*.os libelf.a libelf.so

libelf.a: $(LIBOBJS) Makefile
	$(AR) rcs $@ $(LIBOBJS)

libelf.so: $(PICOBJS) Makefile
	$(CC) $(LDFLAGS) -shared -Wl,-soname,libelf.so.$(MAJOR) \
	  -o $@ $(PICOBJS) $(LDLIBS)

%.o:: %.c $(HEADERS) Makefile
	$(CC) $(CFLAGS) -c -o $@ $<

%.os:: %.c $(HEADERS) Makefile
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

install: install-headers install-static install-shared

install-headers: include/*.h
	mkdir -p $(DESTDIR)$(INCDIR)
	install -m 0644 include/*.h $(DESTDIR)$(INCDIR)

install-static: libelf.a install-headers
	mkdir -p $(DESTDIR)$(LIBDIR)
	install -m 0644 $< $(DESTDIR)$(LIBDIR)

install-shared: libelf.so install-headers
	mkdir -p $(DESTDIR)$(LIBDIR)
	install $< $(DESTDIR)$(LIBDIR)/libelf.so.$(MAJOR).$(MINOR)
	ln -f -s libelf.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libelf.so.$(MAJOR)
	ln -f -s libelf.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libelf.so

.PHONY: all clean install install-*
