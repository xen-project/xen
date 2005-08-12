# libxenstat: statistics-collection library for Xen
# Copyright (C) International Business Machines Corp., 2005
# Author: Josh Triplett <josht@us.ibm.com>
# 
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

XEN_ROOT=../../..
include $(XEN_ROOT)/tools/Rules.mk
LINUX_ROOT := $(XEN_ROOT)/linux-2.6-xen-sparse

INSTALL         = install
INSTALL_PROG    = $(INSTALL) -m0755 -D
INSTALL_DATA    = $(INSTALL) -m0644 -D

prefix=/usr
includedir=$(prefix)/include
libdir=$(prefix)/lib

LDCONFIG=ldconfig
MAKE_LINK=ln -sf

MAJOR=0
MINOR=0

LIB=src/libxenstat.so.$(MAJOR).$(MINOR)
LINKS=src/libxenstat.so.$(MAJOR) src/libxenstat.so
OBJECTS=src/xenstat.o src/xen-interface.o
SONAME_FLAGS=-Wl,-soname -Wl,libxenstat.so.$(MAJOR)

WARN_FLAGS=-Wall -Werror

CFLAGS+=-Isrc
CFLAGS+=-I$(XEN_ROOT)/xen/include/public
CFLAGS+=-I$(LINUX_ROOT)/include/asm-xen/linux-public/
LDFLAGS+=-Lsrc

# Note that the bindings are not built by default, because they require a
# number of external dependencies.
all: $(LIB) $(LINKS)

$(LIB): $(OBJECTS)
	$(CC) $(LDFLAGS) $(SONAME_FLAGS) -shared -o $@ $(OBJECTS)

src/xenstat.o: src/xenstat.c src/xenstat.h src/xen-interface.h
	$(CC) $(CFLAGS) $(WARN_FLAGS) -c -o $@ $<

src/xen-interface.o: src/xen-interface.c src/xen-interface.h
	$(CC) $(CFLAGS) $(WARN_FLAGS) -c -o $@ $<

src/libxenstat.so.$(MAJOR): $(LIB)
	$(MAKE_LINK) $(<F) $@

src/libxenstat.so: src/libxenstat.so.$(MAJOR)
	$(MAKE_LINK) $(<F) $@

install: all
	$(INSTALL_DATA) src/xenstat.h $(DESTDIR)$(includedir)/xenstat.h
	$(INSTALL_PROG) $(LIB) \
	                $(DESTDIR)$(libdir)/libxenstat.so.$(MAJOR).$(MINOR)
	$(MAKE_LINK) libxenstat.so.$(MAJOR).$(MINOR) \
	             $(DESTDIR)$(libdir)/libxenstat.so.$(MAJOR)
	$(MAKE_LINK) libxenstat.so.$(MAJOR) \
	             $(DESTDIR)$(libdir)/libxenstat.so
	-$(LDCONFIG)

PYLIB=bindings/swig/python/_xenstat.so
PYMOD=bindings/swig/python/xenstat.py
PYSRC=bindings/swig/python/_xenstat.c
PERLLIB=bindings/swig/perl/xenstat.so
PERLMOD=bindings/swig/perl/xenstat.pm
PERLSRC=bindings/swig/perl/xenstat.c
BINDINGS=$(PYLIB) $(PYMOD) $(PERLLIB) $(PERLMOD)
BINDINGSRC=$(PYSRC) $(PERLSRC)

# The all-bindings target builds all the language bindings
all-bindings: $(BINDINGS)

$(BINDINGS): $(LIB) $(LINKS) src/xenstat.h

SWIG_FLAGS=-module xenstat -Isrc

PYTHON_VERSION=2.3
PYTHON_FLAGS=-I/usr/include/python$(PYTHON_VERSION) -lpython$(PYTHON_VERSION)
$(PYSRC) $(PYMOD): bindings/swig/xenstat.i
	swig -python $(SWIG_FLAGS) -outdir $(@D) -o $(PYSRC) $<

$(PYLIB): $(PYSRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $(PYTHON_FLAGS) -shared -lxenstat -o $@ $<

PERL_FLAGS=`perl -MConfig -e 'print "$$Config{ccflags} -I$$Config{archlib}/CORE";'`
$(PERLSRC) $(PERLMOD): bindings/swig/xenstat.i
	swig -perl $(SWIG_FLAGS) -outdir $(@D) -o $(PERLSRC) $<

$(PERLLIB): $(PERLSRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $(PERL_FLAGS) -shared -lxenstat -o $@ $<

# The install-bindings target installs all the language bindings
install-bindings: install-perl-bindings install-python-bindings

pythonlibdir=$(prefix)/lib/python$(PYTHON_VERSION)/site-packages
install-python-bindings: $(PYLIB) $(PYMOD)
	$(INSTALL_PROG) $(PYLIB) $(pythonlibdir)/_xenstat.so
	$(INSTALL_PROG) $(PYMOD) $(pythonlibdir)/xenstat.py

perllibdir=$(prefix)/lib/site_perl
perlmoddir=$(prefix)/lib/site_perl
install-perl-bindings: $(PERLLIB) $(PERLMOD)
	$(INSTALL_PROG) $(PERLLIB) $(perllibdir)/xenstat.so
	$(INSTALL_PROG) $(PERLMOD) $(perlmoddir)/xenstat.pm

clean:
	rm -f $(LIB) $(OBJECTS) $(LINKS) $(BINDINGS) $(BINDINGSRC)
