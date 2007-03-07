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

prefix=/usr
includedir=$(prefix)/include
libdir=$(prefix)/lib

LDCONFIG=ldconfig
MAKE_LINK=ln -sf

MAJOR=0
MINOR=0

LIB=src/libxenstat.a
SHLIB=src/libxenstat.so.$(MAJOR).$(MINOR)
SHLIB_LINKS=src/libxenstat.so.$(MAJOR) src/libxenstat.so
OBJECTS-y=src/xenstat.o
OBJECTS-$(CONFIG_Linux) += src/xenstat_linux.o
OBJECTS-$(CONFIG_SunOS) += src/xenstat_solaris.o
SONAME_FLAGS=-Wl,$(SONAME_LDFLAG) -Wl,libxenstat.so.$(MAJOR)

WARN_FLAGS=-Wall -Werror

CFLAGS+=-Isrc -I$(XEN_LIBXC) -I$(XEN_XENSTORE)
LDFLAGS+=-Lsrc -L$(XEN_XENSTORE)/ -L$(XEN_LIBXC)/
LDLIBS-y = -lxenstore -lxenctrl
LDLIBS-$(CONFIG_SunOS) += -lkstat
ARLIBS-y = $(XEN_XENSTORE)/libxenstore.so $(XEN_LIBXC)/libxenctrl.so
ARLIBS-x86_64 = /usr/lib/amd64/libkstat.so
ARLIBS-x86_32 = /usr/lib/libkstat.so
ARLIBS-$(CONFIG_SunOS) += $(ARLIBS-$(XEN_TARGET_ARCH))

.PHONY: all
all: $(LIB)

$(LIB): $(OBJECTS-y)
	$(AR) rc $@ $^ $(ARLIBS-y)
	$(RANLIB) $@

$(SHLIB): $(OBJECTS-y)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SONAME_FLAGS) $(SHLIB_CFLAGS) -o $@ \
	    $(OBJECTS-y) $(LDLIBS-y)

src/xenstat.o: src/xenstat.c src/xenstat.h src/xenstat_priv.h
	$(CC) $(CFLAGS) $(WARN_FLAGS) -c -o $@ $<

src/xenstat_linux.o: src/xenstat_linux.c src/xenstat_priv.h
	$(CC) $(CFLAGS) $(WARN_FLAGS) -c -o $@ $<

src/xenstat_solaris.o: src/xenstat_solaris.c src/xenstat_priv.h
	$(CC) $(CFLAGS) $(WARN_FLAGS) -c -o $@ $<

src/libxenstat.so.$(MAJOR): $(LIB)
	$(MAKE_LINK) $(<F) $@

src/libxenstat.so: src/libxenstat.so.$(MAJOR)
	$(MAKE_LINK) $(<F) $@

.PHONY: install
install: all
#install: all
#	$(INSTALL_DATA) src/xenstat.h $(DESTDIR)$(includedir)/xenstat.h
#	$(INSTALL_PROG) $(LIB) $(DESTDIR)$(libdir)/libxenstat.a
#	$(INSTALL_PROG) $(SHLIB) \
#	                $(DESTDIR)$(libdir)/libxenstat.so.$(MAJOR).$(MINOR)
#	$(MAKE_LINK) libxenstat.so.$(MAJOR).$(MINOR) \
#	             $(DESTDIR)$(libdir)/libxenstat.so.$(MAJOR)
#	$(MAKE_LINK) libxenstat.so.$(MAJOR) \
#	             $(DESTDIR)$(libdir)/libxenstat.so
#	-$(LDCONFIG)

PYLIB=bindings/swig/python/_xenstat.so
PYMOD=bindings/swig/python/xenstat.py
PYSRC=bindings/swig/python/_xenstat.c
PERLLIB=bindings/swig/perl/xenstat.so
PERLMOD=bindings/swig/perl/xenstat.pm
PERLSRC=bindings/swig/perl/xenstat.c
BINDINGS=$(PYLIB) $(PYMOD) $(PERLLIB) $(PERLMOD)
BINDINGSRC=$(PYSRC) $(PERLSRC)

# The all-bindings target builds all the language bindings
.PHONY: all-bindings
all-bindings: perl-bindings python-bindings

# The install-bindings target installs all the language bindings
install-bindings: install-perl-bindings install-python-bindings

$(BINDINGS): $(SHLIB) $(SHLIB_LINKS) src/xenstat.h

SWIG_FLAGS=-module xenstat -Isrc

# Python bindings
PYTHON_VERSION=2.3
PYTHON_FLAGS=-I/usr/include/python$(PYTHON_VERSION) -lpython$(PYTHON_VERSION)
$(PYSRC) $(PYMOD): bindings/swig/xenstat.i
	swig -python $(SWIG_FLAGS) -outdir $(@D) -o $(PYSRC) $<

$(PYLIB): $(PYSRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $(PYTHON_FLAGS) $(SHLIB_CFLAGS) -lxenstat -o $@ $<

python-bindings: $(PYLIB) $(PYMOD)

pythonlibdir=$(prefix)/lib/python$(PYTHON_VERSION)/site-packages
install-python-bindings: $(PYLIB) $(PYMOD)
	$(INSTALL_PROG) $(PYLIB) $(DESTDIR)$(pythonlibdir)/_xenstat.so
	$(INSTALL_PROG) $(PYMOD) $(DESTDIR)$(pythonlibdir)/xenstat.py

ifeq ($(XENSTAT_PYTHON_BINDINGS),y)
.PHONY: all
all: python-bindings
install: install-python-bindings
endif

# Perl bindings
PERL_FLAGS=`perl -MConfig -e 'print "$$Config{ccflags} -I$$Config{archlib}/CORE";'`
$(PERLSRC) $(PERLMOD): bindings/swig/xenstat.i
	swig -perl $(SWIG_FLAGS) -outdir $(@D) -o $(PERLSRC) $<

$(PERLLIB): $(PERLSRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $(PERL_FLAGS) $(SHLIB_CFLAGS) -lxenstat -o $@ $<

.PHONY: perl-bindings
perl-bindings: $(PERLLIB) $(PERLMOD)

.PHONY: install-perl-bindings
perllibdir=$(prefix)/lib/perl5
perlmoddir=$(prefix)/share/perl5
install-perl-bindings: $(PERLLIB) $(PERLMOD)
	$(INSTALL_PROG) $(PERLLIB) $(DESTDIR)$(perllibdir)/xenstat.so
	$(INSTALL_PROG) $(PERLMOD) $(DESTDIR)$(perlmoddir)/xenstat.pm

ifeq ($(XENSTAT_PERL_BINDINGS),y)
.PHONY: all
all: perl-bindings

.PHONY: install
install: install-perl-bindings
endif

.PHONY: clean
clean:
	rm -f $(LIB) $(SHLIB) $(SHLIB_LINKS) $(OBJECTS-y) \
	      $(BINDINGS) $(BINDINGSRC)
