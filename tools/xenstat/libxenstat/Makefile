# libxenstat: statistics-collection library for Xen
# Copyright (C) International Business Machines Corp., 2005
# Author: Josh Triplett <josh@kernel.org>
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

XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

LDCONFIG=ldconfig
MAKE_LINK=ln -sf

MAJOR=0
MINOR=0

LIB=src/libxenstat.a
SHLIB=src/libxenstat.so.$(MAJOR).$(MINOR)
SHLIB_LINKS=src/libxenstat.so.$(MAJOR) src/libxenstat.so
OBJECTS-y=src/xenstat.o src/xenstat_qmp.o
OBJECTS-$(CONFIG_Linux) += src/xenstat_linux.o
OBJECTS-$(CONFIG_SunOS) += src/xenstat_solaris.o
OBJECTS-$(CONFIG_NetBSD) += src/xenstat_netbsd.o
OBJECTS-$(CONFIG_FreeBSD) += src/xenstat_freebsd.o
SONAME_FLAGS=-Wl,$(SONAME_LDFLAG) -Wl,libxenstat.so.$(MAJOR)

CFLAGS+=-fPIC
CFLAGS+=-Isrc $(CFLAGS_libxenctrl) $(CFLAGS_libxenstore) $(CFLAGS_xeninclude) -include $(XEN_ROOT)/tools/config.h

LDLIBS-y = $(LDLIBS_libxenstore) $(LDLIBS_libxenctrl) -lyajl
LDLIBS-$(CONFIG_SunOS) += -lkstat

PKG_CONFIG := xenstat.pc
PKG_CONFIG_VERSION := $(MAJOR).$(MINOR)

ifneq ($(CONFIG_LIBXC_MINIOS),y)
PKG_CONFIG_INST := $(PKG_CONFIG)
$(PKG_CONFIG_INST): PKG_CONFIG_PREFIX = $(prefix)
$(PKG_CONFIG_INST): PKG_CONFIG_INCDIR = $(includedir)
$(PKG_CONFIG_INST): PKG_CONFIG_LIBDIR = $(libdir)
endif

PKG_CONFIG_LOCAL := $(foreach pc,$(PKG_CONFIG),$(PKG_CONFIG_DIR)/$(pc))

$(PKG_CONFIG_LOCAL): PKG_CONFIG_PREFIX = $(XEN_ROOT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_LIBXENSTAT)
$(PKG_CONFIG_LOCAL): PKG_CONFIG_LIBDIR = $(CURDIR)

.PHONY: all
all: $(LIB) $(SHLIB) $(SHLIB_LINKS) $(PKG_CONFIG_INST) $(PKG_CONFIG_LOCAL)

$(OBJECTS-y): src/_paths.h

$(LIB): $(OBJECTS-y)
	$(AR) rc $@ $^
	$(RANLIB) $@

$(SHLIB): $(OBJECTS-y)
	$(CC) $(LDFLAGS) $(SONAME_FLAGS) $(SHLIB_LDFLAGS) -o $@ \
	    $(OBJECTS-y) $(LDLIBS-y) $(APPEND_LDFLAGS)

src/libxenstat.so.$(MAJOR): $(SHLIB)
	$(MAKE_LINK) $(<F) $@

src/libxenstat.so: src/libxenstat.so.$(MAJOR)
	$(MAKE_LINK) $(<F) $@

.PHONY: install
install: all
	$(INSTALL_DATA) src/xenstat.h $(DESTDIR)$(includedir)
	$(INSTALL_DATA) $(LIB) $(DESTDIR)$(libdir)/libxenstat.a
	$(INSTALL_PROG) src/libxenstat.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)
	ln -sf libxenstat.so.$(MAJOR).$(MINOR) $(DESTDIR)$(libdir)/libxenstat.so.$(MAJOR)
	ln -sf libxenstat.so.$(MAJOR) $(DESTDIR)$(libdir)/libxenstat.so
	$(INSTALL_DATA) xenstat.pc $(DESTDIR)$(PKG_INSTALLDIR)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PKG_INSTALLDIR)/xenstat.pc
	rm -f $(DESTDIR)$(libdir)/libxenstat.so
	rm -f $(DESTDIR)$(libdir)/libxenstat.so.$(MAJOR)
	rm -f $(DESTDIR)$(libdir)/libxenstat.so.$(MAJOR).$(MINOR)
	rm -f $(DESTDIR)$(libdir)/libxenstat.a
	rm -f $(DESTDIR)$(includedir)/xenstat.h

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

.PHONY: uninstall-bindings
uninstall-bindings: uninstall-perl-bindings uninstall-python-bindings

$(BINDINGS): $(SHLIB) $(SHLIB_LINKS) src/xenstat.h

SWIG_FLAGS=-module xenstat -Isrc

# Python bindings
PYTHON_VERSION=$(PYTHON:python%=%)
PYTHON_FLAGS=-I/usr/include/python$(PYTHON_VERSION) -lpython$(PYTHON_VERSION)
$(PYMOD): $(PYSRC)
$(PYSRC): bindings/swig/xenstat.i
	swig -python $(SWIG_FLAGS) -outdir $(@D) -o $(PYSRC) $<

$(PYLIB): $(PYSRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $(PYTHON_FLAGS) $(SHLIB_LDFLAGS) -lxenstat -o $@ $< $(APPEND_LDFLAGS)

python-bindings: $(PYLIB) $(PYMOD)

pythonlibdir=$(prefix)/lib/python$(PYTHON_VERSION)/site-packages
install-python-bindings: $(PYLIB) $(PYMOD)
	$(INSTALL_PROG) $(PYLIB) $(DESTDIR)$(pythonlibdir)/_xenstat.so
	$(INSTALL_PROG) $(PYMOD) $(DESTDIR)$(pythonlibdir)/xenstat.py

.PHONY: uninstall-python-bindings
uninstall-python-bindings:
	rm -f $(DESTDIR)$(pythonlibdir)/_xenstat.so
	rm -f $(DESTDIR)$(pythonlibdir)/xenstat.py

ifeq ($(XENSTAT_PYTHON_BINDINGS),y)
.PHONY: all
all: python-bindings
install: install-python-bindings
uninstall: uninstall-python-bindings
endif

# Perl bindings
PERL_FLAGS=`perl -MConfig -e 'print "$$Config{ccflags} -I$$Config{archlib}/CORE";'`
$(PERLMOD): $(PERLSRC)
$(PERLSRC): bindings/swig/xenstat.i
	swig -perl $(SWIG_FLAGS) -outdir $(@D) -o $(PERLSRC) $<

$(PERLLIB): $(PERLSRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $(PERL_FLAGS) $(SHLIB_LDFLAGS) -lxenstat -o $@ $< $(APPEND_LDFLAGS)

.PHONY: perl-bindings
perl-bindings: $(PERLLIB) $(PERLMOD)

.PHONY: install-perl-bindings
perllibdir=$(prefix)/lib/perl5
perlmoddir=$(prefix)/share/perl5
install-perl-bindings: $(PERLLIB) $(PERLMOD)
	$(INSTALL_PROG) $(PERLLIB) $(DESTDIR)$(perllibdir)/xenstat.so
	$(INSTALL_PROG) $(PERLMOD) $(DESTDIR)$(perlmoddir)/xenstat.pm

.PHONY: uninstall-perl-bindings
uninstall-perl-bindings:
	rm -f $(DESTDIR)$(perllibdir)/xenstat.so
	rm -f $(DESTDIR)$(perlmoddir)/xenstat.pm

ifeq ($(XENSTAT_PERL_BINDINGS),y)
.PHONY: all
all: perl-bindings

.PHONY: install
install: install-perl-bindings
uninstall: uninstall-perl-bindings
endif

.PHONY: clean
clean:
	rm -f $(LIB) $(SHLIB) $(SHLIB_LINKS) $(OBJECTS-y) \
	      $(BINDINGS) $(BINDINGSRC) $(DEPS_RM) src/_paths.h
	rm -f xenstat.pc

.PHONY: distclean
distclean: clean

-include $(DEPS_INCLUDE)

genpath-target = $(call buildmakevars2header,src/_paths.h)
$(eval $(genpath-target))
