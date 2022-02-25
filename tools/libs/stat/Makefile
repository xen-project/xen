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

CFLAGS += -include $(XEN_ROOT)/tools/config.h

OBJS-y += xenstat.o
OBJS-y += xenstat_qmp.o
OBJS-$(CONFIG_Linux) += xenstat_linux.o
OBJS-$(CONFIG_SunOS) += xenstat_solaris.o
OBJS-$(CONFIG_NetBSD) += xenstat_netbsd.o
OBJS-$(CONFIG_FreeBSD) += xenstat_freebsd.o

LDLIBS-y += -lyajl
LDLIBS-$(CONFIG_SunOS) += -lkstat
LDLIBS += $(LDLIBS-y)

include $(XEN_ROOT)/tools/libs/libs.mk

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

$(BINDINGS): $(SHLIB) $(SHLIB_LINKS) include/xenstat.h

SWIG_FLAGS=-module xenstat -Iinclude -I.

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
install:: install-python-bindings
uninstall:: uninstall-python-bindings
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
install:: install-perl-bindings
uninstall:: uninstall-perl-bindings
endif

clean::
	$(RM) libxenstat.map $(BINDINGS) $(BINDINGSRC)
