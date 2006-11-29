#
# Copyright (c) 2004, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place - Suite 330, Boston, MA 02111-1307 USA.
#

override XEN_TARGET_ARCH = x86_32
XEN_ROOT = ../../../..
CFLAGS := -I. -I.. -I$(XEN_ROOT)/tools/libxc
include $(XEN_ROOT)/tools/Rules.mk

C_SRC = build.c dsdt.c static_tables.c
H_SRC = $(wildcard *.h)
OBJS  = $(patsubst %.c,%.o,$(C_SRC))

IASL_VER = acpica-unix-20050513
IASL_URL = http://developer.intel.com/technology/iapc/acpi/downloads/$(IASL_VER).tar.gz

vpath iasl $(PATH)
all: acpi.a

dsdt.c: dsdt.asl
	$(MAKE) iasl
	iasl -tc dsdt.asl
	mv dsdt.hex dsdt.c
	echo "int DsdtLen=sizeof(AmlCode);" >> dsdt.c
	rm *.aml

iasl:
	@echo
	@echo "ACPI ASL compiler(iasl) is needed"
	@echo "Download Intel ACPI CA"
	@echo "If wget failed, please download and compile manually from"
	@echo "http://developer.intel.com/technology/iapc/acpi/downloads.htm"
	@echo 
	wget $(IASL_URL)
	tar xzf $(IASL_VER).tar.gz
	make -C $(IASL_VER)/compiler
	$(INSTALL_PROG) $(IASL_VER)/compiler/iasl /usr/bin/iasl

acpi.a: $(OBJS)
	$(AR) rc $@ $(OBJS)

%.o: %.c $(H_SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf *.a *.o $(IASL_VER) $(IASL_VER).tar.gz

install: all
