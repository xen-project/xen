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

XEN_ROOT = ../../../..
include $(XEN_ROOT)/tools/Rules.mk

HOSTCFLAGS += -I. -I.. -I$(XEN_ROOT)/tools/libxc

C_SRC = build.c dsdt.c gen.c static_tables.c
H_SRC = $(wildcard *.h)
ACPI_GEN = acpigen
ACPI_BIN = acpi.bin

IASL_VER = acpica-unix-20050513
IASL_URL = http://developer.intel.com/technology/iapc/acpi/downloads/$(IASL_VER).tar.gz

vpath iasl $(PATH)
all:$(ACPI_BIN)

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

$(ACPI_GEN): $(C_SRC) $(H_SRC)
	$(HOSTCC) -o $(ACPI_GEN) $(HOSTCFLAGS) $(C_SRC)

$(ACPI_BIN): $(ACPI_GEN)
	./$(ACPI_GEN) $(ACPI_BIN)

clean:
	rm -rf *.o $(ACPI_GEN) $(ACPI_BIN) $(IASL_VER) 
	rm -rf  $(IASL_VER).tar.gz

install: all
