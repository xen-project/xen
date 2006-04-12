#/*
# * Copyright (c) 2004, Intel Corporation.
# *
# * This program is free software; you can redistribute it and/or modify it
# * under the terms and conditions of the GNU General Public License,
# * version 2, as published by the Free Software Foundation.
# *
# * This program is distributed in the hope it will be useful, but WITHOUT
# * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# * more details.
# *
# * You should have received a copy of the GNU General Public License along with
# * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# * Place - Suite 330, Boston, MA 02111-1307 USA.
# *
# */
#

XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

# Compiler flag
HOSTCFLAGS += -I. -I../../libxc

# TARGET
C_SRC=$(shell ls *.c)
H_SRC=$(shell ls *.h)
ACPI_GEN=acpigen
ACPI_BIN=acpi.bin

IASL_VER=acpica-unix-20050513
IASL_URL=http://developer.intel.com/technology/iapc/acpi/downloads/$(IASL_VER).tar.gz

vpath iasl $(PATH)
.PHONY: all
all:$(ACPI_BIN)

acpi_dsdt.c:acpi_dsdt.asl
	$(MAKE) iasl
	iasl -oa -tc acpi_dsdt.asl
	mv acpi_dsdt.hex acpi_dsdt.c
	echo "int DsdtLen=sizeof(AmlCode);" >> acpi_dsdt.c
	rm *.aml

.PHONY: iasl
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
	install $(IASL_VER)/compiler/iasl /usr/bin/iasl

$(ACPI_GEN):$(C_SRC) $(H_SRC) acpi_dsdt.c
	$(HOSTCC) -o $(ACPI_GEN) $(HOSTCFLAGS) $(shell ls *.c)

$(ACPI_BIN):$(ACPI_GEN)
	./$(ACPI_GEN) $(ACPI_BIN)

.PHONY: clean
clean:
	rm -rf *.o $(ACPI_GEN) $(ACPI_BIN) $(IASL_VER) 
	rm -rf  $(IASL_VER).tar.gz

.PHONY: install
install: all
