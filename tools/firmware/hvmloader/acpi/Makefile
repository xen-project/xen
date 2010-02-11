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
include $(XEN_ROOT)/tools/firmware/Rules.mk

C_SRC = build.c dsdt.c static_tables.c
OBJS  = $(patsubst %.c,%.o,$(C_SRC))

CFLAGS += -I. -I.. $(CFLAGS_include)

vpath iasl $(PATH)
all: acpi.a

ssdt_pm.h ssdt_tpm.h: %.h: %.asl
	$(MAKE) iasl
	iasl -tc $<
	sed -e 's/AmlCode/$*/g' $*.hex >$@
	rm -f *.aml $*.hex

dsdt.c: dsdt.asl mk_dsdt.c
	$(MAKE) iasl
	$(HOSTCC) $(HOSTCFLAGS) $(CFLAGS_include) -o mk_dsdt mk_dsdt.c
	head -n -1 $< >_dsdt.asl
	./mk_dsdt >>_dsdt.asl
	iasl -tc _dsdt.asl
	sed -e 's/AmlCode/Dsdt/g' _dsdt.hex >dsdt.c
	echo "int DsdtLen=sizeof(Dsdt);" >> dsdt.c
	rm -f *.aml _dsdt.asl mk_dsdt _dsdt.hex

iasl:
	@echo
	@echo "ACPI ASL compiler (iasl) is needed"
	@echo "Download and install Intel ACPI CA from"
	@echo "http://acpica.org/downloads/"
	@echo 
	@exit 1

acpi.a: $(OBJS)
	$(AR) rc $@ $(OBJS)

clean:
	rm -rf *.a *.o $(IASL_VER) $(IASL_VER).tar.gz $(DEPS)

install: all

-include $(DEPS)
