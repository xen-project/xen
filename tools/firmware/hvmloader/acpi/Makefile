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

C_SRC = build.c dsdt_anycpu.c dsdt_15cpu.c static_tables.c
OBJS  = $(patsubst %.c,%.o,$(C_SRC))

CFLAGS += -I. -I.. $(CFLAGS_include)

vpath iasl $(PATH)
all: acpi.a

ssdt_pm.h ssdt_tpm.h: %.h: %.asl iasl
	iasl -p $* -tc $<
	sed -e 's/AmlCode/$*/g' $*.hex >$@
	rm -f $*.hex $*.aml

dsdt_15cpu.c dsdt_anycpu.c: %.c: dsdt.asl mk_dsdt.c iasl
	$(HOSTCC) $(HOSTCFLAGS) $(CFLAGS_include) -o mk_$* mk_dsdt.c
	head -n -1 $< >$*.asl
	./mk_$* >>$*.asl
	iasl -p $* -tc $*.asl
	sed -e 's/AmlCode/$*/g' $*.hex >$@
	echo "int $*_len=sizeof($*);" >>$@
	rm -f $*.hex $*.aml $*.asl mk_$*

iasl:
	@echo
	@echo "ACPI ASL compiler (iasl) is needed"
	@echo "Download and install Intel ACPI CA from"
	@echo "http://acpica.org/downloads/"
	@echo 
	@exit 1

build.o: ssdt_pm.h ssdt_tpm.h

acpi.a: $(OBJS)
	$(AR) rc $@ $(OBJS)

clean:
	rm -rf *.a *.o $(IASL_VER) $(IASL_VER).tar.gz $(DEPS)
	rm -rf ssdt_*.h dsdt*.c *~ *.aml *.hex mk_dsdt mk_dsdt15 dsdt_*cpu.asl

install: all

-include $(DEPS)
