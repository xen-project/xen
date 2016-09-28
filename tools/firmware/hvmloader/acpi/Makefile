#
# Copyright (c) 2004, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; version 2.1 only. with the special
# exception on linking described in file LICENSE.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# NU Lesser General Public License for more details.
#

XEN_ROOT = $(CURDIR)/../../../..
include $(XEN_ROOT)/tools/firmware/Rules.mk

C_SRC-$(GPL) = build.c dsdt_anycpu.c dsdt_15cpu.c dsdt_anycpu_qemu_xen.c
C_SRC = build.c static_tables.c $(C_SRC-y)
OBJS  = $(patsubst %.c,%.o,$(C_SRC))

CFLAGS += $(CFLAGS_xeninclude)

# Suffix for temporary files.
TMP_SUFFIX	= tmp

vpath iasl $(PATH)
all: acpi.a

ssdt_s3.h ssdt_s4.h ssdt_pm.h ssdt_tpm.h: %.h: %.asl iasl
	iasl -vs -p $* -tc $<
	sed -e 's/AmlCode/$*/g' $*.hex >$@
	rm -f $*.hex $*.aml

mk_dsdt: mk_dsdt.c
	$(HOSTCC) $(HOSTCFLAGS) $(CFLAGS_xeninclude) -o $@ mk_dsdt.c

ifeq ($(GPL),y)
dsdt_anycpu_qemu_xen.asl: dsdt.asl dsdt_acpi_info.asl gpl/mk_dsdt_gpl.sh mk_dsdt
	awk 'NR > 1 {print s} {s=$$0}' $< > $@.$(TMP_SUFFIX)
	# Strip license comment
	sed -i '1,/\*\//{/\/\*/,/\*\//d}' $@.$(TMP_SUFFIX)
	$(SHELL) gpl/mk_dsdt_gpl.sh >> $@.$(TMP_SUFFIX)
	cat dsdt_acpi_info.asl >> $@.$(TMP_SUFFIX)
	./mk_dsdt --debug=$(debug) --dm-version qemu-xen >> $@.$(TMP_SUFFIX)
	mv -f $@.$(TMP_SUFFIX) $@

# NB. awk invocation is a portable alternative to 'head -n -1'
dsdt_%cpu.asl: dsdt.asl dsdt_acpi_info.asl gpl/mk_dsdt_gpl.sh mk_dsdt
	awk 'NR > 1 {print s} {s=$$0}' $< > $@.$(TMP_SUFFIX)
	sed -i '1,/\*\//{/\/\*/,/\*\//d}' $@.$(TMP_SUFFIX)
	$(SHELL) gpl/mk_dsdt_gpl.sh >> $@.$(TMP_SUFFIX)
	cat dsdt_acpi_info.asl >> $@.$(TMP_SUFFIX)
	./mk_dsdt --debug=$(debug) --maxcpu $*  >> $@.$(TMP_SUFFIX)
	mv -f $@.$(TMP_SUFFIX) $@
endif

$(filter dsdt_%.c,$(C_SRC)): %.c: iasl %.asl
	iasl -vs -p $* -tc $*.asl
	sed -e 's/AmlCode/$*/g' $*.hex >$@.$(TMP_SUFFIX)
	echo "int $*_len=sizeof($*);" >>$@.$(TMP_SUFFIX)
	mv -f $@.$(TMP_SUFFIX) $@
	rm -f $*.aml $*.hex

iasl:
	@echo
	@echo "ACPI ASL compiler (iasl) is needed"
	@echo "Download and install Intel ACPI CA from"
	@echo "http://acpica.org/downloads/"
	@echo 
	@exit 1

build.o: ssdt_s3.h ssdt_s4.h ssdt_pm.h ssdt_tpm.h

acpi.a: $(OBJS)
	$(AR) rc $@ $(OBJS)

clean:
	rm -rf *.a *.o $(IASL_VER) $(IASL_VER).tar.gz $(DEPS)
	rm -rf ssdt_*.h dsdt*.c *~ *.aml *.hex mk_dsdt dsdt_*cpu*.asl *.$(TMP_SUFFIX)

distclean: clean

install: all

-include $(DEPS)
