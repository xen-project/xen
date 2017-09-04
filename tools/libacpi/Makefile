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
# GNU Lesser General Public License for more details.
#

XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

ifeq ($(ACPI_BUILD_DIR),)
$(error ACPI_BUILD_DIR not set)
endif

MK_DSDT = $(ACPI_BUILD_DIR)/mk_dsdt

C_SRC-$(CONFIG_X86) = dsdt_anycpu.c dsdt_15cpu.c dsdt_anycpu_qemu_xen.c dsdt_pvh.c
C_SRC-$(CONFIG_ARM_64) = dsdt_anycpu_arm.c
DSDT_FILES ?= $(C_SRC-y)
C_SRC = $(addprefix $(ACPI_BUILD_DIR)/, $(DSDT_FILES))
H_SRC = $(addprefix $(ACPI_BUILD_DIR)/, ssdt_s3.h ssdt_s4.h ssdt_pm.h ssdt_tpm.h ssdt_laptop_slate.h)

MKDSDT_CFLAGS-$(CONFIG_ARM_64) = -DCONFIG_ARM_64
MKDSDT_CFLAGS-$(CONFIG_X86) = -DCONFIG_X86

# Suffix for temporary files.
#
# We will also use this suffix to workaround a bug in older iasl
# versions where the tool will ignore everything after last '.' in the
# path ('-p' argument). By adding ".<suffix>" we force iasl to use
# complete $(ACPI_BUILD_DIR) as path, even if it has '.' symbols.
TMP_SUFFIX	= tmp

vpath iasl $(PATH)
all: $(C_SRC) $(H_SRC)

$(H_SRC): $(ACPI_BUILD_DIR)/%.h: %.asl iasl
	iasl -vs -p $(ACPI_BUILD_DIR)/$*.$(TMP_SUFFIX) -tc $<
	sed -e 's/AmlCode/$*/g' $(ACPI_BUILD_DIR)/$*.hex >$@
	rm -f $(addprefix $(ACPI_BUILD_DIR)/, $*.aml $*.hex)
 
$(MK_DSDT): mk_dsdt.c
	$(HOSTCC) $(HOSTCFLAGS) $(MKDSDT_CFLAGS-y) $(CFLAGS_xeninclude) -D__XEN_TOOLS__ -o $@ mk_dsdt.c

$(ACPI_BUILD_DIR)/dsdt_anycpu_qemu_xen.asl: dsdt.asl dsdt_acpi_info.asl $(MK_DSDT)
	# Remove last bracket
	awk 'NR > 1 {print s} {s=$$0}' $< > $@.$(TMP_SUFFIX)
	cat dsdt_acpi_info.asl >> $@.$(TMP_SUFFIX)
	$(MK_DSDT) --debug=$(debug) --dm-version qemu-xen >> $@.$(TMP_SUFFIX)
	mv -f $@.$(TMP_SUFFIX) $@

# NB. awk invocation is a portable alternative to 'head -n -1'
$(ACPI_BUILD_DIR)/dsdt_%cpu.asl: dsdt.asl dsdt_acpi_info.asl  $(MK_DSDT)
	# Remove last bracket
	awk 'NR > 1 {print s} {s=$$0}' $< > $@.$(TMP_SUFFIX)
	cat dsdt_acpi_info.asl >> $@.$(TMP_SUFFIX)
	$(MK_DSDT) --debug=$(debug) --maxcpu $*  >> $@.$(TMP_SUFFIX)
	mv -f $@.$(TMP_SUFFIX) $@

$(ACPI_BUILD_DIR)/dsdt_pvh.asl: dsdt_acpi_info.asl $(MK_DSDT)
	printf "DefinitionBlock (\"DSDT.aml\", \"DSDT\", 5, \"Xen\", \"HVM\", 0)\n{" > $@
	cat dsdt_acpi_info.asl >> $@
	$(MK_DSDT) --debug=$(debug) --maxcpu any --dm-version none >> $@

$(ACPI_BUILD_DIR)/dsdt_anycpu_arm.asl: $(MK_DSDT)
	printf "DefinitionBlock (\"DSDT.aml\", \"DSDT\", 3, \"Xen\", \"ARM\", 1)\n{" > $@.$(TMP_SUFFIX)
	$(MK_DSDT) --debug=$(debug) >> $@.$(TMP_SUFFIX)
	mv -f $@.$(TMP_SUFFIX) $@

$(C_SRC): $(ACPI_BUILD_DIR)/%.c: iasl $(ACPI_BUILD_DIR)/%.asl
	iasl -vs -p $(ACPI_BUILD_DIR)/$*.$(TMP_SUFFIX) -tc $(ACPI_BUILD_DIR)/$*.asl
	sed -e 's/AmlCode/$*/g' $(ACPI_BUILD_DIR)/$*.hex > $@.$(TMP_SUFFIX)
	echo "int $*_len=sizeof($*);" >> $@.$(TMP_SUFFIX)
	mv -f $@.$(TMP_SUFFIX) $@
	rm -f $(addprefix $(ACPI_BUILD_DIR)/, $*.aml $*.hex)

iasl:
	@echo
	@echo "ACPI ASL compiler (iasl) is needed"
	@echo "Download and install Intel ACPI CA from"
	@echo "http://acpica.org/downloads/"
	@echo 
	@exit 1

build.o: ssdt_s3.h ssdt_s4.h ssdt_pm.h ssdt_tpm.h ssdt_laptop_slate.h

acpi.a: $(OBJS)
	$(AR) rc $@ $(OBJS)

clean:
	rm -f $(C_SRC) $(H_SRC) $(MK_DSDT) $(C_SRC:=.$(TMP_SUFFIX))
	rm -f $(patsubst %.c,%.hex,$(C_SRC)) $(patsubst %.c,%.aml,$(C_SRC)) $(patsubst %.c,%.asl,$(C_SRC))

distclean: clean

install: all

-include $(DEPS_INCLUDE)
