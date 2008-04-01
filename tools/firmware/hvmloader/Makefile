#
# Makefile
#
# Leendert van Doorn, leendert@watson.ibm.com
# Copyright (c) 2005, International Business Machines Corporation.
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
XEN_ROOT = ../../..
CFLAGS :=
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS := acpi

# The HVM loader is started in 32-bit mode at the address below:
LOADADDR = 0x100000

# Disable PIE/SSP if GCC supports them. They can break us.
CFLAGS  += $(call cc-option,$(CC),-nopie,)
CFLAGS  += $(call cc-option,$(CC),-fno-stack-protector,)
CFLAGS  += $(call cc-option,$(CC),-fno-stack-protector-all,)

CFLAGS  += -fno-builtin -O2 -msoft-float
CFLAGS  += $(CFLAGS_include) -I.

SRCS = hvmloader.c mp_tables.c util.c smbios.c 32bitbios_support.c
OBJS = $(patsubst %.c,%.o,$(SRCS))

.PHONY: all
all: hvmloader

smbios.o: CFLAGS += -D__SMBIOS_DATE__="\"$(shell date +%m/%d/%Y)\""

hvmloader: roms.h subdirs-all $(OBJS)
	$(LD) $(LDFLAGS_DIRECT) -N -Ttext $(LOADADDR) \
		-o hvmloader.tmp $(OBJS) acpi/acpi.a
	$(OBJCOPY) hvmloader.tmp hvmloader
	rm -f hvmloader.tmp

roms.h: ../rombios/BIOS-bochs-latest ../vgabios/VGABIOS-lgpl-latest.bin \
	../vgabios/VGABIOS-lgpl-latest.cirrus.bin ../etherboot/eb-roms.h \
	../extboot/extboot.bin
	sh ./mkhex rombios ../rombios/BIOS-bochs-latest > roms.h
	sh ./mkhex vgabios_stdvga ../vgabios/VGABIOS-lgpl-latest.bin >> roms.h
	sh ./mkhex vgabios_cirrusvga \
		../vgabios/VGABIOS-lgpl-latest.cirrus.bin >> roms.h
	cat ../etherboot/eb-roms.h >> roms.h
	sh ./mkhex extboot ../extboot/extboot.bin >> roms.h

.PHONY: clean
clean: subdirs-clean
	rm -f roms.h acpi.h
	rm -f hvmloader hvmloader.tmp *.o
