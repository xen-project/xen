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

XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/firmware/Rules.mk

SUBDIRS := acpi

# The HVM loader is started in 32-bit mode at the address below:
LOADADDR = 0x100000

CFLAGS += $(CFLAGS_include) -I.

SRCS  = hvmloader.c mp_tables.c util.c smbios.c 
SRCS += 32bitbios_support.c smp.c cacheattr.c xenbus.c
ifeq ($(debug),y)
SRCS += tests.c
endif
OBJS  = $(patsubst %.c,%.o,$(SRCS))

.PHONY: all
all: subdirs-all
	$(MAKE) hvmloader

hvmloader.o: roms.h
smbios.o: CFLAGS += -D__SMBIOS_DATE__="\"$(shell date +%m/%d/%Y)\""

hvmloader: $(OBJS) acpi/acpi.a
	$(LD) $(LDFLAGS_DIRECT) -N -Ttext $(LOADADDR) -o hvmloader.tmp $^
	$(OBJCOPY) hvmloader.tmp hvmloader
	rm -f hvmloader.tmp

roms.h: ../rombios/BIOS-bochs-latest ../vgabios/VGABIOS-lgpl-latest.bin \
	../vgabios/VGABIOS-lgpl-latest.cirrus.bin ../etherboot/eb-roms.h
	sh ./mkhex rombios ../rombios/BIOS-bochs-latest > roms.h
	sh ./mkhex vgabios_stdvga ../vgabios/VGABIOS-lgpl-latest.bin >> roms.h
	sh ./mkhex vgabios_cirrusvga \
		../vgabios/VGABIOS-lgpl-latest.cirrus.bin >> roms.h
	cat ../etherboot/eb-roms.h >> roms.h

.PHONY: clean
clean: subdirs-clean
	rm -f roms.h acpi.h
	rm -f hvmloader hvmloader.tmp *.o $(DEPS)

-include $(DEPS)
