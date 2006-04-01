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

# External CFLAGS can do more harm than good.
CFLAGS :=

XEN_TARGET_ARCH = x86_32
XEN_ROOT = ../../..
include $(XEN_ROOT)/Config.mk

# The HVM loader is started in 32-bit mode at the address below:
LOADADDR = 0x100000

DEFINES  =-DDEBUG
XENINC   =-I$(XEN_ROOT)/tools/libxc

OBJECTS	 = hvmloader.o acpi_madt.o 

# Disable PIE/SSP if GCC supports them. They can break us.
CFLAGS  += $(call test-gcc-flag,$(CC),-nopie)
CFLAGS  += $(call test-gcc-flag,$(CC),-fno-stack-protector)
CFLAGS  += $(call test-gcc-flag,$(CC),-fno-stack-protector-all)

OBJCOPY  = objcopy
CFLAGS  += $(DEFINES) -I. $(XENINC) -fno-builtin -O2 -msoft-float
LDFLAGS  = -m32 -nostdlib -Wl,-N -Wl,-Ttext -Wl,$(LOADADDR)

all: hvmloader

hvmloader: roms.h hvmloader.c acpi_madt.c
	$(CC) $(CFLAGS) -c hvmloader.c acpi_madt.c
	$(CC) $(LDFLAGS) -o hvmloader.tmp hvmloader.o acpi_madt.o
	$(OBJCOPY) hvmloader.tmp hvmloader
	rm -f hvmloader.tmp

roms.h:	../rombios/BIOS-bochs-latest ../vgabios/VGABIOS-lgpl-latest.bin ../vgabios/VGABIOS-lgpl-latest.cirrus.bin ../vmxassist/vmxassist.bin
	./mkhex rombios ../rombios/BIOS-bochs-latest > roms.h
	./mkhex vgabios_stdvga ../vgabios/VGABIOS-lgpl-latest.bin >> roms.h
	./mkhex vgabios_cirrusvga ../vgabios/VGABIOS-lgpl-latest.cirrus.bin >> roms.h
	./mkhex vmxassist ../vmxassist/vmxassist.bin >> roms.h
	./mkhex acpi ../acpi/acpi.bin >> roms.h

clean:
	rm -f roms.h acpi.h
	rm -f hvmloader hvmloader.tmp hvmloader.o $(OBJECTS)

