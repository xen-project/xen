#
#  GRUB  --  GRand Unified Bootloader
#  Copyright (C) 1999,2000,2001,2002,2003,2004  Free Software Foundation, Inc.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; If not, see <http://www.gnu.org/licenses/>.
#

# 
#  Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
#  Use is subject to license terms.
#

XEN_ROOT = $(CURDIR)/../../..

CFLAGS += -DFSYS_ZFS -DFSIMAGE -I$(XEN_ROOT)/tools/libfsimage/zfs
LIB_SRCS-y = zfs_lzjb.c zfs_sha256.c zfs_fletcher.c fsi_zfs.c fsys_zfs.c

FS = zfs

.PHONY: all
all: fs-all

.PHONY: install
install: fs-install

.PHONY: uninstall
uninstall: fs-uninstall

include $(XEN_ROOT)/tools/libfsimage/Rules.mk
