/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ASM_PCI_H_
#define _ASM_PCI_H_

#include <xen/pci.h>

#define PCIBIOS_MIN_IO  0x1000
#define PCIBIOS_MIN_MEM 0x10000000

extern void pcibios_set_master(struct pci_dev *dev);
extern unsigned int pcibios_assign_all_busses(void);
extern int pcibios_scan_all_fns(struct pci_bus *bus, int devfn);
extern int (*pci_config_read)(int seg, int bus, int dev, int fn, int reg, int len, u32 *value);
extern int (*pci_config_write)(int seg, int bus, int dev, int fn, int reg, int len, u32 value);

#endif
