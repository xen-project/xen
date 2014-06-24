/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#ifndef _ATS_H_
#define _ATS_H_

#include <xen/pci_regs.h>

struct pci_ats_dev {
    struct list_head list;
    u16 seg;
    u8 bus;
    u8 devfn;
    u16 ats_queue_depth;    /* ATS device invalidation queue depth */
    const void *iommu;      /* No common IOMMU struct so use void pointer */
};

#define ATS_REG_CAP    4
#define ATS_REG_CTL    6
#define ATS_QUEUE_DEPTH_MASK     0x1f
#define ATS_ENABLE               (1<<15)

extern struct list_head ats_devices;
extern bool_t ats_enabled;

int enable_ats_device(int seg, int bus, int devfn, const void *iommu);
void disable_ats_device(int seg, int bus, int devfn);
struct pci_ats_dev *get_ats_device(int seg, int bus, int devfn);

static inline int pci_ats_enabled(int seg, int bus, int devfn)
{
    u32 value;
    int pos;

    pos = pci_find_ext_capability(seg, bus, devfn, PCI_EXT_CAP_ID_ATS);
    BUG_ON(!pos);

    value = pci_conf_read16(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                            pos + ATS_REG_CTL);
    return value & ATS_ENABLE;
}

static inline int pci_ats_device(int seg, int bus, int devfn)
{
    if ( !ats_enabled )
        return 0;

    return pci_find_ext_capability(seg, bus, devfn, PCI_EXT_CAP_ID_ATS);
}

#endif /* _ATS_H_ */

