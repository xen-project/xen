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

struct pci_ats_dev {
    struct list_head list;
    u16 seg;
    u8 bus;
    u8 devfn;
    u16 ats_queue_depth;    /* ATS device invalidation queue depth */
};

#ifdef CONFIG_X86_64

#define ATS_REG_CAP    4
#define ATS_REG_CTL    6
#define ATS_QUEUE_DEPTH_MASK     0xF
#define ATS_ENABLE               (1<<15)

extern struct list_head ats_devices;
extern bool_t ats_enabled;

int enable_ats_device(int seg, int bus, int devfn);
void disable_ats_device(int seg, int bus, int devfn);

#else

#define ats_enabled 0
static inline int enable_ats_device(int seg, int bus, int devfn)
{
    BUG();
    return -ENOSYS;
}

static inline void disable_ats_device(int seg, int bus, int devfn)
{
    BUG();
}
#endif

#endif /* _ATS_H_ */

