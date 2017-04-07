/*
 * xen/arch/arm/vgic-v3-its.c
 *
 * ARM Interrupt Translation Service (ITS) emulation
 *
 * Andre Przywara <andre.przywara@arm.com>
 * Copyright (c) 2016,2017 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/bitops.h>
#include <xen/config.h>
#include <xen/domain_page.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/softirq.h>
#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/sizes.h>
#include <asm/current.h>
#include <asm/mmio.h>
#include <asm/gic_v3_defs.h>
#include <asm/gic_v3_its.h>
#include <asm/vgic.h>
#include <asm/vgic-emul.h>

/*
 * Data structure to describe a virtual ITS.
 * If both the vcmd_lock and the its_lock are required, the vcmd_lock must
 * be taken first.
 */
struct virt_its {
    struct domain *d;
    unsigned int devid_bits;
    unsigned int intid_bits;
    spinlock_t vcmd_lock;       /* Protects the virtual command buffer, which */
    uint64_t cwriter;           /* consists of CWRITER and CREADR and those   */
    uint64_t creadr;            /* shadow variables cwriter and creadr. */
    /* Protects the rest of this structure, including the ITS tables. */
    spinlock_t its_lock;
    uint64_t cbaser;
    uint64_t baser_dev, baser_coll;     /* BASER0 and BASER1 for the guest */
    unsigned int max_collections;
    unsigned int max_devices;
    bool enabled;
};

/*
 * An Interrupt Translation Table Entry: this is indexed by a
 * DeviceID/EventID pair and is located in guest memory.
 */
struct vits_itte
{
    uint32_t vlpi;
    uint16_t collection;
    uint16_t pad;
};

int vgic_v3_its_init_domain(struct domain *d)
{
    spin_lock_init(&d->arch.vgic.its_devices_lock);
    d->arch.vgic.its_devices = RB_ROOT;

    return 0;
}

void vgic_v3_its_free_domain(struct domain *d)
{
    ASSERT(RB_EMPTY_ROOT(&d->arch.vgic.its_devices));
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
