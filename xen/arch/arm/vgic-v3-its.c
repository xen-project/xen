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

/*
 * Locking order:
 *
 * its->vcmd_lock                        (protects the command queue)
 *     its->its_lock                     (protects the translation tables)
 *         d->its_devices_lock           (protects the device RB tree)
 *             v->vgic.lock              (protects the struct pending_irq)
 *                 d->pend_lpi_tree_lock (protects the radix tree)
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
#include <asm/guest_access.h>
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
    struct list_head vits_list;
    paddr_t doorbell_address;
    unsigned int devid_bits;
    unsigned int evid_bits;
    spinlock_t vcmd_lock;       /* Protects the virtual command buffer, which */
    uint64_t cwriter;           /* consists of CWRITER and CREADR and those   */
    uint64_t creadr;            /* shadow variables cwriter and creadr. */
    /* Protects the rest of this structure, including the ITS tables. */
    spinlock_t its_lock;
    uint64_t cbaser;
    uint64_t baser_dev, baser_coll;     /* BASER0 and BASER1 for the guest */
    unsigned int max_collections;
    unsigned int max_devices;
    /* changing "enabled" requires to hold *both* the vcmd_lock and its_lock */
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

/*
 * Our collection table encoding:
 * Each entry just contains the VCPU ID of the respective vCPU.
 */
typedef uint16_t coll_table_entry_t;
#define UNMAPPED_COLLECTION      ((coll_table_entry_t)~0)

/*
 * Our device table encodings:
 * Contains the guest physical address of the Interrupt Translation Table in
 * bits [51:8], and the size of it is encoded as the number of bits minus one
 * in the lowest 5 bits of the word.
 */
typedef uint64_t dev_table_entry_t;
#define DEV_TABLE_ITT_ADDR(x) ((x) & GENMASK(51, 8))
#define DEV_TABLE_ITT_SIZE(x) (BIT(((x) & GENMASK(4, 0)) + 1))
#define DEV_TABLE_ENTRY(addr, bits)                     \
        (((addr) & GENMASK(51, 8)) | (((bits) - 1) & GENMASK(4, 0)))

#define GITS_BASER_RO_MASK       (GITS_BASER_TYPE_MASK | \
                                  (0x1fL << GITS_BASER_ENTRY_SIZE_SHIFT))

/*
 * The physical address is encoded slightly differently depending on
 * the used page size: the highest four bits are stored in the lowest
 * four bits of the field for 64K pages.
 */
static paddr_t get_baser_phys_addr(uint64_t reg)
{
    if ( reg & BIT(9) )
        return (reg & GENMASK(47, 16)) |
                ((reg & GENMASK(15, 12)) << 36);
    else
        return reg & GENMASK(47, 12);
}

/* Must be called with the ITS lock held. */
static int its_set_collection(struct virt_its *its, uint16_t collid,
                              coll_table_entry_t vcpu_id)
{
    paddr_t addr = get_baser_phys_addr(its->baser_coll);

    /* The collection table entry must be able to store a VCPU ID. */
    BUILD_BUG_ON(BIT(sizeof(coll_table_entry_t) * 8) < MAX_VIRT_CPUS);

    ASSERT(spin_is_locked(&its->its_lock));

    if ( collid >= its->max_collections )
        return -ENOENT;

    return access_guest_memory_by_ipa(its->d,
                                      addr + collid * sizeof(coll_table_entry_t),
                                      &vcpu_id, sizeof(vcpu_id), true);
}

/* Must be called with the ITS lock held. */
static struct vcpu *get_vcpu_from_collection(struct virt_its *its,
                                             uint16_t collid)
{
    paddr_t addr = get_baser_phys_addr(its->baser_coll);
    coll_table_entry_t vcpu_id;
    int ret;

    ASSERT(spin_is_locked(&its->its_lock));

    if ( collid >= its->max_collections )
        return NULL;

    ret = access_guest_memory_by_ipa(its->d,
                                     addr + collid * sizeof(coll_table_entry_t),
                                     &vcpu_id, sizeof(coll_table_entry_t), false);
    if ( ret )
        return NULL;

    if ( vcpu_id == UNMAPPED_COLLECTION || vcpu_id >= its->d->max_vcpus )
        return NULL;

    return its->d->vcpu[vcpu_id];
}

/* Set the address of an ITT for a given device ID. */
static int its_set_itt_address(struct virt_its *its, uint32_t devid,
                               paddr_t itt_address, uint32_t nr_bits)
{
    paddr_t addr = get_baser_phys_addr(its->baser_dev);
    dev_table_entry_t itt_entry = DEV_TABLE_ENTRY(itt_address, nr_bits);

    if ( devid >= its->max_devices )
        return -ENOENT;

    return access_guest_memory_by_ipa(its->d,
                                      addr + devid * sizeof(dev_table_entry_t),
                                      &itt_entry, sizeof(itt_entry), true);
}

/*
 * Lookup the address of the Interrupt Translation Table associated with
 * that device ID.
 * TODO: add support for walking indirect tables.
 */
static int its_get_itt(struct virt_its *its, uint32_t devid,
                       dev_table_entry_t *itt)
{
    paddr_t addr = get_baser_phys_addr(its->baser_dev);

    if ( devid >= its->max_devices )
        return -EINVAL;

    return access_guest_memory_by_ipa(its->d,
                                      addr + devid * sizeof(dev_table_entry_t),
                                      itt, sizeof(*itt), false);
}

/*
 * Lookup the address of the Interrupt Translation Table associated with
 * a device ID and return the address of the ITTE belonging to the event ID
 * (which is an index into that table).
 */
static paddr_t its_get_itte_address(struct virt_its *its,
                                    uint32_t devid, uint32_t evid)
{
    dev_table_entry_t itt;
    int ret;

    ret = its_get_itt(its, devid, &itt);
    if ( ret )
        return INVALID_PADDR;

    if ( evid >= DEV_TABLE_ITT_SIZE(itt) ||
         DEV_TABLE_ITT_ADDR(itt) == INVALID_PADDR )
        return INVALID_PADDR;

    return DEV_TABLE_ITT_ADDR(itt) + evid * sizeof(struct vits_itte);
}

/*
 * Queries the collection and device tables to get the vCPU and virtual
 * LPI number for a given guest event. This first accesses the guest memory
 * to resolve the address of the ITTE, then reads the ITTE entry at this
 * address and puts the result in vcpu_ptr and vlpi_ptr.
 * Must be called with the ITS lock held.
 */
static bool read_itte(struct virt_its *its, uint32_t devid, uint32_t evid,
                      struct vcpu **vcpu_ptr, uint32_t *vlpi_ptr)
{
    paddr_t addr;
    struct vits_itte itte;
    struct vcpu *vcpu;

    ASSERT(spin_is_locked(&its->its_lock));

    addr = its_get_itte_address(its, devid, evid);
    if ( addr == INVALID_PADDR )
        return false;

    if ( access_guest_memory_by_ipa(its->d, addr, &itte, sizeof(itte), false) )
        return false;

    vcpu = get_vcpu_from_collection(its, itte.collection);
    if ( !vcpu )
        return false;

    *vcpu_ptr = vcpu;
    *vlpi_ptr = itte.vlpi;
    return true;
}

/*
 * Queries the collection and device tables to translate the device ID and
 * event ID and find the appropriate ITTE. The given collection ID and the
 * virtual LPI number are then stored into that entry.
 * If vcpu_ptr is provided, returns the VCPU belonging to that collection.
 * Must be called with the ITS lock held.
 */
static bool write_itte(struct virt_its *its, uint32_t devid,
                       uint32_t evid, uint32_t collid, uint32_t vlpi)
{
    paddr_t addr;
    struct vits_itte itte;

    ASSERT(spin_is_locked(&its->its_lock));

    addr = its_get_itte_address(its, devid, evid);
    if ( addr == INVALID_PADDR )
        return false;

    itte.collection = collid;
    itte.vlpi = vlpi;

    if ( access_guest_memory_by_ipa(its->d, addr, &itte, sizeof(itte), true) )
        return false;

    return true;
}

/**************************************
 * Functions that handle ITS commands *
 **************************************/

static uint64_t its_cmd_mask_field(uint64_t *its_cmd, unsigned int word,
                                   unsigned int shift, unsigned int size)
{
    return (its_cmd[word] >> shift) & GENMASK(size - 1, 0);
}

#define its_cmd_get_command(cmd)        its_cmd_mask_field(cmd, 0,  0,  8)
#define its_cmd_get_deviceid(cmd)       its_cmd_mask_field(cmd, 0, 32, 32)
#define its_cmd_get_size(cmd)           its_cmd_mask_field(cmd, 1,  0,  5)
#define its_cmd_get_id(cmd)             its_cmd_mask_field(cmd, 1,  0, 32)
#define its_cmd_get_physical_id(cmd)    its_cmd_mask_field(cmd, 1, 32, 32)
#define its_cmd_get_collection(cmd)     its_cmd_mask_field(cmd, 2,  0, 16)
#define its_cmd_get_target_addr(cmd)    its_cmd_mask_field(cmd, 2, 16, 32)
#define its_cmd_get_validbit(cmd)       its_cmd_mask_field(cmd, 2, 63,  1)
#define its_cmd_get_ittaddr(cmd)        (its_cmd_mask_field(cmd, 2, 8, 44) << 8)

static int its_handle_int(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    uint32_t eventid = its_cmd_get_id(cmdptr);
    struct vcpu *vcpu;
    uint32_t vlpi;
    bool ret;

    spin_lock(&its->its_lock);
    ret = read_itte(its, devid, eventid, &vcpu, &vlpi);
    spin_unlock(&its->its_lock);
    if ( !ret )
        return -1;

    if ( vlpi == INVALID_LPI )
        return -1;

    vgic_vcpu_inject_lpi(its->d, vlpi);

    return 0;
}

static int its_handle_mapc(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t collid = its_cmd_get_collection(cmdptr);
    uint64_t rdbase = its_cmd_mask_field(cmdptr, 2, 16, 44);

    if ( collid >= its->max_collections )
        return -1;

    if ( rdbase >= its->d->max_vcpus )
        return -1;

    spin_lock(&its->its_lock);

    if ( its_cmd_get_validbit(cmdptr) )
        its_set_collection(its, collid, rdbase);
    else
        its_set_collection(its, collid, UNMAPPED_COLLECTION);

    spin_unlock(&its->its_lock);

    return 0;
}

/*
 * CLEAR removes the pending state from an LPI. */
static int its_handle_clear(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    uint32_t eventid = its_cmd_get_id(cmdptr);
    struct pending_irq *p;
    struct vcpu *vcpu;
    uint32_t vlpi;
    unsigned long flags;
    int ret = -1;

    spin_lock(&its->its_lock);

    /* Translate the DevID/EvID pair into a vCPU/vLPI pair. */
    if ( !read_itte(its, devid, eventid, &vcpu, &vlpi) )
        goto out_unlock;

    p = gicv3_its_get_event_pending_irq(its->d, its->doorbell_address,
                                        devid, eventid);
    /* Protect against an invalid LPI number. */
    if ( unlikely(!p) )
        goto out_unlock;

    /*
     * TODO: This relies on the VCPU being correct in the ITS tables.
     * This can be fixed by either using a per-IRQ lock or by using
     * the VCPU ID from the pending_irq instead.
     */
    spin_lock_irqsave(&vcpu->arch.vgic.lock, flags);

    /*
     * If the LPI is already visible on the guest, it is too late to
     * clear the pending state. However this is a benign race that can
     * happen on real hardware, too: If the LPI has already been forwarded
     * to a CPU interface, a CLEAR request reaching the redistributor has
     * no effect on that LPI anymore. Since LPIs are edge triggered and
     * have no active state, we don't need to care about this here.
     */
    if ( !test_bit(GIC_IRQ_GUEST_VISIBLE, &p->status) )
        vgic_remove_irq_from_queues(vcpu, p);

    spin_unlock_irqrestore(&vcpu->arch.vgic.lock, flags);
    ret = 0;

out_unlock:
    spin_unlock(&its->its_lock);

    return ret;
}

/*
 * For a given virtual LPI read the enabled bit and priority from the virtual
 * property table and update the virtual IRQ's state in the given pending_irq.
 * Must be called with the respective VGIC VCPU lock held.
 */
static int update_lpi_property(struct domain *d, struct pending_irq *p)
{
    paddr_t addr;
    uint8_t property;
    int ret;

    /*
     * If no redistributor has its LPIs enabled yet, we can't access the
     * property table. In this case we just can't update the properties,
     * but this should not be an error from an ITS point of view.
     * The control flow dependency here and a barrier instruction on the
     * write side make sure we can access these without taking a lock.
     */
    if ( !d->arch.vgic.rdists_enabled )
        return 0;

    addr = d->arch.vgic.rdist_propbase & GENMASK(51, 12);

    ret = access_guest_memory_by_ipa(d, addr + p->irq - LPI_OFFSET,
                                     &property, sizeof(property), false);
    if ( ret )
        return ret;

    write_atomic(&p->lpi_priority, property & LPI_PROP_PRIO_MASK);

    if ( property & LPI_PROP_ENABLED )
        set_bit(GIC_IRQ_GUEST_ENABLED, &p->status);
    else
        clear_bit(GIC_IRQ_GUEST_ENABLED, &p->status);

    return 0;
}

/*
 * Checks whether an LPI that got enabled or disabled needs to change
 * something in the VGIC (added or removed from the LR or queues).
 * We don't disable the underlying physical LPI, because this requires
 * queueing a host LPI command, which we can't afford to do on behalf
 * of a guest.
 * Must be called with the VCPU VGIC lock held.
 */
static void update_lpi_vgic_status(struct vcpu *v, struct pending_irq *p)
{
    ASSERT(spin_is_locked(&v->arch.vgic.lock));

    if ( test_bit(GIC_IRQ_GUEST_ENABLED, &p->status) )
    {
        if ( !list_empty(&p->inflight) &&
             !test_bit(GIC_IRQ_GUEST_VISIBLE, &p->status) )
            gic_raise_guest_irq(v, p->irq, p->lpi_priority);
    }
    else
        gic_remove_from_lr_pending(v, p);
}

static int its_handle_inv(struct virt_its *its, uint64_t *cmdptr)
{
    struct domain *d = its->d;
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    uint32_t eventid = its_cmd_get_id(cmdptr);
    struct pending_irq *p;
    unsigned long flags;
    struct vcpu *vcpu;
    uint32_t vlpi;
    int ret = -1;

    /*
     * If no redistributor has its LPIs enabled yet, we can't access the
     * property table, so there is no point in executing this command.
     * The control flow dependency here and a barrier instruction on the
     * write side make sure we can access these without taking a lock.
     */
    if ( !d->arch.vgic.rdists_enabled )
        return 0;

    spin_lock(&its->its_lock);

    /* Translate the event into a vCPU/vLPI pair. */
    if ( !read_itte(its, devid, eventid, &vcpu, &vlpi) )
        goto out_unlock_its;

    if ( vlpi == INVALID_LPI )
        goto out_unlock_its;

    p = gicv3_its_get_event_pending_irq(d, its->doorbell_address,
                                        devid, eventid);
    if ( unlikely(!p) )
        goto out_unlock_its;

    spin_lock_irqsave(&vcpu->arch.vgic.lock, flags);

    /* Read the property table and update our cached status. */
    if ( update_lpi_property(d, p) )
        goto out_unlock;

    /* Check whether the LPI needs to go on a VCPU. */
    update_lpi_vgic_status(vcpu, p);

    ret = 0;

out_unlock:
    spin_unlock_irqrestore(&vcpu->arch.vgic.lock, flags);

out_unlock_its:
    spin_unlock(&its->its_lock);

    return ret;
}

/*
 * INVALL updates the per-LPI configuration status for every LPI mapped to
 * a particular redistributor.
 * We iterate over all mapped LPIs in our radix tree and update those.
 */
static int its_handle_invall(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t collid = its_cmd_get_collection(cmdptr);
    struct vcpu *vcpu;
    struct pending_irq *pirqs[16];
    uint64_t vlpi = 0;          /* 64-bit to catch overflows */
    unsigned int nr_lpis, i;
    unsigned long flags;
    int ret = 0;

    /*
     * As this implementation walks over all mapped LPIs, it might take
     * too long for a real guest, so we might want to revisit this
     * implementation for DomUs.
     * However this command is very rare, also we don't expect many
     * LPIs to be actually mapped, so it's fine for Dom0 to use.
     */
    ASSERT(is_hardware_domain(its->d));

    /*
     * If no redistributor has its LPIs enabled yet, we can't access the
     * property table, so there is no point in executing this command.
     * The control flow dependency here and a barrier instruction on the
     * write side make sure we can access these without taking a lock.
     */
    if ( !its->d->arch.vgic.rdists_enabled )
        return 0;

    spin_lock(&its->its_lock);
    vcpu = get_vcpu_from_collection(its, collid);
    spin_unlock(&its->its_lock);

    spin_lock_irqsave(&vcpu->arch.vgic.lock, flags);
    read_lock(&its->d->arch.vgic.pend_lpi_tree_lock);

    do
    {
        int err;

        nr_lpis = radix_tree_gang_lookup(&its->d->arch.vgic.pend_lpi_tree,
                                         (void **)pirqs, vlpi,
                                         ARRAY_SIZE(pirqs));

        for ( i = 0; i < nr_lpis; i++ )
        {
            /* We only care about LPIs on our VCPU. */
            if ( pirqs[i]->lpi_vcpu_id != vcpu->vcpu_id )
                continue;

            vlpi = pirqs[i]->irq;
            /* If that fails for a single LPI, carry on to handle the rest. */
            err = update_lpi_property(its->d, pirqs[i]);
            if ( !err )
                update_lpi_vgic_status(vcpu, pirqs[i]);
            else
                ret = err;
        }
    /*
     * Loop over the next gang of pending_irqs until we reached the end of
     * a (fully populated) tree or the lookup function returns less LPIs than
     * it has been asked for.
     */
    } while ( (++vlpi < its->d->arch.vgic.nr_lpis) &&
              (nr_lpis == ARRAY_SIZE(pirqs)) );

    read_unlock(&its->d->arch.vgic.pend_lpi_tree_lock);
    spin_unlock_irqrestore(&vcpu->arch.vgic.lock, flags);

    return ret;
}

/* Must be called with the ITS lock held. */
static int its_discard_event(struct virt_its *its,
                             uint32_t vdevid, uint32_t vevid)
{
    struct pending_irq *p;
    unsigned long flags;
    struct vcpu *vcpu;
    uint32_t vlpi;

    ASSERT(spin_is_locked(&its->its_lock));

    if ( !read_itte(its, vdevid, vevid, &vcpu, &vlpi) )
        return -ENOENT;

    if ( vlpi == INVALID_LPI )
        return -ENOENT;

    /*
     * TODO: This relies on the VCPU being correct in the ITS tables.
     * This can be fixed by either using a per-IRQ lock or by using
     * the VCPU ID from the pending_irq instead.
     */
    spin_lock_irqsave(&vcpu->arch.vgic.lock, flags);

    /* Remove the pending_irq from the tree. */
    write_lock(&its->d->arch.vgic.pend_lpi_tree_lock);
    p = radix_tree_delete(&its->d->arch.vgic.pend_lpi_tree, vlpi);
    write_unlock(&its->d->arch.vgic.pend_lpi_tree_lock);

    if ( !p )
    {
        spin_unlock_irqrestore(&vcpu->arch.vgic.lock, flags);

        return -ENOENT;
    }

    /* Cleanup the pending_irq and disconnect it from the LPI. */
    vgic_remove_irq_from_queues(vcpu, p);
    vgic_init_pending_irq(p, INVALID_LPI);

    spin_unlock_irqrestore(&vcpu->arch.vgic.lock, flags);

    /* Remove the corresponding host LPI entry */
    return gicv3_remove_guest_event(its->d, its->doorbell_address,
                                    vdevid, vevid);
}

static void its_unmap_device(struct virt_its *its, uint32_t devid)
{
    dev_table_entry_t itt;
    uint64_t evid;

    spin_lock(&its->its_lock);

    if ( its_get_itt(its, devid, &itt) )
        goto out;

    /*
     * For DomUs we need to check that the number of events per device
     * is really limited, otherwise looping over all events can take too
     * long for a guest. This ASSERT can then be removed if that is
     * covered.
     */
    ASSERT(is_hardware_domain(its->d));

    for ( evid = 0; evid < DEV_TABLE_ITT_SIZE(itt); evid++ )
        /* Don't care about errors here, clean up as much as possible. */
        its_discard_event(its, devid, evid);

out:
    spin_unlock(&its->its_lock);
}

static int its_handle_mapd(struct virt_its *its, uint64_t *cmdptr)
{
    /* size and devid get validated by the functions called below. */
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    unsigned int size = its_cmd_get_size(cmdptr) + 1;
    bool valid = its_cmd_get_validbit(cmdptr);
    paddr_t itt_addr = its_cmd_get_ittaddr(cmdptr);
    int ret;

    /* Sanitize the number of events. */
    if ( valid && (size > its->evid_bits) )
        return -1;

    if ( !valid )
        /* Discard all events and remove pending LPIs. */
        its_unmap_device(its, devid);

    /*
     * There is no easy and clean way for Xen to know the ITS device ID of a
     * particular (PCI) device, so we have to rely on the guest telling
     * us about it. For *now* we are just using the device ID *Dom0* uses,
     * because the driver there has the actual knowledge.
     * Eventually this will be replaced with a dedicated hypercall to
     * announce pass-through of devices.
     */
    if ( is_hardware_domain(its->d) )
    {

        /*
         * Dom0's ITSes are mapped 1:1, so both addresses are the same.
         * Also the device IDs are equal.
         */
        ret = gicv3_its_map_guest_device(its->d, its->doorbell_address, devid,
                                         its->doorbell_address, devid,
                                         BIT(size), valid);
        if ( ret && valid )
            return ret;
    }

    spin_lock(&its->its_lock);

    if ( valid )
        ret = its_set_itt_address(its, devid, itt_addr, size);
    else
        ret = its_set_itt_address(its, devid, INVALID_PADDR, 1);

    spin_unlock(&its->its_lock);

    return ret;
}

static int its_handle_mapti(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    uint32_t eventid = its_cmd_get_id(cmdptr);
    uint32_t intid = its_cmd_get_physical_id(cmdptr), _intid;
    uint16_t collid = its_cmd_get_collection(cmdptr);
    struct pending_irq *pirq;
    struct vcpu *vcpu = NULL;
    int ret = -1;

    if ( its_cmd_get_command(cmdptr) == GITS_CMD_MAPI )
        intid = eventid;

    spin_lock(&its->its_lock);
    /*
     * Check whether there is a valid existing mapping. If yes, behavior is
     * unpredictable, we choose to ignore this command here.
     * This makes sure we start with a pristine pending_irq below.
     */
    if ( read_itte(its, devid, eventid, &vcpu, &_intid) &&
         _intid != INVALID_LPI )
    {
        spin_unlock(&its->its_lock);
        return -1;
    }

    /* Sanitize collection ID and interrupt ID */
    vcpu = get_vcpu_from_collection(its, collid);
    if ( !vcpu || intid >= its->d->arch.vgic.nr_lpis )
    {
        spin_unlock(&its->its_lock);
        return -1;
    }

    /* Enter the mapping in our virtual ITS tables. */
    if ( !write_itte(its, devid, eventid, collid, intid) )
    {
        spin_unlock(&its->its_lock);
        return -1;
    }

    spin_unlock(&its->its_lock);

    /*
     * Connect this virtual LPI to the corresponding host LPI, which is
     * determined by the same device ID and event ID on the host side.
     * This returns us the corresponding, still unused pending_irq.
     */
    pirq = gicv3_assign_guest_event(its->d, its->doorbell_address,
                                    devid, eventid, intid);
    if ( !pirq )
        goto out_remove_mapping;

    vgic_init_pending_irq(pirq, intid);

    /*
     * Now read the guest's property table to initialize our cached state.
     * We don't need the VGIC VCPU lock here, because the pending_irq isn't
     * in the radix tree yet.
     */
    ret = update_lpi_property(its->d, pirq);
    if ( ret )
        goto out_remove_host_entry;

    pirq->lpi_vcpu_id = vcpu->vcpu_id;
    /*
     * Mark this LPI as new, so any older (now unmapped) LPI in any LR
     * can be easily recognised as such.
     */
    set_bit(GIC_IRQ_GUEST_PRISTINE_LPI, &pirq->status);

    /*
     * Now insert the pending_irq into the domain's LPI tree, so that
     * it becomes live.
     */
    write_lock(&its->d->arch.vgic.pend_lpi_tree_lock);
    ret = radix_tree_insert(&its->d->arch.vgic.pend_lpi_tree, intid, pirq);
    write_unlock(&its->d->arch.vgic.pend_lpi_tree_lock);

    if ( !ret )
        return 0;

    /*
     * radix_tree_insert() returns an error either due to an internal
     * condition (like memory allocation failure) or because the LPI already
     * existed in the tree. We don't support the latter case, so we always
     * cleanup and return an error here in any case.
     */
out_remove_host_entry:
    gicv3_remove_guest_event(its->d, its->doorbell_address, devid, eventid);

out_remove_mapping:
    spin_lock(&its->its_lock);
    write_itte(its, devid, eventid, UNMAPPED_COLLECTION, INVALID_LPI);
    spin_unlock(&its->its_lock);

    return ret;
}

static int its_handle_movi(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    uint32_t eventid = its_cmd_get_id(cmdptr);
    uint16_t collid = its_cmd_get_collection(cmdptr);
    unsigned long flags;
    struct pending_irq *p;
    struct vcpu *ovcpu, *nvcpu;
    uint32_t vlpi;
    int ret = -1;

    spin_lock(&its->its_lock);
    /* Check for a mapped LPI and get the LPI number. */
    if ( !read_itte(its, devid, eventid, &ovcpu, &vlpi) )
        goto out_unlock;

    if ( vlpi == INVALID_LPI )
        goto out_unlock;

    /* Check the new collection ID and get the new VCPU pointer */
    nvcpu = get_vcpu_from_collection(its, collid);
    if ( !nvcpu )
        goto out_unlock;

    p = gicv3_its_get_event_pending_irq(its->d, its->doorbell_address,
                                        devid, eventid);
    if ( unlikely(!p) )
        goto out_unlock;

    /*
     * TODO: This relies on the VCPU being correct in the ITS tables.
     * This can be fixed by either using a per-IRQ lock or by using
     * the VCPU ID from the pending_irq instead.
     */
    spin_lock_irqsave(&ovcpu->arch.vgic.lock, flags);

    /* Update our cached vcpu_id in the pending_irq. */
    p->lpi_vcpu_id = nvcpu->vcpu_id;

    spin_unlock_irqrestore(&ovcpu->arch.vgic.lock, flags);

    /*
     * TODO: Investigate if and how to migrate an already pending LPI. This
     * is not really critical, as these benign races happen in hardware too
     * (an affinity change may come too late for a just fired IRQ), but may
     * simplify the code if we can keep the IRQ's associated VCPU in sync,
     * so that we don't have to deal with special cases anymore.
     * Migrating those LPIs is not easy to do at the moment anyway, but should
     * become easier with the introduction of a per-IRQ lock.
     */

    /* Now store the new collection in the translation table. */
    if ( !write_itte(its, devid, eventid, collid, vlpi) )
        goto out_unlock;

    ret = 0;

out_unlock:
    spin_unlock(&its->its_lock);

    return ret;
}

static int its_handle_discard(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    uint32_t eventid = its_cmd_get_id(cmdptr);
    int ret;

    spin_lock(&its->its_lock);

    /* Remove from the radix tree and remove the host entry. */
    ret = its_discard_event(its, devid, eventid);
    if ( ret )
        goto out_unlock;

    /* Remove from the guest's ITTE. */
    if ( !write_itte(its, devid, eventid, UNMAPPED_COLLECTION, INVALID_LPI) )
        ret = -1;

out_unlock:
    spin_unlock(&its->its_lock);

    return ret;
}

#define ITS_CMD_BUFFER_SIZE(baser)      ((((baser) & 0xff) + 1) << 12)
#define ITS_CMD_OFFSET(reg)             ((reg) & GENMASK(19, 5))

static void dump_its_command(uint64_t *command)
{
    gdprintk(XENLOG_WARNING, "  cmd 0x%02lx: %016lx %016lx %016lx %016lx\n",
             its_cmd_get_command(command),
             command[0], command[1], command[2], command[3]);
}

/*
 * Must be called with the vcmd_lock held.
 * TODO: Investigate whether we can be smarter here and don't need to hold
 * the lock all of the time.
 */
static int vgic_its_handle_cmds(struct domain *d, struct virt_its *its)
{
    paddr_t addr = its->cbaser & GENMASK(51, 12);
    uint64_t command[4];

    ASSERT(spin_is_locked(&its->vcmd_lock));

    if ( its->cwriter >= ITS_CMD_BUFFER_SIZE(its->cbaser) )
        return -1;

    while ( its->creadr != its->cwriter )
    {
        int ret;

        ret = access_guest_memory_by_ipa(d, addr + its->creadr,
                                         command, sizeof(command), false);
        if ( ret )
            return ret;

        switch ( its_cmd_get_command(command) )
        {
        case GITS_CMD_CLEAR:
            ret = its_handle_clear(its, command);
            break;
        case GITS_CMD_DISCARD:
            ret = its_handle_discard(its, command);
            break;
        case GITS_CMD_INT:
            ret = its_handle_int(its, command);
            break;
        case GITS_CMD_INV:
            ret = its_handle_inv(its, command);
            break;
        case GITS_CMD_INVALL:
            ret = its_handle_invall(its, command);
            break;
        case GITS_CMD_MAPC:
            ret = its_handle_mapc(its, command);
            break;
        case GITS_CMD_MAPD:
            ret = its_handle_mapd(its, command);
            break;
        case GITS_CMD_MAPI:
        case GITS_CMD_MAPTI:
            ret = its_handle_mapti(its, command);
            break;
        case GITS_CMD_MOVALL:
            gdprintk(XENLOG_G_INFO, "vGITS: ignoring MOVALL command\n");
            break;
        case GITS_CMD_MOVI:
            ret = its_handle_movi(its, command);
            break;
        case GITS_CMD_SYNC:
            /* We handle ITS commands synchronously, so we ignore SYNC. */
            break;
        default:
            gdprintk(XENLOG_WARNING, "vGITS: unhandled ITS command\n");
            dump_its_command(command);
            break;
        }

        write_u64_atomic(&its->creadr, (its->creadr + ITS_CMD_SIZE) %
                         ITS_CMD_BUFFER_SIZE(its->cbaser));

        if ( ret )
        {
            gdprintk(XENLOG_WARNING,
                     "vGITS: ITS command error %d while handling command\n",
                     ret);
            dump_its_command(command);
        }
    }

    return 0;
}

/*****************************
 * ITS registers read access *
 *****************************/

/* Identifying as an ARM IP, using "X" as the product ID. */
#define GITS_IIDR_VALUE                 0x5800034c

static int vgic_v3_its_mmio_read(struct vcpu *v, mmio_info_t *info,
                                 register_t *r, void *priv)
{
    struct virt_its *its = priv;
    uint64_t reg;

    switch ( info->gpa & 0xffff )
    {
    case VREG32(GITS_CTLR):
    {
        /*
         * We try to avoid waiting for the command queue lock and report
         * non-quiescent if that lock is already taken.
         */
        bool have_cmd_lock;

        if ( info->dabt.size != DABT_WORD ) goto bad_width;

        have_cmd_lock = spin_trylock(&its->vcmd_lock);
        reg = its->enabled ? GITS_CTLR_ENABLE : 0;

        if ( have_cmd_lock && its->cwriter == its->creadr )
            reg |= GITS_CTLR_QUIESCENT;

        if ( have_cmd_lock )
            spin_unlock(&its->vcmd_lock);

        *r = vreg_reg32_extract(reg, info);
        break;
    }

    case VREG32(GITS_IIDR):
        if ( info->dabt.size != DABT_WORD ) goto bad_width;
        *r = vreg_reg32_extract(GITS_IIDR_VALUE, info);
        break;

    case VREG64(GITS_TYPER):
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;

        reg = GITS_TYPER_PHYSICAL;
        reg |= (sizeof(struct vits_itte) - 1) << GITS_TYPER_ITT_SIZE_SHIFT;
        reg |= (its->evid_bits - 1) << GITS_TYPER_IDBITS_SHIFT;
        reg |= (its->devid_bits - 1) << GITS_TYPER_DEVIDS_SHIFT;
        *r = vreg_reg64_extract(reg, info);
        break;

    case VRANGE32(0x0018, 0x001C):
        goto read_reserved;
    case VRANGE32(0x0020, 0x003C):
        goto read_impl_defined;
    case VRANGE32(0x0040, 0x007C):
        goto read_reserved;

    case VREG64(GITS_CBASER):
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;
        spin_lock(&its->its_lock);
        *r = vreg_reg64_extract(its->cbaser, info);
        spin_unlock(&its->its_lock);
        break;

    case VREG64(GITS_CWRITER):
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;

        /* CWRITER is only written by the guest, so no extra locking here. */
        reg = its->cwriter;
        *r = vreg_reg64_extract(reg, info);
        break;

    case VREG64(GITS_CREADR):
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;

        /*
         * Lockless access, to avoid waiting for the whole command queue to be
         * finished completely. Xen updates its->creadr atomically after each
         * command has been handled, this allows other VCPUs to monitor the
         * progress.
         */
        reg = read_u64_atomic(&its->creadr);
        *r = vreg_reg64_extract(reg, info);
        break;

    case VRANGE64(0x0098, 0x00F8):
        goto read_reserved;

    case VREG64(GITS_BASER0):           /* device table */
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;
        spin_lock(&its->its_lock);
        *r = vreg_reg64_extract(its->baser_dev, info);
        spin_unlock(&its->its_lock);
        break;

    case VREG64(GITS_BASER1):           /* collection table */
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;
        spin_lock(&its->its_lock);
        *r = vreg_reg64_extract(its->baser_coll, info);
        spin_unlock(&its->its_lock);
        break;

    case VRANGE64(GITS_BASER2, GITS_BASER7):
        goto read_as_zero_64;
    case VRANGE32(0x0140, 0xBFFC):
        goto read_reserved;
    case VRANGE32(0xC000, 0xFFCC):
        goto read_impl_defined;
    case VRANGE32(0xFFD0, 0xFFE4):
        goto read_impl_defined;

    case VREG32(GITS_PIDR2):
        if ( info->dabt.size != DABT_WORD ) goto bad_width;
        *r = vreg_reg32_extract(GIC_PIDR2_ARCH_GICv3, info);
        break;

    case VRANGE32(0xFFEC, 0xFFFC):
        goto read_impl_defined;

    default:
        printk(XENLOG_G_ERR
               "%pv: vGITS: unhandled read r%d offset %#04lx\n",
               v, info->dabt.reg, (unsigned long)info->gpa & 0xffff);
        return 0;
    }

    return 1;

read_as_zero_64:
    if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;
    *r = 0;

    return 1;

read_impl_defined:
    printk(XENLOG_G_DEBUG
           "%pv: vGITS: RAZ on implementation defined register offset %#04lx\n",
           v, info->gpa & 0xffff);
    *r = 0;
    return 1;

read_reserved:
    printk(XENLOG_G_DEBUG
           "%pv: vGITS: RAZ on reserved register offset %#04lx\n",
           v, info->gpa & 0xffff);
    *r = 0;
    return 1;

bad_width:
    printk(XENLOG_G_ERR "vGITS: bad read width %d r%d offset %#04lx\n",
           info->dabt.size, info->dabt.reg, (unsigned long)info->gpa & 0xffff);

    return 0;
}

/******************************
 * ITS registers write access *
 ******************************/

static unsigned int its_baser_table_size(uint64_t baser)
{
    unsigned int ret, page_size[4] = {SZ_4K, SZ_16K, SZ_64K, SZ_64K};

    ret = page_size[(baser >> GITS_BASER_PAGE_SIZE_SHIFT) & 3];

    return ret * ((baser & GITS_BASER_SIZE_MASK) + 1);
}

static unsigned int its_baser_nr_entries(uint64_t baser)
{
    unsigned int entry_size = GITS_BASER_ENTRY_SIZE(baser);

    return its_baser_table_size(baser) / entry_size;
}

/* Must be called with the ITS lock held. */
static bool vgic_v3_verify_its_status(struct virt_its *its, bool status)
{
    ASSERT(spin_is_locked(&its->its_lock));

    if ( !status )
        return false;

    if ( !(its->cbaser & GITS_VALID_BIT) ||
         !(its->baser_dev & GITS_VALID_BIT) ||
         !(its->baser_coll & GITS_VALID_BIT) )
    {
        printk(XENLOG_G_WARNING "d%d tried to enable ITS without having the tables configured.\n",
               its->d->domain_id);
        return false;
    }

    /*
     * TODO: Protect against a guest crafting ITS tables.
     * The spec says that "at the time of the new allocation for use by the ITS"
     * all tables must contain zeroes. We could enforce this here by clearing
     * all the tables, but this would be moot since at the moment the guest
     * can change the tables at any point in time anyway. Right now there are
     * expectations about the tables being consistent (a VCPU lock protecting
     * an LPI), which should go away with proper per-IRQ locking.
     * So for now we ignore this issue and rely on Dom0 not doing bad things.
     */
    ASSERT(is_hardware_domain(its->d));

    return true;
}

static void sanitize_its_base_reg(uint64_t *reg)
{
    uint64_t r = *reg;

    /* Avoid outer shareable. */
    switch ( (r >> GITS_BASER_SHAREABILITY_SHIFT) & 0x03 )
    {
    case GIC_BASER_OuterShareable:
        r &= ~GITS_BASER_SHAREABILITY_MASK;
        r |= GIC_BASER_InnerShareable << GITS_BASER_SHAREABILITY_SHIFT;
        break;
    default:
        break;
    }

    /* Avoid any inner non-cacheable mapping. */
    switch ( (r >> GITS_BASER_INNER_CACHEABILITY_SHIFT) & 0x07 )
    {
    case GIC_BASER_CACHE_nCnB:
    case GIC_BASER_CACHE_nC:
        r &= ~GITS_BASER_INNER_CACHEABILITY_MASK;
        r |= GIC_BASER_CACHE_RaWb << GITS_BASER_INNER_CACHEABILITY_SHIFT;
        break;
    default:
        break;
    }

    /* Only allow non-cacheable or same-as-inner. */
    switch ( (r >> GITS_BASER_OUTER_CACHEABILITY_SHIFT) & 0x07 )
    {
    case GIC_BASER_CACHE_SameAsInner:
    case GIC_BASER_CACHE_nC:
        break;
    default:
        r &= ~GITS_BASER_OUTER_CACHEABILITY_MASK;
        r |= GIC_BASER_CACHE_nC << GITS_BASER_OUTER_CACHEABILITY_SHIFT;
        break;
    }

    *reg = r;
}

static int vgic_v3_its_mmio_write(struct vcpu *v, mmio_info_t *info,
                                  register_t r, void *priv)
{
    struct domain *d = v->domain;
    struct virt_its *its = priv;
    uint64_t reg;
    uint32_t reg32;

    switch ( info->gpa & 0xffff )
    {
    case VREG32(GITS_CTLR):
    {
        uint32_t ctlr;

        if ( info->dabt.size != DABT_WORD ) goto bad_width;

        /*
         * We need to take the vcmd_lock to prevent a guest from disabling
         * the ITS while commands are still processed.
         */
        spin_lock(&its->vcmd_lock);
        spin_lock(&its->its_lock);
        ctlr = its->enabled ? GITS_CTLR_ENABLE : 0;
        reg32 = ctlr;
        vreg_reg32_update(&reg32, r, info);

        if ( ctlr ^ reg32 )
            its->enabled = vgic_v3_verify_its_status(its,
                                                     reg32 & GITS_CTLR_ENABLE);
        spin_unlock(&its->its_lock);
        spin_unlock(&its->vcmd_lock);
        return 1;
    }

    case VREG32(GITS_IIDR):
        goto write_ignore_32;

    case VREG32(GITS_TYPER):
        goto write_ignore_32;

    case VRANGE32(0x0018, 0x001C):
        goto write_reserved;
    case VRANGE32(0x0020, 0x003C):
        goto write_impl_defined;
    case VRANGE32(0x0040, 0x007C):
        goto write_reserved;

    case VREG64(GITS_CBASER):
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;

        spin_lock(&its->its_lock);
        /* Changing base registers with the ITS enabled is UNPREDICTABLE. */
        if ( its->enabled )
        {
            spin_unlock(&its->its_lock);
            gdprintk(XENLOG_WARNING,
                     "vGITS: tried to change CBASER with the ITS enabled.\n");
            return 1;
        }

        reg = its->cbaser;
        vreg_reg64_update(&reg, r, info);
        sanitize_its_base_reg(&reg);

        its->cbaser = reg;
        its->creadr = 0;
        spin_unlock(&its->its_lock);

        return 1;

    case VREG64(GITS_CWRITER):
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;

        spin_lock(&its->vcmd_lock);
        reg = ITS_CMD_OFFSET(its->cwriter);
        vreg_reg64_update(&reg, r, info);
        its->cwriter = ITS_CMD_OFFSET(reg);

        if ( its->enabled )
            if ( vgic_its_handle_cmds(d, its) )
                gdprintk(XENLOG_WARNING, "error handling ITS commands\n");

        spin_unlock(&its->vcmd_lock);

        return 1;

    case VREG64(GITS_CREADR):
        goto write_ignore_64;

    case VRANGE32(0x0098, 0x00FC):
        goto write_reserved;

    case VREG64(GITS_BASER0):           /* device table */
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;

        spin_lock(&its->its_lock);

        /*
         * Changing base registers with the ITS enabled is UNPREDICTABLE,
         * we choose to ignore it, but warn.
         */
        if ( its->enabled )
        {
            spin_unlock(&its->its_lock);
            gdprintk(XENLOG_WARNING, "vGITS: tried to change BASER with the ITS enabled.\n");

            return 1;
        }

        reg = its->baser_dev;
        vreg_reg64_update(&reg, r, info);

        /* We don't support indirect tables for now. */
        reg &= ~(GITS_BASER_RO_MASK | GITS_BASER_INDIRECT);
        reg |= (sizeof(dev_table_entry_t) - 1) << GITS_BASER_ENTRY_SIZE_SHIFT;
        reg |= GITS_BASER_TYPE_DEVICE << GITS_BASER_TYPE_SHIFT;
        sanitize_its_base_reg(&reg);

        if ( reg & GITS_VALID_BIT )
        {
            its->max_devices = its_baser_nr_entries(reg);
            if ( its->max_devices > BIT(its->devid_bits) )
                its->max_devices = BIT(its->devid_bits);
        }
        else
            its->max_devices = 0;

        its->baser_dev = reg;
        spin_unlock(&its->its_lock);
        return 1;

    case VREG64(GITS_BASER1):           /* collection table */
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;

        spin_lock(&its->its_lock);
        /*
         * Changing base registers with the ITS enabled is UNPREDICTABLE,
         * we choose to ignore it, but warn.
         */
        if ( its->enabled )
        {
            spin_unlock(&its->its_lock);
            gdprintk(XENLOG_INFO, "vGITS: tried to change BASER with the ITS enabled.\n");
            return 1;
        }

        reg = its->baser_coll;
        vreg_reg64_update(&reg, r, info);
        /* No indirect tables for the collection table. */
        reg &= ~(GITS_BASER_RO_MASK | GITS_BASER_INDIRECT);
        reg |= (sizeof(coll_table_entry_t) - 1) << GITS_BASER_ENTRY_SIZE_SHIFT;
        reg |= GITS_BASER_TYPE_COLLECTION << GITS_BASER_TYPE_SHIFT;
        sanitize_its_base_reg(&reg);

        if ( reg & GITS_VALID_BIT )
            its->max_collections = its_baser_nr_entries(reg);
        else
            its->max_collections = 0;
        its->baser_coll = reg;
        spin_unlock(&its->its_lock);
        return 1;

    case VRANGE64(GITS_BASER2, GITS_BASER7):
        goto write_ignore_64;

    case VRANGE32(0x0140, 0xBFFC):
        goto write_reserved;
    case VRANGE32(0xC000, 0xFFCC):
        goto write_impl_defined;
    case VRANGE32(0xFFD0, 0xFFE4):      /* IMPDEF identification registers */
        goto write_impl_defined;

    case VREG32(GITS_PIDR2):
        goto write_ignore_32;

    case VRANGE32(0xFFEC, 0xFFFC):      /* IMPDEF identification registers */
        goto write_impl_defined;

    default:
        printk(XENLOG_G_ERR
               "%pv: vGITS: unhandled write r%d offset %#04lx\n",
               v, info->dabt.reg, (unsigned long)info->gpa & 0xffff);
        return 0;
    }

    return 1;

write_ignore_64:
    if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;
    return 1;

write_ignore_32:
    if ( info->dabt.size != DABT_WORD ) goto bad_width;
    return 1;

write_impl_defined:
    printk(XENLOG_G_DEBUG
           "%pv: vGITS: WI on implementation defined register offset %#04lx\n",
           v, info->gpa & 0xffff);
    return 1;

write_reserved:
    printk(XENLOG_G_DEBUG
           "%pv: vGITS: WI on implementation defined register offset %#04lx\n",
           v, info->gpa & 0xffff);
    return 1;

bad_width:
    printk(XENLOG_G_ERR "vGITS: bad write width %d r%d offset %#08lx\n",
           info->dabt.size, info->dabt.reg, (unsigned long)info->gpa & 0xffff);

    return 0;
}

static const struct mmio_handler_ops vgic_its_mmio_handler = {
    .read  = vgic_v3_its_mmio_read,
    .write = vgic_v3_its_mmio_write,
};

static int vgic_v3_its_init_virtual(struct domain *d, paddr_t guest_addr,
                                    unsigned int devid_bits,
                                    unsigned int evid_bits)
{
    struct virt_its *its;
    uint64_t base_attr;

    its = xzalloc(struct virt_its);
    if ( !its )
        return -ENOMEM;

    base_attr  = GIC_BASER_InnerShareable << GITS_BASER_SHAREABILITY_SHIFT;
    base_attr |= GIC_BASER_CACHE_SameAsInner << GITS_BASER_OUTER_CACHEABILITY_SHIFT;
    base_attr |= GIC_BASER_CACHE_RaWaWb << GITS_BASER_INNER_CACHEABILITY_SHIFT;

    its->cbaser  = base_attr;
    base_attr |= 0ULL << GITS_BASER_PAGE_SIZE_SHIFT;    /* 4K pages */
    its->baser_dev = GITS_BASER_TYPE_DEVICE << GITS_BASER_TYPE_SHIFT;
    its->baser_dev |= (sizeof(dev_table_entry_t) - 1) <<
                      GITS_BASER_ENTRY_SIZE_SHIFT;
    its->baser_dev |= base_attr;
    its->baser_coll  = GITS_BASER_TYPE_COLLECTION << GITS_BASER_TYPE_SHIFT;
    its->baser_coll |= (sizeof(coll_table_entry_t) - 1) <<
                       GITS_BASER_ENTRY_SIZE_SHIFT;
    its->baser_coll |= base_attr;
    its->d = d;
    its->doorbell_address = guest_addr + ITS_DOORBELL_OFFSET;
    its->devid_bits = devid_bits;
    its->evid_bits = evid_bits;
    spin_lock_init(&its->vcmd_lock);
    spin_lock_init(&its->its_lock);

    register_mmio_handler(d, &vgic_its_mmio_handler, guest_addr, SZ_64K, its);

    /* Register the virtual ITS to be able to clean it up later. */
    list_add_tail(&its->vits_list, &d->arch.vgic.vits_list);

    return 0;
}

unsigned int vgic_v3_its_count(const struct domain *d)
{
    struct host_its *hw_its;
    unsigned int ret = 0;

    /* Only Dom0 can use emulated ITSes so far. */
    if ( !is_hardware_domain(d) )
        return 0;

    list_for_each_entry(hw_its, &host_its_list, entry)
        ret++;

    return ret;
}

/*
 * For a hardware domain, this will iterate over the host ITSes
 * and map one virtual ITS per host ITS at the same address.
 */
int vgic_v3_its_init_domain(struct domain *d)
{
    int ret;

    INIT_LIST_HEAD(&d->arch.vgic.vits_list);
    spin_lock_init(&d->arch.vgic.its_devices_lock);
    d->arch.vgic.its_devices = RB_ROOT;

    if ( is_hardware_domain(d) )
    {
        struct host_its *hw_its;

        list_for_each_entry(hw_its, &host_its_list, entry)
        {
            /*
             * For each host ITS create a virtual ITS using the same
             * base and thus doorbell address.
             * Use the same number of device ID and event ID bits as the host.
             */
            ret = vgic_v3_its_init_virtual(d, hw_its->addr,
                                           hw_its->devid_bits,
                                           hw_its->evid_bits);
            if ( ret )
                return ret;
            else
                d->arch.vgic.has_its = true;
        }
    }

    return 0;
}

void vgic_v3_its_free_domain(struct domain *d)
{
    struct virt_its *pos, *temp;

    list_for_each_entry_safe( pos, temp, &d->arch.vgic.vits_list, vits_list )
    {
        list_del(&pos->vits_list);
        xfree(pos);
    }

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
