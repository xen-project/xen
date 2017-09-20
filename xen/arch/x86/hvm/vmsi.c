/*
 *  Copyright (C) 2001  MandrakeSoft S.A.
 *
 *    MandrakeSoft S.A.
 *    43, rue d'Aboukir
 *    75002 Paris - France
 *    http://www.linux-mandrake.com/
 *    http://www.mandrakesoft.com/
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * Support for virtual MSI logic
 * Will be merged it with virtual IOAPIC logic, since most is the same
*/

#include <xen/types.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <public/hvm/ioreq.h>
#include <asm/hvm/io.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/support.h>
#include <asm/current.h>
#include <asm/event.h>
#include <asm/io_apic.h>

static void vmsi_inj_irq(
    struct vlapic *target,
    uint8_t vector,
    uint8_t trig_mode,
    uint8_t delivery_mode)
{
    HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "vmsi_inj_irq: vec %02x trig %d dm %d\n",
                vector, trig_mode, delivery_mode);

    switch ( delivery_mode )
    {
    case dest_Fixed:
    case dest_LowestPrio:
        vlapic_set_irq(target, vector, trig_mode);
        break;
    default:
        BUG();
    }
}

int vmsi_deliver(
    struct domain *d, int vector,
    uint8_t dest, uint8_t dest_mode,
    uint8_t delivery_mode, uint8_t trig_mode)
{
    struct vlapic *target;
    struct vcpu *v;

    switch ( delivery_mode )
    {
    case dest_LowestPrio:
        target = vlapic_lowest_prio(d, NULL, 0, dest, dest_mode);
        if ( target != NULL )
        {
            vmsi_inj_irq(target, vector, trig_mode, delivery_mode);
            break;
        }
        HVM_DBG_LOG(DBG_LEVEL_VLAPIC, "null MSI round robin: vector=%02x\n",
                    vector);
        return -ESRCH;

    case dest_Fixed:
        for_each_vcpu ( d, v )
            if ( vlapic_match_dest(vcpu_vlapic(v), NULL,
                                   0, dest, dest_mode) )
                vmsi_inj_irq(vcpu_vlapic(v), vector,
                             trig_mode, delivery_mode);
        break;

    default:
        printk(XENLOG_G_WARNING
               "%pv: Unsupported MSI delivery mode %d for Dom%d\n",
               current, delivery_mode, d->domain_id);
        return -EINVAL;
    }

    return 0;
}

void vmsi_deliver_pirq(struct domain *d, const struct hvm_pirq_dpci *pirq_dpci)
{
    uint32_t flags = pirq_dpci->gmsi.gflags;
    int vector = pirq_dpci->gmsi.gvec;
    uint8_t dest = (uint8_t)flags;
    bool dest_mode = flags & XEN_DOMCTL_VMSI_X86_DM_MASK;
    uint8_t delivery_mode = MASK_EXTR(flags, XEN_DOMCTL_VMSI_X86_DELIV_MASK);
    bool trig_mode = flags & XEN_DOMCTL_VMSI_X86_TRIG_MASK;

    HVM_DBG_LOG(DBG_LEVEL_IOAPIC,
                "msi: dest=%x dest_mode=%x delivery_mode=%x "
                "vector=%x trig_mode=%x\n",
                dest, dest_mode, delivery_mode, vector, trig_mode);

    ASSERT(pirq_dpci->flags & HVM_IRQ_DPCI_GUEST_MSI);

    vmsi_deliver(d, vector, dest, dest_mode, delivery_mode, trig_mode);
}

/* Return value, -1 : multi-dests, non-negative value: dest_vcpu_id */
int hvm_girq_dest_2_vcpu_id(struct domain *d, uint8_t dest, uint8_t dest_mode)
{
    int dest_vcpu_id = -1, w = 0;
    struct vcpu *v;
    
    if ( d->max_vcpus == 1 )
        return 0;
 
    for_each_vcpu ( d, v )
    {
        if ( vlapic_match_dest(vcpu_vlapic(v), NULL, 0, dest, dest_mode) ) 
        {
            w++;
            dest_vcpu_id = v->vcpu_id;
        }
    }
    if ( w > 1 )
        return -1;

    return dest_vcpu_id;
}

/* MSI-X mask bit hypervisor interception */
struct msixtbl_entry
{
    struct list_head list;
    atomic_t refcnt;    /* how many bind_pt_irq called for the device */

    /* TODO: resolve the potential race by destruction of pdev */
    struct pci_dev *pdev;
    unsigned long gtable;       /* gpa of msix table */
    DECLARE_BITMAP(table_flags, MAX_MSIX_TABLE_ENTRIES);
#define MAX_MSIX_ACC_ENTRIES 3
    unsigned int table_len;
    struct { 
        uint32_t msi_ad[3];	/* Shadow of address low, high and data */
    } gentries[MAX_MSIX_ACC_ENTRIES];
    DECLARE_BITMAP(acc_valid, 3 * MAX_MSIX_ACC_ENTRIES);
#define acc_bit(what, ent, slot, idx) \
        what##_bit((slot) * 3 + (idx), (ent)->acc_valid)
    struct rcu_head rcu;
};

static DEFINE_RCU_READ_LOCK(msixtbl_rcu_lock);

/*
 * MSI-X table infrastructure is dynamically initialised when an MSI-X capable
 * device is passed through to a domain, rather than unconditionally for all
 * domains.
 */
static bool msixtbl_initialised(const struct domain *d)
{
    return !!d->arch.hvm_domain.msixtbl_list.next;
}

static struct msixtbl_entry *msixtbl_find_entry(
    struct vcpu *v, unsigned long addr)
{
    struct msixtbl_entry *entry;
    struct domain *d = v->domain;

    list_for_each_entry( entry, &d->arch.hvm_domain.msixtbl_list, list )
        if ( addr >= entry->gtable &&
             addr < entry->gtable + entry->table_len )
            return entry;

    return NULL;
}

static struct msi_desc *msixtbl_addr_to_desc(
    const struct msixtbl_entry *entry, unsigned long addr)
{
    unsigned int nr_entry;
    struct msi_desc *desc;

    if ( !entry || !entry->pdev )
        return NULL;

    nr_entry = (addr - entry->gtable) / PCI_MSIX_ENTRY_SIZE;

    list_for_each_entry( desc, &entry->pdev->msi_list, list )
        if ( desc->msi_attrib.type == PCI_CAP_ID_MSIX &&
             desc->msi_attrib.entry_nr == nr_entry )
            return desc;

    return NULL;
}

static int msixtbl_read(const struct hvm_io_handler *handler,
                        uint64_t address, uint32_t len, uint64_t *pval)
{
    unsigned long offset;
    struct msixtbl_entry *entry;
    unsigned int nr_entry, index;
    int r = X86EMUL_UNHANDLEABLE;

    if ( (len != 4 && len != 8) || (address & (len - 1)) )
        return r;

    rcu_read_lock(&msixtbl_rcu_lock);

    entry = msixtbl_find_entry(current, address);
    if ( !entry )
        goto out;
    offset = address & (PCI_MSIX_ENTRY_SIZE - 1);

    if ( offset != PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET )
    {
        nr_entry = (address - entry->gtable) / PCI_MSIX_ENTRY_SIZE;
        index = offset / sizeof(uint32_t);
        if ( nr_entry >= MAX_MSIX_ACC_ENTRIES ||
             !acc_bit(test, entry, nr_entry, index) )
            goto out;
        *pval = entry->gentries[nr_entry].msi_ad[index];
        if ( len == 8 )
        {
            if ( index )
                offset = PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET;
            else if ( acc_bit(test, entry, nr_entry, 1) )
                *pval |= (u64)entry->gentries[nr_entry].msi_ad[1] << 32;
            else
                goto out;
        }
    }
    if ( offset == PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET )
    {
        const struct msi_desc *msi_desc = msixtbl_addr_to_desc(entry, address);

        if ( !msi_desc )
            goto out;
        if ( len == 4 )
            *pval = MASK_INSR(msi_desc->msi_attrib.guest_masked,
                              PCI_MSIX_VECTOR_BITMASK);
        else
            *pval |= (u64)MASK_INSR(msi_desc->msi_attrib.guest_masked,
                                    PCI_MSIX_VECTOR_BITMASK) << 32;
    }
    
    r = X86EMUL_OKAY;
out:
    rcu_read_unlock(&msixtbl_rcu_lock);
    return r;
}

static int msixtbl_write(struct vcpu *v, unsigned long address,
                         unsigned int len, unsigned long val)
{
    unsigned long offset;
    struct msixtbl_entry *entry;
    const struct msi_desc *msi_desc;
    unsigned int nr_entry, index;
    int r = X86EMUL_UNHANDLEABLE;
    unsigned long flags;
    struct irq_desc *desc;

    if ( (len != 4 && len != 8) || (address & (len - 1)) )
        return r;

    rcu_read_lock(&msixtbl_rcu_lock);

    entry = msixtbl_find_entry(v, address);
    if ( !entry )
        goto out;
    nr_entry = (address - entry->gtable) / PCI_MSIX_ENTRY_SIZE;

    offset = address & (PCI_MSIX_ENTRY_SIZE - 1);
    if ( offset != PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET )
    {
        index = offset / sizeof(uint32_t);
        if ( nr_entry < MAX_MSIX_ACC_ENTRIES ) 
        {
            entry->gentries[nr_entry].msi_ad[index] = val;
            acc_bit(set, entry, nr_entry, index);
            if ( len == 8 && !index )
            {
                entry->gentries[nr_entry].msi_ad[1] = val >> 32;
                acc_bit(set, entry, nr_entry, 1);
            }
        }
        set_bit(nr_entry, &entry->table_flags);
        if ( len != 8 || !index )
            goto out;
        val >>= 32;
        address += 4;
    }

    /* Exit to device model when unmasking and address/data got modified. */
    if ( !(val & PCI_MSIX_VECTOR_BITMASK) &&
         test_and_clear_bit(nr_entry, &entry->table_flags) )
    {
        v->arch.hvm_vcpu.hvm_io.msix_unmask_address = address;
        goto out;
    }

    msi_desc = msixtbl_addr_to_desc(entry, address);
    if ( !msi_desc || msi_desc->irq < 0 )
        goto out;
    
    desc = irq_to_desc(msi_desc->irq);
    if ( !desc )
        goto out;

    spin_lock_irqsave(&desc->lock, flags);

    if ( !desc->msi_desc )
        goto unlock;

    ASSERT(msi_desc == desc->msi_desc);
   
    guest_mask_msi_irq(desc, !!(val & PCI_MSIX_VECTOR_BITMASK));

unlock:
    spin_unlock_irqrestore(&desc->lock, flags);
    if ( len == 4 )
        r = X86EMUL_OKAY;

out:
    rcu_read_unlock(&msixtbl_rcu_lock);
    return r;
}

static int _msixtbl_write(const struct hvm_io_handler *handler,
                          uint64_t address, uint32_t len, uint64_t val)
{
    return msixtbl_write(current, address, len, val);
}

static bool_t msixtbl_range(const struct hvm_io_handler *handler,
                            const ioreq_t *r)
{
    struct vcpu *curr = current;
    unsigned long addr = r->addr;
    const struct msi_desc *desc;

    ASSERT(r->type == IOREQ_TYPE_COPY);

    rcu_read_lock(&msixtbl_rcu_lock);
    desc = msixtbl_addr_to_desc(msixtbl_find_entry(curr, addr), addr);
    rcu_read_unlock(&msixtbl_rcu_lock);

    if ( desc )
        return 1;

    if ( r->state == STATE_IOREQ_READY && r->dir == IOREQ_WRITE )
    {
        unsigned int size = r->size;

        if ( !r->data_is_ptr )
        {
            uint64_t data = r->data;

            if ( size == 8 )
            {
                BUILD_BUG_ON(!(PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET & 4));
                data >>= 32;
                addr += size = 4;
            }
            if ( size == 4 &&
                 ((addr & (PCI_MSIX_ENTRY_SIZE - 1)) ==
                  PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET) &&
                 !(data & PCI_MSIX_VECTOR_BITMASK) )
            {
                curr->arch.hvm_vcpu.hvm_io.msix_snoop_address = addr;
                curr->arch.hvm_vcpu.hvm_io.msix_snoop_gpa = 0;
            }
        }
        else if ( (size == 4 || size == 8) &&
                  /* Only support forward REP MOVS for now. */
                  !r->df &&
                  /*
                   * Only fully support accesses to a single table entry for
                   * now (if multiple ones get written to in one go, only the
                   * final one gets dealt with).
                   */
                  r->count && r->count <= PCI_MSIX_ENTRY_SIZE / size &&
                  !((addr + (size * r->count)) & (PCI_MSIX_ENTRY_SIZE - 1)) )
        {
            BUILD_BUG_ON((PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET + 4) &
                         (PCI_MSIX_ENTRY_SIZE - 1));

            curr->arch.hvm_vcpu.hvm_io.msix_snoop_address =
                addr + size * r->count - 4;
            curr->arch.hvm_vcpu.hvm_io.msix_snoop_gpa =
                r->data + size * r->count - 4;
        }
    }

    return 0;
}

static const struct hvm_io_ops msixtbl_mmio_ops = {
    .accept = msixtbl_range,
    .read = msixtbl_read,
    .write = _msixtbl_write,
};

static void add_msixtbl_entry(struct domain *d,
                              struct pci_dev *pdev,
                              uint64_t gtable,
                              struct msixtbl_entry *entry)
{
    INIT_LIST_HEAD(&entry->list);
    INIT_RCU_HEAD(&entry->rcu);
    atomic_set(&entry->refcnt, 0);

    entry->table_len = pdev->msix->nr_entries * PCI_MSIX_ENTRY_SIZE;
    entry->pdev = pdev;
    entry->gtable = (unsigned long) gtable;

    list_add_rcu(&entry->list, &d->arch.hvm_domain.msixtbl_list);
}

static void free_msixtbl_entry(struct rcu_head *rcu)
{
    struct msixtbl_entry *entry;

    entry = container_of (rcu, struct msixtbl_entry, rcu);

    xfree(entry);
}

static void del_msixtbl_entry(struct msixtbl_entry *entry)
{
    list_del_rcu(&entry->list);
    call_rcu(&entry->rcu, free_msixtbl_entry);
}

int msixtbl_pt_register(struct domain *d, struct pirq *pirq, uint64_t gtable)
{
    struct irq_desc *irq_desc;
    struct msi_desc *msi_desc;
    struct pci_dev *pdev;
    struct msixtbl_entry *entry, *new_entry;
    int r = -EINVAL;

    ASSERT(pcidevs_locked());
    ASSERT(spin_is_locked(&d->event_lock));

    if ( !msixtbl_initialised(d) )
        return -ENODEV;

    /*
     * xmalloc() with irq_disabled causes the failure of check_lock() 
     * for xenpool->lock. So we allocate an entry beforehand.
     */
    new_entry = xzalloc(struct msixtbl_entry);
    if ( !new_entry )
        return -ENOMEM;

    irq_desc = pirq_spin_lock_irq_desc(pirq, NULL);
    if ( !irq_desc )
    {
        xfree(new_entry);
        return r;
    }

    msi_desc = irq_desc->msi_desc;
    if ( !msi_desc )
        goto out;

    pdev = msi_desc->dev;

    list_for_each_entry( entry, &d->arch.hvm_domain.msixtbl_list, list )
        if ( pdev == entry->pdev )
            goto found;

    entry = new_entry;
    new_entry = NULL;
    add_msixtbl_entry(d, pdev, gtable, entry);

found:
    atomic_inc(&entry->refcnt);
    r = 0;

out:
    spin_unlock_irq(&irq_desc->lock);
    xfree(new_entry);

    if ( !r )
    {
        struct vcpu *v;

        for_each_vcpu ( d, v )
        {
            if ( (v->pause_flags & VPF_blocked_in_xen) &&
                 !v->arch.hvm_vcpu.hvm_io.msix_snoop_gpa &&
                 v->arch.hvm_vcpu.hvm_io.msix_snoop_address ==
                 (gtable + msi_desc->msi_attrib.entry_nr *
                           PCI_MSIX_ENTRY_SIZE +
                  PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET) )
                v->arch.hvm_vcpu.hvm_io.msix_unmask_address =
                    v->arch.hvm_vcpu.hvm_io.msix_snoop_address;
        }
    }

    return r;
}

void msixtbl_pt_unregister(struct domain *d, struct pirq *pirq)
{
    struct irq_desc *irq_desc;
    struct msi_desc *msi_desc;
    struct pci_dev *pdev;
    struct msixtbl_entry *entry;

    ASSERT(pcidevs_locked());
    ASSERT(spin_is_locked(&d->event_lock));

    if ( !msixtbl_initialised(d) )
        return;

    irq_desc = pirq_spin_lock_irq_desc(pirq, NULL);
    if ( !irq_desc )
        return;

    msi_desc = irq_desc->msi_desc;
    if ( !msi_desc )
        goto out;

    pdev = msi_desc->dev;

    list_for_each_entry( entry, &d->arch.hvm_domain.msixtbl_list, list )
        if ( pdev == entry->pdev )
            goto found;

out:
    spin_unlock_irq(&irq_desc->lock);
    return;

found:
    if ( !atomic_dec_and_test(&entry->refcnt) )
        del_msixtbl_entry(entry);

    spin_unlock_irq(&irq_desc->lock);
}

void msixtbl_init(struct domain *d)
{
    struct hvm_io_handler *handler;

    if ( !is_hvm_domain(d) || !has_vlapic(d) || msixtbl_initialised(d) )
        return;

    INIT_LIST_HEAD(&d->arch.hvm_domain.msixtbl_list);

    handler = hvm_next_io_handler(d);
    if ( handler )
    {
        handler->type = IOREQ_TYPE_COPY;
        handler->ops = &msixtbl_mmio_ops;
    }
}

void msixtbl_pt_cleanup(struct domain *d)
{
    struct msixtbl_entry *entry, *temp;

    if ( !msixtbl_initialised(d) )
        return;

    spin_lock(&d->event_lock);

    list_for_each_entry_safe( entry, temp,
                              &d->arch.hvm_domain.msixtbl_list, list )
        del_msixtbl_entry(entry);

    spin_unlock(&d->event_lock);
}

void msix_write_completion(struct vcpu *v)
{
    unsigned long ctrl_address = v->arch.hvm_vcpu.hvm_io.msix_unmask_address;
    unsigned long snoop_addr = v->arch.hvm_vcpu.hvm_io.msix_snoop_address;

    v->arch.hvm_vcpu.hvm_io.msix_snoop_address = 0;

    if ( !ctrl_address && snoop_addr &&
         v->arch.hvm_vcpu.hvm_io.msix_snoop_gpa )
    {
        const struct msi_desc *desc;
        uint32_t data;

        rcu_read_lock(&msixtbl_rcu_lock);
        desc = msixtbl_addr_to_desc(msixtbl_find_entry(v, snoop_addr),
                                    snoop_addr);
        rcu_read_unlock(&msixtbl_rcu_lock);

        if ( desc &&
             hvm_copy_from_guest_phys(&data,
                                      v->arch.hvm_vcpu.hvm_io.msix_snoop_gpa,
                                      sizeof(data)) == HVMTRANS_okay &&
             !(data & PCI_MSIX_VECTOR_BITMASK) )
            ctrl_address = snoop_addr;
    }

    if ( !ctrl_address )
        return;

    v->arch.hvm_vcpu.hvm_io.msix_unmask_address = 0;
    if ( msixtbl_write(v, ctrl_address, 4, 0) != X86EMUL_OKAY )
        gdprintk(XENLOG_WARNING, "MSI-X write completion failure\n");
}
