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
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * Support for virtual MSI logic
 * Will be merged it with virtual IOAPIC logic, since most is the same
*/

#include <xen/config.h>
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
    struct domain *d,
    struct vlapic *target,
    uint8_t vector,
    uint8_t trig_mode,
    uint8_t delivery_mode)
{
    HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "vmsi_inj_irq "
                "irq %d trig %d delive mode %d\n",
                vector, trig_mode, delivery_mode);

    switch ( delivery_mode )
    {
    case dest_Fixed:
    case dest_LowestPrio:
        vlapic_set_irq(target, vector, trig_mode);
        break;
    default:
        gdprintk(XENLOG_WARNING, "error delivery mode %d\n", delivery_mode);
        break;
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
    {
        target = vlapic_lowest_prio(d, NULL, 0, dest, dest_mode);
        if ( target != NULL )
            vmsi_inj_irq(d, target, vector, trig_mode, delivery_mode);
        else
            HVM_DBG_LOG(DBG_LEVEL_IOAPIC, "null round robin: "
                        "vector=%x delivery_mode=%x\n",
                        vector, dest_LowestPrio);
        break;
    }

    case dest_Fixed:
    case dest_ExtINT:
    {
        for_each_vcpu ( d, v )
            if ( vlapic_match_dest(vcpu_vlapic(v), NULL,
                                   0, dest, dest_mode) )
                vmsi_inj_irq(d, vcpu_vlapic(v),
                             vector, trig_mode, delivery_mode);
        break;
    }

    case dest_SMI:
    case dest_NMI:
    case dest_INIT:
    case dest__reserved_2:
    default:
        gdprintk(XENLOG_WARNING, "Unsupported delivery mode %d\n",
                 delivery_mode);
        break;
    }
    return 1;
}

void vmsi_deliver_pirq(struct domain *d, const struct hvm_pirq_dpci *pirq_dpci)
{
    uint32_t flags = pirq_dpci->gmsi.gflags;
    int vector = pirq_dpci->gmsi.gvec;
    uint8_t dest = (uint8_t)flags;
    uint8_t dest_mode = !!(flags & VMSI_DM_MASK);
    uint8_t delivery_mode = (flags & VMSI_DELIV_MASK)
        >> GFLAGS_SHIFT_DELIV_MODE;
    uint8_t trig_mode = (flags&VMSI_TRIG_MODE) >> GFLAGS_SHIFT_TRG_MODE;

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
    unsigned long table_len;
    unsigned long table_flags[BITS_TO_LONGS(MAX_MSIX_TABLE_ENTRIES)];
#define MAX_MSIX_ACC_ENTRIES 3
    struct { 
        uint32_t msi_ad[3];	/* Shadow of address low, high and data */
    } gentries[MAX_MSIX_ACC_ENTRIES];
    struct rcu_head rcu;
};

static DEFINE_RCU_READ_LOCK(msixtbl_rcu_lock);

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

static struct msi_desc *virt_to_msi_desc(struct pci_dev *dev, void *virt)
{
    struct msi_desc *desc;

    list_for_each_entry( desc, &dev->msi_list, list )
        if ( desc->msi_attrib.type == PCI_CAP_ID_MSIX  &&
             virt >= desc->mask_base &&
             virt < desc->mask_base + PCI_MSIX_ENTRY_SIZE ) 
            return desc;

    return NULL;
}

static void __iomem *msixtbl_addr_to_virt(
    struct msixtbl_entry *entry, unsigned long addr)
{
    unsigned int idx, nr_page;

    if ( !entry || !entry->pdev )
        return NULL;

    nr_page = (addr >> PAGE_SHIFT) -
              (entry->gtable >> PAGE_SHIFT);

    idx = entry->pdev->msix->table_idx[nr_page];
    if ( !idx )
        return NULL;

    return (void *)(fix_to_virt(idx) +
                    (addr & ((1UL << PAGE_SHIFT) - 1)));
}

static int msixtbl_read(
    struct vcpu *v, unsigned long address,
    unsigned long len, unsigned long *pval)
{
    unsigned long offset;
    struct msixtbl_entry *entry;
    void *virt;
    unsigned int nr_entry, index;
    int r = X86EMUL_UNHANDLEABLE;

    if ( len != 4 || (address & 3) )
        return r;

    rcu_read_lock(&msixtbl_rcu_lock);

    entry = msixtbl_find_entry(v, address);
    if ( !entry )
        goto out;
    offset = address & (PCI_MSIX_ENTRY_SIZE - 1);

    if ( offset != PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET )
    {
        nr_entry = (address - entry->gtable) / PCI_MSIX_ENTRY_SIZE;
        if ( nr_entry >= MAX_MSIX_ACC_ENTRIES )
            goto out;
        index = offset / sizeof(uint32_t);
        *pval = entry->gentries[nr_entry].msi_ad[index];
    }
    else 
    {
        virt = msixtbl_addr_to_virt(entry, address);
        if ( !virt )
            goto out;
        *pval = readl(virt);
    }
    
    r = X86EMUL_OKAY;
out:
    rcu_read_unlock(&msixtbl_rcu_lock);
    return r;
}

static int msixtbl_write(struct vcpu *v, unsigned long address,
                         unsigned long len, unsigned long val)
{
    unsigned long offset;
    struct msixtbl_entry *entry;
    const struct msi_desc *msi_desc;
    void *virt;
    unsigned int nr_entry, index;
    int r = X86EMUL_UNHANDLEABLE;
    unsigned long flags, orig;
    struct irq_desc *desc;

    if ( len != 4 || (address & 3) )
        return r;

    rcu_read_lock(&msixtbl_rcu_lock);

    entry = msixtbl_find_entry(v, address);
    if ( !entry )
        goto out;
    nr_entry = (address - entry->gtable) / PCI_MSIX_ENTRY_SIZE;

    offset = address & (PCI_MSIX_ENTRY_SIZE - 1);
    if ( offset != PCI_MSIX_ENTRY_VECTOR_CTRL_OFFSET)
    {
        if ( nr_entry < MAX_MSIX_ACC_ENTRIES ) 
        {
            index = offset / sizeof(uint32_t);
            entry->gentries[nr_entry].msi_ad[index] = val;
        }
        set_bit(nr_entry, &entry->table_flags);
        goto out;
    }

    /* exit to device model if address/data has been modified */
    if ( test_and_clear_bit(nr_entry, &entry->table_flags) )
    {
        if ( !(val & PCI_MSIX_VECTOR_BITMASK) )
            v->arch.hvm_vcpu.hvm_io.msix_unmask_address = address;
        goto out;
    }

    virt = msixtbl_addr_to_virt(entry, address);
    if ( !virt )
        goto out;

    msi_desc = virt_to_msi_desc(entry->pdev, virt);
    if ( !msi_desc || msi_desc->irq < 0 )
        goto out;
    
    desc = irq_to_desc(msi_desc->irq);
    if ( !desc )
        goto out;

    spin_lock_irqsave(&desc->lock, flags);

    if ( !desc->msi_desc )
        goto unlock;

    ASSERT(msi_desc == desc->msi_desc);
   
    orig = readl(virt);

    /*
     * Do not allow guest to modify MSI-X control bit if it is masked 
     * by Xen. We'll only handle the case where Xen thinks that
     * bit is unmasked, but hardware has silently masked the bit
     * (in case of SR-IOV VF reset, etc). On the other hand, if Xen 
     * thinks that the bit is masked, but it's really not, 
     * we log a warning.
     */
    if ( msi_desc->msi_attrib.masked )
    {
        if ( !(orig & PCI_MSIX_VECTOR_BITMASK) )
            printk(XENLOG_WARNING "MSI-X control bit is unmasked when"
                   " it is expected to be masked [%04x:%02x:%02x.%u]\n", 
                   entry->pdev->seg, entry->pdev->bus,
                   PCI_SLOT(entry->pdev->devfn), 
                   PCI_FUNC(entry->pdev->devfn));

        goto unlock;
    }

    /*
     * The mask bit is the only defined bit in the word. But we 
     * ought to preserve the reserved bits. Clearing the reserved 
     * bits can result in undefined behaviour (see PCI Local Bus
     * Specification revision 2.3).
     */
    val &= PCI_MSIX_VECTOR_BITMASK;
    val |= (orig & ~PCI_MSIX_VECTOR_BITMASK);
    writel(val, virt);

unlock:
    spin_unlock_irqrestore(&desc->lock, flags);
    r = X86EMUL_OKAY;

out:
    rcu_read_unlock(&msixtbl_rcu_lock);
    return r;
}

static int msixtbl_range(struct vcpu *v, unsigned long addr)
{
    struct msixtbl_entry *entry;
    void *virt;

    rcu_read_lock(&msixtbl_rcu_lock);

    entry = msixtbl_find_entry(v, addr);
    virt = msixtbl_addr_to_virt(entry, addr);

    rcu_read_unlock(&msixtbl_rcu_lock);

    return !!virt;
}

const struct hvm_mmio_handler msixtbl_mmio_handler = {
    .check_handler = msixtbl_range,
    .read_handler = msixtbl_read,
    .write_handler = msixtbl_write
};

static void add_msixtbl_entry(struct domain *d,
                              struct pci_dev *pdev,
                              uint64_t gtable,
                              struct msixtbl_entry *entry)
{
    u32 len;

    memset(entry, 0, sizeof(struct msixtbl_entry));
        
    INIT_LIST_HEAD(&entry->list);
    INIT_RCU_HEAD(&entry->rcu);
    atomic_set(&entry->refcnt, 0);

    len = pci_msix_get_table_len(pdev);
    entry->table_len = len;
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

    ASSERT(spin_is_locked(&pcidevs_lock));
    ASSERT(spin_is_locked(&d->event_lock));

    /*
     * xmalloc() with irq_disabled causes the failure of check_lock() 
     * for xenpool->lock. So we allocate an entry beforehand.
     */
    new_entry = xmalloc(struct msixtbl_entry);
    if ( !new_entry )
        return -ENOMEM;

    irq_desc = pirq_spin_lock_irq_desc(pirq, NULL);
    if ( !irq_desc )
    {
        xfree(new_entry);
        return r;
    }

    if ( !irq_desc->msi_desc )
        goto out;

    msi_desc = irq_desc->msi_desc;
    if ( !msi_desc )
        goto out;

    pdev = msi_desc->dev;

    spin_lock(&d->arch.hvm_domain.msixtbl_list_lock);

    list_for_each_entry( entry, &d->arch.hvm_domain.msixtbl_list, list )
        if ( pdev == entry->pdev )
            goto found;

    entry = new_entry;
    new_entry = NULL;
    add_msixtbl_entry(d, pdev, gtable, entry);

found:
    atomic_inc(&entry->refcnt);
    spin_unlock(&d->arch.hvm_domain.msixtbl_list_lock);
    r = 0;

out:
    spin_unlock_irq(&irq_desc->lock);
    xfree(new_entry);
    return r;
}

void msixtbl_pt_unregister(struct domain *d, struct pirq *pirq)
{
    struct irq_desc *irq_desc;
    struct msi_desc *msi_desc;
    struct pci_dev *pdev;
    struct msixtbl_entry *entry;

    ASSERT(spin_is_locked(&pcidevs_lock));
    ASSERT(spin_is_locked(&d->event_lock));

    irq_desc = pirq_spin_lock_irq_desc(pirq, NULL);
    if ( !irq_desc )
        return;

    if ( !irq_desc->msi_desc )
        goto out;

    msi_desc = irq_desc->msi_desc;
    if ( !msi_desc )
        goto out;

    pdev = msi_desc->dev;

    spin_lock(&d->arch.hvm_domain.msixtbl_list_lock);

    list_for_each_entry( entry, &d->arch.hvm_domain.msixtbl_list, list )
        if ( pdev == entry->pdev )
            goto found;

    spin_unlock(&d->arch.hvm_domain.msixtbl_list_lock);


out:
    spin_unlock_irq(&irq_desc->lock);
    return;

found:
    if ( !atomic_dec_and_test(&entry->refcnt) )
        del_msixtbl_entry(entry);

    spin_unlock(&d->arch.hvm_domain.msixtbl_list_lock);
    spin_unlock_irq(&irq_desc->lock);
}

void msixtbl_pt_cleanup(struct domain *d)
{
    struct msixtbl_entry *entry, *temp;
    unsigned long flags;

    /* msixtbl_list_lock must be acquired with irq_disabled for check_lock() */
    local_irq_save(flags); 
    spin_lock(&d->arch.hvm_domain.msixtbl_list_lock);

    list_for_each_entry_safe( entry, temp,
                              &d->arch.hvm_domain.msixtbl_list, list )
        del_msixtbl_entry(entry);

    spin_unlock(&d->arch.hvm_domain.msixtbl_list_lock);
    local_irq_restore(flags);
}

void msix_write_completion(struct vcpu *v)
{
    unsigned long ctrl_address = v->arch.hvm_vcpu.hvm_io.msix_unmask_address;

    if ( !ctrl_address )
        return;

    v->arch.hvm_vcpu.hvm_io.msix_unmask_address = 0;
    if ( msixtbl_write(v, ctrl_address, 4, 0) != X86EMUL_OKAY )
        gdprintk(XENLOG_WARNING, "MSI-X write completion failure\n");
}
