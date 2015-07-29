/*
 * Copyright (c) 2006, Intel Corporation.
 *
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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 * Copyright (C) Xiaohui Xin <xiaohui.xin@intel.com>
 */

#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/iommu.h>
#include <asm/hvm/iommu.h>
#include <xen/time.h>
#include <xen/list.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include "iommu.h"
#include "dmar.h"
#include "vtd.h"
#include "extern.h"

#include <asm/apic.h>
#include <asm/io_apic.h>
#define nr_ioapic_entries(i)  nr_ioapic_entries[i]

/*
 * source validation type (SVT)
 */
#define SVT_NO_VERIFY       0x0  /* no verification is required */
#define SVT_VERIFY_SID_SQ   0x1  /* verify using SID and SQ fiels */
#define SVT_VERIFY_BUS      0x2  /* verify bus of request-id */

/*
 * source-id qualifier (SQ)
 */
#define SQ_ALL_16           0x0  /* verify all 16 bits of request-id */
#define SQ_13_IGNORE_1      0x1  /* verify most significant 13 bits, ignore
                                  * the third least significant bit
                                  */
#define SQ_13_IGNORE_2      0x2  /* verify most significant 13 bits, ignore
                                  * the second and third least significant bits
                                  */
#define SQ_13_IGNORE_3      0x3  /* verify most significant 13 bits, ignore
                                  * the least three significant bits
                                  */

/* apic_pin_2_ir_idx[apicid][pin] = interrupt remapping table index */
static int **apic_pin_2_ir_idx;

static int init_apic_pin_2_ir_idx(void)
{
    int *_apic_pin_2_ir_idx;
    unsigned int nr_pins, i;

    /* Here we shouldn't need to re-init when resuming from S3. */
    if ( apic_pin_2_ir_idx != NULL )
        return 0;

    nr_pins = 0;
    for ( i = 0; i < nr_ioapics; i++ )
        nr_pins += nr_ioapic_entries(i);

    _apic_pin_2_ir_idx = xmalloc_array(int, nr_pins);
    apic_pin_2_ir_idx = xmalloc_array(int *, nr_ioapics);
    if ( (_apic_pin_2_ir_idx == NULL) || (apic_pin_2_ir_idx == NULL) )
    {
        xfree(_apic_pin_2_ir_idx);
        xfree(apic_pin_2_ir_idx);
        return -ENOMEM;
    }

    for ( i = 0; i < nr_pins; i++ )
        _apic_pin_2_ir_idx[i] = -1;

    nr_pins = 0;
    for ( i = 0; i < nr_ioapics; i++ )
    {
        apic_pin_2_ir_idx[i] = &_apic_pin_2_ir_idx[nr_pins];
        nr_pins += nr_ioapic_entries(i);
    }

    return 0;
}

static u16 apicid_to_bdf(int apic_id)
{
    struct acpi_drhd_unit *drhd = ioapic_to_drhd(apic_id);
    struct acpi_ioapic_unit *acpi_ioapic_unit;

    list_for_each_entry ( acpi_ioapic_unit, &drhd->ioapic_list, list )
        if ( acpi_ioapic_unit->apic_id == apic_id )
            return acpi_ioapic_unit->ioapic.info;

    dprintk(XENLOG_ERR VTDPREFIX, "Didn't find the bdf for the apic_id!\n");
    return 0;
}

static u16 hpetid_to_bdf(unsigned int hpet_id)
{
    struct acpi_drhd_unit *drhd = hpet_to_drhd(hpet_id);
    struct acpi_hpet_unit *acpi_hpet_unit;

    list_for_each_entry ( acpi_hpet_unit, &drhd->hpet_list, list )
        if ( acpi_hpet_unit->id == hpet_id )
            return acpi_hpet_unit->bdf;

    dprintk(XENLOG_ERR VTDPREFIX, "Didn't find the bdf for HPET %u!\n", hpet_id);
    return 0;
}

static void set_ire_sid(struct iremap_entry *ire,
                        unsigned int svt, unsigned int sq, unsigned int sid)
{
    ire->hi.svt = svt;
    ire->hi.sq = sq;
    ire->hi.sid = sid;
}

static void set_ioapic_source_id(int apic_id, struct iremap_entry *ire)
{
    set_ire_sid(ire, SVT_VERIFY_SID_SQ, SQ_ALL_16,
                apicid_to_bdf(apic_id));
}

static void set_hpet_source_id(unsigned int id, struct iremap_entry *ire)
{
    /*
     * Should really use SQ_ALL_16. Some platforms are broken.
     * While we figure out the right quirks for these broken platforms, use
     * SQ_13_IGNORE_3 for now.
     */
    set_ire_sid(ire, SVT_VERIFY_SID_SQ, SQ_13_IGNORE_3, hpetid_to_bdf(id));
}

int iommu_supports_eim(void)
{
    struct acpi_drhd_unit *drhd;
    int apic;

    if ( !iommu_qinval || !iommu_intremap || list_empty(&acpi_drhd_units) )
        return 0;

    /* We MUST have a DRHD unit for each IOAPIC. */
    for ( apic = 0; apic < nr_ioapics; apic++ )
        if ( !ioapic_to_drhd(IO_APIC_ID(apic)) )
    {
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "There is not a DRHD for IOAPIC %#x (id: %#x)!\n",
                    apic, IO_APIC_ID(apic));
            return 0;
    }

    for_each_drhd_unit ( drhd )
        if ( !ecap_queued_inval(drhd->iommu->ecap) ||
             !ecap_intr_remap(drhd->iommu->ecap) ||
             !ecap_eim(drhd->iommu->ecap) )
            return 0;

    return 1;
}

/* Mark specified intr remap entry as free */
static void free_remap_entry(struct iommu *iommu, int index)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    if ( index < 0 || index > IREMAP_ENTRY_NR - 1 )
        return;

    ASSERT( spin_is_locked(&ir_ctrl->iremap_lock) );

    GET_IREMAP_ENTRY(ir_ctrl->iremap_maddr, index,
                     iremap_entries, iremap_entry);

    memset(iremap_entry, 0, sizeof(struct iremap_entry));
    iommu_flush_cache_entry(iremap_entry, sizeof(struct iremap_entry));
    iommu_flush_iec_index(iommu, 0, index);

    unmap_vtd_domain_page(iremap_entries);
    ir_ctrl->iremap_num--;
}

/*
 * Look for a free intr remap entry (or a contiguous set thereof).
 * Need hold iremap_lock, and setup returned entry before releasing lock.
 */
static unsigned int alloc_remap_entry(struct iommu *iommu, unsigned int nr)
{
    struct iremap_entry *iremap_entries = NULL;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);
    unsigned int i, found;

    ASSERT( spin_is_locked(&ir_ctrl->iremap_lock) );

    for ( found = i = 0; i < IREMAP_ENTRY_NR; i++ )
    {
        struct iremap_entry *p;
        if ( i % (1 << IREMAP_ENTRY_ORDER) == 0 )
        {
            /* This entry across page boundry */
            if ( iremap_entries )
                unmap_vtd_domain_page(iremap_entries);

            GET_IREMAP_ENTRY(ir_ctrl->iremap_maddr, i,
                             iremap_entries, p);
        }
        else
            p = &iremap_entries[i % (1 << IREMAP_ENTRY_ORDER)];

        if ( p->lo_val || p->hi_val ) /* not a free entry */
            found = 0;
        else if ( ++found == nr )
            break;
    }

    if ( iremap_entries )
        unmap_vtd_domain_page(iremap_entries);

    if ( i < IREMAP_ENTRY_NR ) 
        ir_ctrl->iremap_num += nr;
    return i;
}

static int remap_entry_to_ioapic_rte(
    struct iommu *iommu, int index, struct IO_xAPIC_route_entry *old_rte)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    unsigned long flags;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    if ( index < 0 || index > IREMAP_ENTRY_NR - 1 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: index (%d) for remap table is invalid !\n",
                __func__, index);
        return -EFAULT;
    }

    spin_lock_irqsave(&ir_ctrl->iremap_lock, flags);

    GET_IREMAP_ENTRY(ir_ctrl->iremap_maddr, index,
                     iremap_entries, iremap_entry);

    if ( iremap_entry->hi_val == 0 && iremap_entry->lo_val == 0 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: index (%d) get an empty entry!\n",
                __func__, index);
        unmap_vtd_domain_page(iremap_entries);
        spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
        return -EFAULT;
    }

    old_rte->vector = iremap_entry->lo.vector;
    old_rte->delivery_mode = iremap_entry->lo.dlm;
    old_rte->dest_mode = iremap_entry->lo.dm;
    old_rte->trigger = iremap_entry->lo.tm;
    old_rte->__reserved_2 = 0;
    old_rte->dest.logical.__reserved_1 = 0;
    old_rte->dest.logical.logical_dest = iremap_entry->lo.dst >> 8;

    unmap_vtd_domain_page(iremap_entries);
    spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
    return 0;
}

static int ioapic_rte_to_remap_entry(struct iommu *iommu,
    int apic, unsigned int ioapic_pin, struct IO_xAPIC_route_entry *old_rte,
    unsigned int rte_upper, unsigned int value)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    struct iremap_entry new_ire;
    struct IO_APIC_route_remap_entry *remap_rte;
    struct IO_xAPIC_route_entry new_rte;
    int index;
    unsigned long flags;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    remap_rte = (struct IO_APIC_route_remap_entry *) old_rte;
    spin_lock_irqsave(&ir_ctrl->iremap_lock, flags);

    index = apic_pin_2_ir_idx[apic][ioapic_pin];
    if ( index < 0 )
    {
        index = alloc_remap_entry(iommu, 1);
        if ( index < IREMAP_ENTRY_NR )
            apic_pin_2_ir_idx[apic][ioapic_pin] = index;
    }

    if ( index > IREMAP_ENTRY_NR - 1 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: intremap index (%d) is larger than"
                " the maximum index (%d)!\n",
                __func__, index, IREMAP_ENTRY_NR - 1);
        spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
        return -EFAULT;
    }

    GET_IREMAP_ENTRY(ir_ctrl->iremap_maddr, index,
                     iremap_entries, iremap_entry);

    memcpy(&new_ire, iremap_entry, sizeof(struct iremap_entry));

    if ( rte_upper )
    {
        if ( x2apic_enabled )
            new_ire.lo.dst = value;
        else
            new_ire.lo.dst = (value >> 24) << 8;
    }
    else
    {
        *(((u32 *)&new_rte) + 0) = value;
        new_ire.lo.fpd = 0;
        new_ire.lo.dm = new_rte.dest_mode;
        new_ire.lo.tm = new_rte.trigger;
        new_ire.lo.dlm = new_rte.delivery_mode;
        /* Hardware require RH = 1 for LPR delivery mode */
        new_ire.lo.rh = (new_ire.lo.dlm == dest_LowestPrio);
        new_ire.lo.avail = 0;
        new_ire.lo.res_1 = 0;
        new_ire.lo.vector = new_rte.vector;
        new_ire.lo.res_2 = 0;

        set_ioapic_source_id(IO_APIC_ID(apic), &new_ire);
        new_ire.hi.res_1 = 0;
        new_ire.lo.p = 1;     /* finally, set present bit */

        /* now construct new ioapic rte entry */
        remap_rte->vector = new_rte.vector;
        remap_rte->delivery_mode = 0;    /* has to be 0 for remap format */
        remap_rte->index_15 = (index >> 15) & 0x1;
        remap_rte->index_0_14 = index & 0x7fff;

        remap_rte->delivery_status = new_rte.delivery_status;
        remap_rte->polarity = new_rte.polarity;
        remap_rte->irr = new_rte.irr;
        remap_rte->trigger = new_rte.trigger;
        remap_rte->mask = new_rte.mask;
        remap_rte->reserved = 0;
        remap_rte->format = 1;    /* indicate remap format */
    }

    memcpy(iremap_entry, &new_ire, sizeof(struct iremap_entry));
    iommu_flush_cache_entry(iremap_entry, sizeof(struct iremap_entry));
    iommu_flush_iec_index(iommu, 0, index);

    unmap_vtd_domain_page(iremap_entries);
    spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
    return 0;
}

unsigned int io_apic_read_remap_rte(
    unsigned int apic, unsigned int reg)
{
    unsigned int ioapic_pin = (reg - 0x10) / 2;
    int index;
    struct IO_xAPIC_route_entry old_rte = { 0 };
    int rte_upper = (reg & 1) ? 1 : 0;
    struct iommu *iommu = ioapic_to_iommu(IO_APIC_ID(apic));
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    if ( !ir_ctrl->iremap_num ||
        ( (index = apic_pin_2_ir_idx[apic][ioapic_pin]) < 0 ) )
        return __io_apic_read(apic, reg);

    old_rte = __ioapic_read_entry(apic, ioapic_pin, 1);

    if ( remap_entry_to_ioapic_rte(iommu, index, &old_rte) )
        return __io_apic_read(apic, reg);

    if ( rte_upper )
        return (*(((u32 *)&old_rte) + 1));
    else
        return (*(((u32 *)&old_rte) + 0));
}

void io_apic_write_remap_rte(
    unsigned int apic, unsigned int reg, unsigned int value)
{
    unsigned int ioapic_pin = (reg - 0x10) / 2;
    struct IO_xAPIC_route_entry old_rte = { 0 };
    struct IO_APIC_route_remap_entry *remap_rte;
    unsigned int rte_upper = (reg & 1) ? 1 : 0;
    struct iommu *iommu = ioapic_to_iommu(IO_APIC_ID(apic));
    int saved_mask;

    old_rte = __ioapic_read_entry(apic, ioapic_pin, 1);

    remap_rte = (struct IO_APIC_route_remap_entry *) &old_rte;

    /* mask the interrupt while we change the intremap table */
    saved_mask = remap_rte->mask;
    remap_rte->mask = 1;
    __io_apic_write(apic, reg & ~1, *(u32 *)&old_rte);
    remap_rte->mask = saved_mask;

    if ( ioapic_rte_to_remap_entry(iommu, apic, ioapic_pin,
                                   &old_rte, rte_upper, value) )
    {
        __io_apic_write(apic, reg, value);

        /* Recover the original value of 'mask' bit */
        if ( rte_upper )
            __io_apic_write(apic, reg & ~1, *(u32 *)&old_rte);
    }
    else
        __ioapic_write_entry(apic, ioapic_pin, 1, old_rte);
}

static void set_msi_source_id(struct pci_dev *pdev, struct iremap_entry *ire)
{
    u16 seg;
    u8 bus, devfn, secbus;
    int ret;

    if ( !pdev || !ire )
        return;

    seg = pdev->seg;
    bus = pdev->bus;
    devfn = pdev->devfn;
    switch ( pdev->type )
    {
        unsigned int sq;

    case DEV_TYPE_PCIe_ENDPOINT:
    case DEV_TYPE_PCIe_BRIDGE:
    case DEV_TYPE_PCIe2PCI_BRIDGE:
    case DEV_TYPE_PCI_HOST_BRIDGE:
        switch ( pdev->phantom_stride )
        {
        case 1: sq = SQ_13_IGNORE_3; break;
        case 2: sq = SQ_13_IGNORE_2; break;
        case 4: sq = SQ_13_IGNORE_1; break;
        default: sq = SQ_ALL_16; break;
        }
        set_ire_sid(ire, SVT_VERIFY_SID_SQ, sq, PCI_BDF2(bus, devfn));
        break;

    case DEV_TYPE_PCI:
    case DEV_TYPE_LEGACY_PCI_BRIDGE:
    case DEV_TYPE_PCI2PCIe_BRIDGE:
        ret = find_upstream_bridge(seg, &bus, &devfn, &secbus);
        if ( ret == 0 ) /* integrated PCI device */
        {
            set_ire_sid(ire, SVT_VERIFY_SID_SQ, SQ_ALL_16,
                        PCI_BDF2(bus, devfn));
        }
        else if ( ret == 1 ) /* find upstream bridge */
        {
            if ( pdev_type(seg, bus, devfn) == DEV_TYPE_PCIe2PCI_BRIDGE )
                set_ire_sid(ire, SVT_VERIFY_BUS, SQ_ALL_16,
                            (bus << 8) | pdev->bus);
            else
                set_ire_sid(ire, SVT_VERIFY_SID_SQ, SQ_ALL_16,
                            PCI_BDF2(bus, devfn));
        }
        else
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "d%d: no upstream bridge for %04x:%02x:%02x.%u\n",
                    pdev->domain->domain_id,
                    seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
        break;

    default:
        dprintk(XENLOG_WARNING VTDPREFIX,
                "d%d: unknown(%u): %04x:%02x:%02x.%u\n",
                pdev->domain->domain_id, pdev->type,
                seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
        break;
   }
}

static int remap_entry_to_msi_msg(
    struct iommu *iommu, struct msi_msg *msg, unsigned int index)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    struct msi_msg_remap_entry *remap_rte;
    unsigned long flags;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    remap_rte = (struct msi_msg_remap_entry *) msg;
    index += (remap_rte->address_lo.index_15 << 15) |
             remap_rte->address_lo.index_0_14;

    if ( index >= IREMAP_ENTRY_NR )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: index (%d) for remap table is invalid !\n",
                __func__, index);
        return -EFAULT;
    }

    spin_lock_irqsave(&ir_ctrl->iremap_lock, flags);

    GET_IREMAP_ENTRY(ir_ctrl->iremap_maddr, index,
                     iremap_entries, iremap_entry);

    if ( iremap_entry->hi_val == 0 && iremap_entry->lo_val == 0 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: index (%d) get an empty entry!\n",
                __func__, index);
        unmap_vtd_domain_page(iremap_entries);
        spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
        return -EFAULT;
    }

    msg->address_hi = MSI_ADDR_BASE_HI;
    msg->address_lo =
        MSI_ADDR_BASE_LO |
        ((iremap_entry->lo.dm == 0) ?
            MSI_ADDR_DESTMODE_PHYS:
            MSI_ADDR_DESTMODE_LOGIC) |
        ((iremap_entry->lo.dlm != dest_LowestPrio) ?
            MSI_ADDR_REDIRECTION_CPU:
            MSI_ADDR_REDIRECTION_LOWPRI);
    if ( x2apic_enabled )
        msg->dest32 = iremap_entry->lo.dst;
    else
        msg->dest32 = (iremap_entry->lo.dst >> 8) & 0xff;
    msg->address_lo |= MSI_ADDR_DEST_ID(msg->dest32);

    msg->data =
        MSI_DATA_TRIGGER_EDGE |
        MSI_DATA_LEVEL_ASSERT |
        ((iremap_entry->lo.dlm != dest_LowestPrio) ?
            MSI_DATA_DELIVERY_FIXED:
            MSI_DATA_DELIVERY_LOWPRI) |
        iremap_entry->lo.vector;

    unmap_vtd_domain_page(iremap_entries);
    spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
    return 0;
}

static int msi_msg_to_remap_entry(
    struct iommu *iommu, struct pci_dev *pdev,
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    struct iremap_entry new_ire;
    struct msi_msg_remap_entry *remap_rte;
    unsigned int index, i, nr = 1;
    unsigned long flags;
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);

    if ( msi_desc->msi_attrib.type == PCI_CAP_ID_MSI )
        nr = msi_desc->msi.nvec;

    spin_lock_irqsave(&ir_ctrl->iremap_lock, flags);

    if ( msg == NULL )
    {
        /* Free specified unused IRTEs */
        for ( i = 0; i < nr; ++i )
            free_remap_entry(iommu, msi_desc->remap_index + i);
        spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
        return 0;
    }

    if ( msi_desc->remap_index < 0 )
    {
        index = alloc_remap_entry(iommu, nr);
        for ( i = 0; i < nr; ++i )
            msi_desc[i].remap_index = index + i;
    }
    else
        index = msi_desc->remap_index;

    if ( index > IREMAP_ENTRY_NR - 1 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: intremap index (%d) is larger than"
                " the maximum index (%d)!\n",
                __func__, index, IREMAP_ENTRY_NR - 1);
        for ( i = 0; i < nr; ++i )
            msi_desc[i].remap_index = -1;
        spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
        return -EFAULT;
    }

    GET_IREMAP_ENTRY(ir_ctrl->iremap_maddr, index,
                     iremap_entries, iremap_entry);

    memcpy(&new_ire, iremap_entry, sizeof(struct iremap_entry));

    /* Set interrupt remapping table entry */
    new_ire.lo.fpd = 0;
    new_ire.lo.dm = (msg->address_lo >> MSI_ADDR_DESTMODE_SHIFT) & 0x1;
    new_ire.lo.tm = (msg->data >> MSI_DATA_TRIGGER_SHIFT) & 0x1;
    new_ire.lo.dlm = (msg->data >> MSI_DATA_DELIVERY_MODE_SHIFT) & 0x1;
    /* Hardware require RH = 1 for LPR delivery mode */
    new_ire.lo.rh = (new_ire.lo.dlm == dest_LowestPrio);
    new_ire.lo.avail = 0;
    new_ire.lo.res_1 = 0;
    new_ire.lo.vector = (msg->data >> MSI_DATA_VECTOR_SHIFT) &
                        MSI_DATA_VECTOR_MASK;
    new_ire.lo.res_2 = 0;
    if ( x2apic_enabled )
        new_ire.lo.dst = msg->dest32;
    else
        new_ire.lo.dst = ((msg->address_lo >> MSI_ADDR_DEST_ID_SHIFT)
                          & 0xff) << 8;

    if ( pdev )
        set_msi_source_id(pdev, &new_ire);
    else
        set_hpet_source_id(msi_desc->hpet_id, &new_ire);
    new_ire.hi.res_1 = 0;
    new_ire.lo.p = 1;    /* finally, set present bit */

    /* now construct new MSI/MSI-X rte entry */
    remap_rte = (struct msi_msg_remap_entry *)msg;
    remap_rte->address_lo.dontcare = 0;
    i = index;
    if ( !nr )
        i -= msi_desc->msi_attrib.entry_nr;
    remap_rte->address_lo.index_15 = (i >> 15) & 0x1;
    remap_rte->address_lo.index_0_14 = i & 0x7fff;
    remap_rte->address_lo.SHV = 1;
    remap_rte->address_lo.format = 1;

    remap_rte->address_hi = 0;
    remap_rte->data = index - i;

    memcpy(iremap_entry, &new_ire, sizeof(struct iremap_entry));
    iommu_flush_cache_entry(iremap_entry, sizeof(struct iremap_entry));
    iommu_flush_iec_index(iommu, 0, index);

    unmap_vtd_domain_page(iremap_entries);
    spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);
    return 0;
}

void msi_msg_read_remap_rte(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    struct pci_dev *pdev = msi_desc->dev;
    struct acpi_drhd_unit *drhd = NULL;

    drhd = pdev ? acpi_find_matched_drhd_unit(pdev)
                : hpet_to_drhd(msi_desc->hpet_id);
    if ( drhd )
        remap_entry_to_msi_msg(drhd->iommu, msg,
                               msi_desc->msi_attrib.type == PCI_CAP_ID_MSI
                               ? msi_desc->msi_attrib.entry_nr : 0);
}

int msi_msg_write_remap_rte(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    struct pci_dev *pdev = msi_desc->dev;
    struct acpi_drhd_unit *drhd = NULL;

    drhd = pdev ? acpi_find_matched_drhd_unit(pdev)
                : hpet_to_drhd(msi_desc->hpet_id);
    return drhd ? msi_msg_to_remap_entry(drhd->iommu, pdev, msi_desc, msg)
                : -EINVAL;
}

int __init intel_setup_hpet_msi(struct msi_desc *msi_desc)
{
    struct iommu *iommu = hpet_to_iommu(msi_desc->hpet_id);
    struct ir_ctrl *ir_ctrl = iommu_ir_ctrl(iommu);
    unsigned long flags;
    int rc = 0;

    if ( !ir_ctrl || !ir_ctrl->iremap_maddr )
        return 0;

    spin_lock_irqsave(&ir_ctrl->iremap_lock, flags);
    msi_desc->remap_index = alloc_remap_entry(iommu, 1);
    if ( msi_desc->remap_index >= IREMAP_ENTRY_NR )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "%s: intremap index (%d) is larger than"
                " the maximum index (%d)!\n",
                __func__, msi_desc->remap_index, IREMAP_ENTRY_NR - 1);
        msi_desc->remap_index = -1;
        rc = -ENXIO;
    }
    spin_unlock_irqrestore(&ir_ctrl->iremap_lock, flags);

    return rc;
}

int enable_intremap(struct iommu *iommu, int eim)
{
    struct acpi_drhd_unit *drhd;
    struct ir_ctrl *ir_ctrl;
    u32 sts, gcmd;
    unsigned long flags;

    ASSERT(ecap_intr_remap(iommu->ecap) && iommu_intremap);

    if ( !platform_supports_intremap() )
    {
        printk(XENLOG_ERR VTDPREFIX
               " Platform firmware does not support interrupt remapping\n");
        return -EINVAL;
    }

    ir_ctrl = iommu_ir_ctrl(iommu);
    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);

    /* Return if already enabled by Xen */
    if ( (sts & DMA_GSTS_IRES) && ir_ctrl->iremap_maddr )
        return 0;

    if ( !(sts & DMA_GSTS_QIES) )
    {
        printk(XENLOG_ERR VTDPREFIX
               " Queued invalidation is not enabled on IOMMU #%u:"
               " Should not enable interrupt remapping\n", iommu->index);
        return -EINVAL;
    }

    if ( !eim && (sts & DMA_GSTS_CFIS) )
        printk(XENLOG_WARNING VTDPREFIX
               " Compatibility Format Interrupts permitted on IOMMU #%u:"
               " Device pass-through will be insecure\n", iommu->index);

    if ( ir_ctrl->iremap_maddr == 0 )
    {
        drhd = iommu_to_drhd(iommu);
        ir_ctrl->iremap_maddr = alloc_pgtable_maddr(drhd, IREMAP_ARCH_PAGE_NR);
        if ( ir_ctrl->iremap_maddr == 0 )
        {
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "Cannot allocate memory for ir_ctrl->iremap_maddr\n");
            return -ENOMEM;
        }
        ir_ctrl->iremap_num = 0;
    }

    /* set extended interrupt mode bit */
    ir_ctrl->iremap_maddr |= eim ? IRTA_EIME : 0;

    spin_lock_irqsave(&iommu->register_lock, flags);

    /* set size of the interrupt remapping table */
    ir_ctrl->iremap_maddr |= IRTA_REG_TABLE_SIZE;
    dmar_writeq(iommu->reg, DMAR_IRTA_REG, ir_ctrl->iremap_maddr);

    /* set SIRTP */
    gcmd = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    gcmd |= DMA_GCMD_SIRTP;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, gcmd);

    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  (sts & DMA_GSTS_SIRTPS), sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    /* After set SIRTP, must globally invalidate the interrupt entry cache */
    iommu_flush_iec_global(iommu);

    spin_lock_irqsave(&iommu->register_lock, flags);
    /* enable interrupt remapping hardware */
    gcmd |= DMA_GCMD_IRE;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, gcmd);

    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  (sts & DMA_GSTS_IRES), sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    return init_apic_pin_2_ir_idx();
}

void disable_intremap(struct iommu *iommu)
{
    u32 sts;
    u64 irta;
    unsigned long flags;

    if ( !ecap_intr_remap(iommu->ecap) )
        return;

    spin_lock_irqsave(&iommu->register_lock, flags);
    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    if ( !(sts & DMA_GSTS_IRES) )
        goto out;

    dmar_writel(iommu->reg, DMAR_GCMD_REG, sts & (~DMA_GCMD_IRE));

    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  !(sts & DMA_GSTS_IRES), sts);

    /* If we are disabling Interrupt Remapping, make sure we dont stay in
     * Extended Interrupt Mode, as this is unaffected by the Interrupt 
     * Remapping flag in each DMAR Global Control Register.
     * Specifically, local apics in xapic mode do not like interrupts delivered
     * in x2apic mode.  Any code turning interrupt remapping back on will set
     * EIME back correctly.
     */
    if ( !ecap_eim(iommu->ecap) )
        goto out;

    /* Can't read the register unless we ecaps says we can */
    irta = dmar_readl(iommu->reg, DMAR_IRTA_REG);
    if ( !(irta & IRTA_EIME) )
        goto out;

    dmar_writel(iommu->reg, DMAR_IRTA_REG, irta & ~IRTA_EIME);
    IOMMU_WAIT_OP(iommu, DMAR_IRTA_REG, dmar_readl,
                  !(irta & IRTA_EIME), irta);

out:
    spin_unlock_irqrestore(&iommu->register_lock, flags);
}

/*
 * This function is used to enable Interrupt remapping when
 * enable x2apic
 */
int iommu_enable_x2apic_IR(void)
{
    struct acpi_drhd_unit *drhd;
    struct iommu *iommu;

    if ( !iommu_supports_eim() )
        return -1;

    if ( !platform_supports_x2apic() )
        return -1;

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;

        /* Clear previous faults */
        clear_fault_bits(iommu);

        /*
         * Disable interrupt remapping and queued invalidation if
         * already enabled by BIOS
         */
        disable_intremap(iommu);
        disable_qinval(iommu);
    }

    /* Enable queue invalidation */
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        if ( enable_qinval(iommu) != 0 )
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "Failed to enable Queued Invalidation!\n");
            return -1;
        }
    }

    /* Enable interrupt remapping */
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        if ( enable_intremap(iommu, 1) )
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "Failed to enable Interrupt Remapping!\n");
            return -1;
        }
    }

    return 0;
}

/*
 * This function is used to disable Interrutp remapping when
 * suspend local apic
 */
void iommu_disable_x2apic_IR(void)
{
    struct acpi_drhd_unit *drhd;

    if ( !iommu_supports_eim() )
        return;

    for_each_drhd_unit ( drhd )
        disable_intremap(drhd->iommu);

    for_each_drhd_unit ( drhd )
        disable_qinval(drhd->iommu);
}
