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


#include <xen/sched.h>
#include <xen/iommu.h>
#include <xen/time.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include "iommu.h"
#include "dmar.h"
#include "vtd.h"
#include "extern.h"
#include "../ats.h"

/* Each entry is 16 bytes, and there can be up to 2^7 pages. */
#define QINVAL_MAX_ENTRY_NR (1u << (7 + PAGE_SHIFT_4K - 4))

/* Status data flag */
#define QINVAL_STAT_INIT  0
#define QINVAL_STAT_DONE  1

static unsigned int __read_mostly qi_pg_order;
static unsigned int __read_mostly qi_entry_nr;

static int __must_check invalidate_sync(struct vtd_iommu *iommu);

static void print_qi_regs(const struct vtd_iommu *iommu)
{
    printk(" IQA = %"PRIx64"\n", dmar_readq(iommu->reg, DMAR_IQA_REG));
    printk(" IQH = %"PRIx64"\n", dmar_readq(iommu->reg, DMAR_IQH_REG));
    printk(" IQT = %"PRIx64"\n", dmar_readq(iommu->reg, DMAR_IQT_REG));
}

static unsigned int qinval_next_index(struct vtd_iommu *iommu)
{
    unsigned int tail = dmar_readl(iommu->reg, DMAR_IQT_REG);

    tail /= sizeof(struct qinval_entry);

    /* (tail+1 == head) indicates a full queue, wait for HW */
    while ( ((tail + 1) & (qi_entry_nr - 1)) ==
            (dmar_readl(iommu->reg, DMAR_IQH_REG) / sizeof(struct qinval_entry)) )
    {
        printk_once(XENLOG_ERR VTDPREFIX " IOMMU#%u: no QI slot available\n",
                    iommu->index);
        cpu_relax();
    }

    return tail;
}

static void qinval_update_qtail(struct vtd_iommu *iommu, unsigned int index)
{
    unsigned int val;

    /* Need hold register lock when update tail */
    ASSERT( spin_is_locked(&iommu->register_lock) );
    val = (index + 1) & (qi_entry_nr - 1);
    dmar_writel(iommu->reg, DMAR_IQT_REG, val * sizeof(struct qinval_entry));
}

static struct qinval_entry *qi_map_entry(const struct vtd_iommu *iommu,
                                         unsigned int index)
{
    paddr_t base = iommu->qinval_maddr +
                   ((index * sizeof(struct qinval_entry)) & PAGE_MASK);
    struct qinval_entry *entries = map_vtd_domain_page(base);

    return &entries[index % (PAGE_SIZE / sizeof(*entries))];
}

static int __must_check queue_invalidate_context_sync(struct vtd_iommu *iommu,
                                                      u16 did, u16 source_id,
                                                      u8 function_mask,
                                                      u8 granu)
{
    unsigned long flags;
    unsigned int index;
    struct qinval_entry *qinval_entry;

    spin_lock_irqsave(&iommu->register_lock, flags);
    index = qinval_next_index(iommu);
    qinval_entry = qi_map_entry(iommu, index);

    qinval_entry->q.cc_inv_dsc.lo.type = TYPE_INVAL_CONTEXT;
    qinval_entry->q.cc_inv_dsc.lo.granu = granu;
    qinval_entry->q.cc_inv_dsc.lo.res_1 = 0;
    qinval_entry->q.cc_inv_dsc.lo.did = did;
    qinval_entry->q.cc_inv_dsc.lo.sid = source_id;
    qinval_entry->q.cc_inv_dsc.lo.fm = function_mask;
    qinval_entry->q.cc_inv_dsc.lo.res_2 = 0;
    qinval_entry->q.cc_inv_dsc.hi.res = 0;

    qinval_update_qtail(iommu, index);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    unmap_vtd_domain_page(qinval_entry);

    return invalidate_sync(iommu);
}

static int __must_check queue_invalidate_iotlb_sync(struct vtd_iommu *iommu,
                                                    u8 granu, u8 dr, u8 dw,
                                                    u16 did, u8 am, u8 ih,
                                                    u64 addr)
{
    unsigned long flags;
    unsigned int index;
    struct qinval_entry *qinval_entry;

    spin_lock_irqsave(&iommu->register_lock, flags);
    index = qinval_next_index(iommu);
    qinval_entry = qi_map_entry(iommu, index);

    qinval_entry->q.iotlb_inv_dsc.lo.type = TYPE_INVAL_IOTLB;
    qinval_entry->q.iotlb_inv_dsc.lo.granu = granu;
    qinval_entry->q.iotlb_inv_dsc.lo.dr = dr;
    qinval_entry->q.iotlb_inv_dsc.lo.dw = dw;
    qinval_entry->q.iotlb_inv_dsc.lo.res_1 = 0;
    qinval_entry->q.iotlb_inv_dsc.lo.did = did;
    qinval_entry->q.iotlb_inv_dsc.lo.res_2 = 0;

    qinval_entry->q.iotlb_inv_dsc.hi.am = am;
    qinval_entry->q.iotlb_inv_dsc.hi.ih = ih;
    qinval_entry->q.iotlb_inv_dsc.hi.res_1 = 0;
    qinval_entry->q.iotlb_inv_dsc.hi.addr = addr >> PAGE_SHIFT_4K;

    qinval_update_qtail(iommu, index);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    unmap_vtd_domain_page(qinval_entry);

    return invalidate_sync(iommu);
}

static int __must_check queue_invalidate_wait(struct vtd_iommu *iommu,
                                              u8 iflag, u8 sw, u8 fn,
                                              bool flush_dev_iotlb)
{
    static DEFINE_PER_CPU(uint32_t, poll_slot);
    unsigned int index;
    unsigned long flags;
    struct qinval_entry *qinval_entry;
    uint32_t *this_poll_slot = &this_cpu(poll_slot);

    spin_lock_irqsave(&iommu->register_lock, flags);
    ACCESS_ONCE(*this_poll_slot) = QINVAL_STAT_INIT;
    index = qinval_next_index(iommu);
    qinval_entry = qi_map_entry(iommu, index);

    qinval_entry->q.inv_wait_dsc.lo.type = TYPE_INVAL_WAIT;
    qinval_entry->q.inv_wait_dsc.lo.iflag = iflag;
    qinval_entry->q.inv_wait_dsc.lo.sw = sw;
    qinval_entry->q.inv_wait_dsc.lo.fn = fn;
    qinval_entry->q.inv_wait_dsc.lo.res_1 = 0;
    qinval_entry->q.inv_wait_dsc.lo.sdata = QINVAL_STAT_DONE;
    qinval_entry->q.inv_wait_dsc.hi.saddr = virt_to_maddr(this_poll_slot);

    qinval_update_qtail(iommu, index);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    unmap_vtd_domain_page(qinval_entry);

    /* Now we don't support interrupt method */
    if ( sw )
    {
        static unsigned int __read_mostly threshold = 1;
        s_time_t start = NOW();
        s_time_t timeout = start + (flush_dev_iotlb
                                    ? iommu_dev_iotlb_timeout
                                    : 100) * MILLISECS(threshold);

        while ( ACCESS_ONCE(*this_poll_slot) != QINVAL_STAT_DONE )
        {
            if ( timeout && NOW() > timeout )
            {
                threshold |= threshold << 1;
                printk(XENLOG_WARNING VTDPREFIX
                       " IOMMU#%u: QI%s wait descriptor taking too long\n",
                       iommu->index, flush_dev_iotlb ? " dev" : "");
                print_qi_regs(iommu);
                timeout = 0;
            }
            cpu_relax();
        }

        if ( !timeout )
            printk(XENLOG_WARNING VTDPREFIX
                   " IOMMU#%u: QI%s wait descriptor took %lums\n",
                   iommu->index, flush_dev_iotlb ? " dev" : "",
                   (NOW() - start) / 10000000);

        return 0;
    }

    return -EOPNOTSUPP;
}

static int __must_check invalidate_sync(struct vtd_iommu *iommu)
{
    ASSERT(iommu->qinval_maddr);

    return queue_invalidate_wait(iommu, 0, 1, 1, 0);
}

static int __must_check dev_invalidate_sync(struct vtd_iommu *iommu,
                                            struct pci_dev *pdev, u16 did)
{
    int rc;

    ASSERT(iommu->qinval_maddr);
    rc = queue_invalidate_wait(iommu, 0, 1, 1, 1);
    if ( rc == -ETIMEDOUT && !pdev->broken )
    {
        struct domain *d = rcu_lock_domain_by_id(did_to_domain_id(iommu, did));

        /*
         * In case the domain has been freed or the IOMMU domid bitmap is
         * not valid, the device no longer belongs to this domain.
         */
        if ( d == NULL )
            return rc;

        iommu_dev_iotlb_flush_timeout(d, pdev);
        rcu_unlock_domain(d);
    }
    else if ( rc == -ETIMEDOUT )
        /*
         * The device is already marked as broken, ignore the error in order to
         * allow {de,}assign to succeed.
         */
        rc = 0;

    return rc;
}

int qinval_device_iotlb_sync(struct vtd_iommu *iommu, struct pci_dev *pdev,
                             u16 did, u16 size, u64 addr)
{
    unsigned long flags;
    unsigned int index;
    struct qinval_entry *qinval_entry;

    ASSERT(pdev);
    spin_lock_irqsave(&iommu->register_lock, flags);
    index = qinval_next_index(iommu);
    qinval_entry = qi_map_entry(iommu, index);

    qinval_entry->q.dev_iotlb_inv_dsc.lo.type = TYPE_INVAL_DEVICE_IOTLB;
    qinval_entry->q.dev_iotlb_inv_dsc.lo.res_1 = 0;
    qinval_entry->q.dev_iotlb_inv_dsc.lo.max_invs_pend = pdev->ats.queue_depth;
    qinval_entry->q.dev_iotlb_inv_dsc.lo.res_2 = 0;
    qinval_entry->q.dev_iotlb_inv_dsc.lo.sid = pdev->sbdf.bdf;
    qinval_entry->q.dev_iotlb_inv_dsc.lo.res_3 = 0;

    qinval_entry->q.dev_iotlb_inv_dsc.hi.size = size;
    qinval_entry->q.dev_iotlb_inv_dsc.hi.res_1 = 0;
    qinval_entry->q.dev_iotlb_inv_dsc.hi.addr = addr >> PAGE_SHIFT_4K;

    qinval_update_qtail(iommu, index);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    unmap_vtd_domain_page(qinval_entry);

    return dev_invalidate_sync(iommu, pdev, did);
}

static int __must_check queue_invalidate_iec_sync(struct vtd_iommu *iommu,
                                                  u8 granu, u8 im, u16 iidx)
{
    unsigned long flags;
    unsigned int index;
    struct qinval_entry *qinval_entry;
    int ret;

    spin_lock_irqsave(&iommu->register_lock, flags);
    index = qinval_next_index(iommu);
    qinval_entry = qi_map_entry(iommu, index);

    qinval_entry->q.iec_inv_dsc.lo.type = TYPE_INVAL_IEC;
    qinval_entry->q.iec_inv_dsc.lo.granu = granu;
    qinval_entry->q.iec_inv_dsc.lo.res_1 = 0;
    qinval_entry->q.iec_inv_dsc.lo.im = im;
    qinval_entry->q.iec_inv_dsc.lo.iidx = iidx;
    qinval_entry->q.iec_inv_dsc.lo.res_2 = 0;
    qinval_entry->q.iec_inv_dsc.hi.res = 0;

    qinval_update_qtail(iommu, index);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    unmap_vtd_domain_page(qinval_entry);

    ret = invalidate_sync(iommu);

    /*
     * reading vt-d architecture register will ensure
     * draining happens in implementation independent way.
     */
    (void)dmar_readq(iommu->reg, DMAR_CAP_REG);

    return ret;
}

int iommu_flush_iec_global(struct vtd_iommu *iommu)
{
    return queue_invalidate_iec_sync(iommu, IEC_GLOBAL_INVL, 0, 0);
}

int iommu_flush_iec_index(struct vtd_iommu *iommu, u8 im, u16 iidx)
{
    return queue_invalidate_iec_sync(iommu, IEC_INDEX_INVL, im, iidx);
}

static int __must_check cf_check flush_context_qi(
    struct vtd_iommu *iommu, u16 did, u16 sid, u8 fm, u64 type,
    bool flush_non_present_entry)
{
    ASSERT(iommu->qinval_maddr);

    /*
     * In the non-present entry flush case, if hardware doesn't cache
     * non-present entry we do nothing and if hardware cache non-present
     * entry, we flush entries of domain 0 (the domain id is used to cache
     * any non-present entries)
     */
    if ( flush_non_present_entry )
    {
        if ( !cap_caching_mode(iommu->cap) )
            return 1;
        else
            did = 0;
    }

    return queue_invalidate_context_sync(iommu, did, sid, fm,
                                         type >> DMA_CCMD_INVL_GRANU_OFFSET);
}

static int __must_check cf_check flush_iotlb_qi(
    struct vtd_iommu *iommu, u16 did, u64 addr, unsigned int size_order,
    u64 type, bool flush_non_present_entry, bool flush_dev_iotlb)
{
    u8 dr = 0, dw = 0;
    int ret = 0, rc;

    ASSERT(iommu->qinval_maddr);

    /*
     * In the non-present entry flush case, if hardware doesn't cache
     * non-present entries we do nothing.
     */
    if ( flush_non_present_entry && !cap_caching_mode(iommu->cap) )
        return 1;

    /* use queued invalidation */
    if (cap_write_drain(iommu->cap))
        dw = 1;
    if (cap_read_drain(iommu->cap))
        dr = 1;
    /* Need to conside the ih bit later */
    rc = queue_invalidate_iotlb_sync(iommu,
                                     type >> DMA_TLB_FLUSH_GRANU_OFFSET,
                                     dr, dw, did, size_order, 0, addr);
    if ( !ret )
        ret = rc;

    if ( flush_dev_iotlb )
    {
        rc = dev_invalidate_iotlb(iommu, did, addr, size_order, type);
        if ( !ret )
            ret = rc;
    }
    return ret;
}

int enable_qinval(struct vtd_iommu *iommu)
{
    u32 sts;
    unsigned long flags;

    if ( !ecap_queued_inval(iommu->ecap) || !iommu_qinval )
        return -ENOENT;

    /* Return if already enabled by Xen */
    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    if ( (sts & DMA_GSTS_QIES) && iommu->qinval_maddr )
        return 0;

    if ( iommu->qinval_maddr == 0 )
    {
        if ( !qi_entry_nr )
        {
            /*
             * With the present synchronous model, we need two slots for every
             * operation (the operation itself and a wait descriptor).  There
             * can be one such pair of requests pending per CPU.  One extra
             * entry is needed as the ring is considered full when there's
             * only one entry left.
             */
            BUILD_BUG_ON(CONFIG_NR_CPUS * 2 >= QINVAL_MAX_ENTRY_NR);
            qi_pg_order = get_order_from_bytes((num_present_cpus() * 2 + 1) *
                                               sizeof(struct qinval_entry));
            qi_entry_nr = (PAGE_SIZE << qi_pg_order) /
                          sizeof(struct qinval_entry);

            dprintk(XENLOG_INFO VTDPREFIX,
                    "QI: using %u-entry ring(s)\n", qi_entry_nr);
        }

        iommu->qinval_maddr =
            alloc_pgtable_maddr(PFN_DOWN(qi_entry_nr *
                                         sizeof(struct qinval_entry)),
                                iommu->node);
        if ( iommu->qinval_maddr == 0 )
        {
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "Cannot allocate memory for qi_ctrl->qinval_maddr\n");
            return -ENOMEM;
        }
    }

    iommu->flush.context = flush_context_qi;
    iommu->flush.iotlb   = flush_iotlb_qi;

    spin_lock_irqsave(&iommu->register_lock, flags);

    /*
     * Setup Invalidation Queue Address (IQA) register with the address of the
     * pages we just allocated.  The QS field at bits[2:0] indicates the size
     * (page order) of the queue.
     *
     * Queued Head (IQH) and Queue Tail (IQT) registers are automatically
     * reset to 0 with write to IQA register.
     */
    dmar_writeq(iommu->reg, DMAR_IQA_REG,
                iommu->qinval_maddr | qi_pg_order);

    dmar_writeq(iommu->reg, DMAR_IQT_REG, 0);

    /* enable queued invalidation hardware */
    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    dmar_writel(iommu->reg, DMAR_GCMD_REG, sts | DMA_GCMD_QIE);

    /* Make sure hardware complete it */
    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  (sts & DMA_GSTS_QIES), sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    return 0;
}

static int cf_check vtd_flush_context_noop(
    struct vtd_iommu *iommu, uint16_t did, uint16_t source_id,
    uint8_t function_mask, uint64_t type, bool flush_non_present_entry)
{
    WARN();
    return -EIO;
}

static int cf_check vtd_flush_iotlb_noop(
    struct vtd_iommu *iommu, uint16_t did, uint64_t addr,
    unsigned int size_order, uint64_t type, bool flush_non_present_entry,
    bool flush_dev_iotlb)
{
    WARN();
    return -EIO;
}

void disable_qinval(struct vtd_iommu *iommu)
{
    u32 sts;
    unsigned long flags;

    if ( !ecap_queued_inval(iommu->ecap) )
        return;

    spin_lock_irqsave(&iommu->register_lock, flags);
    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    if ( !(sts & DMA_GSTS_QIES) )
        goto out;

    dmar_writel(iommu->reg, DMAR_GCMD_REG, sts & (~DMA_GCMD_QIE));

    /* Make sure hardware complete it */
    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  !(sts & DMA_GSTS_QIES), sts);
out:
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    /*
     * Assign callbacks to noop to catch errors if register-based invalidation
     * isn't supported.
     */
    if ( has_register_based_invalidation(iommu) )
    {
        iommu->flush.context = vtd_flush_context_reg;
        iommu->flush.iotlb   = vtd_flush_iotlb_reg;
    }
    else
    {
        iommu->flush.context = vtd_flush_context_noop;
        iommu->flush.iotlb   = vtd_flush_iotlb_noop;
    }
}
