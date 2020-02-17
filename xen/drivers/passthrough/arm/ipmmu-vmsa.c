/*
 * xen/drivers/passthrough/arm/ipmmu-vmsa.c
 *
 * Driver for the Renesas IPMMU-VMSA found in R-Car Gen3 SoCs.
 *
 * The IPMMU-VMSA is VMSA-compatible I/O Memory Management Unit (IOMMU)
 * which provides address translation and access protection functionalities
 * to processing units and interconnect networks.
 *
 * Please note, current driver is supposed to work only with newest
 * R-Car Gen3 SoCs revisions which IPMMU hardware supports stage 2 translation
 * table format and is able to use CPU's P2M table as is.
 *
 * Based on Linux's IPMMU-VMSA driver from Renesas BSP:
 *    drivers/iommu/ipmmu-vmsa.c
 * you can found at:
 *    url: git://git.kernel.org/pub/scm/linux/kernel/git/horms/renesas-bsp.git
 *    branch: v4.14.75-ltsi/rcar-3.9.6
 *    commit: e206eb5b81a60e64c35fbc3a999b1a0db2b98044
 * and Xen's SMMU driver:
 *    xen/drivers/passthrough/arm/smmu.c
 *
 * Copyright (C) 2014-2019 Renesas Electronics Corporation
 *
 * Copyright (C) 2016-2019 EPAM Systems Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/delay.h>
#include <xen/err.h>
#include <xen/iommu.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/list.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/vmap.h>

#include <asm/atomic.h>
#include <asm/device.h>
#include <asm/io.h>
#include <asm/iommu_fwspec.h>

#define dev_name(dev) dt_node_full_name(dev_to_dt(dev))

/* Device logger functions */
#define dev_print(dev, lvl, fmt, ...)    \
    printk(lvl "ipmmu: %s: " fmt, dev_name(dev), ## __VA_ARGS__)

#define dev_info(dev, fmt, ...)    \
    dev_print(dev, XENLOG_INFO, fmt, ## __VA_ARGS__)
#define dev_warn(dev, fmt, ...)    \
    dev_print(dev, XENLOG_WARNING, fmt, ## __VA_ARGS__)
#define dev_err(dev, fmt, ...)     \
    dev_print(dev, XENLOG_ERR, fmt, ## __VA_ARGS__)
#define dev_err_ratelimited(dev, fmt, ...)    \
    dev_print(dev, XENLOG_ERR, fmt, ## __VA_ARGS__)

/*
 * R-Car Gen3 SoCs make use of up to 8 IPMMU contexts (sets of page table) and
 * these can be managed independently. Each context is mapped to one Xen domain.
 */
#define IPMMU_CTX_MAX     8
/* R-Car Gen3 SoCs make use of up to 48 micro-TLBs per IPMMU device. */
#define IPMMU_UTLB_MAX    48

/* IPMMU context supports IPA size up to 40 bit. */
#define IPMMU_MAX_P2M_IPA_BITS    40

/*
 * Xen's domain IPMMU information stored in dom_iommu(d)->arch.priv
 *
 * As each context (set of page table) is mapped to one Xen domain,
 * all associated IPMMU domains use the same context mapped to this Xen domain.
 * This makes all master devices being attached to the same Xen domain share
 * the same context (P2M table).
 */
struct ipmmu_vmsa_xen_domain {
    /*
     * Used to protect everything which belongs to this Xen domain:
     * device assignment, domain init/destroy, flush ops, etc
     */
    spinlock_t lock;
    /* One or more Cache IPMMU domains associated with this Xen domain */
    struct list_head cache_domains;
    /* Root IPMMU domain associated with this Xen domain */
    struct ipmmu_vmsa_domain *root_domain;
};

/* Xen master device's IPMMU information stored in fwspec->iommu_priv */
struct ipmmu_vmsa_xen_device {
    /* Cache IPMMU domain this master device is logically attached to */
    struct ipmmu_vmsa_domain *domain;
    /* Cache IPMMU this master device is physically connected to */
    struct ipmmu_vmsa_device *mmu;
};

/* Root/Cache IPMMU device's information */
struct ipmmu_vmsa_device {
    struct device *dev;
    void __iomem *base;
    struct ipmmu_vmsa_device *root;
    struct list_head list;
    unsigned int num_utlbs;
    unsigned int num_ctx;
    spinlock_t lock;    /* Protects ctx and domains[] */
    DECLARE_BITMAP(ctx, IPMMU_CTX_MAX);
    struct ipmmu_vmsa_domain *domains[IPMMU_CTX_MAX];
};

/*
 * Root/Cache IPMMU domain's information
 *
 * Root IPMMU device is assigned to Root IPMMU domain while Cache IPMMU device
 * is assigned to Cache IPMMU domain. Master devices are connected to Cache
 * IPMMU devices through specific ports called micro-TLBs.
 * All Cache IPMMU devices, in turn, are connected to Root IPMMU device
 * which manages IPMMU context.
 */
struct ipmmu_vmsa_domain {
    /*
     * IPMMU device assigned to this IPMMU domain.
     * Either Root device which is located at the main memory bus domain or
     * Cache device which is located at each hierarchy bus domain.
     */
    struct ipmmu_vmsa_device *mmu;

    /* Context used for this IPMMU domain */
    unsigned int context_id;

    /* Xen domain associated with this IPMMU domain */
    struct domain *d;

    /* The fields below are used for Cache IPMMU domain only */

    /*
     * Used to keep track of the master devices which are attached to this
     * IPMMU domain (domain users). Master devices behind the same IPMMU device
     * are grouped together by putting into the same IPMMU domain.
     * Only when the refcount reaches 0 this IPMMU domain can be destroyed.
     */
    unsigned int refcount;
    /* Used to link this IPMMU domain for the same Xen domain */
    struct list_head list;
};

/* Used to keep track of registered IPMMU devices */
static LIST_HEAD(ipmmu_devices);
static DEFINE_SPINLOCK(ipmmu_devices_lock);

#define TLB_LOOP_TIMEOUT    100 /* 100us */

/* Registers Definition */
#define IM_CTX_SIZE    0x40

#define IMCTR                0x0000
/*
 * These fields are implemented in IPMMU-MM only. So, can be set for
 * Root IPMMU only.
 */
#define IMCTR_VA64           (1 << 29)
#define IMCTR_TRE            (1 << 17)
#define IMCTR_AFE            (1 << 16)
#define IMCTR_RTSEL_MASK     (3 << 4)
#define IMCTR_RTSEL_SHIFT    4
#define IMCTR_TREN           (1 << 3)
/*
 * These fields are common for all IPMMU devices. So, can be set for
 * Cache IPMMUs as well.
 */
#define IMCTR_INTEN          (1 << 2)
#define IMCTR_FLUSH          (1 << 1)
#define IMCTR_MMUEN          (1 << 0)
#define IMCTR_COMMON_MASK    (7 << 0)

#define IMCAAR               0x0004

#define IMTTBCR                        0x0008
#define IMTTBCR_EAE                    (1 << 31)
#define IMTTBCR_PMB                    (1 << 30)
#define IMTTBCR_SH1_NON_SHAREABLE      (0 << 28)
#define IMTTBCR_SH1_OUTER_SHAREABLE    (2 << 28)
#define IMTTBCR_SH1_INNER_SHAREABLE    (3 << 28)
#define IMTTBCR_SH1_MASK               (3 << 28)
#define IMTTBCR_ORGN1_NC               (0 << 26)
#define IMTTBCR_ORGN1_WB_WA            (1 << 26)
#define IMTTBCR_ORGN1_WT               (2 << 26)
#define IMTTBCR_ORGN1_WB               (3 << 26)
#define IMTTBCR_ORGN1_MASK             (3 << 26)
#define IMTTBCR_IRGN1_NC               (0 << 24)
#define IMTTBCR_IRGN1_WB_WA            (1 << 24)
#define IMTTBCR_IRGN1_WT               (2 << 24)
#define IMTTBCR_IRGN1_WB               (3 << 24)
#define IMTTBCR_IRGN1_MASK             (3 << 24)
#define IMTTBCR_TSZ1_MASK              (0x1f << 16)
#define IMTTBCR_TSZ1_SHIFT             16
#define IMTTBCR_SH0_NON_SHAREABLE      (0 << 12)
#define IMTTBCR_SH0_OUTER_SHAREABLE    (2 << 12)
#define IMTTBCR_SH0_INNER_SHAREABLE    (3 << 12)
#define IMTTBCR_SH0_MASK               (3 << 12)
#define IMTTBCR_ORGN0_NC               (0 << 10)
#define IMTTBCR_ORGN0_WB_WA            (1 << 10)
#define IMTTBCR_ORGN0_WT               (2 << 10)
#define IMTTBCR_ORGN0_WB               (3 << 10)
#define IMTTBCR_ORGN0_MASK             (3 << 10)
#define IMTTBCR_IRGN0_NC               (0 << 8)
#define IMTTBCR_IRGN0_WB_WA            (1 << 8)
#define IMTTBCR_IRGN0_WT               (2 << 8)
#define IMTTBCR_IRGN0_WB               (3 << 8)
#define IMTTBCR_IRGN0_MASK             (3 << 8)
#define IMTTBCR_SL0_LVL_2              (0 << 6)
#define IMTTBCR_SL0_LVL_1              (1 << 6)
#define IMTTBCR_TSZ0_MASK              (0x1f << 0)
#define IMTTBCR_TSZ0_SHIFT             0

#define IMTTLBR0              0x0010
#define IMTTLBR0_TTBR_MASK    (0xfffff << 12)
#define IMTTUBR0              0x0014
#define IMTTUBR0_TTBR_MASK    (0xff << 0)
#define IMTTLBR1              0x0018
#define IMTTLBR1_TTBR_MASK    (0xfffff << 12)
#define IMTTUBR1              0x001c
#define IMTTUBR1_TTBR_MASK    (0xff << 0)

#define IMSTR                          0x0020
#define IMSTR_ERRLVL_MASK              (3 << 12)
#define IMSTR_ERRLVL_SHIFT             12
#define IMSTR_ERRCODE_TLB_FORMAT       (1 << 8)
#define IMSTR_ERRCODE_ACCESS_PERM      (4 << 8)
#define IMSTR_ERRCODE_SECURE_ACCESS    (5 << 8)
#define IMSTR_ERRCODE_MASK             (7 << 8)
#define IMSTR_MHIT                     (1 << 4)
#define IMSTR_ABORT                    (1 << 2)
#define IMSTR_PF                       (1 << 1)
#define IMSTR_TF                       (1 << 0)

#define IMELAR    0x0030
#define IMEUAR    0x0034

#define IMUCTR(n)              ((n) < 32 ? IMUCTR0(n) : IMUCTR32(n))
#define IMUCTR0(n)             (0x0300 + ((n) * 16))
#define IMUCTR32(n)            (0x0600 + (((n) - 32) * 16))
#define IMUCTR_FIXADDEN        (1 << 31)
#define IMUCTR_FIXADD_MASK     (0xff << 16)
#define IMUCTR_FIXADD_SHIFT    16
#define IMUCTR_TTSEL_MMU(n)    ((n) << 4)
#define IMUCTR_TTSEL_PMB       (8 << 4)
#define IMUCTR_TTSEL_MASK      (15 << 4)
#define IMUCTR_TTSEL_SHIFT     4
#define IMUCTR_FLUSH           (1 << 1)
#define IMUCTR_MMUEN           (1 << 0)

#define IMUASID(n)             ((n) < 32 ? IMUASID0(n) : IMUASID32(n))
#define IMUASID0(n)            (0x0308 + ((n) * 16))
#define IMUASID32(n)           (0x0608 + (((n) - 32) * 16))
#define IMUASID_ASID8_MASK     (0xff << 8)
#define IMUASID_ASID8_SHIFT    8
#define IMUASID_ASID0_MASK     (0xff << 0)
#define IMUASID_ASID0_SHIFT    0

#define IMSAUXCTLR          0x0504
#define IMSAUXCTLR_S2PTE    (1 << 3)

static struct ipmmu_vmsa_device *to_ipmmu(struct device *dev)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);

    return fwspec && fwspec->iommu_priv ?
        ((struct ipmmu_vmsa_xen_device *)fwspec->iommu_priv)->mmu : NULL;
}

static void set_ipmmu(struct device *dev, struct ipmmu_vmsa_device *mmu)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);

    ((struct ipmmu_vmsa_xen_device *)fwspec->iommu_priv)->mmu = mmu;
}

static struct ipmmu_vmsa_domain *to_domain(struct device *dev)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);

    return fwspec && fwspec->iommu_priv ?
        ((struct ipmmu_vmsa_xen_device *)fwspec->iommu_priv)->domain : NULL;
}

static void set_domain(struct device *dev, struct ipmmu_vmsa_domain *domain)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);

    ((struct ipmmu_vmsa_xen_device *)fwspec->iommu_priv)->domain = domain;
}

static struct ipmmu_vmsa_device *ipmmu_find_mmu_by_dev(struct device *dev)
{
    struct ipmmu_vmsa_device *mmu = NULL;
    bool found = false;

    spin_lock(&ipmmu_devices_lock);

    list_for_each_entry ( mmu, &ipmmu_devices, list )
    {
        if ( mmu->dev == dev )
        {
            found = true;
            break;
        }
    }

    spin_unlock(&ipmmu_devices_lock);

    return found ? mmu : NULL;
}

/* Root device handling */
static bool ipmmu_is_root(struct ipmmu_vmsa_device *mmu)
{
    return mmu->root == mmu;
}

static struct ipmmu_vmsa_device *ipmmu_find_root(void)
{
    struct ipmmu_vmsa_device *mmu = NULL;
    bool found = false;

    spin_lock(&ipmmu_devices_lock);

    list_for_each_entry( mmu, &ipmmu_devices, list )
    {
        if ( ipmmu_is_root(mmu) )
        {
            found = true;
            break;
        }
    }

    spin_unlock(&ipmmu_devices_lock);

    return found ? mmu : NULL;
}

/* Read/Write Access */
static uint32_t ipmmu_read(struct ipmmu_vmsa_device *mmu, uint32_t offset)
{
    return readl(mmu->base + offset);
}

static void ipmmu_write(struct ipmmu_vmsa_device *mmu, uint32_t offset,
                        uint32_t data)
{
    writel(data, mmu->base + offset);
}

static uint32_t ipmmu_ctx_read_root(struct ipmmu_vmsa_domain *domain,
                                    uint32_t reg)
{
    return ipmmu_read(domain->mmu->root,
                      domain->context_id * IM_CTX_SIZE + reg);
}

static void ipmmu_ctx_write_root(struct ipmmu_vmsa_domain *domain,
                                 uint32_t reg, uint32_t data)
{
    ipmmu_write(domain->mmu->root,
                domain->context_id * IM_CTX_SIZE + reg, data);
}

static void ipmmu_ctx_write_cache(struct ipmmu_vmsa_domain *domain,
                                  uint32_t reg, uint32_t data)
{
    /* We expect only IMCTR value to be passed as a reg. */
    ASSERT(reg == IMCTR);

    /* Mask fields which are implemented in IPMMU-MM only. */
    if ( !ipmmu_is_root(domain->mmu) )
        ipmmu_write(domain->mmu, domain->context_id * IM_CTX_SIZE + reg,
                    data & IMCTR_COMMON_MASK);
}

/*
 * Write the context to both Root IPMMU and all Cache IPMMUs assigned
 * to this Xen domain.
 */
static void ipmmu_ctx_write_all(struct ipmmu_vmsa_domain *domain,
                                uint32_t reg, uint32_t data)
{
    struct ipmmu_vmsa_xen_domain *xen_domain = dom_iommu(domain->d)->arch.priv;
    struct ipmmu_vmsa_domain *cache_domain;

    list_for_each_entry( cache_domain, &xen_domain->cache_domains, list )
        ipmmu_ctx_write_cache(cache_domain, reg, data);

    ipmmu_ctx_write_root(domain, reg, data);
}

/* TLB and micro-TLB Management */

/* Wait for any pending TLB invalidations to complete. */
static void ipmmu_tlb_sync(struct ipmmu_vmsa_domain *domain)
{
    unsigned int count = 0;

    while ( ipmmu_ctx_read_root(domain, IMCTR) & IMCTR_FLUSH )
    {
        cpu_relax();
        if ( ++count == TLB_LOOP_TIMEOUT )
        {
            dev_err_ratelimited(domain->mmu->dev, "TLB sync timed out -- MMU may be deadlocked\n");
            return;
        }
        udelay(1);
    }
}

static void ipmmu_tlb_invalidate(struct ipmmu_vmsa_domain *domain)
{
    uint32_t data;

    data = ipmmu_ctx_read_root(domain, IMCTR);
    data |= IMCTR_FLUSH;
    ipmmu_ctx_write_all(domain, IMCTR, data);

    ipmmu_tlb_sync(domain);
}

/* Enable MMU translation for the micro-TLB. */
static int ipmmu_utlb_enable(struct ipmmu_vmsa_domain *domain,
                             unsigned int utlb)
{
    struct ipmmu_vmsa_device *mmu = domain->mmu;
    uint32_t imuctr;

    /*
     * We need to prevent the use cases where devices which use the same
     * micro-TLB are assigned to different Xen domains (micro-TLB cannot be
     * shared between multiple Xen domains, since it points to the context bank
     * to use for the page walk).
     * As each Xen domain uses individual context bank pointed by context_id,
     * we can potentially recognize that use case by comparing current and new
     * context_id for already enabled micro-TLB and prevent different context
     * bank from being set.
     */
    imuctr = ipmmu_read(mmu, IMUCTR(utlb));
    if ( imuctr & IMUCTR_MMUEN )
    {
        unsigned int context_id;

        context_id = (imuctr & IMUCTR_TTSEL_MASK) >> IMUCTR_TTSEL_SHIFT;
        if ( domain->context_id != context_id )
        {
            dev_err(mmu->dev, "Micro-TLB %u already assigned to IPMMU context %u\n",
                    utlb, context_id);
            return -EINVAL;
        }
    }

    /*
     * TODO: Reference-count the micro-TLB as several bus masters can be
     * connected to the same micro-TLB.
     */
    ipmmu_write(mmu, IMUASID(utlb), 0);
    ipmmu_write(mmu, IMUCTR(utlb), imuctr |
                IMUCTR_TTSEL_MMU(domain->context_id) | IMUCTR_MMUEN);

    return 0;
}

/* Disable MMU translation for the micro-TLB. */
static void ipmmu_utlb_disable(struct ipmmu_vmsa_domain *domain,
                               unsigned int utlb)
{
    struct ipmmu_vmsa_device *mmu = domain->mmu;

    ipmmu_write(mmu, IMUCTR(utlb), 0);
}

/* Domain/Context Management */
static int ipmmu_domain_allocate_context(struct ipmmu_vmsa_device *mmu,
                                         struct ipmmu_vmsa_domain *domain)
{
    unsigned long flags;
    int ret;

    spin_lock_irqsave(&mmu->lock, flags);

    ret = find_first_zero_bit(mmu->ctx, mmu->num_ctx);
    if ( ret != mmu->num_ctx )
    {
        mmu->domains[ret] = domain;
        set_bit(ret, mmu->ctx);
    }
    else
        ret = -EBUSY;

    spin_unlock_irqrestore(&mmu->lock, flags);

    return ret;
}

static void ipmmu_domain_free_context(struct ipmmu_vmsa_device *mmu,
                                      unsigned int context_id)
{
    unsigned long flags;

    spin_lock_irqsave(&mmu->lock, flags);

    clear_bit(context_id, mmu->ctx);
    mmu->domains[context_id] = NULL;

    spin_unlock_irqrestore(&mmu->lock, flags);
}

static int ipmmu_domain_init_context(struct ipmmu_vmsa_domain *domain)
{
    uint64_t ttbr;
    uint32_t tsz0;
    int ret;

    /* Find an unused context. */
    ret = ipmmu_domain_allocate_context(domain->mmu->root, domain);
    if ( ret < 0 )
        return ret;

    domain->context_id = ret;

    /*
     * TTBR0
     * Use P2M table for this Xen domain.
     */
    ASSERT(domain->d != NULL);
    ttbr = page_to_maddr(domain->d->arch.p2m.root);

    dev_info(domain->mmu->root->dev, "%pd: Set IPMMU context %u (pgd 0x%"PRIx64")\n",
             domain->d, domain->context_id, ttbr);

    ipmmu_ctx_write_root(domain, IMTTLBR0, ttbr & IMTTLBR0_TTBR_MASK);
    ipmmu_ctx_write_root(domain, IMTTUBR0, (ttbr >> 32) & IMTTUBR0_TTBR_MASK);

    /*
     * TTBCR
     * We use long descriptors and allocate the whole "p2m_ipa_bits" IPA space
     * to TTBR0. Use 4KB page granule. Start page table walks at first level.
     * Always bypass stage 1 translation.
     */
    tsz0 = (64 - p2m_ipa_bits) << IMTTBCR_TSZ0_SHIFT;
    ipmmu_ctx_write_root(domain, IMTTBCR, IMTTBCR_EAE | IMTTBCR_PMB |
                         IMTTBCR_SL0_LVL_1 | tsz0);

    /*
     * IMSTR
     * Clear all interrupt flags.
     */
    ipmmu_ctx_write_root(domain, IMSTR, ipmmu_ctx_read_root(domain, IMSTR));

    /*
     * IMCTR
     * Enable the MMU and interrupt generation. The long-descriptor
     * translation table format doesn't use TEX remapping. Don't enable AF
     * software management as we have no use for it. Use VMSAv8-64 mode.
     * Enable the context for Root IPMMU only. Flush the TLB as required
     * when modifying the context registers.
     */
    ipmmu_ctx_write_root(domain, IMCTR,
                         IMCTR_VA64 | IMCTR_INTEN | IMCTR_FLUSH | IMCTR_MMUEN);

    return 0;
}

static void ipmmu_domain_destroy_context(struct ipmmu_vmsa_domain *domain)
{
    if ( !domain->mmu )
        return;

    /*
     * Disable the context for Root IPMMU only. Flush the TLB as required
     * when modifying the context registers.
     */
    ipmmu_ctx_write_root(domain, IMCTR, IMCTR_FLUSH);
    ipmmu_tlb_sync(domain);

    ipmmu_domain_free_context(domain->mmu->root, domain->context_id);
}

/* Fault Handling */
static void ipmmu_domain_irq(struct ipmmu_vmsa_domain *domain)
{
    const uint32_t err_mask = IMSTR_MHIT | IMSTR_ABORT | IMSTR_PF | IMSTR_TF;
    struct ipmmu_vmsa_device *mmu = domain->mmu;
    uint32_t status;
    uint64_t iova;

    status = ipmmu_ctx_read_root(domain, IMSTR);
    if ( !(status & err_mask) )
        return;

    iova = ipmmu_ctx_read_root(domain, IMELAR) |
        ((uint64_t)ipmmu_ctx_read_root(domain, IMEUAR) << 32);

    /*
     * Clear the error status flags. Unlike traditional interrupt flag
     * registers that must be cleared by writing 1, this status register
     * seems to require 0. The error address register must be read before,
     * otherwise its value will be 0.
     */
    ipmmu_ctx_write_root(domain, IMSTR, 0);

    /* Log fatal errors. */
    if ( status & IMSTR_MHIT )
        dev_err_ratelimited(mmu->dev, "%pd: Multiple TLB hits @0x%"PRIx64"\n",
                            domain->d, iova);
    if ( status & IMSTR_ABORT )
        dev_err_ratelimited(mmu->dev, "%pd: Page Table Walk Abort @0x%"PRIx64"\n",
                            domain->d, iova);

    /* Return if it is neither Permission Fault nor Translation Fault. */
    if ( !(status & (IMSTR_PF | IMSTR_TF)) )
        return;

    dev_err_ratelimited(mmu->dev, "%pd: Unhandled fault: status 0x%08x iova 0x%"PRIx64"\n",
                        domain->d, status, iova);
}

static void ipmmu_irq(int irq, void *dev, struct cpu_user_regs *regs)
{
    struct ipmmu_vmsa_device *mmu = dev;
    unsigned int i;
    unsigned long flags;

    spin_lock_irqsave(&mmu->lock, flags);

    /*
     * When interrupt arrives, we don't know the context it is related to.
     * So, check interrupts for all active contexts to locate a context
     * with status bits set.
    */
    for ( i = 0; i < mmu->num_ctx; i++ )
    {
        if ( !mmu->domains[i] )
            continue;
        ipmmu_domain_irq(mmu->domains[i]);
    }

    spin_unlock_irqrestore(&mmu->lock, flags);
}

/* Master devices management */
static int ipmmu_attach_device(struct ipmmu_vmsa_domain *domain,
                               struct device *dev)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
    struct ipmmu_vmsa_device *mmu = to_ipmmu(dev);
    unsigned int i;

    if ( !mmu )
    {
        dev_err(dev, "Cannot attach to IPMMU\n");
        return -ENXIO;
    }

    if ( !domain->mmu )
    {
        /* The domain hasn't been used yet, initialize it. */
        domain->mmu = mmu;

        /*
         * We have already enabled context for Root IPMMU assigned to this
         * Xen domain in ipmmu_domain_init_context().
         * Enable the context for Cache IPMMU only. Flush the TLB as required
         * when modifying the context registers.
         */
        ipmmu_ctx_write_cache(domain, IMCTR,
                              ipmmu_ctx_read_root(domain, IMCTR) | IMCTR_FLUSH);

        dev_info(dev, "Using IPMMU context %u\n", domain->context_id);
    }
    else if ( domain->mmu != mmu )
    {
        /*
         * Something is wrong, we can't attach two master devices using
         * different IOMMUs to the same IPMMU domain.
         */
        dev_err(dev, "Can't attach IPMMU %s to domain on IPMMU %s\n",
                dev_name(mmu->dev), dev_name(domain->mmu->dev));
        return -EINVAL;
    }
    else
        dev_info(dev, "Reusing IPMMU context %u\n", domain->context_id);

    for ( i = 0; i < fwspec->num_ids; ++i )
    {
        int ret = ipmmu_utlb_enable(domain, fwspec->ids[i]);

        if ( ret )
        {
            while ( i-- )
                ipmmu_utlb_disable(domain, fwspec->ids[i]);

            return ret;
        }
    }

    return 0;
}

static void ipmmu_detach_device(struct ipmmu_vmsa_domain *domain,
                                struct device *dev)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
    unsigned int i;

    for ( i = 0; i < fwspec->num_ids; ++i )
        ipmmu_utlb_disable(domain, fwspec->ids[i]);
}

static int ipmmu_init_platform_device(struct device *dev,
                                      const struct dt_phandle_args *args)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
    struct ipmmu_vmsa_device *mmu;

    mmu = ipmmu_find_mmu_by_dev(dt_to_dev(args->np));
    if ( !mmu )
        return -ENODEV;

    fwspec->iommu_priv = xzalloc(struct ipmmu_vmsa_xen_device);
    if ( !fwspec->iommu_priv )
        return -ENOMEM;

    set_ipmmu(dev, mmu);

    return 0;
}

static void ipmmu_device_reset(struct ipmmu_vmsa_device *mmu)
{
    unsigned int i;

    /* Disable all contexts. */
    for ( i = 0; i < mmu->num_ctx; ++i )
        ipmmu_write(mmu, i * IM_CTX_SIZE + IMCTR, 0);
}

/* R-Car Gen3 SoCs product and cut information. */
#define RCAR_PRODUCT_MASK    0x00007F00
#define RCAR_PRODUCT_H3      0x00004F00
#define RCAR_PRODUCT_M3W     0x00005200
#define RCAR_PRODUCT_M3N     0x00005500
#define RCAR_CUT_MASK        0x000000FF
#define RCAR_CUT_VER30       0x00000020

static __init bool ipmmu_stage2_supported(void)
{
    struct dt_device_node *np;
    uint64_t addr, size;
    void __iomem *base;
    uint32_t product, cut;
    bool stage2_supported = false;

    np = dt_find_compatible_node(NULL, NULL, "renesas,prr");
    if ( !np )
    {
        printk(XENLOG_ERR "ipmmu: Failed to find PRR node\n");
        return false;
    }

    if ( dt_device_get_address(np, 0, &addr, &size) )
    {
        printk(XENLOG_ERR "ipmmu: Failed to get PRR MMIO\n");
        return false;
    }

    base = ioremap_nocache(addr, size);
    if ( !base )
    {
        printk(XENLOG_ERR "ipmmu: Failed to ioremap PRR MMIO\n");
        return false;
    }

    product = readl(base);
    cut = product & RCAR_CUT_MASK;
    product &= RCAR_PRODUCT_MASK;

    switch ( product )
    {
    case RCAR_PRODUCT_H3:
    case RCAR_PRODUCT_M3W:
        if ( cut >= RCAR_CUT_VER30 )
            stage2_supported = true;
        break;

    case RCAR_PRODUCT_M3N:
        stage2_supported = true;
        break;

    default:
        printk(XENLOG_ERR "ipmmu: Unsupported SoC version\n");
        break;
    }

    iounmap(base);

    return stage2_supported;
}

/*
 * This function relies on the fact that Root IPMMU device is being probed
 * the first. If not the case, it denies further Cache IPMMU device probes
 * (returns the -EAGAIN) until the Root IPMMU device has been registered
 * for sure.
 */
static int ipmmu_probe(struct dt_device_node *node)
{
    struct ipmmu_vmsa_device *mmu;
    uint64_t addr, size;
    int irq, ret;

    mmu = xzalloc(struct ipmmu_vmsa_device);
    if ( !mmu )
    {
        dev_err(&node->dev, "Cannot allocate device data\n");
        return -ENOMEM;
    }

    mmu->dev = &node->dev;
    mmu->num_utlbs = IPMMU_UTLB_MAX;
    mmu->num_ctx = IPMMU_CTX_MAX;
    spin_lock_init(&mmu->lock);
    bitmap_zero(mmu->ctx, IPMMU_CTX_MAX);

    /* Map I/O memory and request IRQ. */
    ret = dt_device_get_address(node, 0, &addr, &size);
    if ( ret )
    {
        dev_err(&node->dev, "Failed to get MMIO\n");
        goto out;
    }

    mmu->base = ioremap_nocache(addr, size);
    if ( !mmu->base )
    {
        dev_err(&node->dev, "Failed to ioremap MMIO (addr 0x%"PRIx64" size 0x%"PRIx64")\n",
                addr, size);
        ret = -ENOMEM;
        goto out;
    }

    /*
     * Determine if this IPMMU node is a Root device by checking for
     * the lack of renesas,ipmmu-main property.
     */
    if ( !dt_find_property(node, "renesas,ipmmu-main", NULL) )
        mmu->root = mmu;
    else
        mmu->root = ipmmu_find_root();

    /* Wait until the Root device has been registered for sure. */
    if ( !mmu->root )
    {
        ret = -EAGAIN;
        goto out;
    }

    /* Root devices have mandatory IRQs. */
    if ( ipmmu_is_root(mmu) )
    {
        if ( !ipmmu_stage2_supported() )
        {
            printk(XENLOG_ERR "ipmmu: P2M sharing is not supported in current SoC revision\n");
            ret = -ENODEV;
            goto out;
        }

        /* Set maximum Stage-2 input size supported by the IPMMU. */
        p2m_restrict_ipa_bits(IPMMU_MAX_P2M_IPA_BITS);

        irq = platform_get_irq(node, 0);
        if ( irq < 0 )
        {
            dev_err(&node->dev, "No IRQ found\n");
            ret = irq;
            goto out;
        }

        ret = request_irq(irq, 0, ipmmu_irq, dev_name(&node->dev), mmu);
        if ( ret < 0 )
        {
            dev_err(&node->dev, "Failed to request IRQ %d\n", irq);
            goto out;
        }

        ipmmu_device_reset(mmu);

        /*
         * Use stage 2 translation table format when stage 2 translation
         * enabled.
         */
        ipmmu_write(mmu, IMSAUXCTLR,
                    ipmmu_read(mmu, IMSAUXCTLR) | IMSAUXCTLR_S2PTE);

        dev_info(&node->dev, "IPMMU context 0 is reserved\n");
        set_bit(0, mmu->ctx);
    }

    spin_lock(&ipmmu_devices_lock);
    list_add(&mmu->list, &ipmmu_devices);
    spin_unlock(&ipmmu_devices_lock);

    dev_info(&node->dev, "Registered %s IPMMU\n",
             ipmmu_is_root(mmu) ? "Root" : "Cache");

    return 0;

out:
    if ( mmu->base )
        iounmap(mmu->base);
    xfree(mmu);

    return ret;
}

/* Xen IOMMU ops */
static int __must_check ipmmu_iotlb_flush_all(struct domain *d)
{
    struct ipmmu_vmsa_xen_domain *xen_domain = dom_iommu(d)->arch.priv;

    if ( !xen_domain || !xen_domain->root_domain )
        return 0;

    spin_lock(&xen_domain->lock);
    ipmmu_tlb_invalidate(xen_domain->root_domain);
    spin_unlock(&xen_domain->lock);

    return 0;
}

static int __must_check ipmmu_iotlb_flush(struct domain *d, dfn_t dfn,
                                          unsigned int page_count,
                                          unsigned int flush_flags)
{
    ASSERT(flush_flags);

    /* The hardware doesn't support selective TLB flush. */
    return ipmmu_iotlb_flush_all(d);
}

static struct ipmmu_vmsa_domain *ipmmu_get_cache_domain(struct domain *d,
                                                        struct device *dev)
{
    struct ipmmu_vmsa_xen_domain *xen_domain = dom_iommu(d)->arch.priv;
    struct ipmmu_vmsa_device *mmu = to_ipmmu(dev);
    struct ipmmu_vmsa_domain *domain;

    if ( !mmu )
        return NULL;

    /*
     * Loop through all Cache IPMMU domains associated with this Xen domain
     * to locate an IPMMU domain this IPMMU device is assigned to.
     */
    list_for_each_entry( domain, &xen_domain->cache_domains, list )
    {
        if ( domain->mmu == mmu )
            return domain;
    }

    return NULL;
}

static struct ipmmu_vmsa_domain *ipmmu_alloc_cache_domain(struct domain *d)
{
    struct ipmmu_vmsa_xen_domain *xen_domain = dom_iommu(d)->arch.priv;
    struct ipmmu_vmsa_domain *domain;

    domain = xzalloc(struct ipmmu_vmsa_domain);
    if ( !domain )
        return ERR_PTR(-ENOMEM);

    /*
     * We don't assign the Cache IPMMU device here, it will be assigned when
     * attaching master device to this domain in ipmmu_attach_device().
     * domain->mmu = NULL;
     */

    domain->d = d;
    /* Use the same context mapped to this Xen domain. */
    domain->context_id = xen_domain->root_domain->context_id;

    return domain;
}

static void ipmmu_free_cache_domain(struct ipmmu_vmsa_domain *domain)
{
    list_del(&domain->list);
    /*
     * Disable the context for Cache IPMMU only. Flush the TLB as required
     * when modifying the context registers.
     */
    ipmmu_ctx_write_cache(domain, IMCTR, IMCTR_FLUSH);
    xfree(domain);
}

static struct ipmmu_vmsa_domain *ipmmu_alloc_root_domain(struct domain *d)
{
    struct ipmmu_vmsa_domain *domain;
    struct ipmmu_vmsa_device *root;
    int ret;

    /* If we are here then Root device must has been registered. */
    root = ipmmu_find_root();
    if ( !root )
    {
        printk(XENLOG_ERR "ipmmu: Unable to locate Root IPMMU\n");
        return ERR_PTR(-ENODEV);
    }

    domain = xzalloc(struct ipmmu_vmsa_domain);
    if ( !domain )
        return ERR_PTR(-ENOMEM);

    domain->mmu = root;
    domain->d = d;

    /* Initialize the context to be mapped to this Xen domain. */
    ret = ipmmu_domain_init_context(domain);
    if ( ret < 0 )
    {
        dev_err(root->dev, "%pd: Unable to initialize IPMMU context\n", d);
        xfree(domain);
        return ERR_PTR(ret);
    }

    return domain;
}

static void ipmmu_free_root_domain(struct ipmmu_vmsa_domain *domain)
{
    ipmmu_domain_destroy_context(domain);
    xfree(domain);
}

static int ipmmu_assign_device(struct domain *d, u8 devfn, struct device *dev,
                               uint32_t flag)
{
    struct ipmmu_vmsa_xen_domain *xen_domain = dom_iommu(d)->arch.priv;
    struct ipmmu_vmsa_domain *domain;
    int ret;

    if ( !xen_domain )
        return -EINVAL;

    if ( !to_ipmmu(dev) )
        return -ENODEV;

    spin_lock(&xen_domain->lock);

    /*
     * The IPMMU context for the Xen domain is not allocated beforehand
     * (at the Xen domain creation time), but on demand only, when the first
     * master device being attached to it.
     * Create Root IPMMU domain which context will be mapped to this Xen domain
     * if not exits yet.
     */
    if ( !xen_domain->root_domain )
    {
        domain = ipmmu_alloc_root_domain(d);
        if ( IS_ERR(domain) )
        {
            ret = PTR_ERR(domain);
            goto out;
        }

        xen_domain->root_domain = domain;
    }

    if ( to_domain(dev) )
    {
        dev_err(dev, "Already attached to IPMMU domain\n");
        ret = -EEXIST;
        goto out;
    }

    /*
     * Master devices behind the same Cache IPMMU can be attached to the same
     * Cache IPMMU domain.
     * Before creating new IPMMU domain check to see if the required one
     * already exists for this Xen domain.
     */
    domain = ipmmu_get_cache_domain(d, dev);
    if ( !domain )
    {
        /* Create new IPMMU domain this master device will be attached to. */
        domain = ipmmu_alloc_cache_domain(d);
        if ( IS_ERR(domain) )
        {
            ret = PTR_ERR(domain);
            goto out;
        }

        /* Chain new IPMMU domain to the Xen domain. */
        list_add(&domain->list, &xen_domain->cache_domains);
    }

    ret = ipmmu_attach_device(domain, dev);
    if ( ret )
    {
        /*
         * Destroy Cache IPMMU domain only if there are no master devices
         * attached to it.
         */
        if ( !domain->refcount )
            ipmmu_free_cache_domain(domain);
    }
    else
    {
        domain->refcount++;
        set_domain(dev, domain);
    }

out:
    spin_unlock(&xen_domain->lock);

    return ret;
}

static int ipmmu_deassign_device(struct domain *d, struct device *dev)
{
    struct ipmmu_vmsa_xen_domain *xen_domain = dom_iommu(d)->arch.priv;
    struct ipmmu_vmsa_domain *domain = to_domain(dev);

    if ( !domain || domain->d != d )
    {
        dev_err(dev, "Not attached to %pd\n", d);
        return -ESRCH;
    }

    spin_lock(&xen_domain->lock);

    ipmmu_detach_device(domain, dev);
    set_domain(dev, NULL);
    domain->refcount--;

    /*
     * Destroy Cache IPMMU domain only if there are no master devices
     * attached to it.
     */
    if ( !domain->refcount )
        ipmmu_free_cache_domain(domain);

    spin_unlock(&xen_domain->lock);

    return 0;
}

static int ipmmu_reassign_device(struct domain *s, struct domain *t,
                                 u8 devfn,  struct device *dev)
{
    int ret = 0;

    /* Don't allow remapping on other domain than hwdom */
    if ( t && t != hardware_domain )
        return -EPERM;

    if ( t == s )
        return 0;

    ret = ipmmu_deassign_device(s, dev);
    if ( ret )
        return ret;

    if ( t )
    {
        /* No flags are defined for ARM. */
        ret = ipmmu_assign_device(t, devfn, dev, 0);
        if ( ret )
            return ret;
    }

    return 0;
}

static int ipmmu_dt_xlate(struct device *dev,
                          const struct dt_phandle_args *spec)
{
    int ret;

    /*
     * Perform sanity check of passed DT IOMMU specifier. Each master device
     * gets micro-TLB (device ID) assignment via the "iommus" property
     * in DT. We expect #iommu-cells to be 1 (Multiple-master IOMMU) and
     * this cell for the micro-TLB (device ID).
     */
    if ( spec->args_count != 1 || spec->args[0] >= IPMMU_UTLB_MAX )
        return -EINVAL;

    ret = iommu_fwspec_add_ids(dev, spec->args, 1);
    if ( ret )
        return ret;

    /* Initialize once - xlate() will call multiple times. */
    if ( to_ipmmu(dev) )
        return 0;

    return ipmmu_init_platform_device(dev, spec);
}

static int ipmmu_add_device(u8 devfn, struct device *dev)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);

    /* Only let through devices that have been verified in xlate(). */
    if ( !to_ipmmu(dev) )
        return -ENODEV;

    if ( dt_device_is_protected(dev_to_dt(dev)) )
    {
        dev_err(dev, "Already added to IPMMU\n");
        return -EEXIST;
    }

    /* Let Xen know that the master device is protected by an IOMMU. */
    dt_device_set_protected(dev_to_dt(dev));

    dev_info(dev, "Added master device (IPMMU %s micro-TLBs %u)\n",
             dev_name(fwspec->iommu_dev), fwspec->num_ids);

    return 0;
}

static int ipmmu_iommu_domain_init(struct domain *d)
{
    struct ipmmu_vmsa_xen_domain *xen_domain;

    xen_domain = xzalloc(struct ipmmu_vmsa_xen_domain);
    if ( !xen_domain )
        return -ENOMEM;

    spin_lock_init(&xen_domain->lock);
    INIT_LIST_HEAD(&xen_domain->cache_domains);
    /*
     * We don't create Root IPMMU domain here, it will be created on demand
     * only, when attaching the first master device to this Xen domain in
     * ipmmu_assign_device().
     * xen_domain->root_domain = NULL;
    */

    dom_iommu(d)->arch.priv = xen_domain;

    return 0;
}

static void __hwdom_init ipmmu_iommu_hwdom_init(struct domain *d)
{
    /* Set to false options not supported on ARM. */
    if ( iommu_hwdom_inclusive )
        printk(XENLOG_WARNING "ipmmu: map-inclusive dom0-iommu option is not supported on ARM\n");
    iommu_hwdom_inclusive = false;
    if ( iommu_hwdom_reserved == 1 )
        printk(XENLOG_WARNING "ipmmu: map-reserved dom0-iommu option is not supported on ARM\n");
    iommu_hwdom_reserved = 0;

    arch_iommu_hwdom_init(d);
}

static void ipmmu_iommu_domain_teardown(struct domain *d)
{
    struct ipmmu_vmsa_xen_domain *xen_domain = dom_iommu(d)->arch.priv;

    if ( !xen_domain )
        return;

    /*
     * Destroy Root IPMMU domain which context is mapped to this Xen domain
     * if exits.
     */
    if ( xen_domain->root_domain )
        ipmmu_free_root_domain(xen_domain->root_domain);

    /*
     * We assume that all master devices have already been detached from
     * this Xen domain and there must be no associated Cache IPMMU domains
     * in use.
     */
    ASSERT(list_empty(&xen_domain->cache_domains));
    xfree(xen_domain);
    dom_iommu(d)->arch.priv = NULL;
}

static const struct iommu_ops ipmmu_iommu_ops =
{
    .init            = ipmmu_iommu_domain_init,
    .hwdom_init      = ipmmu_iommu_hwdom_init,
    .teardown        = ipmmu_iommu_domain_teardown,
    .iotlb_flush     = ipmmu_iotlb_flush,
    .iotlb_flush_all = ipmmu_iotlb_flush_all,
    .assign_device   = ipmmu_assign_device,
    .reassign_device = ipmmu_reassign_device,
    .map_page        = arm_iommu_map_page,
    .unmap_page      = arm_iommu_unmap_page,
    .dt_xlate        = ipmmu_dt_xlate,
    .add_device      = ipmmu_add_device,
};

static const struct dt_device_match ipmmu_dt_match[] __initconst =
{
    DT_MATCH_COMPATIBLE("renesas,ipmmu-r8a7795"),
    DT_MATCH_COMPATIBLE("renesas,ipmmu-r8a77965"),
    DT_MATCH_COMPATIBLE("renesas,ipmmu-r8a7796"),
    { /* sentinel */ },
};

static __init int ipmmu_init(struct dt_device_node *node, const void *data)
{
    int ret;

    /*
     * Even if the device can't be initialized, we don't want to give
     * the IPMMU device to dom0.
     */
    dt_device_set_used_by(node, DOMID_XEN);

    ret = ipmmu_probe(node);
    if ( ret )
    {
        dev_err(&node->dev, "Failed to init IPMMU (%d)\n", ret);
        return ret;
    }

    iommu_set_ops(&ipmmu_iommu_ops);

    return 0;
}

DT_DEVICE_START(ipmmu, "Renesas IPMMU-VMSA", DEVICE_IOMMU)
    .dt_match = ipmmu_dt_match,
    .init = ipmmu_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
