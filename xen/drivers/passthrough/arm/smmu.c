/*
 * IOMMU API for ARM architected SMMU implementations.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Based on Linux drivers/iommu/arm-smmu.c (commit 89a23cd)
 * Copyright (C) 2013 ARM Limited
 *
 * Author: Will Deacon <will.deacon@arm.com>
 *
 * Xen modification:
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (C) 2014 Linaro Limited.
 *
 * This driver currently supports:
 *  - SMMUv1 and v2 implementations (didn't try v2 SMMU)
 *  - Stream-matching and stream-indexing
 *  - v7/v8 long-descriptor format
 *  - Non-secure access to the SMMU
 *  - 4k pages, p2m shared with the processor
 *  - Up to 40-bit addressing
 *  - Context fault reporting
 */

#include <xen/config.h>
#include <xen/delay.h>
#include <xen/errno.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/list.h>
#include <xen/mm.h>
#include <xen/vmap.h>
#include <xen/rbtree.h>
#include <xen/sched.h>
#include <asm/atomic.h>
#include <asm/device.h>
#include <asm/io.h>
#include <asm/platform.h>

/* Driver options */
#define SMMU_OPT_SECURE_CONFIG_ACCESS   (1 << 0)

/* Maximum number of stream IDs assigned to a single device */
#define MAX_MASTER_STREAMIDS    MAX_PHANDLE_ARGS

/* Maximum stream ID */
#define SMMU_MAX_STREAMIDS      (PAGE_SIZE_64K - 1)

/* Maximum number of context banks per SMMU */
#define SMMU_MAX_CBS        128

/* Maximum number of mapping groups per SMMU */
#define SMMU_MAX_SMRS       128

/* SMMU global address space */
#define SMMU_GR0(smmu)      ((smmu)->base)
#define SMMU_GR1(smmu)      ((smmu)->base + (smmu)->pagesize)

/*
 * SMMU global address space with conditional offset to access secure aliases of
 * non-secure registers (e.g. nsCR0: 0x400, nsGFSR: 0x448, nsGFSYNR0: 0x450)
 */
#define SMMU_GR0_NS(smmu)                                   \
    ((smmu)->base +                                         \
     ((smmu->options & SMMU_OPT_SECURE_CONFIG_ACCESS)    \
        ? 0x400 : 0))

/* Page table bits */
#define SMMU_PTE_PAGE           (((pteval_t)3) << 0)
#define SMMU_PTE_CONT           (((pteval_t)1) << 52)
#define SMMU_PTE_AF             (((pteval_t)1) << 10)
#define SMMU_PTE_SH_NS          (((pteval_t)0) << 8)
#define SMMU_PTE_SH_OS          (((pteval_t)2) << 8)
#define SMMU_PTE_SH_IS          (((pteval_t)3) << 8)

#if PAGE_SIZE == PAGE_SIZE_4K
#define SMMU_PTE_CONT_ENTRIES   16
#elif PAGE_SIZE == PAGE_SIZE_64K
#define SMMU_PTE_CONT_ENTRIES   32
#else
#define SMMU_PTE_CONT_ENTRIES   1
#endif

#define SMMU_PTE_CONT_SIZE      (PAGE_SIZE * SMMU_PTE_CONT_ENTRIES)
#define SMMU_PTE_CONT_MASK      (~(SMMU_PTE_CONT_SIZE - 1))
#define SMMU_PTE_HWTABLE_SIZE   (PTRS_PER_PTE * sizeof(pte_t))

/* Stage-1 PTE */
#define SMMU_PTE_AP_UNPRIV      (((pteval_t)1) << 6)
#define SMMU_PTE_AP_RDONLY      (((pteval_t)2) << 6)
#define SMMU_PTE_ATTRINDX_SHIFT 2
#define SMMU_PTE_nG             (((pteval_t)1) << 11)

/* Stage-2 PTE */
#define SMMU_PTE_HAP_FAULT      (((pteval_t)0) << 6)
#define SMMU_PTE_HAP_READ       (((pteval_t)1) << 6)
#define SMMU_PTE_HAP_WRITE      (((pteval_t)2) << 6)
#define SMMU_PTE_MEMATTR_OIWB   (((pteval_t)0xf) << 2)
#define SMMU_PTE_MEMATTR_NC     (((pteval_t)0x5) << 2)
#define SMMU_PTE_MEMATTR_DEV    (((pteval_t)0x1) << 2)

/* Configuration registers */
#define SMMU_GR0_sCR0           0x0
#define SMMU_sCR0_CLIENTPD      (1 << 0)
#define SMMU_sCR0_GFRE          (1 << 1)
#define SMMU_sCR0_GFIE          (1 << 2)
#define SMMU_sCR0_GCFGFRE       (1 << 4)
#define SMMU_sCR0_GCFGFIE       (1 << 5)
#define SMMU_sCR0_USFCFG        (1 << 10)
#define SMMU_sCR0_VMIDPNE       (1 << 11)
#define SMMU_sCR0_PTM           (1 << 12)
#define SMMU_sCR0_FB            (1 << 13)
#define SMMU_sCR0_BSU_SHIFT     14
#define SMMU_sCR0_BSU_MASK      0x3

/* Identification registers */
#define SMMU_GR0_ID0            0x20
#define SMMU_GR0_ID1            0x24
#define SMMU_GR0_ID2            0x28
#define SMMU_GR0_ID3            0x2c
#define SMMU_GR0_ID4            0x30
#define SMMU_GR0_ID5            0x34
#define SMMU_GR0_ID6            0x38
#define SMMU_GR0_ID7            0x3c
#define SMMU_GR0_sGFSR          0x48
#define SMMU_GR0_sGFSYNR0       0x50
#define SMMU_GR0_sGFSYNR1       0x54
#define SMMU_GR0_sGFSYNR2       0x58
#define SMMU_GR0_PIDR0          0xfe0
#define SMMU_GR0_PIDR1          0xfe4
#define SMMU_GR0_PIDR2          0xfe8

#define SMMU_ID0_S1TS           (1 << 30)
#define SMMU_ID0_S2TS           (1 << 29)
#define SMMU_ID0_NTS            (1 << 28)
#define SMMU_ID0_SMS            (1 << 27)
#define SMMU_ID0_PTFS_SHIFT     24
#define SMMU_ID0_PTFS_MASK      0x2
#define SMMU_ID0_PTFS_V8_ONLY   0x2
#define SMMU_ID0_CTTW           (1 << 14)
#define SMMU_ID0_NUMIRPT_SHIFT  16
#define SMMU_ID0_NUMIRPT_MASK   0xff
#define SMMU_ID0_NUMSMRG_SHIFT  0
#define SMMU_ID0_NUMSMRG_MASK   0xff

#define SMMU_ID1_PAGESIZE            (1 << 31)
#define SMMU_ID1_NUMPAGENDXB_SHIFT   28
#define SMMU_ID1_NUMPAGENDXB_MASK    7
#define SMMU_ID1_NUMS2CB_SHIFT       16
#define SMMU_ID1_NUMS2CB_MASK        0xff
#define SMMU_ID1_NUMCB_SHIFT         0
#define SMMU_ID1_NUMCB_MASK          0xff

#define SMMU_ID2_OAS_SHIFT           4
#define SMMU_ID2_OAS_MASK            0xf
#define SMMU_ID2_IAS_SHIFT           0
#define SMMU_ID2_IAS_MASK            0xf
#define SMMU_ID2_UBS_SHIFT           8
#define SMMU_ID2_UBS_MASK            0xf
#define SMMU_ID2_PTFS_4K             (1 << 12)
#define SMMU_ID2_PTFS_16K            (1 << 13)
#define SMMU_ID2_PTFS_64K            (1 << 14)

#define SMMU_PIDR2_ARCH_SHIFT        4
#define SMMU_PIDR2_ARCH_MASK         0xf

/* Global TLB invalidation */
#define SMMU_GR0_STLBIALL           0x60
#define SMMU_GR0_TLBIVMID           0x64
#define SMMU_GR0_TLBIALLNSNH        0x68
#define SMMU_GR0_TLBIALLH           0x6c
#define SMMU_GR0_sTLBGSYNC          0x70
#define SMMU_GR0_sTLBGSTATUS        0x74
#define SMMU_sTLBGSTATUS_GSACTIVE   (1 << 0)
#define SMMU_TLB_LOOP_TIMEOUT       1000000 /* 1s! */

/* Stream mapping registers */
#define SMMU_GR0_SMR(n)             (0x800 + ((n) << 2))
#define SMMU_SMR_VALID              (1 << 31)
#define SMMU_SMR_MASK_SHIFT         16
#define SMMU_SMR_MASK_MASK          0x7fff
#define SMMU_SMR_ID_SHIFT           0
#define SMMU_SMR_ID_MASK            0x7fff

#define SMMU_GR0_S2CR(n)        (0xc00 + ((n) << 2))
#define SMMU_S2CR_CBNDX_SHIFT   0
#define SMMU_S2CR_CBNDX_MASK    0xff
#define SMMU_S2CR_TYPE_SHIFT    16
#define SMMU_S2CR_TYPE_MASK     0x3
#define SMMU_S2CR_TYPE_TRANS    (0 << SMMU_S2CR_TYPE_SHIFT)
#define SMMU_S2CR_TYPE_BYPASS   (1 << SMMU_S2CR_TYPE_SHIFT)
#define SMMU_S2CR_TYPE_FAULT    (2 << SMMU_S2CR_TYPE_SHIFT)

/* Context bank attribute registers */
#define SMMU_GR1_CBAR(n)                    (0x0 + ((n) << 2))
#define SMMU_CBAR_VMID_SHIFT                0
#define SMMU_CBAR_VMID_MASK                 0xff
#define SMMU_CBAR_S1_MEMATTR_SHIFT          12
#define SMMU_CBAR_S1_MEMATTR_MASK           0xf
#define SMMU_CBAR_S1_MEMATTR_WB             0xf
#define SMMU_CBAR_TYPE_SHIFT                16
#define SMMU_CBAR_TYPE_MASK                 0x3
#define SMMU_CBAR_TYPE_S2_TRANS             (0 << SMMU_CBAR_TYPE_SHIFT)
#define SMMU_CBAR_TYPE_S1_TRANS_S2_BYPASS   (1 << SMMU_CBAR_TYPE_SHIFT)
#define SMMU_CBAR_TYPE_S1_TRANS_S2_FAULT    (2 << SMMU_CBAR_TYPE_SHIFT)
#define SMMU_CBAR_TYPE_S1_TRANS_S2_TRANS    (3 << SMMU_CBAR_TYPE_SHIFT)
#define SMMU_CBAR_IRPTNDX_SHIFT             24
#define SMMU_CBAR_IRPTNDX_MASK              0xff

#define SMMU_GR1_CBA2R(n)                   (0x800 + ((n) << 2))
#define SMMU_CBA2R_RW64_32BIT               (0 << 0)
#define SMMU_CBA2R_RW64_64BIT               (1 << 0)

/* Translation context bank */
#define SMMU_CB_BASE(smmu)                  ((smmu)->base + ((smmu)->size >> 1))
#define SMMU_CB(smmu, n)                    ((n) * (smmu)->pagesize)

#define SMMU_CB_SCTLR                       0x0
#define SMMU_CB_RESUME                      0x8
#define SMMU_CB_TCR2                        0x10
#define SMMU_CB_TTBR0_LO                    0x20
#define SMMU_CB_TTBR0_HI                    0x24
#define SMMU_CB_TCR                         0x30
#define SMMU_CB_S1_MAIR0                    0x38
#define SMMU_CB_FSR                         0x58
#define SMMU_CB_FAR_LO                      0x60
#define SMMU_CB_FAR_HI                      0x64
#define SMMU_CB_FSYNR0                      0x68
#define SMMU_CB_S1_TLBIASID                 0x610

#define SMMU_SCTLR_S1_ASIDPNE               (1 << 12)
#define SMMU_SCTLR_CFCFG                    (1 << 7)
#define SMMU_SCTLR_CFIE                     (1 << 6)
#define SMMU_SCTLR_CFRE                     (1 << 5)
#define SMMU_SCTLR_E                        (1 << 4)
#define SMMU_SCTLR_AFE                      (1 << 2)
#define SMMU_SCTLR_TRE                      (1 << 1)
#define SMMU_SCTLR_M                        (1 << 0)
#define SMMU_SCTLR_EAE_SBOP                 (SMMU_SCTLR_AFE | SMMU_SCTLR_TRE)

#define SMMU_RESUME_RETRY                   (0 << 0)
#define SMMU_RESUME_TERMINATE               (1 << 0)

#define SMMU_TCR_EAE                        (1 << 31)

#define SMMU_TCR_PASIZE_SHIFT               16
#define SMMU_TCR_PASIZE_MASK                0x7

#define SMMU_TCR_TG0_4K                     (0 << 14)
#define SMMU_TCR_TG0_64K                    (1 << 14)

#define SMMU_TCR_SH0_SHIFT                  12
#define SMMU_TCR_SH0_MASK                   0x3
#define SMMU_TCR_SH_NS                      0
#define SMMU_TCR_SH_OS                      2
#define SMMU_TCR_SH_IS                      3

#define SMMU_TCR_ORGN0_SHIFT                10
#define SMMU_TCR_IRGN0_SHIFT                8
#define SMMU_TCR_RGN_MASK                   0x3
#define SMMU_TCR_RGN_NC                     0
#define SMMU_TCR_RGN_WBWA                   1
#define SMMU_TCR_RGN_WT                     2
#define SMMU_TCR_RGN_WB                     3

#define SMMU_TCR_SL0_SHIFT                  6
#define SMMU_TCR_SL0_MASK                   0x3
#define SMMU_TCR_SL0_LVL_2                  0
#define SMMU_TCR_SL0_LVL_1                  1

#define SMMU_TCR_T1SZ_SHIFT                 16
#define SMMU_TCR_T0SZ_SHIFT                 0
#define SMMU_TCR_SZ_MASK                    0xf

#define SMMU_TCR2_SEP_SHIFT                 15
#define SMMU_TCR2_SEP_MASK                  0x7

#define SMMU_TCR2_PASIZE_SHIFT              0
#define SMMU_TCR2_PASIZE_MASK               0x7

/* Common definitions for PASize and SEP fields */
#define SMMU_TCR2_ADDR_32                   0
#define SMMU_TCR2_ADDR_36                   1
#define SMMU_TCR2_ADDR_40                   2
#define SMMU_TCR2_ADDR_42                   3
#define SMMU_TCR2_ADDR_44                   4
#define SMMU_TCR2_ADDR_48                   5

#define SMMU_TTBRn_HI_ASID_SHIFT            16

#define SMMU_MAIR_ATTR_SHIFT(n)             ((n) << 3)
#define SMMU_MAIR_ATTR_MASK                 0xff
#define SMMU_MAIR_ATTR_DEVICE               0x04
#define SMMU_MAIR_ATTR_NC                   0x44
#define SMMU_MAIR_ATTR_WBRWA                0xff
#define SMMU_MAIR_ATTR_IDX_NC               0
#define SMMU_MAIR_ATTR_IDX_CACHE            1
#define SMMU_MAIR_ATTR_IDX_DEV              2

#define SMMU_FSR_MULTI                      (1 << 31)
#define SMMU_FSR_SS                         (1 << 30)
#define SMMU_FSR_UUT                        (1 << 8)
#define SMMU_FSR_ASF                        (1 << 7)
#define SMMU_FSR_TLBLKF                     (1 << 6)
#define SMMU_FSR_TLBMCF                     (1 << 5)
#define SMMU_FSR_EF                         (1 << 4)
#define SMMU_FSR_PF                         (1 << 3)
#define SMMU_FSR_AFF                        (1 << 2)
#define SMMU_FSR_TF                         (1 << 1)

#define SMMU_FSR_IGN                        (SMMU_FSR_AFF | SMMU_FSR_ASF |    \
                                             SMMU_FSR_TLBMCF | SMMU_FSR_TLBLKF)
#define SMMU_FSR_FAULT                      (SMMU_FSR_MULTI | SMMU_FSR_SS |   \
                                             SMMU_FSR_UUT | SMMU_FSR_EF |     \
                                             SMMU_FSR_PF | SMMU_FSR_TF |      \
                                             SMMU_FSR_IGN)

#define SMMU_FSYNR0_WNR                     (1 << 4)

#define smmu_print(dev, lvl, fmt, ...)                                        \
    printk(lvl "smmu: %s: " fmt, dt_node_full_name(dev->node), ## __VA_ARGS__)

#define smmu_err(dev, fmt, ...) smmu_print(dev, XENLOG_ERR, fmt, ## __VA_ARGS__)

#define smmu_dbg(dev, fmt, ...)                                             \
    smmu_print(dev, XENLOG_DEBUG, fmt, ## __VA_ARGS__)

#define smmu_info(dev, fmt, ...)                                            \
    smmu_print(dev, XENLOG_INFO, fmt, ## __VA_ARGS__)

#define smmu_warn(dev, fmt, ...)                                            \
    smmu_print(dev, XENLOG_WARNING, fmt, ## __VA_ARGS__)

struct arm_smmu_device {
    const struct dt_device_node *node;

    void __iomem                *base;
    unsigned long               size;
    unsigned long               pagesize;

#define SMMU_FEAT_COHERENT_WALK (1 << 0)
#define SMMU_FEAT_STREAM_MATCH  (1 << 1)
#define SMMU_FEAT_TRANS_S1      (1 << 2)
#define SMMU_FEAT_TRANS_S2      (1 << 3)
#define SMMU_FEAT_TRANS_NESTED  (1 << 4)
    u32                         features;
    u32                         options;
    int                         version;

    u32                         num_context_banks;
    u32                         num_s2_context_banks;
    DECLARE_BITMAP(context_map, SMMU_MAX_CBS);
    atomic_t                    irptndx;

    u32                         num_mapping_groups;
    DECLARE_BITMAP(smr_map, SMMU_MAX_SMRS);

    unsigned long               input_size;
    unsigned long               s1_output_size;
    unsigned long               s2_output_size;

    u32                         num_global_irqs;
    u32                         num_context_irqs;
    unsigned int                *irqs;

    u32                         smr_mask_mask;
    u32                         smr_id_mask;

    unsigned long               *sids;

    struct list_head            list;
    struct rb_root              masters;
};

struct arm_smmu_smr {
    u8                          idx;
    u16                         mask;
    u16                         id;
};

#define INVALID_IRPTNDX         0xff

#define SMMU_CB_ASID(cfg)       ((cfg)->cbndx)
#define SMMU_CB_VMID(cfg)       ((cfg)->cbndx + 1)

struct arm_smmu_domain_cfg {
    struct arm_smmu_device  *smmu;
    u8                      cbndx;
    u8                      irptndx;
    u32                     cbar;
    /* Domain associated to this device */
    struct domain           *domain;
    /* List of master which use this structure */
    struct list_head        masters;

    /* Used to link domain context for a same domain */
    struct list_head        list;
};

struct arm_smmu_master {
    const struct dt_device_node *dt_node;

    /*
     * The following is specific to the master's position in the
     * SMMU chain.
     */
    struct rb_node              node;
    u32                         num_streamids;
    u16                         streamids[MAX_MASTER_STREAMIDS];
    int                         num_s2crs;

    struct arm_smmu_smr         *smrs;
    struct arm_smmu_domain_cfg  *cfg;

    /* Used to link masters in a same domain context */
    struct list_head            list;
};

static LIST_HEAD(arm_smmu_devices);

struct arm_smmu_domain {
    spinlock_t lock;
    struct list_head contexts;
};

struct arm_smmu_option_prop {
    u32         opt;
    const char  *prop;
};

static const struct arm_smmu_option_prop arm_smmu_options [] __initconst =
{
    { SMMU_OPT_SECURE_CONFIG_ACCESS, "calxeda,smmu-secure-config-access" },
    { 0, NULL},
};

static void __init check_driver_options(struct arm_smmu_device *smmu)
{
    int i = 0;

    do {
        if ( dt_property_read_bool(smmu->node, arm_smmu_options[i].prop) )
        {
            smmu->options |= arm_smmu_options[i].opt;
            smmu_dbg(smmu, "option %s\n", arm_smmu_options[i].prop);
        }
    } while ( arm_smmu_options[++i].opt );
}

static void arm_smmu_context_fault(int irq, void *data,
                                   struct cpu_user_regs *regs)
{
    u32 fsr, far, fsynr;
    uint64_t iova;
    struct arm_smmu_domain_cfg *cfg = data;
    struct arm_smmu_device *smmu = cfg->smmu;
    void __iomem *cb_base;

    cb_base = SMMU_CB_BASE(smmu) + SMMU_CB(smmu, cfg->cbndx);
    fsr = readl_relaxed(cb_base + SMMU_CB_FSR);

    if ( !(fsr & SMMU_FSR_FAULT) )
        return;

    if ( fsr & SMMU_FSR_IGN )
        smmu_err(smmu, "Unexpected context fault (fsr 0x%u)\n", fsr);

    fsynr = readl_relaxed(cb_base + SMMU_CB_FSYNR0);
    far = readl_relaxed(cb_base + SMMU_CB_FAR_LO);
    iova = far;
    far = readl_relaxed(cb_base + SMMU_CB_FAR_HI);
    iova |= ((uint64_t)far << 32);

    smmu_err(smmu, "Unhandled context fault for domain %u\n",
             cfg->domain->domain_id);
    smmu_err(smmu, "\tFSR 0x%x, IOVA 0x%"PRIx64", FSYNR 0x%x,  CB %d\n",
             fsr, iova, fsynr, cfg->cbndx);

    /* Clear the faulting FSR */
    writel(fsr, cb_base + SMMU_CB_FSR);

    /* Terminate any stalled transactions */
    if ( fsr & SMMU_FSR_SS )
        writel_relaxed(SMMU_RESUME_TERMINATE, cb_base + SMMU_CB_RESUME);
}

static void arm_smmu_global_fault(int irq, void *data,
                                  struct cpu_user_regs *regs)
{
    u32 gfsr, gfsynr0, gfsynr1, gfsynr2;
    struct arm_smmu_device *smmu = data;
    void __iomem *gr0_base = SMMU_GR0_NS(smmu);

    gfsr = readl_relaxed(gr0_base + SMMU_GR0_sGFSR);
    gfsynr0 = readl_relaxed(gr0_base + SMMU_GR0_sGFSYNR0);
    gfsynr1 = readl_relaxed(gr0_base + SMMU_GR0_sGFSYNR1);
    gfsynr2 = readl_relaxed(gr0_base + SMMU_GR0_sGFSYNR2);

    if ( !gfsr )
        return;

    smmu_err(smmu, "Unexpected global fault, this could be serious\n");
    smmu_err(smmu,
             "\tGFSR 0x%08x, GFSYNR0 0x%08x, GFSYNR1 0x%08x, GFSYNR2 0x%08x\n",
             gfsr, gfsynr0, gfsynr1, gfsynr2);
    writel(gfsr, gr0_base + SMMU_GR0_sGFSR);
}

static struct arm_smmu_master *
find_smmu_master(struct arm_smmu_device *smmu,
                 const struct dt_device_node *dev_node)
{
    struct rb_node *node = smmu->masters.rb_node;

    while ( node )
    {
        struct arm_smmu_master *master;

        master = container_of(node, struct arm_smmu_master, node);

        if ( dev_node < master->dt_node )
            node = node->rb_left;
        else if ( dev_node > master->dt_node )
            node = node->rb_right;
        else
            return master;
    }

    return NULL;
}

static __init int insert_smmu_master(struct arm_smmu_device *smmu,
                                     struct arm_smmu_master *master)
{
    struct rb_node **new, *parent;

    new = &smmu->masters.rb_node;
    parent = NULL;
    while ( *new )
    {
        struct arm_smmu_master *this;

        this = container_of(*new, struct arm_smmu_master, node);

        parent = *new;
        if ( master->dt_node < this->dt_node )
            new = &((*new)->rb_left);
        else if (master->dt_node > this->dt_node)
            new = &((*new)->rb_right);
        else
            return -EEXIST;
    }

    rb_link_node(&master->node, parent, new);
    rb_insert_color(&master->node, &smmu->masters);
    return 0;
}

static __init int register_smmu_master(struct arm_smmu_device *smmu,
                                       struct dt_phandle_args *masterspec)
{
    int i, sid;
    struct arm_smmu_master *master;
    int rc = 0;

    smmu_dbg(smmu, "Try to add master %s\n", masterspec->np->name);

    master = find_smmu_master(smmu, masterspec->np);
    if ( master )
    {
        smmu_err(smmu,
                 "rejecting multiple registrations for master device %s\n",
                 masterspec->np->name);
        return -EBUSY;
    }

    if ( masterspec->args_count > MAX_MASTER_STREAMIDS )
    {
        smmu_err(smmu,
            "reached maximum number (%d) of stream IDs for master device %s\n",
            MAX_MASTER_STREAMIDS, masterspec->np->name);
        return -ENOSPC;
    }

    master = xzalloc(struct arm_smmu_master);
    if ( !master )
        return -ENOMEM;

    INIT_LIST_HEAD(&master->list);
    master->dt_node = masterspec->np;
    master->num_streamids = masterspec->args_count;

    dt_device_set_protected(masterspec->np);

    for ( i = 0; i < master->num_streamids; ++i )
    {
        sid = masterspec->args[i];
        if ( test_and_set_bit(sid, smmu->sids) )
        {
            smmu_err(smmu, "duplicate stream ID (%d)\n", sid);
            xfree(master);
            return -EEXIST;
        }
        master->streamids[i] = masterspec->args[i];
    }

    rc = insert_smmu_master(smmu, master);
    /* Insertion should never fail */
    ASSERT(rc == 0);

    return 0;
}

static int __arm_smmu_alloc_bitmap(unsigned long *map, int start, int end)
{
    int idx;

    do
    {
        idx = find_next_zero_bit(map, end, start);
        if ( idx == end )
            return -ENOSPC;
    } while ( test_and_set_bit(idx, map) );

    return idx;
}

static void __arm_smmu_free_bitmap(unsigned long *map, int idx)
{
    clear_bit(idx, map);
}

static void arm_smmu_tlb_sync(struct arm_smmu_device *smmu)
{
    int count = 0;
    void __iomem *gr0_base = SMMU_GR0(smmu);

    writel_relaxed(0, gr0_base + SMMU_GR0_sTLBGSYNC);
    while ( readl_relaxed(gr0_base + SMMU_GR0_sTLBGSTATUS) &
            SMMU_sTLBGSTATUS_GSACTIVE )
    {
        cpu_relax();
        if ( ++count == SMMU_TLB_LOOP_TIMEOUT )
        {
            smmu_err(smmu, "TLB sync timed out -- SMMU may be deadlocked\n");
            return;
        }
        udelay(1);
    }
}

static void arm_smmu_tlb_inv_context(struct arm_smmu_domain_cfg *cfg)
{
    struct arm_smmu_device *smmu = cfg->smmu;
    void __iomem *base = SMMU_GR0(smmu);

    writel_relaxed(SMMU_CB_VMID(cfg),
                   base + SMMU_GR0_TLBIVMID);

    arm_smmu_tlb_sync(smmu);
}

static void arm_smmu_iotlb_flush_all(struct domain *d)
{
    struct arm_smmu_domain *smmu_domain = domain_hvm_iommu(d)->arch.priv;
    struct arm_smmu_domain_cfg *cfg;

    spin_lock(&smmu_domain->lock);
    list_for_each_entry(cfg, &smmu_domain->contexts, list)
        arm_smmu_tlb_inv_context(cfg);
    spin_unlock(&smmu_domain->lock);
}

static void arm_smmu_iotlb_flush(struct domain *d, unsigned long gfn,
                                 unsigned int page_count)
{
    /* ARM SMMU v1 doesn't have flush by VMA and VMID */
    arm_smmu_iotlb_flush_all(d);
}

static int determine_smr_mask(struct arm_smmu_device *smmu,
                              struct arm_smmu_master *master,
                              struct arm_smmu_smr *smr, int start, int order)
{
    u16 i, zero_bits_mask, one_bits_mask, const_mask;
    int nr;

    nr = 1 << order;

    if ( nr == 1 )
    {
        /* no mask, use streamid to match and be done with it */
        smr->mask = 0;
        smr->id = master->streamids[start];
        return 0;
    }

    zero_bits_mask = 0;
    one_bits_mask = 0xffff;
    for ( i = start; i < start + nr; i++)
    {
        zero_bits_mask |= master->streamids[i];   /* const 0 bits */
        one_bits_mask &= master->streamids[i]; /* const 1 bits */
    }
    zero_bits_mask = ~zero_bits_mask;

    /* bits having constant values (either 0 or 1) */
    const_mask = zero_bits_mask | one_bits_mask;

    i = hweight16(~const_mask);
    if ( (1 << i) == nr )
    {
        smr->mask = ~const_mask;
        smr->id = one_bits_mask;
    }
    else
        /* no usable mask for this set of streamids */
        return 1;

    if ( ((smr->mask & smmu->smr_mask_mask) != smr->mask) ||
         ((smr->id & smmu->smr_id_mask) != smr->id) )
        /* insufficient number of mask/id bits */
        return 1;

    return 0;
}

static int determine_smr_mapping(struct arm_smmu_device *smmu,
                                 struct arm_smmu_master *master,
                                 struct arm_smmu_smr *smrs, int max_smrs)
{
    int nr_sid, nr, i, bit, start;

    /*
     * This function is called only once -- when a master is added
     * to a domain. If master->num_s2crs != 0 then this master
     * was already added to a domain.
     */
    BUG_ON(master->num_s2crs);

    start = nr = 0;
    nr_sid = master->num_streamids;
    do
    {
        /*
         * largest power-of-2 number of streamids for which to
         * determine a usable mask/id pair for stream matching
         */
        bit = fls(nr_sid);
        if (!bit)
            return 0;

        /*
         * iterate over power-of-2 numbers to determine
         * largest possible mask/id pair for stream matching
         * of next 2**i streamids
         */
        for ( i = bit - 1; i >= 0; i-- )
        {
            if( !determine_smr_mask(smmu, master,
                                    &smrs[master->num_s2crs],
                                    start, i))
                break;
        }

        if ( i < 0 )
            goto out;

        nr = 1 << i;
        nr_sid -= nr;
        start += nr;
        master->num_s2crs++;
    } while ( master->num_s2crs <= max_smrs );

out:
    if ( nr_sid )
    {
        /* not enough mapping groups available */
        master->num_s2crs = 0;
        return -ENOSPC;
    }

    return 0;
}

static int arm_smmu_master_configure_smrs(struct arm_smmu_device *smmu,
                                          struct arm_smmu_master *master)
{
    int i, max_smrs, ret;
    struct arm_smmu_smr *smrs;
    void __iomem *gr0_base = SMMU_GR0(smmu);

    if ( !(smmu->features & SMMU_FEAT_STREAM_MATCH) )
        return 0;

    if ( master->smrs )
        return -EEXIST;

    max_smrs = min(smmu->num_mapping_groups, master->num_streamids);
    smrs = xmalloc_array(struct arm_smmu_smr, max_smrs);
    if ( !smrs )
    {
        smmu_err(smmu, "failed to allocated %d SMRs for master %s\n",
                 max_smrs, dt_node_name(master->dt_node));
        return -ENOMEM;
    }

    ret = determine_smr_mapping(smmu, master, smrs, max_smrs);
    if ( ret )
        goto err_free_smrs;

    /* Allocate the SMRs on the root SMMU */
    for ( i = 0; i < master->num_s2crs; ++i )
    {
        int idx = __arm_smmu_alloc_bitmap(smmu->smr_map, 0,
                                          smmu->num_mapping_groups);
        if ( idx < 0 )
        {
            smmu_err(smmu, "failed to allocate free SMR\n");
            goto err_free_bitmap;
        }
        smrs[i].idx = idx;
    }

    /* It worked! Now, poke the actual hardware */
    for ( i = 0; i < master->num_s2crs; ++i )
    {
        u32 reg = SMMU_SMR_VALID | smrs[i].id << SMMU_SMR_ID_SHIFT |
            smrs[i].mask << SMMU_SMR_MASK_SHIFT;
        smmu_dbg(smmu, "SMR%d: 0x%x\n", smrs[i].idx, reg);
        writel_relaxed(reg, gr0_base + SMMU_GR0_SMR(smrs[i].idx));
    }

    master->smrs = smrs;
    return 0;

err_free_bitmap:
    while (--i >= 0)
        __arm_smmu_free_bitmap(smmu->smr_map, smrs[i].idx);
    master->num_s2crs = 0;
err_free_smrs:
    xfree(smrs);
    return -ENOSPC;
}

/* Forward declaration */
static void arm_smmu_destroy_domain_context(struct arm_smmu_domain_cfg *cfg);

static int arm_smmu_domain_add_master(struct domain *d,
                                      struct arm_smmu_domain_cfg *cfg,
                                      struct arm_smmu_master *master)
{
    int i, ret;
    struct arm_smmu_device *smmu = cfg->smmu;
    void __iomem *gr0_base = SMMU_GR0(smmu);
    struct arm_smmu_smr *smrs = master->smrs;

    if ( master->cfg )
        return -EBUSY;

    ret = arm_smmu_master_configure_smrs(smmu, master);
    if ( ret )
        return ret;

    /* Now we're at the root, time to point at our context bank */
    if ( !master->num_s2crs )
        master->num_s2crs = master->num_streamids;

    for ( i = 0; i < master->num_s2crs; ++i )
    {
        u32 idx, s2cr;

        idx = smrs ? smrs[i].idx : master->streamids[i];
        s2cr = (SMMU_S2CR_TYPE_TRANS << SMMU_S2CR_TYPE_SHIFT) |
            (cfg->cbndx << SMMU_S2CR_CBNDX_SHIFT);
        smmu_dbg(smmu, "S2CR%d: 0x%x\n", idx, s2cr);
        writel_relaxed(s2cr, gr0_base + SMMU_GR0_S2CR(idx));
    }

    master->cfg = cfg;
    list_add(&master->list, &cfg->masters);

    return 0;
}

static void arm_smmu_domain_remove_master(struct arm_smmu_master *master)
{
    int i;
    struct arm_smmu_domain_cfg *cfg = master->cfg;
    struct arm_smmu_device *smmu = cfg->smmu;
    void __iomem *gr0_base = SMMU_GR0(smmu);
    struct arm_smmu_smr *smrs = master->smrs;

    /*
     * We *must* clear the S2CR first, because freeing the SMR means
     * that it can be reallocated immediately
     */
    for ( i = 0; i < master->num_streamids; ++i )
    {
        u16 sid = master->streamids[i];
        writel_relaxed(SMMU_S2CR_TYPE_FAULT,
                       gr0_base + SMMU_GR0_S2CR(sid));
    }

    /* Invalidate the SMRs before freeing back to the allocator */
    for (i = 0; i < master->num_s2crs; ++i) {
        u8 idx = smrs[i].idx;
        writel_relaxed(~SMMU_SMR_VALID, gr0_base + SMMU_GR0_SMR(idx));
        __arm_smmu_free_bitmap(smmu->smr_map, idx);
    }

    master->smrs = NULL;
    master->num_s2crs = 0;
    xfree(smrs);

    master->cfg = NULL;
    list_del(&master->list);
    INIT_LIST_HEAD(&master->list);
}

static void arm_smmu_init_context_bank(struct arm_smmu_domain_cfg *cfg)
{
    u32 reg;
    struct arm_smmu_device *smmu = cfg->smmu;
    void __iomem *cb_base, *gr1_base;
    paddr_t p2maddr;

    ASSERT(cfg->domain != NULL);
    p2maddr = page_to_maddr(cfg->domain->arch.p2m.root);

    gr1_base = SMMU_GR1(smmu);
    cb_base = SMMU_CB_BASE(smmu) + SMMU_CB(smmu, cfg->cbndx);

    /* CBAR */
    reg = cfg->cbar;
    if ( smmu->version == 1 )
        reg |= cfg->irptndx << SMMU_CBAR_IRPTNDX_SHIFT;

    reg |= SMMU_CB_VMID(cfg) << SMMU_CBAR_VMID_SHIFT;
    writel_relaxed(reg, gr1_base + SMMU_GR1_CBAR(cfg->cbndx));

    if ( smmu->version > 1 )
    {
        /* CBA2R */
#ifdef CONFIG_ARM_64
        reg = SMMU_CBA2R_RW64_64BIT;
#else
        reg = SMMU_CBA2R_RW64_32BIT;
#endif
        writel_relaxed(reg, gr1_base + SMMU_GR1_CBA2R(cfg->cbndx));
    }

    /* TTBR0 */
    reg = (p2maddr & ((1ULL << 32) - 1));
    writel_relaxed(reg, cb_base + SMMU_CB_TTBR0_LO);
    reg = (p2maddr >> 32);
    writel_relaxed(reg, cb_base + SMMU_CB_TTBR0_HI);

    /*
     * TCR
     * We use long descriptor, with inner-shareable WBWA tables in TTBR0.
     */
    if ( smmu->version > 1 )
    {
        /* 4K Page Table */
        if ( PAGE_SIZE == PAGE_SIZE_4K )
            reg = SMMU_TCR_TG0_4K;
        else
            reg = SMMU_TCR_TG0_64K;

        switch ( smmu->s2_output_size ) {
        case 32:
            reg |= (SMMU_TCR2_ADDR_32 << SMMU_TCR_PASIZE_SHIFT);
            break;
        case 36:
            reg |= (SMMU_TCR2_ADDR_36 << SMMU_TCR_PASIZE_SHIFT);
            break;
        case 40:
            reg |= (SMMU_TCR2_ADDR_40 << SMMU_TCR_PASIZE_SHIFT);
            break;
        case 42:
            reg |= (SMMU_TCR2_ADDR_42 << SMMU_TCR_PASIZE_SHIFT);
            break;
        case 44:
            reg |= (SMMU_TCR2_ADDR_44 << SMMU_TCR_PASIZE_SHIFT);
            break;
        case 48:
            reg |= (SMMU_TCR2_ADDR_48 << SMMU_TCR_PASIZE_SHIFT);
            break;
        }
    }
    else
        reg = 0;

    /* The attribute to walk the page table should be the same as VTCR_EL2 */
    reg |= SMMU_TCR_EAE |
        (SMMU_TCR_SH_IS << SMMU_TCR_SH0_SHIFT) |
        (SMMU_TCR_RGN_WBWA << SMMU_TCR_ORGN0_SHIFT) |
        (SMMU_TCR_RGN_WBWA << SMMU_TCR_IRGN0_SHIFT) |
        (SMMU_TCR_SL0_LVL_1 << SMMU_TCR_SL0_SHIFT) |
        /* T0SZ=(1)100 = -8 ( 32 -(-8) = 40 bit physical addresses ) */
        (0x18 << SMMU_TCR_T0SZ_SHIFT);
    writel_relaxed(reg, cb_base + SMMU_CB_TCR);

    /* SCTLR */
    reg = SMMU_SCTLR_CFCFG |
        SMMU_SCTLR_CFIE |
        SMMU_SCTLR_CFRE |
        SMMU_SCTLR_M |
        SMMU_SCTLR_EAE_SBOP;

    writel_relaxed(reg, cb_base + SMMU_CB_SCTLR);
}

static struct arm_smmu_domain_cfg *
arm_smmu_alloc_domain_context(struct domain *d,
                              struct arm_smmu_device *smmu)
{
    unsigned int irq;
    int ret, start;
    struct arm_smmu_domain_cfg *cfg;
    struct arm_smmu_domain *smmu_domain = domain_hvm_iommu(d)->arch.priv;

    ASSERT(spin_is_locked(&smmu_domain->lock));

    cfg = xzalloc(struct arm_smmu_domain_cfg);
    if ( !cfg )
        return NULL;

    /* Master already initialized to another domain ... */
    if ( cfg->domain != NULL )
        goto out_free_mem;

    cfg->cbar = SMMU_CBAR_TYPE_S2_TRANS;
    start = 0;

    ret = __arm_smmu_alloc_bitmap(smmu->context_map, start,
                                  smmu->num_context_banks);
    if ( ret < 0 )
        goto out_free_mem;

    cfg->cbndx = ret;
    if ( smmu->version == 1 )
    {
        cfg->irptndx = atomic_inc_return(&smmu->irptndx);
        cfg->irptndx %= smmu->num_context_irqs;
    }
    else
        cfg->irptndx = cfg->cbndx;

    irq = smmu->irqs[smmu->num_global_irqs + cfg->irptndx];
    ret = request_irq(irq, IRQF_SHARED, arm_smmu_context_fault,
                      "arm-smmu-context-fault", cfg);
    if ( ret )
    {
        smmu_err(smmu, "failed to request context IRQ %d (%u)\n",
                 cfg->irptndx, irq);
        cfg->irptndx = INVALID_IRPTNDX;
        goto out_free_context;
    }

    cfg->domain = d;
    cfg->smmu = smmu;
    if ( smmu->features & SMMU_FEAT_COHERENT_WALK )
        iommu_set_feature(d, IOMMU_FEAT_COHERENT_WALK);

    arm_smmu_init_context_bank(cfg);
    list_add(&cfg->list, &smmu_domain->contexts);
    INIT_LIST_HEAD(&cfg->masters);

    return cfg;

out_free_context:
    __arm_smmu_free_bitmap(smmu->context_map, cfg->cbndx);
out_free_mem:
    xfree(cfg);

    return NULL;
}

static void arm_smmu_destroy_domain_context(struct arm_smmu_domain_cfg *cfg)
{
    struct domain *d = cfg->domain;
    struct arm_smmu_domain *smmu_domain = domain_hvm_iommu(d)->arch.priv;
    struct arm_smmu_device *smmu = cfg->smmu;
    void __iomem *cb_base;
    unsigned int irq;

    ASSERT(spin_is_locked(&smmu_domain->lock));
    BUG_ON(!list_empty(&cfg->masters));

    /* Disable the context bank and nuke the TLB before freeing it */
    cb_base = SMMU_CB_BASE(smmu) + SMMU_CB(smmu, cfg->cbndx);
    writel_relaxed(0, cb_base + SMMU_CB_SCTLR);
    arm_smmu_tlb_inv_context(cfg);

    if ( cfg->irptndx != INVALID_IRPTNDX )
    {
        irq = smmu->irqs[smmu->num_global_irqs + cfg->irptndx];
        release_irq(irq, cfg);
    }

    __arm_smmu_free_bitmap(smmu->context_map, cfg->cbndx);
    list_del(&cfg->list);
    xfree(cfg);
}

static struct arm_smmu_device *
arm_smmu_find_smmu_by_dev(const struct dt_device_node *dev)
{
    struct arm_smmu_device *smmu;
    struct arm_smmu_master *master = NULL;

    list_for_each_entry( smmu, &arm_smmu_devices, list )
    {
        master = find_smmu_master(smmu, dev);
        if ( master )
            break;
    }

    if ( !master )
        return NULL;

    return smmu;
}

static int arm_smmu_attach_dev(struct domain *d,
                               const struct dt_device_node *dev)
{
    struct arm_smmu_device *smmu = arm_smmu_find_smmu_by_dev(dev);
    struct arm_smmu_master *master;
    struct arm_smmu_domain *smmu_domain = domain_hvm_iommu(d)->arch.priv;
    struct arm_smmu_domain_cfg *cfg = NULL;
    struct arm_smmu_domain_cfg *curr;
    int ret;

    printk(XENLOG_DEBUG "arm-smmu: attach %s to domain %d\n",
           dt_node_full_name(dev), d->domain_id);

    if ( !smmu )
    {
        printk(XENLOG_ERR "%s: cannot attach to SMMU, is it on the same bus?\n",
               dt_node_full_name(dev));
        return -ENODEV;
    }

    master = find_smmu_master(smmu, dev);
    BUG_ON(master == NULL);

    /* Check if the device is already assigned to someone */
    if ( master->cfg )
        return -EBUSY;

    spin_lock(&smmu_domain->lock);
    list_for_each_entry( curr, &smmu_domain->contexts, list )
    {
        if ( curr->smmu == smmu )
        {
            cfg = curr;
            break;
        }
    }

    if ( !cfg )
    {
        cfg = arm_smmu_alloc_domain_context(d, smmu);
        if ( !cfg )
        {
            smmu_err(smmu, "unable to allocate context for domain %u\n",
                     d->domain_id);
            spin_unlock(&smmu_domain->lock);
            return -ENOMEM;
        }
    }
    spin_unlock(&smmu_domain->lock);

    ret = arm_smmu_domain_add_master(d, cfg, master);
    if ( ret )
    {
        spin_lock(&smmu_domain->lock);
        if ( list_empty(&cfg->masters) )
            arm_smmu_destroy_domain_context(cfg);
        spin_unlock(&smmu_domain->lock);
    }

    return ret;
}

static int arm_smmu_detach_dev(struct domain *d,
                               const struct dt_device_node *dev)
{
    struct arm_smmu_domain *smmu_domain = domain_hvm_iommu(d)->arch.priv;
    struct arm_smmu_master *master;
    struct arm_smmu_device *smmu = arm_smmu_find_smmu_by_dev(dev);
    struct arm_smmu_domain_cfg *cfg;

    printk(XENLOG_DEBUG "arm-smmu: detach %s to domain %d\n",
           dt_node_full_name(dev), d->domain_id);

    if ( !smmu )
    {
        printk(XENLOG_ERR "%s: cannot find the SMMU, is it on the same bus?\n",
               dt_node_full_name(dev));
        return -ENODEV;
    }

    master = find_smmu_master(smmu, dev);
    BUG_ON(master == NULL);

    cfg = master->cfg;

    /* Sanity check to avoid removing a device that doesn't belong to
     * the domain
     */
    if ( !cfg || cfg->domain != d )
    {
        printk(XENLOG_ERR "%s: was not attach to domain %d\n",
               dt_node_full_name(dev), d->domain_id);
        return -ESRCH;
    }

    arm_smmu_domain_remove_master(master);

    spin_lock(&smmu_domain->lock);
    if ( list_empty(&cfg->masters) )
        arm_smmu_destroy_domain_context(cfg);
    spin_unlock(&smmu_domain->lock);

    return 0;
}

static int arm_smmu_reassign_dt_dev(struct domain *s, struct domain *t,
                                    const struct dt_device_node *dev)
{
    int ret = 0;

    /* Don't allow remapping on other domain than hwdom */
    if ( t != hardware_domain )
        return -EPERM;

    if ( t == s )
        return 0;

    ret = arm_smmu_detach_dev(s, dev);
    if ( ret )
        return ret;

    ret = arm_smmu_attach_dev(t, dev);

    return ret;
}

static __init int arm_smmu_id_size_to_bits(int size)
{
    switch ( size )
    {
    case 0:
        return 32;
    case 1:
        return 36;
    case 2:
        return 40;
    case 3:
        return 42;
    case 4:
        return 44;
    case 5:
    default:
        return 48;
    }
}

static __init int arm_smmu_device_cfg_probe(struct arm_smmu_device *smmu)
{
    unsigned long size;
    void __iomem *gr0_base = SMMU_GR0(smmu);
    u32 id;

    smmu_info(smmu, "probing hardware configuration...\n");

    /*
     * Primecell ID
     */
    id = readl_relaxed(gr0_base + SMMU_GR0_PIDR2);
    smmu->version = ((id >> SMMU_PIDR2_ARCH_SHIFT) & SMMU_PIDR2_ARCH_MASK) + 1;
    smmu_info(smmu, "SMMUv%d with:\n", smmu->version);

    /* ID0 */
    id = readl_relaxed(gr0_base + SMMU_GR0_ID0);
#ifndef CONFIG_ARM_64
    if ( ((id >> SMMU_ID0_PTFS_SHIFT) & SMMU_ID0_PTFS_MASK) ==
            SMMU_ID0_PTFS_V8_ONLY )
    {
        smmu_err(smmu, "\tno v7 descriptor support!\n");
        return -ENODEV;
    }
#endif
    if ( id & SMMU_ID0_S1TS )
    {
        smmu->features |= SMMU_FEAT_TRANS_S1;
        smmu_info(smmu, "\tstage 1 translation\n");
    }

    if ( id & SMMU_ID0_S2TS )
    {
        smmu->features |= SMMU_FEAT_TRANS_S2;
        smmu_info(smmu, "\tstage 2 translation\n");
    }

    if ( id & SMMU_ID0_NTS )
    {
        smmu->features |= SMMU_FEAT_TRANS_NESTED;
        smmu_info(smmu, "\tnested translation\n");
    }

    if ( !(smmu->features &
           (SMMU_FEAT_TRANS_S1 | SMMU_FEAT_TRANS_S2 |
            SMMU_FEAT_TRANS_NESTED)) )
    {
        smmu_err(smmu, "\tno translation support!\n");
        return -ENODEV;
    }

    /* We need at least support for Stage 2 */
    if ( !(smmu->features & SMMU_FEAT_TRANS_S2) )
    {
        smmu_err(smmu, "\tno stage 2 translation!\n");
        return -ENODEV;
    }

    if ( id & SMMU_ID0_CTTW )
    {
        smmu->features |= SMMU_FEAT_COHERENT_WALK;
        smmu_info(smmu, "\tcoherent table walk\n");
    }

    if ( id & SMMU_ID0_SMS )
    {
        u32 smr, sid, mask;

        smmu->features |= SMMU_FEAT_STREAM_MATCH;
        smmu->num_mapping_groups = (id >> SMMU_ID0_NUMSMRG_SHIFT) &
            SMMU_ID0_NUMSMRG_MASK;
        if ( smmu->num_mapping_groups == 0 )
        {
            smmu_err(smmu,
                     "stream-matching supported, but no SMRs present!\n");
            return -ENODEV;
        }

        smr = SMMU_SMR_MASK_MASK << SMMU_SMR_MASK_SHIFT;
        smr |= (SMMU_SMR_ID_MASK << SMMU_SMR_ID_SHIFT);
        writel_relaxed(smr, gr0_base + SMMU_GR0_SMR(0));
        smr = readl_relaxed(gr0_base + SMMU_GR0_SMR(0));

        mask = (smr >> SMMU_SMR_MASK_SHIFT) & SMMU_SMR_MASK_MASK;
        sid = (smr >> SMMU_SMR_ID_SHIFT) & SMMU_SMR_ID_MASK;
        if ( (mask & sid) != sid )
        {
            smmu_err(smmu,
                     "SMR mask bits (0x%x) insufficient for ID field (0x%x)\n",
                     mask, sid);
            return -ENODEV;
        }
        smmu->smr_mask_mask = mask;
        smmu->smr_id_mask = sid;

        smmu_info(smmu,
                  "\tstream matching with %u register groups, mask 0x%x\n",
                  smmu->num_mapping_groups, mask);
    }

    /* ID1 */
    id = readl_relaxed(gr0_base + SMMU_GR0_ID1);
    smmu->pagesize = (id & SMMU_ID1_PAGESIZE) ? PAGE_SIZE_64K : PAGE_SIZE_4K;

    /* Check for size mismatch of SMMU address space from mapped region */
    size = 1 << (((id >> SMMU_ID1_NUMPAGENDXB_SHIFT) &
                  SMMU_ID1_NUMPAGENDXB_MASK) + 1);
    size *= (smmu->pagesize << 1);
    if ( smmu->size != size )
        smmu_warn(smmu, "SMMU address space size (0x%lx) differs "
                  "from mapped region size (0x%lx)!\n", size, smmu->size);

    smmu->num_s2_context_banks = (id >> SMMU_ID1_NUMS2CB_SHIFT) &
        SMMU_ID1_NUMS2CB_MASK;
    smmu->num_context_banks = (id >> SMMU_ID1_NUMCB_SHIFT) &
        SMMU_ID1_NUMCB_MASK;
    if ( smmu->num_s2_context_banks > smmu->num_context_banks )
    {
        smmu_err(smmu, "impossible number of S2 context banks!\n");
        return -ENODEV;
    }
    smmu_info(smmu, "\t%u context banks (%u stage-2 only)\n",
              smmu->num_context_banks, smmu->num_s2_context_banks);

    /* ID2 */
    id = readl_relaxed(gr0_base + SMMU_GR0_ID2);
    size = arm_smmu_id_size_to_bits((id >> SMMU_ID2_IAS_SHIFT) &
                                    SMMU_ID2_IAS_MASK);

    /*
     * Stage-1 output limited by stage-2 input size due to VTCR_EL2
     * setup (see setup_virt_paging)
     */
    /* Current maximum output size of 40 bits */
    smmu->s1_output_size = min(40UL, size);

    /* The stage-2 output mask is also applied for bypass */
    size = arm_smmu_id_size_to_bits((id >> SMMU_ID2_OAS_SHIFT) &
                                    SMMU_ID2_OAS_MASK);
    smmu->s2_output_size = min((unsigned long)PADDR_BITS, size);

    if ( smmu->version == 1 )
        smmu->input_size = 32;
    else
    {
#ifdef CONFIG_ARM_64
        size = (id >> SMMU_ID2_UBS_SHIFT) & SMMU_ID2_UBS_MASK;
        size = min(39, arm_smmu_id_size_to_bits(size));
#else
        size = 32;
#endif
        smmu->input_size = size;

        if ( (PAGE_SIZE == PAGE_SIZE_4K && !(id & SMMU_ID2_PTFS_4K) ) ||
             (PAGE_SIZE == PAGE_SIZE_64K && !(id & SMMU_ID2_PTFS_64K)) ||
             (PAGE_SIZE != PAGE_SIZE_4K && PAGE_SIZE != PAGE_SIZE_64K) )
        {
            smmu_err(smmu, "CPU page size 0x%lx unsupported\n",
                     PAGE_SIZE);
            return -ENODEV;
        }
    }

    smmu_info(smmu, "\t%lu-bit VA, %lu-bit IPA, %lu-bit PA\n",
              smmu->input_size, smmu->s1_output_size, smmu->s2_output_size);
    return 0;
}

static __init void arm_smmu_device_reset(struct arm_smmu_device *smmu)
{
    void __iomem *gr0_base = SMMU_GR0(smmu);
    void __iomem *cb_base;
    int i = 0;
    u32 reg;

    smmu_dbg(smmu, "device reset\n");

    /* Clear Global FSR */
    reg = readl_relaxed(SMMU_GR0_NS(smmu) + SMMU_GR0_sGFSR);
    writel(reg, SMMU_GR0_NS(smmu) + SMMU_GR0_sGFSR);

    /* Mark all SMRn as invalid and all S2CRn as fault */
    for ( i = 0; i < smmu->num_mapping_groups; ++i )
    {
        writel_relaxed(~SMMU_SMR_VALID, gr0_base + SMMU_GR0_SMR(i));
        writel_relaxed(SMMU_S2CR_TYPE_FAULT, gr0_base + SMMU_GR0_S2CR(i));
    }

    /* Make sure all context banks are disabled and clear CB_FSR  */
    for ( i = 0; i < smmu->num_context_banks; ++i )
    {
        cb_base = SMMU_CB_BASE(smmu) + SMMU_CB(smmu, i);
        writel_relaxed(0, cb_base + SMMU_CB_SCTLR);
        writel_relaxed(SMMU_FSR_FAULT, cb_base + SMMU_CB_FSR);
    }

    /* Invalidate the TLB, just in case */
    writel_relaxed(0, gr0_base + SMMU_GR0_STLBIALL);
    writel_relaxed(0, gr0_base + SMMU_GR0_TLBIALLH);
    writel_relaxed(0, gr0_base + SMMU_GR0_TLBIALLNSNH);

    reg = readl_relaxed(SMMU_GR0_NS(smmu) + SMMU_GR0_sCR0);

    /* Enable fault reporting */
    reg |= (SMMU_sCR0_GFRE | SMMU_sCR0_GFIE |
            SMMU_sCR0_GCFGFRE | SMMU_sCR0_GCFGFIE);

    /* Disable TLB broadcasting. */
    reg |= (SMMU_sCR0_VMIDPNE | SMMU_sCR0_PTM);

    /* Enable client access, generate a fault if no mapping is found */
    reg &= ~(SMMU_sCR0_CLIENTPD);
    reg |= SMMU_sCR0_USFCFG;

    /* Disable forced broadcasting */
    reg &= ~SMMU_sCR0_FB;

    /* Don't upgrade barriers when client devices are not mapped to
     * a translation context banks (just here for clarity as Xen policy
     * is to deny invalid transaction). */
    reg &= ~(SMMU_sCR0_BSU_MASK << SMMU_sCR0_BSU_SHIFT);

    /* Push the button */
    arm_smmu_tlb_sync(smmu);
    writel_relaxed(reg, SMMU_GR0_NS(smmu) + SMMU_GR0_sCR0);
}

static int arm_smmu_iommu_domain_init(struct domain *d)
{
    struct arm_smmu_domain *smmu_domain;

    smmu_domain = xzalloc(struct arm_smmu_domain);
    if ( !smmu_domain )
        return -ENOMEM;

    spin_lock_init(&smmu_domain->lock);
    INIT_LIST_HEAD(&smmu_domain->contexts);

    domain_hvm_iommu(d)->arch.priv = smmu_domain;

    return 0;
}

static void __hwdom_init arm_smmu_iommu_hwdom_init(struct domain *d)
{
}

static void arm_smmu_iommu_domain_teardown(struct domain *d)
{
    struct arm_smmu_domain *smmu_domain = domain_hvm_iommu(d)->arch.priv;

    ASSERT(list_empty(&smmu_domain->contexts));
    xfree(smmu_domain);
}

static int arm_smmu_map_page(struct domain *d, unsigned long gfn,
                             unsigned long mfn, unsigned int flags)
{
    p2m_type_t t;

    /* Grant mappings can be used for DMA requests. The dev_bus_addr returned by
     * the hypercall is the MFN (not the IPA). For device protected by
     * an IOMMU, Xen needs to add a 1:1 mapping in the domain p2m to
     * allow DMA request to work.
     * This is only valid when the domain is directed mapped. Hence this
     * function should only be used by gnttab code with gfn == mfn.
     */
    BUG_ON(!is_domain_direct_mapped(d));
    BUG_ON(mfn != gfn);

    /* We only support readable and writable flags */
    if ( !(flags & (IOMMUF_readable | IOMMUF_writable)) )
        return -EINVAL;

    t = (flags & IOMMUF_writable) ? p2m_iommu_map_rw : p2m_iommu_map_ro;

    /* The function guest_physmap_add_entry replaces the current mapping
     * if there is already one...
     */
    return guest_physmap_add_entry(d, gfn, mfn, 0, t);
}

static int arm_smmu_unmap_page(struct domain *d, unsigned long gfn)
{
    /* This function should only be used by gnttab code when the domain
     * is direct mapped
     */
    if ( !is_domain_direct_mapped(d) )
        return -EINVAL;

    guest_physmap_remove_page(d, gfn, gfn, 0);

    return 0;
}

static const struct iommu_ops arm_smmu_iommu_ops = {
    .init = arm_smmu_iommu_domain_init,
    .hwdom_init = arm_smmu_iommu_hwdom_init,
    .teardown = arm_smmu_iommu_domain_teardown,
    .iotlb_flush = arm_smmu_iotlb_flush,
    .iotlb_flush_all = arm_smmu_iotlb_flush_all,
    .assign_dt_device = arm_smmu_attach_dev,
    .reassign_dt_device = arm_smmu_reassign_dt_dev,
    .map_page = arm_smmu_map_page,
    .unmap_page = arm_smmu_unmap_page,
};

static int __init smmu_init(struct dt_device_node *dev,
                            const void *data)
{
    struct arm_smmu_device *smmu;
    int res;
    u64 addr, size;
    unsigned int num_irqs, i;
    struct dt_phandle_args masterspec;
    struct rb_node *node;

    /* Even if the device can't be initialized, we don't want to give
     * the smmu device to dom0.
     */
    dt_device_set_used_by(dev, DOMID_XEN);

    smmu = xzalloc(struct arm_smmu_device);
    if ( !smmu )
    {
        printk(XENLOG_ERR "%s: failed to allocate arm_smmu_device\n",
               dt_node_full_name(dev));
        return -ENOMEM;
    }

    smmu->node = dev;
    check_driver_options(smmu);

    res = dt_device_get_address(smmu->node, 0, &addr, &size);
    if ( res )
    {
        smmu_err(smmu, "unable to retrieve the base address of the SMMU\n");
        goto out_err;
    }

    smmu->base = ioremap_nocache(addr, size);
    if ( !smmu->base )
    {
        smmu_err(smmu, "unable to map the SMMU memory\n");
        goto out_err;
    }

    smmu->size = size;

    if ( !dt_property_read_u32(smmu->node, "#global-interrupts",
                               &smmu->num_global_irqs) )
    {
        smmu_err(smmu, "missing #global-interrupts\n");
        goto out_unmap;
    }

    num_irqs = dt_number_of_irq(smmu->node);
    if ( num_irqs > smmu->num_global_irqs )
        smmu->num_context_irqs = num_irqs - smmu->num_global_irqs;

    if ( !smmu->num_context_irqs )
    {
        smmu_err(smmu, "found %d interrupts but expected at least %d\n",
                 num_irqs, smmu->num_global_irqs + 1);
        goto out_unmap;
    }

    smmu->irqs = xzalloc_array(unsigned int, num_irqs);
    if ( !smmu->irqs )
    {
        smmu_err(smmu, "failed to allocated %d irqs\n", num_irqs);
        goto out_unmap;
    }

    for ( i = 0; i < num_irqs; i++ )
    {
        res = platform_get_irq(smmu->node, i);
        if ( res < 0 )
        {
            smmu_err(smmu, "failed to get irq index %d\n", i);
            goto out_free_irqs;
        }
        smmu->irqs[i] = res;
    }

    smmu->sids = xzalloc_array(unsigned long,
                               BITS_TO_LONGS(SMMU_MAX_STREAMIDS));
    if ( !smmu->sids )
    {
        smmu_err(smmu, "failed to allocated bitmap for stream ID tracking\n");
        goto out_free_masters;
    }


    i = 0;
    smmu->masters = RB_ROOT;
    while ( !dt_parse_phandle_with_args(smmu->node, "mmu-masters",
                                        "#stream-id-cells", i, &masterspec) )
    {
        res = register_smmu_master(smmu, &masterspec);
        if ( res )
        {
            smmu_err(smmu, "failed to add master %s\n",
                     masterspec.np->name);
            goto out_free_masters;
        }
        i++;
    }

    smmu_info(smmu, "registered %d master devices\n", i);

    res = arm_smmu_device_cfg_probe(smmu);
    if ( res )
    {
        smmu_err(smmu, "failed to probe the SMMU\n");
        goto out_free_masters;
    }

    if ( smmu->version > 1 &&
         smmu->num_context_banks != smmu->num_context_irqs )
    {
        smmu_err(smmu,
                 "found only %d context interrupt(s) but %d required\n",
                 smmu->num_context_irqs, smmu->num_context_banks);
        goto out_free_masters;
    }

    smmu_dbg(smmu, "register global IRQs handler\n");

    for ( i = 0; i < smmu->num_global_irqs; ++i )
    {
        smmu_dbg(smmu, "\t- global IRQ %u\n", smmu->irqs[i]);
        res = request_irq(smmu->irqs[i], IRQF_SHARED, arm_smmu_global_fault,
                          "arm-smmu global fault", smmu);
        if ( res )
        {
            smmu_err(smmu, "failed to request global IRQ %d (%u)\n",
                     i, smmu->irqs[i]);
            goto out_release_irqs;
        }
    }

    INIT_LIST_HEAD(&smmu->list);
    list_add(&smmu->list, &arm_smmu_devices);

    arm_smmu_device_reset(smmu);

    iommu_set_ops(&arm_smmu_iommu_ops);

    /* sids field can be freed... */
    xfree(smmu->sids);
    smmu->sids = NULL;

    return 0;

out_release_irqs:
    while (i--)
        release_irq(smmu->irqs[i], smmu);

out_free_masters:
    for ( node = rb_first(&smmu->masters); node; node = rb_next(node) )
    {
        struct arm_smmu_master *master;

        master = container_of(node, struct arm_smmu_master, node);
        xfree(master);
    }

    xfree(smmu->sids);

out_free_irqs:
    xfree(smmu->irqs);

out_unmap:
    iounmap(smmu->base);

out_err:
    xfree(smmu);

    return -ENODEV;
}

static const char * const smmu_dt_compat[] __initconst =
{
    "arm,mmu-400",
    NULL
};

DT_DEVICE_START(smmu, "ARM SMMU", DEVICE_IOMMU)
    .compatible = smmu_dt_compat,
    .init = smmu_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
