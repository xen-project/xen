/*
 * psr.c: Platform Shared Resource related service for guest.
 *
 * Copyright (c) 2014, Intel Corporation
 * Author: Dongxiao Xu <dongxiao.xu@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
#include <xen/cpu.h>
#include <xen/err.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <asm/psr.h>

/*
 * Terminology:
 * - CAT         Cache Allocation Technology
 * - CBM         Capacity BitMasks
 * - CDP         Code and Data Prioritization
 * - CMT         Cache Monitoring Technology
 * - COS/CLOS    Class of Service. Also mean COS registers.
 * - COS_MAX     Max number of COS for the feature (minus 1)
 * - MSRs        Machine Specific Registers
 * - PSR         Intel Platform Shared Resource
 */

#define PSR_CMT        (1<<0)
#define PSR_CAT        (1<<1)
#define PSR_CDP        (1<<2)

#define CAT_CBM_LEN_MASK 0x1f
#define CAT_COS_MAX_MASK 0xffff

/*
 * Per SDM chapter 'Cache Allocation Technology: Cache Mask Configuration',
 * the MSRs ranging from 0C90H through 0D0FH (inclusive), enables support for
 * up to 128 L3 CAT Classes of Service. The COS_ID=[0,127].
 *
 * The MSRs ranging from 0D10H through 0D4FH (inclusive), enables support for
 * up to 64 L2 CAT COS. The COS_ID=[0,63].
 *
 * So, the maximum COS register count of one feature is 128.
 */
#define MAX_COS_REG_CNT  128

#define ASSOC_REG_SHIFT 32

/*
 * Every PSR feature uses some COS registers for each COS ID, e.g. CDP uses 2
 * COS registers (DATA and CODE) for one COS ID, but CAT uses 1 COS register.
 * We use below macro as the max number of COS registers used by all features.
 * So far, it is 2 which means CDP's COS registers number.
 */
#define MAX_COS_NUM 2

enum psr_feat_type {
    FEAT_TYPE_L3_CAT,
    FEAT_TYPE_NUM,
};

/*
 * This structure represents one feature.
 * cos_max     - The max COS registers number got through CPUID.
 * cbm_len     - The length of CBM got through CPUID.
 * cos_reg_val - Array to store the values of COS registers. One entry stores
 *               the value of one COS register.
 *               For L3 CAT and L2 CAT, one entry corresponds to one COS_ID.
 *               For CDP, two entries correspond to one COS_ID. E.g.
 *               COS_ID=0 corresponds to cos_reg_val[0] (Data) and
 *               cos_reg_val[1] (Code).
 */
struct feat_node {
    /* cos_max and cbm_len are common values for all features so far. */
    unsigned int cos_max;
    unsigned int cbm_len;
    uint32_t cos_reg_val[MAX_COS_REG_CNT];
};

/*
 * This structure defines feature specific values, e.g. cos_num.
 *
 * Array 'feat_props' is defined to save every feature's properties. We use
 * 'enum psr_feat_type' as index.
 */
static const struct feat_props {
    /*
     * cos_num - COS registers number that feature uses for one COS ID.
     *           It is defined in SDM.
     */
    unsigned int cos_num;

    /*
     * An array to save all 'enum cbm_type' values of the feature. It is
     * used with cos_num together to get/write a feature's COS registers
     * values one by one.
     */
    enum cbm_type type[MAX_COS_NUM];

    /*
     * alt_type is 'alternative type'. When this 'alt_type' is input, the
     * feature does some special operations.
     */
    enum cbm_type alt_type;
} *feat_props[FEAT_TYPE_NUM];

/*
 * PSR features are managed per socket. Below structure defines the members
 * used to manage these features.
 * feat_init - Indicate if features on a socket have been initialized.
 * features  - A feature node array used to manage all features enabled.
 * ref_lock  - A lock to protect cos_ref.
 * cos_ref   - A reference count array to record how many domains are using the
 *             COS ID. Every entry of cos_ref corresponds to one COS ID.
 */
struct psr_socket_info {
    bool feat_init;
    /* Feature array's index is 'enum psr_feat_type' which is same as 'props' */
    struct feat_node *features[FEAT_TYPE_NUM];
    spinlock_t ref_lock;
    unsigned int cos_ref[MAX_COS_REG_CNT];
};

struct psr_assoc {
    uint64_t val;
    uint64_t cos_mask;
};

struct psr_cmt *__read_mostly psr_cmt;

static struct psr_socket_info *__read_mostly socket_info;

static unsigned int opt_psr;
static unsigned int __initdata opt_rmid_max = 255;
static unsigned int __read_mostly opt_cos_max = MAX_COS_REG_CNT;
static uint64_t rmid_mask;
static DEFINE_PER_CPU(struct psr_assoc, psr_assoc);

/*
 * Declare global feature node for every feature to facilitate the feature
 * array creation. It is used to transiently store a spare node.
 */
static struct feat_node *feat_l3;

/* Common functions */
#define cat_default_val(len) (0xffffffff >> (32 - (len)))

/*
 * Use this function to check if any allocation feature has been enabled
 * in cmdline.
 */
static bool psr_alloc_feat_enabled(void)
{
    return !!socket_info;
}

static void free_socket_resources(unsigned int socket)
{
    unsigned int i;
    struct psr_socket_info *info = socket_info + socket;

    if ( !info )
        return;

    /*
     * Free resources of features. The global feature object, e.g. feat_l3,
     * may not be freed here if it is not added into array. It is simply being
     * kept until the next CPU online attempt.
     */
    for ( i = 0; i < ARRAY_SIZE(info->features); i++ )
    {
        xfree(info->features[i]);
        info->features[i] = NULL;
    }

    info->feat_init = false;

    memset(info->cos_ref, 0, MAX_COS_REG_CNT * sizeof(unsigned int));
}

/* CAT common functions implementation. */
static int cat_init_feature(const struct cpuid_leaf *regs,
                            struct feat_node *feat,
                            struct psr_socket_info *info,
                            enum psr_feat_type type)
{
    /* No valid value so do not enable feature. */
    if ( !regs->a || !regs->d )
        return -ENOENT;

    feat->cbm_len = (regs->a & CAT_CBM_LEN_MASK) + 1;
    feat->cos_max = min(opt_cos_max, regs->d & CAT_COS_MAX_MASK);

    switch ( type )
    {
    case FEAT_TYPE_L3_CAT:
        if ( feat->cos_max < 1 )
            return -ENOENT;

        /* We reserve cos=0 as default cbm (all bits within cbm_len are 1). */
        feat->cos_reg_val[0] = cat_default_val(feat->cbm_len);

        wrmsrl(MSR_IA32_PSR_L3_MASK(0), cat_default_val(feat->cbm_len));

        break;

    default:
        return -ENOENT;
    }

    /* Add this feature into array. */
    info->features[type] = feat;

    if ( !opt_cpu_info )
        return 0;

    printk(XENLOG_INFO "CAT: enabled on socket %u, cos_max:%u, cbm_len:%u\n",
           cpu_to_socket(smp_processor_id()), feat->cos_max, feat->cbm_len);

    return 0;
}

/* L3 CAT props */
static const struct feat_props l3_cat_props = {
    .cos_num = 1,
    .type[0] = PSR_CBM_TYPE_L3,
    .alt_type = PSR_CBM_TYPE_UNKNOWN,
};

static void __init parse_psr_bool(char *s, char *value, char *feature,
                                  unsigned int mask)
{
    if ( !strcmp(s, feature) )
    {
        if ( !value )
            opt_psr |= mask;
        else
        {
            int val_int = parse_bool(value);

            if ( val_int == 0 )
                opt_psr &= ~mask;
            else if ( val_int == 1 )
                opt_psr |= mask;
        }
    }
}

static void __init parse_psr_param(char *s)
{
    char *ss, *val_str;

    do {
        ss = strchr(s, ',');
        if ( ss )
            *ss = '\0';

        val_str = strchr(s, ':');
        if ( val_str )
            *val_str++ = '\0';

        parse_psr_bool(s, val_str, "cmt", PSR_CMT);
        parse_psr_bool(s, val_str, "cat", PSR_CAT);
        parse_psr_bool(s, val_str, "cdp", PSR_CDP);

        if ( val_str && !strcmp(s, "rmid_max") )
            opt_rmid_max = simple_strtoul(val_str, NULL, 0);

        if ( val_str && !strcmp(s, "cos_max") )
            opt_cos_max = simple_strtoul(val_str, NULL, 0);

        s = ss + 1;
    } while ( ss );
}
custom_param("psr", parse_psr_param);

static void __init init_psr_cmt(unsigned int rmid_max)
{
    unsigned int eax, ebx, ecx, edx;
    unsigned int rmid;

    if ( !boot_cpu_has(X86_FEATURE_PQM) )
        return;

    cpuid_count(0xf, 0, &eax, &ebx, &ecx, &edx);
    if ( !edx )
        return;

    psr_cmt = xzalloc(struct psr_cmt);
    if ( !psr_cmt )
        return;

    psr_cmt->features = edx;
    psr_cmt->rmid_max = min(rmid_max, ebx);
    rmid_mask = ~(~0ull << get_count_order(ebx));

    if ( psr_cmt->features & PSR_RESOURCE_TYPE_L3 )
    {
        cpuid_count(0xf, 1, &eax, &ebx, &ecx, &edx);
        psr_cmt->l3.upscaling_factor = ebx;
        psr_cmt->l3.rmid_max = ecx;
        psr_cmt->l3.features = edx;
    }

    psr_cmt->rmid_max = min(psr_cmt->rmid_max, psr_cmt->l3.rmid_max);
    psr_cmt->rmid_to_dom = xmalloc_array(domid_t, psr_cmt->rmid_max + 1UL);
    if ( !psr_cmt->rmid_to_dom )
    {
        xfree(psr_cmt);
        psr_cmt = NULL;
        return;
    }

    /*
     * Once CMT is enabled each CPU will always require a RMID to associate
     * with it. To reduce the waste of RMID, reserve RMID 0 for all CPUs that
     * have no domain being monitored.
     */
    psr_cmt->rmid_to_dom[0] = DOMID_XEN;
    for ( rmid = 1; rmid <= psr_cmt->rmid_max; rmid++ )
        psr_cmt->rmid_to_dom[rmid] = DOMID_INVALID;

    printk(XENLOG_INFO "Cache Monitoring Technology enabled\n");
}

/* Called with domain lock held, no psr specific lock needed */
int psr_alloc_rmid(struct domain *d)
{
    unsigned int rmid;

    ASSERT(psr_cmt_enabled());

    if ( d->arch.psr_rmid > 0 )
        return -EEXIST;

    for ( rmid = 1; rmid <= psr_cmt->rmid_max; rmid++ )
    {
        if ( psr_cmt->rmid_to_dom[rmid] != DOMID_INVALID )
            continue;

        psr_cmt->rmid_to_dom[rmid] = d->domain_id;
        break;
    }

    /* No RMID available, assign RMID=0 by default. */
    if ( rmid > psr_cmt->rmid_max )
    {
        d->arch.psr_rmid = 0;
        return -EOVERFLOW;
    }

    d->arch.psr_rmid = rmid;

    return 0;
}

/* Called with domain lock held, no psr specific lock needed */
void psr_free_rmid(struct domain *d)
{
    unsigned int rmid;

    rmid = d->arch.psr_rmid;
    /* We do not free system reserved "RMID=0". */
    if ( rmid == 0 )
        return;

    psr_cmt->rmid_to_dom[rmid] = DOMID_INVALID;
    d->arch.psr_rmid = 0;
}

static unsigned int get_max_cos_max(const struct psr_socket_info *info)
{
    unsigned int cos_max = 0, i;

    for ( i = 0; i < ARRAY_SIZE(info->features); i++ )
    {
        const struct feat_node *feat = info->features[i];

        if ( feat )
            cos_max = max(feat->cos_max, cos_max);
    }

    return cos_max;
}

static void psr_assoc_init(void)
{
    struct psr_assoc *psra = &this_cpu(psr_assoc);

    if ( psr_alloc_feat_enabled() )
    {
        unsigned int socket = cpu_to_socket(smp_processor_id());
        const struct psr_socket_info *info = socket_info + socket;
        unsigned int cos_max = get_max_cos_max(info);

        if ( info->feat_init )
            psra->cos_mask = ((1ull << get_count_order(cos_max)) - 1) <<
                             ASSOC_REG_SHIFT;
    }

    if ( psr_cmt_enabled() || psra->cos_mask )
        rdmsrl(MSR_IA32_PSR_ASSOC, psra->val);
}

static inline void psr_assoc_rmid(uint64_t *reg, unsigned int rmid)
{
    *reg = (*reg & ~rmid_mask) | (rmid & rmid_mask);
}

static uint64_t psr_assoc_cos(uint64_t reg, unsigned int cos,
                              uint64_t cos_mask)
{
    return (reg & ~cos_mask) |
            (((uint64_t)cos << ASSOC_REG_SHIFT) & cos_mask);
}

void psr_ctxt_switch_to(struct domain *d)
{
    struct psr_assoc *psra = &this_cpu(psr_assoc);
    uint64_t reg = psra->val;

    if ( psr_cmt_enabled() )
        psr_assoc_rmid(&reg, d->arch.psr_rmid);

    /* If domain's 'psr_cos_ids' is NULL, we set default value for it. */
    if ( psra->cos_mask )
        reg = psr_assoc_cos(reg,
                  (d->arch.psr_cos_ids ?
                   d->arch.psr_cos_ids[cpu_to_socket(smp_processor_id())] :
                   0),
                  psra->cos_mask);

    if ( reg != psra->val )
    {
        wrmsrl(MSR_IA32_PSR_ASSOC, reg);
        psra->val = reg;
    }
}

int psr_get_cat_l3_info(unsigned int socket, uint32_t *cbm_len,
                        uint32_t *cos_max, uint32_t *flags)
{
    return 0;
}

int psr_get_l3_cbm(struct domain *d, unsigned int socket,
                   uint64_t *cbm, enum cbm_type type)
{
    return 0;
}

int psr_set_l3_cbm(struct domain *d, unsigned int socket,
                   uint64_t cbm, enum cbm_type type)
{
    return 0;
}

/* Called with domain lock held, no extra lock needed for 'psr_cos_ids' */
static void psr_free_cos(struct domain *d)
{
    xfree(d->arch.psr_cos_ids);
    d->arch.psr_cos_ids = NULL;
}

static void psr_alloc_cos(struct domain *d)
{
    d->arch.psr_cos_ids = xzalloc_array(unsigned int, nr_sockets);
    if ( !d->arch.psr_cos_ids )
        printk(XENLOG_WARNING "Failed to alloc psr_cos_ids!\n");
}

void psr_domain_init(struct domain *d)
{
    if ( psr_alloc_feat_enabled() )
        psr_alloc_cos(d);
}

void psr_domain_free(struct domain *d)
{
    psr_free_rmid(d);
    psr_free_cos(d);
}

static void __init init_psr(void)
{
    if ( opt_cos_max < 1 )
    {
        printk(XENLOG_INFO "CAT: disabled, cos_max is too small\n");
        return;
    }

    socket_info = xzalloc_array(struct psr_socket_info, nr_sockets);

    if ( !socket_info )
    {
        printk(XENLOG_WARNING "Failed to alloc socket_info!\n");
        return;
    }
}

static void __init psr_free(void)
{
    xfree(socket_info);
    socket_info = NULL;
}

static int psr_cpu_prepare(void)
{
    if ( !psr_alloc_feat_enabled() )
        return 0;

    /* Malloc memory for the global feature node here. */
    if ( feat_l3 == NULL &&
         (feat_l3 = xzalloc(struct feat_node)) == NULL )
        return -ENOMEM;

    return 0;
}

static void psr_cpu_init(void)
{
    struct psr_socket_info *info;
    unsigned int socket, cpu = smp_processor_id();
    struct feat_node *feat;
    struct cpuid_leaf regs;

    if ( !psr_alloc_feat_enabled() || !boot_cpu_has(X86_FEATURE_PQE) )
        goto assoc_init;

    if ( boot_cpu_data.cpuid_level < PSR_CPUID_LEVEL_CAT )
    {
        setup_clear_cpu_cap(X86_FEATURE_PQE);
        goto assoc_init;
    }

    socket = cpu_to_socket(cpu);
    info = socket_info + socket;
    if ( info->feat_init )
        goto assoc_init;

    spin_lock_init(&info->ref_lock);

    cpuid_count_leaf(PSR_CPUID_LEVEL_CAT, 0, &regs);
    if ( regs.b & PSR_RESOURCE_TYPE_L3 )
    {
        cpuid_count_leaf(PSR_CPUID_LEVEL_CAT, 1, &regs);

        feat = feat_l3;
        feat_l3 = NULL;

        if ( !cat_init_feature(&regs, feat, info, FEAT_TYPE_L3_CAT) )
            feat_props[FEAT_TYPE_L3_CAT] = &l3_cat_props;
        else
            feat_l3 = feat;
    }

    info->feat_init = true;

 assoc_init:
    psr_assoc_init();
}

static void psr_cpu_fini(unsigned int cpu)
{
    unsigned int socket = cpu_to_socket(cpu);

    if ( !psr_alloc_feat_enabled() )
        return;

    /*
     * We only free when we are the last CPU in the socket. The socket_cpumask
     * is cleared prior to this notification code by remove_siblinginfo().
     */
    if ( socket_cpumask[socket] && cpumask_empty(socket_cpumask[socket]) )
        free_socket_resources(socket);
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    int rc = 0;
    unsigned int cpu = (unsigned long)hcpu;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        rc = psr_cpu_prepare();
        break;
    case CPU_STARTING:
        psr_cpu_init();
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        psr_cpu_fini(cpu);
        break;
    }

    return !rc ? NOTIFY_DONE : notifier_from_errno(rc);
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback,
    /*
     * Ensure socket_cpumask is still valid in CPU_DEAD notification
     * (E.g. our CPU_DEAD notification should be called ahead of
     * cpu_smpboot_free).
     */
    .priority = -1
};

static int __init psr_presmp_init(void)
{
    if ( (opt_psr & PSR_CMT) && opt_rmid_max )
        init_psr_cmt(opt_rmid_max);

    if ( opt_psr & PSR_CAT )
        init_psr();

    if ( psr_cpu_prepare() )
        psr_free();

    psr_cpu_init();
    if ( psr_cmt_enabled() || psr_alloc_feat_enabled() )
        register_cpu_notifier(&cpu_nfb);

    return 0;
}
presmp_initcall(psr_presmp_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
