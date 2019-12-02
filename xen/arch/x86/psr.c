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
 * - MBA         Memory Bandwidth Allocation
 * - MSRs        Machine Specific Registers
 * - PSR         Intel Platform Shared Resource
 * - THRTL_MAX   Max throttle value (delay value) of MBA
 */

#define PSR_CMT        (1u << 0)
#define PSR_CAT        (1u << 1)
#define PSR_CDP        (1u << 2)
#define PSR_MBA        (1u << 3)

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

#define MBA_LINEAR_MASK    (1u << 2)
#define MBA_THRTL_MAX_MASK 0xfff

enum psr_feat_type {
    FEAT_TYPE_L3_CAT,
    FEAT_TYPE_L3_CDP,
    FEAT_TYPE_L2_CAT,
    FEAT_TYPE_MBA,
    FEAT_TYPE_NUM,
    FEAT_TYPE_UNKNOWN,
};

/*
 * This structure represents one feature.
 * cos_max     - The max COS registers number got through CPUID.
 * cos_reg_val - Array to store the values of COS registers. One entry stores
 *               the value of one COS register.
 *               For L3 CAT and L2 CAT, one entry corresponds to one COS_ID.
 *               For CDP, two entries correspond to one COS_ID. E.g.
 *               COS_ID=0 corresponds to cos_reg_val[0] (Data) and
 *               cos_reg_val[1] (Code).
 */
struct feat_node {
    /* cos_max is common among all features so far. */
    unsigned int cos_max;

    /* Feature specific HW info. */
    union {
        struct {
            /* The length of CBM got through CPUID. */
            unsigned int cbm_len;
        } cat;

        struct {
            /* The max throttling value got through CPUID. */
            unsigned int thrtl_max;
            bool linear;
        } mba;
    };

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
     * An array to save all 'enum psr_type' values of the feature. It is
     * used with cos_num together to get/write a feature's COS registers
     * values one by one.
     */
    enum psr_type type[MAX_COS_NUM];

    /*
     * alt_type is 'alternative type'. When this 'alt_type' is input, the
     * feature does some special operations.
     */
    enum psr_type alt_type;

    /* get_feat_info is used to return feature HW info through sysctl. */
    bool (*get_feat_info)(const struct feat_node *feat,
                          uint32_t data[], unsigned int array_len);

    /* write_msr is used to write out feature MSR register. */
    void (*write_msr)(unsigned int cos, uint32_t val, enum psr_type type);

    /*
     * sanitize is used to check if input val fulfills SDM requirement.
     * And change it to valid value if SDM allows.
     */
    bool (*sanitize)(const struct feat_node *feat, uint32_t *val);
} *feat_props[FEAT_TYPE_NUM];

/*
 * PSR features are managed per socket. Below structure defines the members
 * used to manage these features.
 * feat_init - Indicate if features on a socket have been initialized.
 * features  - A feature node array used to manage all features enabled.
 * ref_lock  - A lock to protect cos_ref.
 * cos_ref   - A reference count array to record how many domains are using the
 *             COS ID. Every entry of cos_ref corresponds to one COS ID.
 * dom_set   - A bitmap to indicate which domain's cos id has been set.
 */
struct psr_socket_info {
    bool feat_init;
    /* Feature array's index is 'enum psr_feat_type' which is same as 'props' */
    struct feat_node *features[FEAT_TYPE_NUM];
    spinlock_t ref_lock;
    unsigned int cos_ref[MAX_COS_REG_CNT];
    /* Every bit corresponds to a domain. Index is domain_id. */
    DECLARE_BITMAP(dom_set, DOMID_IDLE + 1);
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
static struct feat_node *feat_l2_cat;
static struct feat_node *feat_mba;

/* Common functions */
#define cat_default_val(len) (0xffffffff >> (32 - (len)))

/*
 * get_cdp_data - get DATA COS register value from input COS ID.
 * @feat:        the feature node.
 * @cos:         the COS ID.
 */
#define get_cdp_data(feat, cos)              \
            ((feat)->cos_reg_val[(cos) * 2])

/*
 * get_cdp_code - get CODE COS register value from input COS ID.
 * @feat:        the feature node.
 * @cos:         the COS ID.
 */
#define get_cdp_code(feat, cos)              \
            ((feat)->cos_reg_val[(cos) * 2 + 1])

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

    ASSERT(socket_info);

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

    bitmap_zero(info->dom_set, DOMID_IDLE + 1);
}

static enum psr_feat_type psr_type_to_feat_type(enum psr_type type)
{
    enum psr_feat_type feat_type = FEAT_TYPE_UNKNOWN;

    switch ( type )
    {
    case PSR_TYPE_L3_CBM:
        feat_type = FEAT_TYPE_L3_CAT;

        /*
         * If type is L3 CAT but we cannot find it in feat_props array,
         * try CDP.
         */
        if ( !feat_props[feat_type] )
            feat_type = FEAT_TYPE_L3_CDP;

        break;

    case PSR_TYPE_L3_DATA:
    case PSR_TYPE_L3_CODE:
        feat_type = FEAT_TYPE_L3_CDP;
        break;

    case PSR_TYPE_L2_CBM:
        feat_type = FEAT_TYPE_L2_CAT;
        break;

    case PSR_TYPE_MBA_THRTL:
        feat_type = FEAT_TYPE_MBA;
        break;

    default:
        ASSERT_UNREACHABLE();
    }

    return feat_type;
}

/* Implementation of allocation features' functions. */
static bool cat_check_cbm(const struct feat_node *feat, uint32_t *val)
{
    unsigned int first_bit, zero_bit;
    unsigned int cbm_len = feat->cat.cbm_len;
    unsigned long cbm = *val;

    /* Set bits should only in the range of [0, cbm_len). */
    if ( cbm & (~0ul << cbm_len) )
        return false;

    /* At least one bit need to be set. */
    if ( cbm == 0 )
        return false;

    first_bit = find_first_bit(&cbm, cbm_len);
    zero_bit = find_next_zero_bit(&cbm, cbm_len, first_bit);

    /* Set bits should be contiguous. */
    if ( zero_bit < cbm_len &&
         find_next_bit(&cbm, cbm_len, zero_bit) < cbm_len )
        return false;

    return true;
}

static bool cat_init_feature(const struct cpuid_leaf *regs,
                             struct feat_node *feat,
                             struct psr_socket_info *info,
                             enum psr_feat_type type)
{
    const char *const cat_feat_name[FEAT_TYPE_NUM] = {
        [FEAT_TYPE_L3_CAT] = "L3 CAT",
        [FEAT_TYPE_L3_CDP] = "L3 CDP",
        [FEAT_TYPE_L2_CAT] = "L2 CAT",
    };

    /* No valid value so do not enable feature. */
    if ( !regs->a || !regs->d )
        return false;

    feat->cos_max = min(opt_cos_max, regs->d & CAT_COS_MAX_MASK);
    feat->cat.cbm_len = (regs->a & CAT_CBM_LEN_MASK) + 1;

    switch ( type )
    {
    case FEAT_TYPE_L3_CAT:
    case FEAT_TYPE_L2_CAT:
        if ( feat->cos_max < 1 )
            return false;

        /* We reserve cos=0 as default cbm (all bits within cbm_len are 1). */
        feat->cos_reg_val[0] = cat_default_val(feat->cat.cbm_len);

        wrmsrl((type == FEAT_TYPE_L3_CAT ?
                MSR_IA32_PSR_L3_MASK(0) :
                MSR_IA32_PSR_L2_MASK(0)),
               cat_default_val(feat->cat.cbm_len));

        break;

    case FEAT_TYPE_L3_CDP:
    {
        uint64_t val;

        if ( feat->cos_max < 3 )
            return false;

        /* Cut half of cos_max when CDP is enabled. */
        feat->cos_max = (feat->cos_max - 1) >> 1;

        /* We reserve cos=0 as default cbm (all bits within cbm_len are 1). */
        get_cdp_code(feat, 0) = cat_default_val(feat->cat.cbm_len);
        get_cdp_data(feat, 0) = cat_default_val(feat->cat.cbm_len);

        wrmsrl(MSR_IA32_PSR_L3_MASK(0), cat_default_val(feat->cat.cbm_len));
        wrmsrl(MSR_IA32_PSR_L3_MASK(1), cat_default_val(feat->cat.cbm_len));
        rdmsrl(MSR_IA32_PSR_L3_QOS_CFG, val);
        wrmsrl(MSR_IA32_PSR_L3_QOS_CFG,
               val | (1ull << PSR_L3_QOS_CDP_ENABLE_BIT));

        break;
    }

    default:
        return false;
    }

    /* Add this feature into array. */
    info->features[type] = feat;

    if ( opt_cpu_info )
        printk(XENLOG_INFO "%s: enabled on socket %u, cos_max:%u, cbm_len:%u\n",
               cat_feat_name[type], cpu_to_socket(smp_processor_id()),
               feat->cos_max, feat->cat.cbm_len);

    return true;
}

static bool mba_init_feature(const struct cpuid_leaf *regs,
                            struct feat_node *feat,
                            struct psr_socket_info *info,
                            enum psr_feat_type type)
{
    /* No valid value so do not enable feature. */
    if ( !regs->a || !regs->d || type != FEAT_TYPE_MBA )
        return false;

    feat->cos_max = min(opt_cos_max, MASK_EXTR(regs->d, CAT_COS_MAX_MASK));
    if ( feat->cos_max < 1 )
        return false;

    feat->mba.thrtl_max = MASK_EXTR(regs->a, MBA_THRTL_MAX_MASK) + 1;

    if ( regs->c & MBA_LINEAR_MASK )
    {
        feat->mba.linear = true;

        if ( feat->mba.thrtl_max >= 100 )
            return false;
    }

    wrmsrl(MSR_IA32_PSR_MBA_MASK(0), 0);

    /* Add this feature into array. */
    info->features[type] = feat;

    if ( opt_cpu_info )
        printk(XENLOG_INFO
               "MBA: enabled on socket %u, cos_max:%u, thrtl_max:%u, linear:%d\n",
               cpu_to_socket(smp_processor_id()),
               feat->cos_max, feat->mba.thrtl_max, feat->mba.linear);

    return true;
}

static bool cat_get_feat_info(const struct feat_node *feat,
                              uint32_t data[], unsigned int array_len)
{
    if ( array_len != PSR_INFO_ARRAY_SIZE )
        return false;

    data[PSR_INFO_IDX_COS_MAX] = feat->cos_max;
    data[PSR_INFO_IDX_CAT_CBM_LEN] = feat->cat.cbm_len;
    data[PSR_INFO_IDX_CAT_FLAGS] = 0;

    return true;
}

/* L3 CAT props */
static void l3_cat_write_msr(unsigned int cos, uint32_t val,
                             enum psr_type type)
{
    wrmsrl(MSR_IA32_PSR_L3_MASK(cos), val);
}

static const struct feat_props l3_cat_props = {
    .cos_num = 1,
    .type[0] = PSR_TYPE_L3_CBM,
    .alt_type = PSR_TYPE_UNKNOWN,
    .get_feat_info = cat_get_feat_info,
    .write_msr = l3_cat_write_msr,
    .sanitize = cat_check_cbm,
};

/* L3 CDP props */
static bool l3_cdp_get_feat_info(const struct feat_node *feat,
                                 uint32_t data[], uint32_t array_len)
{
    if ( !cat_get_feat_info(feat, data, array_len) )
        return false;

    data[PSR_INFO_IDX_CAT_FLAGS] |= XEN_SYSCTL_PSR_CAT_L3_CDP;

    return true;
}

static void l3_cdp_write_msr(unsigned int cos, uint32_t val,
                             enum psr_type type)
{
    wrmsrl(((type == PSR_TYPE_L3_DATA) ?
            MSR_IA32_PSR_L3_MASK_DATA(cos) :
            MSR_IA32_PSR_L3_MASK_CODE(cos)),
           val);
}

static const struct feat_props l3_cdp_props = {
    .cos_num = 2,
    .type[0] = PSR_TYPE_L3_DATA,
    .type[1] = PSR_TYPE_L3_CODE,
    .alt_type = PSR_TYPE_L3_CBM,
    .get_feat_info = l3_cdp_get_feat_info,
    .write_msr = l3_cdp_write_msr,
    .sanitize = cat_check_cbm,
};

/* L2 CAT props */
static void l2_cat_write_msr(unsigned int cos, uint32_t val,
                             enum psr_type type)
{
    wrmsrl(MSR_IA32_PSR_L2_MASK(cos), val);
}

static const struct feat_props l2_cat_props = {
    .cos_num = 1,
    .type[0] = PSR_TYPE_L2_CBM,
    .alt_type = PSR_TYPE_UNKNOWN,
    .get_feat_info = cat_get_feat_info,
    .write_msr = l2_cat_write_msr,
    .sanitize = cat_check_cbm,
};

/* MBA props */
static bool mba_get_feat_info(const struct feat_node *feat,
                              uint32_t data[], unsigned int array_len)
{
    ASSERT(array_len == PSR_INFO_ARRAY_SIZE);

    data[PSR_INFO_IDX_COS_MAX] = feat->cos_max;
    data[PSR_INFO_IDX_MBA_THRTL_MAX] = feat->mba.thrtl_max;

    if ( feat->mba.linear )
        data[PSR_INFO_IDX_MBA_FLAGS] |= XEN_SYSCTL_PSR_MBA_LINEAR;

    return true;
}

static void mba_write_msr(unsigned int cos, uint32_t val,
                          enum psr_type type)
{
    wrmsrl(MSR_IA32_PSR_MBA_MASK(cos), val);
}

static bool mba_sanitize_thrtl(const struct feat_node *feat, uint32_t *thrtl)
{
    /*
     * Per SDM (chapter "Memory Bandwidth Allocation Configuration"):
     * 1. Linear mode: In the linear mode the input precision is defined
     *    as 100-(MBA_MAX). For instance, if the MBA_MAX value is 90, the
     *    input precision is 10%. Values not an even multiple of the
     *    precision (e.g., 12%) will be rounded down (e.g., to 10% delay
     *    applied).
     * 2. Non-linear mode: Input delay values are powers-of-two from zero
     *    to the MBA_MAX value from CPUID. In this case any values not a
     *    power of two will be rounded down the next nearest power of two.
     */
    if ( feat->mba.linear )
        *thrtl -= *thrtl % (100 - feat->mba.thrtl_max);
    else
    {
        /* Not power of 2. */
        if ( *thrtl & (*thrtl - 1) )
            *thrtl = 1 << (fls(*thrtl) - 1);
    }

    return *thrtl <= feat->mba.thrtl_max;
}

static const struct feat_props mba_props = {
    .cos_num = 1,
    .type[0] = PSR_TYPE_MBA_THRTL,
    .alt_type = PSR_TYPE_UNKNOWN,
    .get_feat_info = mba_get_feat_info,
    .write_msr = mba_write_msr,
    .sanitize = mba_sanitize_thrtl,
};

static bool __init parse_psr_bool(const char *s, const char *delim,
                                  const char *ss, const char *feature,
                                  unsigned int mask)
{
    /* If cmdline is 'psr=', we need make sure delim != s */
    if ( delim != s && !strncmp(s, feature, delim - s) )
    {
        if ( !*delim || *delim == ',' )
            opt_psr |= mask;
        else
        {
            int val_int = parse_bool(delim + 1, ss);

            if ( val_int == 0 )
                opt_psr &= ~mask;
            else if ( val_int == 1 )
                opt_psr |= mask;
            else
                return false;
        }
        return true;
    }
    return false;
}

static int __init parse_psr_param(const char *s)
{
    const char *ss, *val_delim;
    const char *q;
    int rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        val_delim = strchr(s, ':');
        if ( !val_delim )
            val_delim = strchr(s, '\0');

        /* E.g. 'psr=cmt,rmid_max:200' */
        if ( val_delim > ss )
            val_delim = ss;

        if ( *val_delim && !cmdline_strcmp(s, "rmid_max") )
        {
            opt_rmid_max = simple_strtoul(val_delim + 1, &q, 0);
            if ( *q && *q != ',' )
                rc = -EINVAL;
        }
        else if ( *val_delim && !cmdline_strcmp(s, "cos_max") )
        {
            opt_cos_max = simple_strtoul(val_delim + 1, &q, 0);
            if ( *q && *q != ',' )
                rc = -EINVAL;
        }
        else if ( !parse_psr_bool(s, val_delim, ss, "cmt", PSR_CMT) &&
                  !parse_psr_bool(s, val_delim, ss, "cat", PSR_CAT) &&
                  !parse_psr_bool(s, val_delim, ss, "cdp", PSR_CDP) &&
                  !parse_psr_bool(s, val_delim, ss, "mba", PSR_MBA) )
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
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

    /*
     * If the domain is not set in 'dom_set' bitmap, that means the domain's
     * cos id is not valid. So, we have to use default value (0) to set ASSOC
     * register. Furthermore, if domain's 'psr_cos_ids' is NULL, we need
     * default value for it too (for case that the domain's psr_cos_ids is not
     * successfully allocated).
     */
    if ( psra->cos_mask )
    {
        unsigned int socket = cpu_to_socket(smp_processor_id());
        struct psr_socket_info *info = socket_info + socket;
        unsigned int cos = 0;

        if ( likely(test_bit(d->domain_id, info->dom_set)) &&
             d->arch.psr_cos_ids )
            cos = d->arch.psr_cos_ids[socket];

        reg = psr_assoc_cos(reg, cos, psra->cos_mask);
    }

    if ( reg != psra->val )
    {
        wrmsrl(MSR_IA32_PSR_ASSOC, reg);
        psra->val = reg;
    }
}

static struct psr_socket_info *get_socket_info(unsigned int socket)
{
    if ( !socket_info )
        return ERR_PTR(-ENODEV);

    if ( socket >= nr_sockets )
        return ERR_PTR(-ERANGE);

    if ( !socket_info[socket].feat_init )
        return ERR_PTR(-ENOENT);

    return socket_info + socket;
}

int psr_get_info(unsigned int socket, enum psr_type type,
                 uint32_t data[], unsigned int array_len)
{
    const struct psr_socket_info *info = get_socket_info(socket);
    const struct feat_node *feat;
    enum psr_feat_type feat_type;

    ASSERT(data);

    if ( IS_ERR(info) )
        return PTR_ERR(info);

    feat_type = psr_type_to_feat_type(type);
    if ( feat_type >= ARRAY_SIZE(info->features) )
        return -ENOENT;

    feat = info->features[feat_type];
    if ( !feat )
        return -ENOENT;

    if ( !feat_props[feat_type] )
    {
        ASSERT_UNREACHABLE();
        return -ENOENT;
    }

    if ( feat_props[feat_type]->get_feat_info(feat, data, array_len) )
        return 0;

    return -EINVAL;
}

int psr_get_val(struct domain *d, unsigned int socket,
                uint32_t *val, enum psr_type type)
{
    const struct psr_socket_info *info = get_socket_info(socket);
    const struct feat_node *feat;
    enum psr_feat_type feat_type;
    unsigned int cos, i;

    ASSERT(val);

    if ( IS_ERR(info) )
        return PTR_ERR(info);

    feat_type = psr_type_to_feat_type(type);
    if ( feat_type >= ARRAY_SIZE(info->features) )
        return -ENOENT;

    feat = info->features[feat_type];
    if ( !feat )
        return -ENOENT;

    if ( !feat_props[feat_type] )
    {
        ASSERT_UNREACHABLE();
        return -ENOENT;
    }

    domain_lock(d);
    if ( !test_and_set_bit(d->domain_id, socket_info[socket].dom_set) )
        d->arch.psr_cos_ids[socket] = 0;

    cos = d->arch.psr_cos_ids[socket];
    domain_unlock(d);

    /*
     * If input cos exceeds current feature's cos_max, we should return its
     * default value which is stored in cos 0. This case only happens
     * when more than two features enabled concurrently and at least one
     * features's cos_max is bigger than others. When a domain's working cos
     * id is bigger than some features' cos_max, HW automatically works as
     * default value for those features which cos_max is smaller.
     */
    if ( cos > feat->cos_max )
        cos = 0;

    for ( i = 0; i < feat_props[feat_type]->cos_num; i++ )
    {
        if ( type == feat_props[feat_type]->type[i] )
        {
            *val = feat->cos_reg_val[cos * feat_props[feat_type]->cos_num + i];
            return 0;
        }
    }

    return -EINVAL;
}

/* Set value functions */
static unsigned int get_cos_num(void)
{
    unsigned int num = 0, i;

    /* Get all features total amount. */
    for ( i = 0; i < ARRAY_SIZE(feat_props); i++ )
        if ( feat_props[i] )
            num += feat_props[i]->cos_num;

    return num;
}

static int gather_val_array(uint32_t val[],
                            unsigned int array_len,
                            const struct psr_socket_info *info,
                            unsigned int old_cos)
{
    unsigned int i;

    if ( !val )
        return -EINVAL;

    /* Get all features current values according to old_cos. */
    for ( i = 0; i < ARRAY_SIZE(info->features); i++ )
    {
        unsigned int cos = old_cos, j;
        const struct feat_node *feat = info->features[i];
        const struct feat_props *props = feat_props[i];

        if ( !feat )
            continue;

        if ( !props )
        {
            ASSERT_UNREACHABLE();
            return -ENOENT;
        }

        if ( array_len < props->cos_num )
            return -ENOSPC;

        /*
         * If old_cos exceeds current feature's cos_max, we should get
         * default value. So assign cos to 0 which stores default value.
         */
        if ( cos > feat->cos_max )
            cos = 0;

        /* Value getting order is same as feature array. */
        for ( j = 0; j < props->cos_num; j++ )
            val[j] = feat->cos_reg_val[cos * props->cos_num + j];

        array_len -= props->cos_num;
        val += props->cos_num;
    }

    return 0;
}

static int skip_prior_features(unsigned int *array_len,
                               enum psr_feat_type feat_type)
{
    unsigned int i, skip_len = 0;

    for ( i = 0; i < feat_type; i++ )
    {
        const struct feat_props *props = feat_props[i];

        if ( !props )
            continue;

        if ( *array_len <= props->cos_num )
            return -ENOSPC;

        *array_len -= props->cos_num;
        skip_len += props->cos_num;
    }

    return skip_len;
}

static int insert_val_into_array(uint32_t val[],
                                 unsigned int array_len,
                                 const struct psr_socket_info *info,
                                 enum psr_feat_type feat_type,
                                 enum psr_type type,
                                 uint32_t new_val)
{
    const struct feat_node *feat;
    const struct feat_props *props;
    unsigned int i;
    int ret;

    ASSERT(feat_type < FEAT_TYPE_NUM);

    ret = skip_prior_features(&array_len, feat_type);
    if ( ret < 0 )
        return ret;

    val += ret;

    feat = info->features[feat_type];
    if ( !feat )
        return -ENOENT;

    props = feat_props[feat_type];
    if ( !props )
    {
        ASSERT_UNREACHABLE();
        return -ENOENT;
    }

    if ( array_len < props->cos_num )
        return -ENOSPC;

    if ( !props->sanitize(feat, &new_val) )
        return -EINVAL;

    /*
     * Value setting position is same as feature array.
     * For CDP, user may set both DATA and CODE to same value. For such case,
     * user input 'PSR_TYPE_L3_CBM' as type. The alternative type of CDP is
     * same as it. So we should set new_val to both of DATA and CODE under such
     * case.
     */
    for ( i = 0; i < props->cos_num; i++ )
    {
        if ( type == props->type[i] )
        {
            val[i] = new_val;
            ret = 0;
            break;
        }
        else if ( type == props->alt_type )
            val[i] = new_val;
        else
            ret = -EINVAL;
    }

    return ret;
}

static int compare_val(const uint32_t val[],
                       const struct feat_node *feat,
                       const struct feat_props *props,
                       unsigned int cos)
{
    unsigned int i;

    for ( i = 0; i < props->cos_num; i++ )
    {
        uint32_t feat_val;

        /* If cos is bigger than cos_max, we need compare default value. */
        if ( cos > feat->cos_max )
        {
            /*
             * COS ID 0 always stores the default value.
             * For CDP:
             * - DATA default value stored in cos_reg_val[0];
             * - CODE default value stored in cos_reg_val[1].
             */
            feat_val = feat->cos_reg_val[i];

            /*
             * If cos is bigger than feature's cos_max, the val should be
             * default value. Otherwise, it fails to find a COS ID. So we
             * have to exit find flow.
             */
            if ( val[i] != feat_val )
                return -EINVAL;
        }
        else
        {
            feat_val = feat->cos_reg_val[cos * props->cos_num + i];
            if ( val[i] != feat_val )
                return 0;
        }
    }

    return 1;
}

static int find_cos(const uint32_t val[], unsigned int array_len,
                    enum psr_feat_type feat_type,
                    const struct psr_socket_info *info)
{
    unsigned int cos, cos_max;
    const unsigned int *ref = info->cos_ref;
    const struct feat_node *feat;

    /* cos_max is the one of the feature which is being set. */
    feat = info->features[feat_type];
    if ( !feat )
        return -ENOENT;

    cos_max = feat->cos_max;

    for ( cos = 0; cos <= cos_max; cos++ )
    {
        const uint32_t *val_ptr = val;
        unsigned int len = array_len, i;
        int rc = 0;

        if ( cos && !ref[cos] )
            continue;

        for ( i = 0; i < ARRAY_SIZE(info->features); i++ )
        {
            const struct feat_props *props = feat_props[i];

            feat = info->features[i];
            if ( !feat )
                continue;

            if ( !props )
            {
                ASSERT_UNREACHABLE();
                return -ENOENT;
            }

            if ( len < props->cos_num )
                return -ENOSPC;

            /*
             * Compare value according to feature array order.
             * We must follow this order because value array is assembled
             * as this order.
             */
            rc = compare_val(val_ptr, feat, props, cos);
            if ( rc < 0 )
                return rc;

            /* If fail to match, go to next cos to compare. */
            if ( !rc )
                break;

            len -= props->cos_num;
            val_ptr += props->cos_num;
        }

        /* For this COS ID all entries in the values array do match. Use it. */
        if ( rc )
            return cos;
    }

    return -ENOENT;
}

static bool fits_cos_max(const uint32_t val[],
                         uint32_t array_len,
                         const struct psr_socket_info *info,
                         unsigned int cos)
{
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(info->features); i++ )
    {
        const struct feat_node *feat = info->features[i];
        const struct feat_props *props = feat_props[i];

        if ( !feat )
            continue;

        if ( !props )
        {
            ASSERT_UNREACHABLE();
            return false;
        }

        if ( array_len < props->cos_num )
            return false;

        if ( cos > feat->cos_max )
        {
            unsigned int j;

            for ( j = 0; j < props->cos_num; j++ )
            {
                /* Get default value, the COS ID of which is zero. */
                uint32_t default_val = feat->cos_reg_val[j];

                if ( val[j] != default_val )
                    return false;
            }
        }

        array_len -= props->cos_num;
        val += props->cos_num;
    }

    return true;
}

static int pick_avail_cos(const struct psr_socket_info *info,
                          const uint32_t val[], unsigned int array_len,
                          unsigned int old_cos,
                          enum psr_feat_type feat_type)
{
    unsigned int cos, cos_max = 0;
    const struct feat_node *feat;
    const unsigned int *ref = info->cos_ref;

    /* cos_max is the one of the feature which is being set. */
    feat = info->features[feat_type];
    if ( !feat )
        return -ENOENT;

    cos_max = feat->cos_max;
    if ( !cos_max )
        return -ENOENT;

    /* We cannot use id 0 because it stores the default values. */
    if ( old_cos && ref[old_cos] == 1 &&
         fits_cos_max(val, array_len, info, old_cos) )
            return old_cos;

    /* Find an unused one other than cos0. */
    for ( cos = 1; cos <= cos_max; cos++ )
    {
        /*
         * ref is 0 means this COS is not used by other domain and
         * can be used for current setting.
         */
        if ( !ref[cos] )
        {
            if ( !fits_cos_max(val, array_len, info, cos) )
                break;

            return cos;
        }
    }

    return -EOVERFLOW;
}

static unsigned int get_socket_cpu(unsigned int socket)
{
    if ( likely(socket < nr_sockets) )
        return cpumask_any(socket_cpumask[socket]);

    return nr_cpu_ids;
}

struct cos_write_info
{
    unsigned int cos;
    unsigned int array_len;
    const uint32_t *val;
};

static void do_write_psr_msrs(void *data)
{
    const struct cos_write_info *info = data;
    unsigned int i, index, cos = info->cos;
    const struct psr_socket_info *socket_info =
        get_socket_info(cpu_to_socket(smp_processor_id()));

    /*
     * Iterate all featuers to write different value (not same as MSR) for
     * each feature.
     */
    for ( index = i = 0; i < ARRAY_SIZE(feat_props); i++ )
    {
        struct feat_node *feat = socket_info->features[i];
        const struct feat_props *props = feat_props[i];
        unsigned int cos_num, j;

        if ( !feat || !props )
            continue;

        cos_num = props->cos_num;
        ASSERT(info->array_len >= index + cos_num);

        /*
         * Multiple RDT features may co-exist and their COS_MAX may be
         * different. So we should prevent one feature to write COS
         * register which exceeds its COS_MAX.
         */
        if ( cos > feat->cos_max )
        {
            index += cos_num;
            continue;
        }

        for ( j = 0; j < cos_num; j++, index++ )
        {
            if ( feat->cos_reg_val[cos * cos_num + j] != info->val[index] )
            {
                feat->cos_reg_val[cos * cos_num + j] = info->val[index];
                props->write_msr(cos, info->val[index], props->type[j]);
            }
        }
    }
}

static int write_psr_msrs(unsigned int socket, unsigned int cos,
                          const uint32_t val[], unsigned int array_len,
                          enum psr_feat_type feat_type)
{
    struct psr_socket_info *info = get_socket_info(socket);
    struct cos_write_info data =
    {
        .cos = cos,
        .val = val,
        .array_len = array_len,
    };

    if ( cos > info->features[feat_type]->cos_max )
        return -EINVAL;

    if ( socket == cpu_to_socket(smp_processor_id()) )
        do_write_psr_msrs(&data);
    else
    {
        unsigned int cpu = get_socket_cpu(socket);

        if ( cpu >= nr_cpu_ids )
            return -ENOTSOCK;
        on_selected_cpus(cpumask_of(cpu), do_write_psr_msrs, &data, 1);
    }

    return 0;
}

int psr_set_val(struct domain *d, unsigned int socket,
                uint64_t new_val, enum psr_type type)
{
    unsigned int old_cos, array_len;
    int cos, ret;
    unsigned int *ref;
    uint32_t *val_array, val;
    struct psr_socket_info *info = get_socket_info(socket);
    enum psr_feat_type feat_type;

    if ( IS_ERR(info) )
        return PTR_ERR(info);

    val = new_val;
    if ( new_val != val )
        return -EINVAL;

    feat_type = psr_type_to_feat_type(type);
    if ( feat_type >= ARRAY_SIZE(info->features) ||
         !info->features[feat_type] )
        return -ENOENT;

    /*
     * Step 0:
     * old_cos means the COS ID current domain is using. By default, it is 0.
     *
     * For every COS ID, there is a reference count to record how many domains
     * are using the COS register corresponding to this COS ID.
     * - If ref[old_cos] is 0, that means this COS is not used by any domain.
     * - If ref[old_cos] is 1, that means this COS is only used by current
     *   domain.
     * - If ref[old_cos] is more than 1, that mean multiple domains are using
     *   this COS.
     */
    domain_lock(d);
    if ( !test_and_set_bit(d->domain_id, info->dom_set) )
        d->arch.psr_cos_ids[socket] = 0;

    old_cos = d->arch.psr_cos_ids[socket];
    domain_unlock(d);

    ASSERT(old_cos < MAX_COS_REG_CNT);

    ref = info->cos_ref;

    /*
     * Step 1:
     * Gather a value array to store all features cos_reg_val[old_cos].
     * And, set the input new val into array according to the feature's
     * position in array.
     */
    array_len = get_cos_num();
    val_array = xzalloc_array(uint32_t, array_len);
    if ( !val_array )
        return -ENOMEM;

    if ( (ret = gather_val_array(val_array, array_len, info, old_cos)) != 0 )
        goto free_array;

    if ( (ret = insert_val_into_array(val_array, array_len, info,
                                      feat_type, type, val)) != 0 )
        goto free_array;

    spin_lock(&info->ref_lock);

    /*
     * Step 2:
     * Try to find if there is already a COS ID on which all features' values
     * are same as the array. Then, we can reuse this COS ID.
     */
    cos = find_cos(val_array, array_len, feat_type, info);
    if ( cos == old_cos )
    {
        ret = 0;
        goto unlock_free_array;
    }

    /*
     * Step 3:
     * If fail to find, we need pick an available COS ID.
     * In fact, only COS ID which ref is 1 or 0 can be picked for current
     * domain. If old_cos is not 0 and its ref==1, that means only current
     * domain is using this old_cos ID. So, this old_cos ID certainly can
     * be reused by current domain. Ref==0 means there is no any domain
     * using this COS ID. So it can be used for current domain too.
     */
    if ( cos < 0 )
    {
        cos = pick_avail_cos(info, val_array, array_len, old_cos, feat_type);
        if ( cos < 0 )
        {
            ret = cos;
            goto unlock_free_array;
        }

        /*
         * Step 4:
         * Write the feature's MSRs according to the COS ID.
         */
        ret = write_psr_msrs(socket, cos, val_array, array_len, feat_type);
        if ( ret )
            goto unlock_free_array;
    }

    /*
     * Step 5:
     * Find the COS ID (find_cos result is '>= 0' or an available COS ID is
     * picked, then update ref according to COS ID.
     */
    ref[cos]++;
    ASSERT(!cos || ref[cos]);
    ASSERT(!old_cos || ref[old_cos]);
    ref[old_cos]--;
    spin_unlock(&info->ref_lock);

    /*
     * Step 6:
     * Save the COS ID into current domain's psr_cos_ids[] so that we can know
     * which COS the domain is using on the socket. One domain can only use
     * one COS ID at same time on each socket.
     */
    domain_lock(d);
    d->arch.psr_cos_ids[socket] = cos;
    domain_unlock(d);

    goto free_array;

 unlock_free_array:
    spin_unlock(&info->ref_lock);

 free_array:
    xfree(val_array);
    return ret;
}

static void psr_free_cos(struct domain *d)
{
    unsigned int socket, cos;

    if ( !d->arch.psr_cos_ids )
        return;

    ASSERT(socket_info);

    /* Domain is destroyed so its cos_ref should be decreased. */
    for ( socket = 0; socket < nr_sockets; socket++ )
    {
        struct psr_socket_info *info = socket_info + socket;

        clear_bit(d->domain_id, info->dom_set);

        /* cos 0 is default one which does not need be handled. */
        cos = d->arch.psr_cos_ids[socket];
        if ( cos == 0 )
            continue;

        spin_lock(&info->ref_lock);
        ASSERT(info->cos_ref[cos]);
        info->cos_ref[cos]--;
        spin_unlock(&info->ref_lock);
    }

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

    if ( feat_l2_cat == NULL &&
         (feat_l2_cat = xzalloc(struct feat_node)) == NULL )
        return -ENOMEM;

    if ( feat_mba == NULL &&
         (feat_mba = xzalloc(struct feat_node)) == NULL )
        return -ENOMEM;

    return 0;
}

static void psr_cpu_init(void)
{
    struct psr_socket_info *info;
    unsigned int socket, cpu = smp_processor_id();
    struct feat_node *feat;
    struct cpuid_leaf regs;
    uint32_t feat_mask;

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
    feat_mask = regs.b;
    if ( feat_mask & PSR_RESOURCE_TYPE_L3 )
    {
        cpuid_count_leaf(PSR_CPUID_LEVEL_CAT, 1, &regs);

        feat = feat_l3;
        feat_l3 = NULL;

        if ( (regs.c & PSR_CAT_CDP_CAPABILITY) && (opt_psr & PSR_CDP) &&
             cat_init_feature(&regs, feat, info, FEAT_TYPE_L3_CDP) )
            feat_props[FEAT_TYPE_L3_CDP] = &l3_cdp_props;

        /* If CDP init fails, try to work as L3 CAT. */
        if ( !feat_props[FEAT_TYPE_L3_CDP] )
        {
            if ( cat_init_feature(&regs, feat, info, FEAT_TYPE_L3_CAT) )
                feat_props[FEAT_TYPE_L3_CAT] = &l3_cat_props;
            else
                feat_l3 = feat;
        }
    }

    if ( feat_mask & PSR_RESOURCE_TYPE_L2 )
    {
        cpuid_count_leaf(PSR_CPUID_LEVEL_CAT, 2, &regs);

        feat = feat_l2_cat;
        feat_l2_cat = NULL;
        if ( cat_init_feature(&regs, feat, info, FEAT_TYPE_L2_CAT) )
            feat_props[FEAT_TYPE_L2_CAT] = &l2_cat_props;
        else
            feat_l2_cat = feat;
    }

    if ( feat_mask & PSR_RESOURCE_TYPE_MBA )
    {
        cpuid_count_leaf(PSR_CPUID_LEVEL_CAT, 3, &regs);

        feat = feat_mba;
        feat_mba = NULL;
        if ( mba_init_feature(&regs, feat, info, FEAT_TYPE_MBA) )
            feat_props[FEAT_TYPE_MBA] = &mba_props;
        else
            feat_mba = feat;
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

    if ( opt_psr & (PSR_CAT | PSR_CDP | PSR_MBA) )
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
