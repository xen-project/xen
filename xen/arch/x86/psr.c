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
#include <xen/init.h>
#include <xen/cpu.h>
#include <xen/sched.h>
#include <asm/psr.h>

#define PSR_CMT        (1<<0)
#define PSR_CAT        (1<<1)

struct psr_cat_cbm {
    uint64_t cbm;
    unsigned int ref;
};

struct psr_cat_socket_info {
    unsigned int cbm_len;
    unsigned int cos_max;
    struct psr_cat_cbm *cos_to_cbm;
    spinlock_t cbm_lock;
};

struct psr_assoc {
    uint64_t val;
};

struct psr_cmt *__read_mostly psr_cmt;

static unsigned long *__read_mostly cat_socket_enable;
static struct psr_cat_socket_info *__read_mostly cat_socket_info;

static unsigned int __initdata opt_psr;
static unsigned int __initdata opt_rmid_max = 255;
static unsigned int __read_mostly opt_cos_max = 255;
static uint64_t rmid_mask;
static DEFINE_PER_CPU(struct psr_assoc, psr_assoc);

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

    if ( !boot_cpu_has(X86_FEATURE_CMT) )
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
        return -EUSERS;
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

static inline void psr_assoc_init(void)
{
    struct psr_assoc *psra = &this_cpu(psr_assoc);

    if ( psr_cmt_enabled() )
        rdmsrl(MSR_IA32_PSR_ASSOC, psra->val);
}

static inline void psr_assoc_rmid(uint64_t *reg, unsigned int rmid)
{
    *reg = (*reg & ~rmid_mask) | (rmid & rmid_mask);
}

void psr_ctxt_switch_to(struct domain *d)
{
    struct psr_assoc *psra = &this_cpu(psr_assoc);
    uint64_t reg = psra->val;

    if ( psr_cmt_enabled() )
        psr_assoc_rmid(&reg, d->arch.psr_rmid);

    if ( reg != psra->val )
    {
        wrmsrl(MSR_IA32_PSR_ASSOC, reg);
        psra->val = reg;
    }
}

/* Called with domain lock held, no extra lock needed for 'psr_cos_ids' */
static void psr_free_cos(struct domain *d)
{
    unsigned int socket;
    unsigned int cos;
    struct psr_cat_socket_info *info;

    if( !d->arch.psr_cos_ids )
        return;

    for_each_set_bit(socket, cat_socket_enable, nr_sockets)
    {
        if ( (cos = d->arch.psr_cos_ids[socket]) == 0 )
            continue;

        info = cat_socket_info + socket;
        spin_lock(&info->cbm_lock);
        info->cos_to_cbm[cos].ref--;
        spin_unlock(&info->cbm_lock);
    }

    xfree(d->arch.psr_cos_ids);
    d->arch.psr_cos_ids = NULL;
}

int psr_domain_init(struct domain *d)
{
    if ( cat_socket_info )
    {
        d->arch.psr_cos_ids = xzalloc_array(unsigned int, nr_sockets);
        if ( !d->arch.psr_cos_ids )
            return -ENOMEM;
    }

    return 0;
}

void psr_domain_free(struct domain *d)
{
    psr_free_rmid(d);
    psr_free_cos(d);
}

static int cat_cpu_prepare(unsigned int cpu)
{
    struct psr_cat_socket_info *info;
    unsigned int socket;

    if ( !cat_socket_info )
        return 0;

    socket = cpu_to_socket(cpu);
    if ( socket >= nr_sockets )
        return -ENOSPC;

    info = cat_socket_info + socket;
    if ( info->cos_to_cbm )
        return 0;

    info->cos_to_cbm = xzalloc_array(struct psr_cat_cbm, opt_cos_max + 1UL);
    return info->cos_to_cbm ? 0 : -ENOMEM;
}

static void cat_cpu_init(void)
{
    unsigned int eax, ebx, ecx, edx;
    struct psr_cat_socket_info *info;
    unsigned int socket;
    unsigned int cpu = smp_processor_id();
    const struct cpuinfo_x86 *c = cpu_data + cpu;

    if ( !cpu_has(c, X86_FEATURE_CAT) || c->cpuid_level < PSR_CPUID_LEVEL_CAT )
        return;

    socket = cpu_to_socket(cpu);
    if ( test_bit(socket, cat_socket_enable) )
        return;

    cpuid_count(PSR_CPUID_LEVEL_CAT, 0, &eax, &ebx, &ecx, &edx);
    if ( ebx & PSR_RESOURCE_TYPE_L3 )
    {
        cpuid_count(PSR_CPUID_LEVEL_CAT, 1, &eax, &ebx, &ecx, &edx);
        info = cat_socket_info + socket;
        info->cbm_len = (eax & 0x1f) + 1;
        info->cos_max = min(opt_cos_max, edx & 0xffff);

        /* cos=0 is reserved as default cbm(all ones). */
        info->cos_to_cbm[0].cbm = (1ull << info->cbm_len) - 1;

        spin_lock_init(&info->cbm_lock);

        set_bit(socket, cat_socket_enable);
        printk(XENLOG_INFO "CAT: enabled on socket %u, cos_max:%u, cbm_len:%u\n",
               socket, info->cos_max, info->cbm_len);
    }
}

static void cat_cpu_fini(unsigned int cpu)
{
    unsigned int socket = cpu_to_socket(cpu);

    if ( !socket_cpumask[socket] || cpumask_empty(socket_cpumask[socket]) )
    {
        struct psr_cat_socket_info *info = cat_socket_info + socket;

        if ( info->cos_to_cbm )
        {
            xfree(info->cos_to_cbm);
            info->cos_to_cbm = NULL;
        }
        clear_bit(socket, cat_socket_enable);
    }
}

static void __init psr_cat_free(void)
{
    xfree(cat_socket_enable);
    cat_socket_enable = NULL;
    xfree(cat_socket_info);
    cat_socket_info = NULL;
}

static void __init init_psr_cat(void)
{
    if ( opt_cos_max < 1 )
    {
        printk(XENLOG_INFO "CAT: disabled, cos_max is too small\n");
        return;
    }

    cat_socket_enable = xzalloc_array(unsigned long, BITS_TO_LONGS(nr_sockets));
    cat_socket_info = xzalloc_array(struct psr_cat_socket_info, nr_sockets);

    if ( !cat_socket_enable || !cat_socket_info )
        psr_cat_free();
}

static int psr_cpu_prepare(unsigned int cpu)
{
    return cat_cpu_prepare(cpu);
}

static void psr_cpu_init(void)
{
    if ( cat_socket_info )
        cat_cpu_init();

    psr_assoc_init();
}

static void psr_cpu_fini(unsigned int cpu)
{
    if ( cat_socket_info )
        cat_cpu_fini(cpu);
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    int rc = 0;
    unsigned int cpu = (unsigned long)hcpu;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        rc = psr_cpu_prepare(cpu);
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
        init_psr_cat();

    if ( psr_cpu_prepare(0) )
        psr_cat_free();

    psr_cpu_init();
    if ( psr_cmt_enabled() || cat_socket_info )
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
