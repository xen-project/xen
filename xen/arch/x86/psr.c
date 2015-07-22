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
#include <xen/err.h>
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
    uint64_t cos_mask;
};

struct psr_cmt *__read_mostly psr_cmt;

static unsigned long *__read_mostly cat_socket_enable;
static struct psr_cat_socket_info *__read_mostly cat_socket_info;

static unsigned int __initdata opt_psr;
static unsigned int __initdata opt_rmid_max = 255;
static unsigned int __read_mostly opt_cos_max = 255;
static uint64_t rmid_mask;
static DEFINE_PER_CPU(struct psr_assoc, psr_assoc);

static struct psr_cat_cbm *temp_cos_to_cbm;

static unsigned int get_socket_cpu(unsigned int socket)
{
    if ( likely(socket < nr_sockets) )
        return cpumask_any(socket_cpumask[socket]);

    return nr_cpu_ids;
}

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

static inline void psr_assoc_init(void)
{
    struct psr_assoc *psra = &this_cpu(psr_assoc);

    if ( cat_socket_info )
    {
        unsigned int socket = cpu_to_socket(smp_processor_id());

        if ( test_bit(socket, cat_socket_enable) )
            psra->cos_mask = ((1ull << get_count_order(
                             cat_socket_info[socket].cos_max)) - 1) << 32;
    }

    if ( psr_cmt_enabled() || psra->cos_mask )
        rdmsrl(MSR_IA32_PSR_ASSOC, psra->val);
}

static inline void psr_assoc_rmid(uint64_t *reg, unsigned int rmid)
{
    *reg = (*reg & ~rmid_mask) | (rmid & rmid_mask);
}

static inline void psr_assoc_cos(uint64_t *reg, unsigned int cos,
                                 uint64_t cos_mask)
{
    *reg = (*reg & ~cos_mask) | (((uint64_t)cos << 32) & cos_mask);
}

void psr_ctxt_switch_to(struct domain *d)
{
    struct psr_assoc *psra = &this_cpu(psr_assoc);
    uint64_t reg = psra->val;

    if ( psr_cmt_enabled() )
        psr_assoc_rmid(&reg, d->arch.psr_rmid);

    if ( psra->cos_mask )
        psr_assoc_cos(&reg, d->arch.psr_cos_ids ?
                      d->arch.psr_cos_ids[cpu_to_socket(smp_processor_id())] :
                      0, psra->cos_mask);

    if ( reg != psra->val )
    {
        wrmsrl(MSR_IA32_PSR_ASSOC, reg);
        psra->val = reg;
    }
}
static struct psr_cat_socket_info *get_cat_socket_info(unsigned int socket)
{
    if ( !cat_socket_info )
        return ERR_PTR(-ENODEV);

    if ( socket >= nr_sockets )
        return ERR_PTR(-ENOTSOCK);

    if ( !test_bit(socket, cat_socket_enable) )
        return ERR_PTR(-ENOENT);

    return cat_socket_info + socket;
}

int psr_get_cat_l3_info(unsigned int socket, uint32_t *cbm_len,
                        uint32_t *cos_max)
{
    struct psr_cat_socket_info *info = get_cat_socket_info(socket);

    if ( IS_ERR(info) )
        return PTR_ERR(info);

    *cbm_len = info->cbm_len;
    *cos_max = info->cos_max;

    return 0;
}

int psr_get_l3_cbm(struct domain *d, unsigned int socket, uint64_t *cbm)
{
    struct psr_cat_socket_info *info = get_cat_socket_info(socket);

    if ( IS_ERR(info) )
        return PTR_ERR(info);

    *cbm = info->cos_to_cbm[d->arch.psr_cos_ids[socket]].cbm;

    return 0;
}

static bool_t psr_check_cbm(unsigned int cbm_len, uint64_t cbm)
{
    unsigned int first_bit, zero_bit;

    /* Set bits should only in the range of [0, cbm_len). */
    if ( cbm & (~0ull << cbm_len) )
        return 0;

    /* At least one bit need to be set. */
    if ( cbm == 0 )
        return 0;

    first_bit = find_first_bit(&cbm, cbm_len);
    zero_bit = find_next_zero_bit(&cbm, cbm_len, first_bit);

    /* Set bits should be contiguous. */
    if ( zero_bit < cbm_len &&
         find_next_bit(&cbm, cbm_len, zero_bit) < cbm_len )
        return 0;

    return 1;
}

struct cos_cbm_info
{
    unsigned int cos;
    uint64_t cbm;
};

static void do_write_l3_cbm(void *data)
{
    struct cos_cbm_info *info = data;

    wrmsrl(MSR_IA32_PSR_L3_MASK(info->cos), info->cbm);
}

static int write_l3_cbm(unsigned int socket, unsigned int cos, uint64_t cbm)
{
    struct cos_cbm_info info = { .cos = cos, .cbm = cbm };

    if ( socket == cpu_to_socket(smp_processor_id()) )
        do_write_l3_cbm(&info);
    else
    {
        unsigned int cpu = get_socket_cpu(socket);

        if ( cpu >= nr_cpu_ids )
            return -ENOTSOCK;
        on_selected_cpus(cpumask_of(cpu), do_write_l3_cbm, &info, 1);
    }

    return 0;
}

int psr_set_l3_cbm(struct domain *d, unsigned int socket, uint64_t cbm)
{
    unsigned int old_cos, cos;
    struct psr_cat_cbm *map, *found = NULL;
    struct psr_cat_socket_info *info = get_cat_socket_info(socket);

    if ( IS_ERR(info) )
        return PTR_ERR(info);

    if ( !psr_check_cbm(info->cbm_len, cbm) )
        return -EINVAL;

    old_cos = d->arch.psr_cos_ids[socket];
    map = info->cos_to_cbm;

    spin_lock(&info->cbm_lock);

    for ( cos = 0; cos <= info->cos_max; cos++ )
    {
        /* If still not found, then keep unused one. */
        if ( !found && cos != 0 && map[cos].ref == 0 )
            found = map + cos;
        else if ( map[cos].cbm == cbm )
        {
            if ( unlikely(cos == old_cos) )
            {
                ASSERT(cos == 0 || map[cos].ref != 0);
                spin_unlock(&info->cbm_lock);
                return 0;
            }
            found = map + cos;
            break;
        }
    }

    /* If old cos is referred only by the domain, then use it. */
    if ( !found && map[old_cos].ref == 1 )
        found = map + old_cos;

    if ( !found )
    {
        spin_unlock(&info->cbm_lock);
        return -EOVERFLOW;
    }

    cos = found - map;
    if ( found->cbm != cbm )
    {
        int ret = write_l3_cbm(socket, cos, cbm);

        if ( ret )
        {
            spin_unlock(&info->cbm_lock);
            return ret;
        }
        found->cbm = cbm;
    }

    found->ref++;
    map[old_cos].ref--;
    spin_unlock(&info->cbm_lock);

    d->arch.psr_cos_ids[socket] = cos;

    return 0;
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
    if ( !cat_socket_info )
        return 0;

    if ( temp_cos_to_cbm == NULL &&
         (temp_cos_to_cbm = xzalloc_array(struct psr_cat_cbm,
                                          opt_cos_max + 1UL)) == NULL )
        return -ENOMEM;

    return 0;
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

        info->cos_to_cbm = temp_cos_to_cbm;
        temp_cos_to_cbm = NULL;
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
