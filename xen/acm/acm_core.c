/****************************************************************
 * acm_core.c
 * 
 * Copyright (C) 2005 IBM Corporation
 *
 * Author:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * Contributors:
 * Stefan Berger <stefanb@watson.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * sHype access control module (ACM)
 *       This file handles initialization of the ACM
 *       as well as initializing/freeing security 
 *       identifiers for domains (it calls on active
 *       policy hook functions).
 *
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/delay.h>
#include <xen/sched.h>
#include <xen/multiboot.h>
#include <acm/acm_hooks.h>
#include <acm/acm_endian.h>

/* debug: 
 *   include/acm/acm_hooks.h defines a constant ACM_TRACE_MODE;
 *   define/undefine this constant to receive / suppress any
 *   security hook debug output of sHype
 *
 *   include/public/acm.h defines a constant ACM_DEBUG
 *   define/undefine this constant to receive non-hook-related
 *   debug output.
 */

/* function prototypes */
void acm_init_chwall_policy(void);
void acm_init_ste_policy(void);

extern struct acm_operations acm_chinesewall_ops, 
    acm_simple_type_enforcement_ops, acm_null_ops;

/* global ops structs called by the hooks */
struct acm_operations *acm_primary_ops = NULL;
/* called in hook if-and-only-if primary succeeds */
struct acm_operations *acm_secondary_ops = NULL;

/* acm global binary policy (points to 'local' primary and secondary policies */
struct acm_binary_policy acm_bin_pol;
/* acm binary policy lock */
rwlock_t acm_bin_pol_rwlock = RW_LOCK_UNLOCKED;

/* until we have endian support in Xen, we discover it at runtime */
u8 little_endian = 1;
void acm_set_endian(void)
{
    u32 test = 1;
    if (*((u8 *)&test) == 1)
    {
        printk("ACM module running in LITTLE ENDIAN.\n");
        little_endian = 1;
    }
    else
    {
        printk("ACM module running in BIG ENDIAN.\n");
        little_endian = 0;
    }
}

/* initialize global security policy for Xen; policy write-locked already */
static void
acm_init_binary_policy(void *primary, void *secondary)
{
    acm_bin_pol.primary_policy_code = 0;
    acm_bin_pol.secondary_policy_code = 0;
    acm_bin_pol.primary_binary_policy = primary;
    acm_bin_pol.secondary_binary_policy = secondary;
}

static int
acm_setup(unsigned int *initrdidx,
          const multiboot_info_t *mbi,
          unsigned long initial_images_start)
{
    int i;
    module_t *mod = (module_t *)__va(mbi->mods_addr);
    int rc = ACM_OK;

    if (mbi->mods_count > 1)
        *initrdidx = 1;

    /*
     * Try all modules and see whichever could be the binary policy.
     * Adjust the initrdidx if module[1] is the binary policy.
     */
    for (i = mbi->mods_count-1; i >= 1; i--)
    {
        struct acm_policy_buffer *pol;
        char *_policy_start; 
        unsigned long _policy_len;
#if defined(__i386__)
        _policy_start = (char *)(initial_images_start + (mod[i].mod_start-mod[0].mod_start));
#elif defined(__x86_64__)
        _policy_start = __va(initial_images_start + (mod[i].mod_start-mod[0].mod_start));
#else
#error Architecture unsupported by sHype
#endif
        _policy_len   = mod[i].mod_end - mod[i].mod_start;
        if (_policy_len < sizeof(struct acm_policy_buffer))
            continue; /* not a policy */

        pol = (struct acm_policy_buffer *)_policy_start;
        if (ntohl(pol->magic) == ACM_MAGIC)
        {
            rc = acm_set_policy((void *)_policy_start,
                                (u32)_policy_len,
                                0);
            if (rc == ACM_OK)
            {
                printf("Policy len  0x%lx, start at %p.\n",_policy_len,_policy_start);
                if (i == 1)
                {
                    if (mbi->mods_count > 2)
                    {
                        *initrdidx = 2;
                    }
                    else {
                        *initrdidx = 0;
                    }
                }
                else
                {
                    *initrdidx = 1;
                }
                break;
            }
            else
            {
                printk("Invalid policy. %d.th module line.\n", i+1);
            }
        } /* end if a binary policy definition, i.e., (ntohl(pol->magic) == ACM_MAGIC ) */
    }
    return rc;
}


int
acm_init(unsigned int *initrdidx,
         const multiboot_info_t *mbi,
         unsigned long initial_images_start)
{
    int ret = ACM_OK;

    acm_set_endian();
    write_lock(&acm_bin_pol_rwlock);
    acm_init_binary_policy(NULL, NULL);

    /* set primary policy component */
    switch ((ACM_USE_SECURITY_POLICY) & 0x0f)
    {

    case ACM_CHINESE_WALL_POLICY:
        acm_init_chwall_policy();
        acm_bin_pol.primary_policy_code = ACM_CHINESE_WALL_POLICY;
        acm_primary_ops = &acm_chinesewall_ops;
        break;

    case ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY:
        acm_init_ste_policy();
        acm_bin_pol.primary_policy_code = ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY;
        acm_primary_ops = &acm_simple_type_enforcement_ops;
        break;

    default:
        /* NULL or Unknown policy not allowed primary;
         * NULL/NULL will not compile this code */
        ret = -EINVAL;
        goto out;
    }

    /* secondary policy component part */
    switch ((ACM_USE_SECURITY_POLICY) >> 4) {
    case ACM_NULL_POLICY:
        acm_bin_pol.secondary_policy_code = ACM_NULL_POLICY;
        acm_secondary_ops = &acm_null_ops;
        break;

    case ACM_CHINESE_WALL_POLICY:
        if (acm_bin_pol.primary_policy_code == ACM_CHINESE_WALL_POLICY)
        {   /* not a valid combination */
            ret = -EINVAL;
            goto out;
        }
        acm_init_chwall_policy();
        acm_bin_pol.secondary_policy_code = ACM_CHINESE_WALL_POLICY;
        acm_secondary_ops = &acm_chinesewall_ops;
        break;

    case ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY:
        if (acm_bin_pol.primary_policy_code == ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY)
        {   /* not a valid combination */
            ret = -EINVAL;
            goto out;
        }
        acm_init_ste_policy();
        acm_bin_pol.secondary_policy_code = ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY;
        acm_secondary_ops = &acm_simple_type_enforcement_ops;
        break;

    default:
        ret = -EINVAL;
        goto out;
    }

 out:
    write_unlock(&acm_bin_pol_rwlock);

    if (ret != ACM_OK)
    {
        printk("%s: Error initializing policies.\n", __func__);
        /* here one could imagine a clean panic */
        return -EINVAL;
    }
    if (acm_setup(initrdidx, mbi, initial_images_start) != ACM_OK)
    {
        printk("%s: Error loading policy at boot time.\n", __func__);
        /* ignore, just continue with the minimal hardcoded startup policy */
    }
    printk("%s: Enforcing Primary %s, Secondary %s.\n", __func__, 
           ACM_POLICY_NAME(acm_bin_pol.primary_policy_code),
           ACM_POLICY_NAME(acm_bin_pol.secondary_policy_code));
    return ret;
}

int
acm_init_domain_ssid(domid_t id, ssidref_t ssidref)
{
    struct acm_ssid_domain *ssid;
    struct domain *subj = find_domain_by_id(id);
    int ret1, ret2;
 
    if (subj == NULL)
    {
        printk("%s: ACM_NULL_POINTER ERROR (id=%x).\n", __func__, id);
        return ACM_NULL_POINTER_ERROR;
    }
    if ((ssid = xmalloc(struct acm_ssid_domain)) == NULL)
    {
        put_domain(subj);
        return ACM_INIT_SSID_ERROR;
    }

    ssid->datatype       = DOMAIN;
    ssid->subject        = subj;
    ssid->domainid      = subj->domain_id;
    ssid->primary_ssid   = NULL;
    ssid->secondary_ssid = NULL;

    if (ACM_USE_SECURITY_POLICY != ACM_NULL_POLICY)
        ssid->ssidref = ssidref;
    else
        ssid->ssidref = ACM_DEFAULT_SSID;

    subj->ssid           = ssid;
    /* now fill in primary and secondary parts; we only get here through hooks */
    if (acm_primary_ops->init_domain_ssid != NULL)
        ret1 = acm_primary_ops->init_domain_ssid(&(ssid->primary_ssid), ssidref);
    else
        ret1 = ACM_OK;

    if (acm_secondary_ops->init_domain_ssid != NULL)
        ret2 = acm_secondary_ops->init_domain_ssid(&(ssid->secondary_ssid), ssidref);
    else
        ret2 = ACM_OK;

    if ((ret1 != ACM_OK) || (ret2 != ACM_OK))
    {
        printk("%s: ERROR instantiating individual ssids for domain 0x%02x.\n",
               __func__, subj->domain_id);
        acm_free_domain_ssid(ssid); 
        put_domain(subj);
        return ACM_INIT_SSID_ERROR;
    }
    printk("%s: assigned domain %x the ssidref=%x.\n",
           __func__, id, ssid->ssidref);
    put_domain(subj);
    return ACM_OK;
}


void
acm_free_domain_ssid(struct acm_ssid_domain *ssid)
{
    /* domain is already gone, just ssid is left */
    if (ssid == NULL)
        return;

    ssid->subject = NULL;
    if (acm_primary_ops->free_domain_ssid != NULL) /* null policy */
        acm_primary_ops->free_domain_ssid(ssid->primary_ssid);
    ssid->primary_ssid = NULL;
    if (acm_secondary_ops->free_domain_ssid != NULL)
        acm_secondary_ops->free_domain_ssid(ssid->secondary_ssid);
    ssid->secondary_ssid = NULL;
    xfree(ssid);
    printkd("%s: Freed individual domain ssid (domain=%02x).\n",
            __func__, id);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
