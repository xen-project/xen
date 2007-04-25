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

/* global ACM policy  (now dynamically determined at boot time) */
u16 acm_active_security_policy = ACM_POLICY_UNDEFINED;

/* global ops structs called by the hooks */
struct acm_operations *acm_primary_ops = NULL;
/* called in hook if-and-only-if primary succeeds */
struct acm_operations *acm_secondary_ops = NULL;

/* acm global binary policy (points to 'local' primary and secondary policies */
struct acm_binary_policy acm_bin_pol;
/* acm binary policy lock */
DEFINE_RWLOCK(acm_bin_pol_rwlock);

/* ACM's only accepted policy name during boot */
char polname[80];
char *acm_accepted_boot_policy_name = NULL;

/* a lits of all chained ssid structures */
LIST_HEAD(ssid_list);
DEFINE_RWLOCK(ssid_list_rwlock);

static void __init set_dom0_ssidref(const char *val)
{
    /* expected format:
         ssidref=<hex number>:<policy name>
         Policy name must not have a 'space'.
     */
    const char *c;
    int lo, hi;
    int i;
    int dom0_ssidref = simple_strtoull(val, &c, 0);

    if (!strncmp(&c[0],":ACM:", 5)) {
        lo = dom0_ssidref & 0xffff;
        if (lo < ACM_MAX_NUM_TYPES && lo >= 1)
            dom0_chwall_ssidref = lo;
        hi = dom0_ssidref >> 16;
        if (hi < ACM_MAX_NUM_TYPES && hi >= 1)
            dom0_ste_ssidref = hi;
        for (i = 0; i < sizeof(polname); i++) {
            polname[i] = c[7+i];
            if (polname[i] == '\0' || polname[i] == '\t' ||
                polname[i] == '\n' || polname[i] == ' '  ||
                polname[i] == ':') {
                break;
            }
        }
        polname[i] = 0;
        acm_accepted_boot_policy_name = polname;
    }
}

custom_param("ssidref", set_dom0_ssidref);

int
acm_set_policy_reference(u8 *buf, u32 buf_size)
{
    char *name = (char *)(buf + sizeof(struct acm_policy_reference_buffer));
    struct acm_policy_reference_buffer *pr = (struct acm_policy_reference_buffer *)buf;

    if (acm_accepted_boot_policy_name != NULL) {
        if (strcmp(acm_accepted_boot_policy_name, name)) {
            printk("Policy's name '%s' is not the expected one '%s'.\n",
                   name, acm_accepted_boot_policy_name);
            return ACM_ERROR;
        }
    }

    acm_bin_pol.policy_reference_name = (char *)xmalloc_array(u8, be32_to_cpu(pr->len));

    if (!acm_bin_pol.policy_reference_name)
        return -ENOMEM;
    strlcpy(acm_bin_pol.policy_reference_name, name, be32_to_cpu(pr->len));

    printk("%s: Activating policy %s\n", __func__,
           acm_bin_pol.policy_reference_name);
    return 0;
}

int
acm_dump_policy_reference(u8 *buf, u32 buf_size)
{
    struct acm_policy_reference_buffer *pr_buf = (struct acm_policy_reference_buffer *)buf;
    int ret = sizeof(struct acm_policy_reference_buffer) + strlen(acm_bin_pol.policy_reference_name) + 1;

    ret = (ret + 7) & ~7;
    if (buf_size < ret)
        return -EINVAL;

    memset(buf, 0, ret);
    pr_buf->len = cpu_to_be32(strlen(acm_bin_pol.policy_reference_name) + 1); /* including stringend '\0' */
    strlcpy((char *)(buf + sizeof(struct acm_policy_reference_buffer)),
            acm_bin_pol.policy_reference_name,
            be32_to_cpu(pr_buf->len));
    return ret;
}

int
acm_init_binary_policy(u32 policy_code)
{
    int ret = ACM_OK;

    acm_bin_pol.primary_policy_code = (policy_code & 0x0f);
    acm_bin_pol.secondary_policy_code = (policy_code >> 4) & 0x0f;

    write_lock(&acm_bin_pol_rwlock);

    /* set primary policy component */
    switch ((policy_code) & 0x0f)
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

    case ACM_NULL_POLICY:
        acm_bin_pol.primary_policy_code = ACM_NULL_POLICY;
        acm_primary_ops = &acm_null_ops;
        break;

    default:
        /* Unknown policy not allowed primary */
        ret = -EINVAL;
        goto out;
    }

    /* secondary policy component part */
    switch ((policy_code) >> 4)
    {

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
    return ret;
}

int
acm_is_policy(char *buf, unsigned long len)
{
    struct acm_policy_buffer *pol;

    if (buf == NULL || len < sizeof(struct acm_policy_buffer))
        return 0;

    pol = (struct acm_policy_buffer *)buf;
    return be32_to_cpu(pol->magic) == ACM_MAGIC;
}


static int
acm_setup(char *policy_start,
          unsigned long policy_len,
          int is_bootpolicy)
{
    int rc = ACM_OK;
    struct acm_policy_buffer *pol;

    if (policy_start == NULL || policy_len < sizeof(struct acm_policy_buffer))
        return rc;

    pol = (struct acm_policy_buffer *)policy_start;
    if (be32_to_cpu(pol->magic) != ACM_MAGIC)
        return rc;

    rc = do_acm_set_policy((void *)policy_start, (u32)policy_len,
                           is_bootpolicy,
                           NULL, NULL, NULL);
    if (rc == ACM_OK)
    {
        printkd("Policy len  0x%lx, start at %p.\n",policy_len,policy_start);
    }
    else
    {
        printk("Invalid policy.\n");
        /* load default policy later */
        acm_active_security_policy = ACM_POLICY_UNDEFINED;
    }
    return rc;
}


int
acm_init(char *policy_start,
         unsigned long policy_len)
{
    int ret = ACM_OK;

    /* first try to load the boot policy (uses its own locks) */
    acm_setup(policy_start, policy_len, 1);

    /* a user-provided policy may have any name; only matched during boot */
    acm_accepted_boot_policy_name = NULL;

    if (acm_active_security_policy != ACM_POLICY_UNDEFINED)
    {
        printk("%s: Enforcing %s boot policy.\n", __func__,
               ACM_POLICY_NAME(acm_active_security_policy));
        goto out;
    }
    /* else continue with the minimal hardcoded default startup policy */
    printk("%s: Loading default policy (%s).\n",
           __func__, ACM_POLICY_NAME(ACM_DEFAULT_SECURITY_POLICY));

    /* (re-)set dom-0 ssidref to default */
    dom0_ste_ssidref = dom0_chwall_ssidref = 0x0001;

    if (acm_init_binary_policy(ACM_DEFAULT_SECURITY_POLICY)) {
        ret = -EINVAL;
        goto out;
    }
    acm_active_security_policy = ACM_DEFAULT_SECURITY_POLICY;
    if (acm_active_security_policy != ACM_NULL_POLICY)
        acm_bin_pol.policy_reference_name = "DEFAULT";
    else
        acm_bin_pol.policy_reference_name = "NULL";

 out:
    if (ret != ACM_OK)
    {
        printk("%s: Error initializing policies.\n", __func__);
        /* here one could imagine a clean panic */
        return -EINVAL;
    }
    return ret;
}

int
acm_init_domain_ssid(domid_t id, ssidref_t ssidref)
{
    struct domain *subj = rcu_lock_domain_by_id(id);
    int ret;
 
    if (subj == NULL)
    {
        printk("%s: ACM_NULL_POINTER ERROR (id=%x).\n", __func__, id);
        return ACM_NULL_POINTER_ERROR;
    }

    ret = acm_init_domain_ssid_new(subj, ssidref);

    rcu_unlock_domain(subj);

    return ret;
}

int acm_init_domain_ssid_new(struct domain *subj, ssidref_t ssidref)
{
    struct acm_ssid_domain *ssid;
    int ret1, ret2;
    if ((ssid = xmalloc(struct acm_ssid_domain)) == NULL)
    {
        return ACM_INIT_SSID_ERROR;
    }

    INIT_LIST_HEAD(&ssid->node);
    ssid->datatype       = ACM_DATATYPE_domain;
    ssid->subject        = subj;
    ssid->domainid       = subj->domain_id;
    ssid->primary_ssid   = NULL;
    ssid->secondary_ssid = NULL;

    if (acm_active_security_policy != ACM_NULL_POLICY)
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
        return ACM_INIT_SSID_ERROR;
    }

    write_lock(&ssid_list_rwlock);
    list_add(&ssid->node, &ssid_list);
    write_unlock(&ssid_list_rwlock);

    printkd("%s: assigned domain %x the ssidref=%x.\n",
           __func__, subj->domain_id, ssid->ssidref);
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

    write_lock(&ssid_list_rwlock);
    list_del(&ssid->node);
    write_unlock(&ssid_list_rwlock);

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
