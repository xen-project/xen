/*
 *  This work is based on the LSM implementation in Linux 2.6.13.4.
 *
 *  Author:  George Coker, <gscoker@alpha.ncsc.mil>
 *
 *  Contributors: Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#include <xen/init.h>
#include <xen/errno.h>
#include <xen/lib.h>

#include <xen/hypercall.h>
#include <xsm/xsm.h>

#ifdef XSM_ENABLE

#define XSM_FRAMEWORK_VERSION    "1.0.0"

struct xsm_operations *xsm_ops;

static inline int verify(struct xsm_operations *ops)
{
    /* verify the security_operations structure exists */
    if ( !ops )
        return -EINVAL;
    xsm_fixup_ops(ops);
    return 0;
}

static void __init do_xsm_initcalls(void)
{
    xsm_initcall_t *call;
    call = __xsm_initcall_start;
    while ( call < __xsm_initcall_end )
    {
        (*call) ();
        call++;
    }
}

static int __init xsm_core_init(void)
{
    if ( verify(&dummy_xsm_ops) )
    {
        printk("%s could not verify "
               "dummy_xsm_ops structure.\n", __FUNCTION__);
        return -EIO;
    }

    xsm_ops = &dummy_xsm_ops;
    do_xsm_initcalls();

    return 0;
}

#ifdef CONFIG_MULTIBOOT
int __init xsm_multiboot_init(unsigned long *module_map,
                              const multiboot_info_t *mbi,
                              void *(*bootstrap_map)(const module_t *))
{
    int ret = 0;

    printk("XSM Framework v" XSM_FRAMEWORK_VERSION " initialized\n");

    if ( XSM_MAGIC )
    {
        ret = xsm_multiboot_policy_init(module_map, mbi, bootstrap_map);
        if ( ret )
        {
            bootstrap_map(NULL);
            printk("%s: Error initializing policy.\n", __FUNCTION__);
            return -EINVAL;
        }
    }

    ret = xsm_core_init();
    bootstrap_map(NULL);

    return 0;
}
#endif

#ifdef HAS_DEVICE_TREE
int __init xsm_dt_init(void)
{
    int ret = 0;

    printk("XSM Framework v" XSM_FRAMEWORK_VERSION " initialized\n");

    if ( XSM_MAGIC )
    {
        ret = xsm_dt_policy_init();
        if ( ret )
        {
            printk("%s: Error initializing policy (rc = %d).\n",
                   __FUNCTION__, ret);
            return -EINVAL;
        }
    }

    ret = xsm_core_init();

    xfree(policy_buffer);

    return ret;
}
#endif

int register_xsm(struct xsm_operations *ops)
{
    if ( verify(ops) )
    {
        printk("%s could not verify "
               "security_operations structure.\n", __FUNCTION__);
        return -EINVAL;
    }

    if ( xsm_ops != &dummy_xsm_ops )
        return -EAGAIN;

    xsm_ops = ops;

    return 0;
}


int unregister_xsm(struct xsm_operations *ops)
{
    if ( ops != xsm_ops )
    {
        printk("%s: trying to unregister "
               "a security_opts structure that is not "
               "registered, failing.\n", __FUNCTION__);
        return -EINVAL;
    }

    xsm_ops = &dummy_xsm_ops;

    return 0;
}

#endif

long do_xsm_op (XEN_GUEST_HANDLE_PARAM(xsm_op_t) op)
{
    return xsm_do_xsm_op(op);
}

#ifdef CONFIG_COMPAT
int compat_xsm_op (XEN_GUEST_HANDLE_PARAM(xsm_op_t) op)
{
    return xsm_do_compat_op(op);
}
#endif
