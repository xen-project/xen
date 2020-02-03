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
#include <xen/param.h>

#include <xen/hypercall.h>
#include <xsm/xsm.h>

#ifdef CONFIG_XSM

#ifdef CONFIG_MULTIBOOT
#include <asm/setup.h>
#endif

#ifdef CONFIG_HAS_DEVICE_TREE
#include <asm/setup.h>
#endif

#define XSM_FRAMEWORK_VERSION    "1.0.0"

struct xsm_operations *xsm_ops;

enum xsm_bootparam {
    XSM_BOOTPARAM_DUMMY,
    XSM_BOOTPARAM_FLASK,
    XSM_BOOTPARAM_SILO,
};

static enum xsm_bootparam __initdata xsm_bootparam =
#ifdef CONFIG_XSM_FLASK_DEFAULT
    XSM_BOOTPARAM_FLASK;
#elif CONFIG_XSM_SILO_DEFAULT
    XSM_BOOTPARAM_SILO;
#else
    XSM_BOOTPARAM_DUMMY;
#endif

static int __init parse_xsm_param(const char *s)
{
    int rc = 0;

    if ( !strcmp(s, "dummy") )
        xsm_bootparam = XSM_BOOTPARAM_DUMMY;
#ifdef CONFIG_XSM_FLASK
    else if ( !strcmp(s, "flask") )
        xsm_bootparam = XSM_BOOTPARAM_FLASK;
#endif
#ifdef CONFIG_XSM_SILO
    else if ( !strcmp(s, "silo") )
        xsm_bootparam = XSM_BOOTPARAM_SILO;
#endif
    else
        rc = -EINVAL;

    return rc;
}
custom_param("xsm", parse_xsm_param);

static inline int verify(struct xsm_operations *ops)
{
    /* verify the security_operations structure exists */
    if ( !ops )
        return -EINVAL;
    xsm_fixup_ops(ops);
    return 0;
}

static int __init xsm_core_init(const void *policy_buffer, size_t policy_size)
{
#ifdef CONFIG_XSM_FLASK_POLICY
    if ( policy_size == 0 )
    {
        policy_buffer = xsm_flask_init_policy;
        policy_size = xsm_flask_init_policy_size;
    }
#endif

    if ( verify(&dummy_xsm_ops) )
    {
        printk(XENLOG_ERR "Could not verify dummy_xsm_ops structure\n");
        return -EIO;
    }

    xsm_ops = &dummy_xsm_ops;

    switch ( xsm_bootparam )
    {
    case XSM_BOOTPARAM_DUMMY:
        break;

    case XSM_BOOTPARAM_FLASK:
        flask_init(policy_buffer, policy_size);
        break;

    case XSM_BOOTPARAM_SILO:
        silo_init();
        break;

    default:
        ASSERT_UNREACHABLE();
        break;
    }

    return 0;
}

#ifdef CONFIG_MULTIBOOT
int __init xsm_multiboot_init(unsigned long *module_map,
                              const multiboot_info_t *mbi)
{
    int ret = 0;
    void *policy_buffer = NULL;
    size_t policy_size = 0;

    printk("XSM Framework v" XSM_FRAMEWORK_VERSION " initialized\n");

    if ( XSM_MAGIC )
    {
        ret = xsm_multiboot_policy_init(module_map, mbi,
                                        &policy_buffer, &policy_size);
        if ( ret )
        {
            bootstrap_map(NULL);
            printk(XENLOG_ERR "Error %d initializing XSM policy\n", ret);
            return -EINVAL;
        }
    }

    ret = xsm_core_init(policy_buffer, policy_size);
    bootstrap_map(NULL);

    return 0;
}
#endif

#ifdef CONFIG_HAS_DEVICE_TREE
int __init xsm_dt_init(void)
{
    int ret = 0;
    void *policy_buffer = NULL;
    size_t policy_size = 0;

    printk("XSM Framework v" XSM_FRAMEWORK_VERSION " initialized\n");

    if ( XSM_MAGIC )
    {
        ret = xsm_dt_policy_init(&policy_buffer, &policy_size);
        if ( ret )
        {
            printk(XENLOG_ERR "Error %d initializing XSM policy\n", ret);
            return -EINVAL;
        }
    }

    ret = xsm_core_init(policy_buffer, policy_size);

    xfree(policy_buffer);

    return ret ?: (xsm_bootparam == XSM_BOOTPARAM_SILO);
}

/**
 * has_xsm_magic - Check XSM Magic of the module header by phy address
 * A XSM module has a special header
 * ------------------------------------------------
 * uint magic | uint target_len | uchar target[8] |
 * 0xf97cff8c |        8        |    "XenFlask"   |
 * ------------------------------------------------
 * 0xf97cff8c is policy magic number (XSM_MAGIC).
 * Here we only check the "magic" of the module.
 */
bool __init has_xsm_magic(paddr_t start)
{
    xsm_magic_t magic;

    if ( XSM_MAGIC )
    {
        copy_from_paddr(&magic, start, sizeof(magic) );
        return ( magic == XSM_MAGIC );
    }

    return false;
}
#endif

int __init register_xsm(struct xsm_operations *ops)
{
    if ( verify(ops) )
    {
        printk(XENLOG_ERR "Could not verify xsm_operations structure\n");
        return -EINVAL;
    }

    if ( xsm_ops != &dummy_xsm_ops )
        return -EAGAIN;

    xsm_ops = ops;

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
