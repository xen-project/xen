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
#include <asm/bootinfo.h>
#include <asm/setup.h>
#endif

#ifdef CONFIG_HAS_DEVICE_TREE
#include <asm/setup.h>
#endif

#define XSM_FRAMEWORK_VERSION    "1.0.1"

struct xsm_ops __alt_call_maybe_initdata xsm_ops;

enum xsm_ops_state {
    XSM_OPS_UNREGISTERED,
    XSM_OPS_REG_FAILED,
    XSM_OPS_REGISTERED,
};

static enum xsm_ops_state __initdata xsm_ops_registered = XSM_OPS_UNREGISTERED;

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

static int __init cf_check parse_xsm_param(const char *s)
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

static int __init xsm_core_init(const void *policy_buffer, size_t policy_size)
{
    const struct xsm_ops *ops = NULL;

#ifdef CONFIG_XSM_FLASK_POLICY
    if ( policy_size == 0 )
    {
        policy_buffer = xsm_flask_init_policy;
        policy_size = xsm_flask_init_policy_size;
    }
#endif

    if ( xsm_ops_registered != XSM_OPS_UNREGISTERED )
    {
        printk(XENLOG_ERR
               "Could not init XSM, xsm_ops register already attempted\n");
        return -EIO;
    }

    switch ( xsm_bootparam )
    {
    case XSM_BOOTPARAM_DUMMY:
        xsm_ops_registered = XSM_OPS_REGISTERED;
        break;

    case XSM_BOOTPARAM_FLASK:
        ops = flask_init(policy_buffer, policy_size);
        break;

    case XSM_BOOTPARAM_SILO:
        ops = silo_init();
        break;

    default:
        ASSERT_UNREACHABLE();
        break;
    }

    if ( ops )
    {
        xsm_ops_registered = XSM_OPS_REGISTERED;
        xsm_ops = *ops;
    }
    /*
     * This handles three cases,
     *   - dummy policy module was selected
     *   - a policy module does not provide all handlers
     *   - a policy module failed to init
     */
    xsm_fixup_ops(&xsm_ops);

    if ( xsm_ops_registered != XSM_OPS_REGISTERED )
    {
        xsm_ops_registered = XSM_OPS_REG_FAILED;
        printk(XENLOG_ERR
               "Could not init XSM, xsm_ops register failed\n");
        return -EFAULT;
    }

    return 0;
}

#ifdef CONFIG_MULTIBOOT
int __init xsm_multiboot_init(struct boot_info *bi)
{
    int ret = 0;
    void *policy_buffer = NULL;
    size_t policy_size = 0;

    printk("XSM Framework v" XSM_FRAMEWORK_VERSION " initialized\n");

    if ( XSM_MAGIC )
    {
        ret = xsm_multiboot_policy_init(bi, &policy_buffer, &policy_size);
        if ( ret )
        {
            bootstrap_unmap();
            printk(XENLOG_ERR "Error %d initializing XSM policy\n", ret);
            return -EINVAL;
        }
    }

    ret = xsm_core_init(policy_buffer, policy_size);
    bootstrap_unmap();

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

#endif

long do_xsm_op(XEN_GUEST_HANDLE_PARAM(void) op)
{
    return xsm_do_xsm_op(op);
}

#ifdef CONFIG_COMPAT
int compat_xsm_op(XEN_GUEST_HANDLE_PARAM(void) op)
{
    return xsm_do_compat_op(op);
}
#endif
