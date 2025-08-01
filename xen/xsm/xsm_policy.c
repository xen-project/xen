/*
 *  Copyright (C) 2005 IBM Corporation
 *
 *  Authors:
 *  Reiner Sailer, <sailer@watson.ibm.com>
 *  Stefan Berger, <stefanb@watson.ibm.com>
 *
 *  Contributors:
 *  Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *  George Coker, <gscoker@alpha.ncsc.mil>
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 *
 *
 *  This file contains the XSM policy init functions for Xen.
 *
 */

#include <xsm/xsm.h>
#ifdef CONFIG_MULTIBOOT
#include <asm/bootinfo.h>
#include <asm/setup.h>
#endif
#include <xen/bitops.h>
#ifdef CONFIG_HAS_DEVICE_TREE_DISCOVERY
# include <asm/setup.h>
# include <xen/device_tree.h>
#endif

#ifdef CONFIG_MULTIBOOT
int __init xsm_multiboot_policy_init(
    struct boot_info *bi, void **policy_buffer, size_t *policy_size)
{
    unsigned int i;
    int rc = 0;
    u32 *_policy_start;
    unsigned long _policy_len;

    for_each_boot_module_by_type ( i, bi, BOOTMOD_UNKNOWN )
    {
        struct boot_module *bm = &bi->mods[i];

        _policy_start = bootstrap_map_bm(bm);
        _policy_len   = bm->size;

        if ( (xsm_magic_t)(*_policy_start) == XSM_MAGIC )
        {
            *policy_buffer = _policy_start;
            *policy_size = _policy_len;

            printk("Policy len %#lx, start at %p.\n",
                   _policy_len,_policy_start);

            bm->kind = BOOTMOD_XSM_POLICY;
            break;

        }

        bootstrap_unmap();
    }

    return rc;
}
#endif

#ifdef CONFIG_HAS_DEVICE_TREE_DISCOVERY
int __init xsm_dt_policy_init(void **policy_buffer, size_t *policy_size)
{
    struct boot_module *mod = boot_module_find_by_kind(BOOTMOD_XSM_POLICY);
    paddr_t paddr, len;

    if ( !mod || !mod->size )
        return 0;

    paddr = mod->start;
    len = mod->size;

    if ( !has_xsm_magic(paddr) )
    {
        printk(XENLOG_ERR "xsm: Invalid magic for XSM blob\n");
        return -EINVAL;
    }

    printk("xsm: Policy len = 0x%"PRIpaddr" start at 0x%"PRIpaddr"\n",
           len, paddr);

    *policy_buffer = xmalloc_bytes(len);
    if ( !*policy_buffer )
        return -ENOMEM;

    copy_from_paddr(*policy_buffer, paddr, len);
    *policy_size = len;

    return 0;
}
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
