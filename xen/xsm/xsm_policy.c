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
#include <xen/multiboot.h>
#include <asm/bitops.h>

char *__initdata policy_buffer = NULL;
u32 __initdata policy_size = 0;

int xsm_policy_init(unsigned long *module_map, const multiboot_info_t *mbi,
                    void *(*bootstrap_map)(const module_t *))
{
    int i;
    module_t *mod = (module_t *)__va(mbi->mods_addr);
    int rc = 0;
    u32 *_policy_start;
    unsigned long _policy_len;

    /*
     * Try all modules and see whichever could be the binary policy.
     * Adjust module_map for the module that is the binary policy.
     */
    for ( i = mbi->mods_count-1; i >= 1; i-- )
    {
        if ( !test_bit(i, module_map) )
            continue;

        _policy_start = bootstrap_map(mod + i);
        _policy_len   = mod[i].mod_end;

        if ( (xsm_magic_t)(*_policy_start) == XSM_MAGIC )
        {
            policy_buffer = (char *)_policy_start;
            policy_size = _policy_len;

            printk("Policy len  0x%lx, start at %p.\n",
                   _policy_len,_policy_start);

            __clear_bit(i, module_map);
            break;

        }

        bootstrap_map(NULL);
    }

    return rc;
}
