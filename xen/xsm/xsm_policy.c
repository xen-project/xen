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
 *  This file is based on the ACM functions of the same name.
 *
 */

#define XSM_ENABLE
#include <xsm/xsm.h>
#include <xen/multiboot.h>

char *policy_buffer = NULL;
u32 policy_size = 0;

int xsm_policy_init(unsigned int *initrdidx, const multiboot_info_t *mbi,
                           unsigned long initial_images_start)
{
    int i;
    module_t *mod = (module_t *)__va(mbi->mods_addr);
    int rc = 0;
    u32 *_policy_start;
    unsigned long start, _policy_len;

    /*
     * Try all modules and see whichever could be the binary policy.
     * Adjust the initrdidx if module[1] is the binary policy.
     */
    for ( i = mbi->mods_count-1; i >= 1; i-- )
    {
        start = initial_images_start + (mod[i].mod_start-mod[0].mod_start);
#if defined(__i386__)
        _policy_start = (u32 *)start;
#elif defined(__x86_64__)
        _policy_start = maddr_to_virt(start);
#else
        _policy_start = NULL;
#endif
        _policy_len   = mod[i].mod_end - mod[i].mod_start;

        if ( (xsm_magic_t)(*_policy_start) == XSM_MAGIC )
        {
            policy_buffer = (char *)_policy_start;
            policy_size = _policy_len;

            printk("Policy len  0x%lx, start at %p.\n",
                   _policy_len,_policy_start);

            if ( i == 1 )
                *initrdidx = (mbi->mods_count > 2) ? 2 : 0;
            break;

        }
    }

    return rc;
}
