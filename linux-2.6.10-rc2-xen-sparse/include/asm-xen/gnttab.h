/******************************************************************************
 * gnttab.h
 * 
 * Two sets of functionality:
 * 1. Granting foreign access to our memory reservation.
 * 2. Accessing others' memory reservations via grant references.
 * (i.e., mechanisms for both sender and recipient of grant references)
 * 
 * Copyright (c) 2004, K A Fraser
 */

#ifndef __ASM_GNTTAB_H__
#define __ASM_GNTTAB_H__

#include <linux/config.h>
#include <asm-xen/hypervisor.h>
#include <asm-xen/xen-public/grant_table.h>

int
gnttab_grant_foreign_access(
    domid_t domid, unsigned long frame, int readonly);

void
gnttab_end_foreign_access(
    grant_ref_t ref, int readonly);

int
gnttab_grant_foreign_transfer(
    domid_t domid);

unsigned long
gnttab_end_foreign_transfer(
    grant_ref_t ref);

#endif /* __ASM_GNTTAB_H__ */
