/******************************************************************************
 * gnttab.c
 * 
 * Two sets of functionality:
 * 1. Granting foreign access to our memory reservation.
 * 2. Accessing others' memory reservations via grant references.
 * (i.e., mechanisms for both sender and recipient of grant references)
 * 
 * Copyright (c) 2004, K A Fraser
 */

#include <linux/config.h>
#include <linux/module.h>
#include <asm-xen/gnttab.h>

EXPORT_SYMBOL(gnttab_grant_foreign_access);
EXPORT_SYMBOL(gnttab_end_foreign_access);
EXPORT_SYMBOL(gnttab_grant_foreign_transfer);
EXPORT_SYMBOL(gnttab_end_foreign_transfer);

grant_ref_t
gnttab_grant_foreign_access(
    domid_t domid, unsigned long frame, int readonly)
{
    return 0;
}

void
gnttab_end_foreign_access(
    grant_ref_t ref, int readonly)
{
}

grant_ref_t
gnttab_grant_foreign_transfer(
    domid_t domid)
{
    return 0;
}

unsigned long
gnttab_end_foreign_transfer(
    grant_ref_t ref)
{
    return 0;
}
