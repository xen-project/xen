/******************************************************************************
 * gnttab.h
 * 
 * Two sets of functionality:
 * 1. Granting foreign access to our memory reservation.
 * 2. Accessing others' memory reservations via grant references.
 * (i.e., mechanisms for both sender and recipient of grant references)
 * 
 * Copyright (c) 2004, K A Fraser
 * Copyright (c) 2005, Christopher Clark
 */

#ifndef __ASM_GNTTAB_H__
#define __ASM_GNTTAB_H__

#include <linux/config.h>
#include <asm-xen/hypervisor.h>
#include <asm-xen/xen-public/grant_table.h>

/* NR_GRANT_FRAMES must be less than or equal to that configured in Xen */
#define NR_GRANT_FRAMES 4
#define NR_GRANT_ENTRIES (NR_GRANT_FRAMES * PAGE_SIZE / sizeof(grant_entry_t))

int
gnttab_grant_foreign_access(
    domid_t domid, unsigned long frame, int readonly);

void
gnttab_end_foreign_access(
    grant_ref_t ref, int readonly);

int
gnttab_grant_foreign_transfer(
    domid_t domid, unsigned long pfn);

unsigned long
gnttab_end_foreign_transfer(
    grant_ref_t ref);

int
gnttab_query_foreign_access( 
    grant_ref_t ref );

/*
 * operations on reserved batches of grant references
 */
int
gnttab_alloc_grant_references(
    u16 count, grant_ref_t *pprivate_head, grant_ref_t *private_terminal );

void
gnttab_free_grant_references(
    u16 count, grant_ref_t private_head );

int
gnttab_claim_grant_reference( grant_ref_t *pprivate_head, grant_ref_t terminal
);

void
gnttab_release_grant_reference(
    grant_ref_t *private_head, grant_ref_t release );

void
gnttab_grant_foreign_access_ref(
    grant_ref_t ref, domid_t domid, unsigned long frame, int readonly);

void
gnttab_grant_foreign_transfer_ref(
    grant_ref_t, domid_t domid, unsigned long pfn);


#endif /* __ASM_GNTTAB_H__ */
