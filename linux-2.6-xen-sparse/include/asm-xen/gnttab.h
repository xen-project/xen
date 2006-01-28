/******************************************************************************
 * gnttab.h
 * 
 * Two sets of functionality:
 * 1. Granting foreign access to our memory reservation.
 * 2. Accessing others' memory reservations via grant references.
 * (i.e., mechanisms for both sender and recipient of grant references)
 * 
 * Copyright (c) 2004-2005, K A Fraser
 * Copyright (c) 2005, Christopher Clark
 */

#ifndef __ASM_GNTTAB_H__
#define __ASM_GNTTAB_H__

#include <linux/config.h>
#include <asm/hypervisor.h>
#include <asm-xen/xen-public/grant_table.h>

/* NR_GRANT_FRAMES must be less than or equal to that configured in Xen */
#ifdef __ia64__
#define NR_GRANT_FRAMES 1
#else
#define NR_GRANT_FRAMES 4
#endif

struct gnttab_free_callback {
	struct gnttab_free_callback *next;
	void (*fn)(void *);
	void *arg;
	u16 count;
};

int gnttab_grant_foreign_access(domid_t domid, unsigned long frame,
				int readonly);

/*
 * End access through the given grant reference, iff the grant entry is no
 * longer in use.  Return 1 if the grant entry was freed, 0 if it is still in
 * use.
 */
int gnttab_end_foreign_access_ref(grant_ref_t ref, int readonly);

/*
 * Eventually end access through the given grant reference, and once that
 * access has been ended, free the given page too.  Access will be ended
 * immediately iff the grant entry is not in use, otherwise it will happen
 * some time later.  page may be 0, in which case no freeing will occur.
 */
void gnttab_end_foreign_access(grant_ref_t ref, int readonly,
			       unsigned long page);

int gnttab_grant_foreign_transfer(domid_t domid);

unsigned long gnttab_end_foreign_transfer_ref(grant_ref_t ref);
unsigned long gnttab_end_foreign_transfer(grant_ref_t ref);

int gnttab_query_foreign_access(grant_ref_t ref);

/*
 * operations on reserved batches of grant references
 */
int gnttab_alloc_grant_references(u16 count, grant_ref_t *pprivate_head);

void gnttab_free_grant_reference(grant_ref_t ref);

void gnttab_free_grant_references(grant_ref_t head);

int gnttab_claim_grant_reference(grant_ref_t *pprivate_head);

void gnttab_release_grant_reference(grant_ref_t *private_head,
				    grant_ref_t release);

void gnttab_request_free_callback(struct gnttab_free_callback *callback,
				  void (*fn)(void *), void *arg, u16 count);

void gnttab_grant_foreign_access_ref(grant_ref_t ref, domid_t domid,
				     unsigned long frame, int readonly);

void gnttab_grant_foreign_transfer_ref(grant_ref_t, domid_t domid);

#ifdef __ia64__
#define gnttab_map_vaddr(map) __va(map.dev_bus_addr)
#else
#define gnttab_map_vaddr(map) ((void *)(map.host_virt_addr))
#endif

#endif /* __ASM_GNTTAB_H__ */

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
