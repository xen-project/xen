/******************************************************************************
 * grant_table.h
 * 
 * Interface for granting foreign access to page frames, and receiving
 * page-ownership transfers.
 * 
 * Copyright (c) 2004, K A Fraser
 * 
 * Some rough guidelines on accessing and updating grant-table entries
 * in a concurreny-safe manner. For more information, Linux contains a
 * reference implementation for guest OSes (arch/xen/kernel/grant_table.c).
 * 
 * NB. WMB is a no-op on current-generation x86 processors.
 * 
 * Introducing a valid entry into the grant table:
 *  1. Write ent->domid.
 *  2. Write ent->frame (to zero if installing GTF_accept_transfer).
 *  3. Write memory barrier (WMB).
 *  4. Write ent->flags, inc. valid type.
 * 
 * Removing an unused GTF_permit_access entry:
 *  1. flags = ent->flags.
 *  2. Observe that !(flags & (GTF_reading|GTF_writing)).
 *  3. Check result of SMP-safe CMPXCHG(&ent->flags, flags, 0).
 *  4. WMB.
 * 
 * Removing an unused GTF_accept_transfer entry:
 *  1. Clear ent->flags.
 *  2. WMB.
 * 
 * Changing a GTF_permit_access from writable to read-only:
 *  Use SMP-safe CMPXCHG to set GTF_readonly, while checking !GTF_writing.
 * 
 * Changing a GTF_permit_access from read-only to writable:
 *  Use SMP-safe bit-setting instruction.
 */

#ifndef __HYPERVISOR_IFS_GRANT_TABLE_H__
#define __HYPERVISOR_IFS_GRANT_TABLE_H__

/*
 * A grant table comprises a packed array of grant entries in one or more
 * page frames shared between Xen and a guest.
 * [XEN]: This field is written by Xen and read by the sharing guest.
 * [GST]: This field is written by the guest and read by Xen.
 */
typedef struct {
    /* GTF_xxx: various type and flag information.  [XEN,GST] */
    u16     flags;      /* 0 */
    /* The domain being granted foreign privileges. [GST] */
    domid_t domid;      /* 2 */
    /*
     * GTF_permit_access: Frame that @domid is allowed to map and access. [GST]
     * GTF_accept_transfer: Frame whose ownership transferred by @domid. [XEN]
     */
    u32     frame;      /* 4 */
} PACKED grant_entry_t; /* 8 bytes */

/*
 * Reference to a grant entry in a specified domain's grant table.
 */
typedef u16 grant_ref_t;

/*
 * Type of grant entry.
 *  GTF_invalid: This grant entry grants no privileges.
 *  GTF_permit_access: Allow @domid to map/access @frame.
 *  GTF_accept_transfer: Allow @domid to transfer ownership of one page frame
 *                       to this guest. Xen writes the page number to @frame.
 */
#define GTF_invalid         (0<<0)
#define GTF_permit_access   (1<<0)
#define GTF_accept_transfer (2<<0)
#define GTF_type_mask       (3<<0)

/*
 * Subflags for GTF_permit_access.
 *  GTF_readonly: Restrict @domid to read-only mappings and accesses. [GST]
 *  GTF_reading: Grant entry is currently mapped for reading by @domid. [XEN]
 *  GTF_writing: Grant entry is currently mapped for writing by @domid. [XEN]
 */
#define _GTF_readonly       (2)
#define GTF_readonly        (1<<_GTF_readonly)
#define _GTF_reading        (3)
#define GTF_reading         (1<<_GTF_inuse)
#define _GTF_writing        (4)
#define GTF_writing         (1<<_GTF_inuse)

#endif /* __HYPERVISOR_IFS_GRANT_TABLE_H__ */
