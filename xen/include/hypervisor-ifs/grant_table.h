/******************************************************************************
 * grant_table.h
 * 
 * Interface for granting foreign access to page frames, and receiving
 * page-ownership transfers.
 * 
 * Copyright (c) 2004, K A Fraser
 */

#ifndef __HYPERVISOR_IFS_GRANT_TABLE_H__
#define __HYPERVISOR_IFS_GRANT_TABLE_H__


/***********************************
 * GRANT TABLE REPRESENTATION
 */

/* Some rough guidelines on accessing and updating grant-table entries
 * in a concurrency-safe manner. For more information, Linux contains a
 * reference implementation for guest OSes (arch/xen/kernel/grant_table.c).
 * 
 * NB. WMB is a no-op on current-generation x86 processors. However, a
 *     compiler barrier will still be required.
 * 
 * Introducing a valid entry into the grant table:
 *  1. Write ent->domid.
 *  2. Write ent->frame (to zero if installing GTF_accept_transfer).
 *  3. Write memory barrier (WMB).
 *  4. Write ent->flags, inc. valid type.
 * 
 * Invalidating an unused GTF_permit_access entry:
 *  1. flags = ent->flags.
 *  2. Observe that !(flags & (GTF_reading|GTF_writing)).
 *  3. Check result of SMP-safe CMPXCHG(&ent->flags, flags, 0).
 *  NB. No need for WMB as reuse of entry is control-dependent on success of
 *      step 3, and all architectures guarantee ordering of ctrl-dep writes.
 *
 * Invalidating an in-use GTF_permit_access entry:
 *  This cannot be done directly. Request assistance from the domain controller
 *  which can set a timeout on the use of a grant entry and take necessary
 *  action. (NB. This is not yet implemented!).
 * 
 * Invalidating an unused GTF_accept_transfer entry:
 *  1. flags = ent->flags.
 *  2. Observe that !(flags & GTF_transfer_committed). [*]
 *  3. Check result of SMP-safe CMPXCHG(&ent->flags, flags, 0).
 *  NB. No need for WMB as reuse of entry is control-dependent on success of
 *      step 3, and all architectures guarantee ordering of ctrl-dep writes.
 *  [*] If GTF_transfer_committed is set then the grant entry is 'committed'.
 *      The guest must /not/ modify the grant entry until the address of the
 *      transferred frame is written. It is safe for the guest to spin waiting
 *      for this to occur (detect by observing non-zero value in ent->frame).
 *
 * Invalidating a committed GTF_accept_transfer entry:
 *  1. Wait for ent->frame != 0.
 *
 * Changing a GTF_permit_access from writable to read-only:
 *  Use SMP-safe CMPXCHG to set GTF_readonly, while checking !GTF_writing.
 * 
 * Changing a GTF_permit_access from read-only to writable:
 *  Use SMP-safe bit-setting instruction.
 */

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
#define GTF_reading         (1<<_GTF_reading)
#define _GTF_writing        (4)
#define GTF_writing         (1<<_GTF_writing)

/*
 * Subflags for GTF_accept_transfer:
 *  GTF_transfer_committed: Xen sets this flag to indicate that it is committed
 *      to transferring ownership of a page frame. When a guest sees this flag
 *      it must /not/ modify the grant entry until the address of the
 *      transferred frame is written into the entry.
 *      NB. It is safe for the guest to spin-wait on the frame address:
 *          Xen will always write the frame address in a timely manner.
 */
#define _GTF_transfer_committed (2)
#define GTF_transfer_committed  (1<<_GTF_transfer_committed)


/***********************************
 * GRANT TABLE QUERIES AND USES
 */

/*
 * Reference to a grant entry in a specified domain's grant table.
 */
typedef u16 grant_ref_t;

/*
 * GNTTABOP_update_pin_status: Change the pin status of of <dom>'s grant entry
 * with reference <ref>.
 * NOTES:
 *  1. If GNTPIN_dev_accessible is specified then <dev_bus_addr> is the address
 *     via which I/O devices may access the granted frame.
 *  2. If GNTPIN_host_accessible is specified then <host_phys_addr> is the
 *     physical address of the frame, which may be mapped into the caller's
 *     page tables.
 */
#define GNTTABOP_update_pin_status    0
typedef struct {
    /* IN parameters. */
    domid_t     dom;                  /*  0 */
    grant_ref_t ref;                  /*  2 */
    u16         pin_flags;            /*  4 */
    u16         __pad;                /*  6 */
    /* OUT parameters. */
    memory_t    dev_bus_addr;         /*  8 */
    MEMORY_PADDING;
    memory_t    host_phys_addr;       /* 12 */
    MEMORY_PADDING;
} PACKED gnttab_update_pin_status_t; /* 16 bytes */

/*
 * GNTTABOP_setup_table: Set up a grant table for <dom> comprising at least
 * <nr_frames> pages. The frame addresses are written to the <frame_list>.
 * Only <nr_frames> addresses are written, even if the table is larger.
 * NOTES:
 *  1. <dom> may be specified as DOMID_SELF.
 *  2. Only a sufficiently-privileged domain may specify <dom> != DOMID_SELF.
 *  3. Xen may not support more than a single grant-table page per domain.
 */
#define GNTTABOP_setup_table          1
typedef struct {
    /* IN parameters. */
    domid_t     dom;                  /*  0 */
    u16         nr_frames;            /*  2 */
    u32         __pad;
    /* OUT parameters. */
    unsigned long *frame_list;        /*  8 */
    MEMORY_PADDING;
} PACKED gnttab_setup_table_t; /* 16 bytes */

typedef struct {
    u32 cmd; /* GNTTABOP_* */         /*  0 */
    u32 __reserved;                   /*  4 */
    union {                           /*  8 */
        gnttab_update_pin_status_t update_pin_status;
        gnttab_setup_table_t       setup_table;
        u8                         __dummy[16];
    } PACKED u;
} PACKED gnttab_op_t; /* 24 bytes */

/*
 * Bitfield values for <pin_flags>.
 */
 /* Pin the grant entry for access by I/O devices. */
#define _GNTPIN_dev_accessible  (0)
#define GNTPIN_dev_accessible   (1<<_GNTPIN_dev_accessible)
 /* Pin the grant entry for access by host CPUs. */
#define _GNTPIN_host_accessible (1)
#define GNTPIN_host_accessible  (1<<_GNTPIN_host_accessible)
 /* Accesses to the granted frame will be restricted to read-only access. */
#define _GNTPIN_readonly        (2)
#define GNTPIN_readonly         (1<<_GNTPIN_readonly)

#endif /* __HYPERVISOR_IFS_GRANT_TABLE_H__ */
