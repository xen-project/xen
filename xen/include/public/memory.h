/******************************************************************************
 * memory.h
 * 
 * Memory reservation and information.
 * 
 * Copyright (c) 2005, Keir Fraser <keir@xensource.com>
 */

#ifndef __XEN_PUBLIC_MEMORY_H__
#define __XEN_PUBLIC_MEMORY_H__

/* arg == addr of struct xen_memory_reservation. */
#define XENMEM_increase_reservation 0

/* arg == addr of struct xen_memory_reservation. */
#define XENMEM_decrease_reservation 1

/* arg == addr of unsigned long. */
#define XENMEM_maximum_ram_page     2

typedef struct xen_memory_reservation {

    /*
     * MFN bases of extents to free (XENMEM_decrease_reservation).
     * MFN bases of extents that were allocated (XENMEM_increase_reservation).
     */
    unsigned long *extent_start;

    /* Number of extents, and size/alignment of each (2^extent_order pages). */
    unsigned long  nr_extents;
    unsigned int   extent_order;

    /*
     * XENMEM_increase_reservation: maximum # bits addressable by the user
     * of the allocated region (e.g., I/O devices often have a 32-bit
     * limitation even in 64-bit systems). If zero then the user has no
     * addressing restriction.
     * XENMEM_decrease_reservation: unused.
     */
    unsigned int   address_bits;

    /*
     * Domain whose reservation is being changed.
     * Unprivileged domains can specify only DOMID_SELF.
     */
    domid_t        domid;

} xen_memory_reservation_t;

#endif /* __XEN_PUBLIC_MEMORY_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
