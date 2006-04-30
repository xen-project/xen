
#ifndef __XEN_PUBLIC_PHYSDEV_H__
#define __XEN_PUBLIC_PHYSDEV_H__

/*
 * Prototype for this hypercall is:
 *  int physdev_op(int cmd, void *args)
 * @cmd  == PHYSDEVOP_??? (physdev operation).
 * @args == Operation-specific extra arguments (NULL if none).
 */

/*
 * Notify end-of-interrupt (EOI) for the specified IRQ.
 * @arg == pointer to physdev_eoi structure.
 */
#define PHYSDEVOP_eoi                   12
typedef struct physdev_eoi {
    /* IN */
    uint32_t irq;
} physdev_eoi_t;
DEFINE_XEN_GUEST_HANDLE(physdev_eoi_t);

/*
 * Query the status of an IRQ line.
 * @arg == pointer to physdev_irq_status_query structure.
 */
#define PHYSDEVOP_irq_status_query       5
typedef struct physdev_irq_status_query {
    /* IN */
    uint32_t irq;
    /* OUT */
    uint32_t flags; /* XENIRQSTAT_* */
} physdev_irq_status_query_t;
DEFINE_XEN_GUEST_HANDLE(physdev_irq_status_query_t);

/* Need to call PHYSDEVOP_eoi when the IRQ has been serviced? */
#define _XENIRQSTAT_needs_eoi   (0)
#define  XENIRQSTAT_needs_eoi   (1<<_XENIRQSTAT_needs_eoi)

/*
 * Set the current VCPU's I/O privilege level.
 * @arg == pointer to physdev_set_iopl structure.
 */
#define PHYSDEVOP_set_iopl               6
typedef struct physdev_set_iopl {
    /* IN */
    uint32_t iopl;
} physdev_set_iopl_t;
DEFINE_XEN_GUEST_HANDLE(physdev_set_iopl_t);

/*
 * Set the current VCPU's I/O-port permissions bitmap.
 * @arg == pointer to physdev_set_iobitmap structure.
 */
#define PHYSDEVOP_set_iobitmap           7
typedef struct physdev_set_iobitmap {
    /* IN */
    uint8_t *bitmap;
    uint32_t nr_ports;
} physdev_set_iobitmap_t;
DEFINE_XEN_GUEST_HANDLE(physdev_set_iobitmap_t);

/*
 * Read or write an IO-APIC register.
 * @arg == pointer to physdev_apic structure.
 */
#define PHYSDEVOP_apic_read              8
#define PHYSDEVOP_apic_write             9
typedef struct physdev_apic {
    /* IN */
    unsigned long apic_physbase;
    uint32_t reg;
    /* IN or OUT */
    uint32_t value;
} physdev_apic_t;
DEFINE_XEN_GUEST_HANDLE(physdev_apic_t);

/*
 * Allocate or free a physical upcall vector for the specified IRQ line.
 * @arg == pointer to physdev_irq structure.
 */
#define PHYSDEVOP_alloc_irq_vector      10
#define PHYSDEVOP_free_irq_vector       11
typedef struct physdev_irq {
    /* IN */
    uint32_t irq;
    /* IN or OUT */
    uint32_t vector;
} physdev_irq_t;
DEFINE_XEN_GUEST_HANDLE(physdev_irq_t);

/*
 * Argument to physdev_op_compat() hypercall. Superceded by new physdev_op()
 * hypercall since 0x00030202.
 */
typedef struct physdev_op {
    uint32_t cmd;
    union {
        physdev_irq_status_query_t      irq_status_query;
        physdev_set_iopl_t              set_iopl;
        physdev_set_iobitmap_t          set_iobitmap;
        physdev_apic_t                  apic_op;
        physdev_irq_t                   irq_op;
    } u;
} physdev_op_t;
DEFINE_XEN_GUEST_HANDLE(physdev_op_t);

/*
 * Notify that some PIRQ-bound event channels have been unmasked.
 * ** This command is obsolete since interface version 0x00030202 and is **
 * ** unsupported by newer versions of Xen.                              **
 */
#define PHYSDEVOP_IRQ_UNMASK_NOTIFY      4

/*
 * These all-capitals physdev operation names are superceded by the new names
 * (defined above) since interface version 0x00030202.
 */
#define PHYSDEVOP_IRQ_STATUS_QUERY       PHYSDEVOP_irq_status_query
#define PHYSDEVOP_SET_IOPL               PHYSDEVOP_set_iopl
#define PHYSDEVOP_SET_IOBITMAP           PHYSDEVOP_set_iobitmap
#define PHYSDEVOP_APIC_READ              PHYSDEVOP_apic_read
#define PHYSDEVOP_APIC_WRITE             PHYSDEVOP_apic_write
#define PHYSDEVOP_ASSIGN_VECTOR          PHYSDEVOP_alloc_irq_vector
#define PHYSDEVOP_IRQ_NEEDS_UNMASK_NOTIFY XENIRQSTAT_needs_eoi

#endif /* __XEN_PUBLIC_PHYSDEV_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
