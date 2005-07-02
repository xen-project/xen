
#ifndef __XEN_PUBLIC_PHYSDEV_H__
#define __XEN_PUBLIC_PHYSDEV_H__

/* Commands to HYPERVISOR_physdev_op() */
#define PHYSDEVOP_IRQ_UNMASK_NOTIFY     4
#define PHYSDEVOP_IRQ_STATUS_QUERY      5
#define PHYSDEVOP_SET_IOPL              6
#define PHYSDEVOP_SET_IOBITMAP          7
#define PHYSDEVOP_APIC_READ             8
#define PHYSDEVOP_APIC_WRITE            9
#define PHYSDEVOP_ASSIGN_VECTOR         10

typedef struct physdevop_irq_status_query {
    /* IN */
    u32 irq;
    /* OUT */
/* Need to call PHYSDEVOP_IRQ_UNMASK_NOTIFY when the IRQ has been serviced? */
#define PHYSDEVOP_IRQ_NEEDS_UNMASK_NOTIFY (1<<0)
    u32 flags;
} physdevop_irq_status_query_t;

typedef struct physdevop_set_iopl {
    /* IN */
    u32 iopl;
} physdevop_set_iopl_t;

typedef struct physdevop_set_iobitmap {
    /* IN */
    memory_t bitmap;
    u32      nr_ports;
} physdevop_set_iobitmap_t;

typedef struct physdevop_apic {
    /* IN */
    u32 apic;
    u32 offset;
    /* IN or OUT */
    u32 value;
} physdevop_apic_t; 

typedef struct physdevop_irq {
    /* IN */
    u32 irq;
    /* OUT */
    u32 vector;
} physdevop_irq_t; 

typedef struct physdev_op {
    u32 cmd;
    union {
        physdevop_irq_status_query_t      irq_status_query;
        physdevop_set_iopl_t              set_iopl;
        physdevop_set_iobitmap_t          set_iobitmap;
        physdevop_apic_t                  apic_op;
        physdevop_irq_t                   irq_op;
    } u;
} physdev_op_t;

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
