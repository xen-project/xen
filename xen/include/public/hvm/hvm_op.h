#ifndef __XEN_PUBLIC_HVM_HVM_OP_H__
#define __XEN_PUBLIC_HVM_HVM_OP_H__

/* Get/set subcommands: extra argument == pointer to xen_hvm_param struct. */
#define HVMOP_set_param     0
#define HVMOP_get_param     1
struct xen_hvm_param {
    domid_t domid;     /* IN */
    uint32_t index;    /* IN */
    uint64_t value;    /* IN/OUT */
};
typedef struct xen_hvm_param xen_hvm_param_t;
DEFINE_XEN_GUEST_HANDLE(xen_hvm_param_t);

/* Set the logical level of one of a domain's IRQ lines. */
#define HVMOP_set_irq_level 2
struct xen_hvm_set_irq_level {
    domid_t  domid;    /* Domain to be updated.          */
    uint16_t level;    /* New level of the IRQ (0 or 1). */
    uint32_t irq;      /* IRQ to be updated.             */
};
typedef struct xen_hvm_set_irq_level xen_hvm_set_irq_level_t;
DEFINE_XEN_GUEST_HANDLE(xen_hvm_set_irq_level_t);

#endif /* __XEN_PUBLIC_HVM_HVM_OP_H__ */
