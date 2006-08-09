#ifndef __XEN_PUBLIC_HVM_PARAMS_H__
#define __XEN_PUBLIC_HVM_PARAMS_H__

/* Parameter space. */
#define HVM_PARAM_CALLBACK_IRQ 0
#define HVM_PARAM_STORE_PFN    1
#define HVM_PARAM_STORE_EVTCHN 2
#define HVM_PARAM_APIC_ENABLED 3
#define HVM_PARAM_PAE_ENABLED  4
#define HVM_NR_PARAMS          5

/* Get/set subcommands: extra argument == pointer to xen_hvm_param struct. */
#define HVMOP_set_param 0
#define HVMOP_get_param 1

struct xen_hvm_param {
    domid_t domid;     /* IN */
    uint32_t index;    /* IN */
    uint64_t value;    /* IN/OUT */
};
typedef struct xen_hvm_param xen_hvm_param_t;
DEFINE_XEN_GUEST_HANDLE(xen_hvm_param_t);

#endif /* __XEN_PUBLIC_HVM_PARAMS_H__ */
