/* Simple wrappers around HVM functions */
#ifndef XEN_HVM_H__
#define XEN_HVM_H__

#include <xen/interface/hvm/params.h>
#include <asm/hypercall.h>

static inline unsigned long hvm_get_parameter(int idx)
{
	struct xen_hvm_param xhv;

	xhv.domid = DOMID_SELF;
	xhv.index = idx;
	return HYPERVISOR_hvm_op(HVMOP_get_param, &xhv);
}

#endif /* XEN_HVM_H__ */
