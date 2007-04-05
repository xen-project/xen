/* Simple wrappers around HVM functions */
#ifndef XEN_HVM_H__
#define XEN_HVM_H__

#include <xen/interface/hvm/params.h>

static inline unsigned long hvm_get_parameter(int idx)
{
	struct xen_hvm_param xhv;
	int r;

	xhv.domid = DOMID_SELF;
	xhv.index = idx;
	r = HYPERVISOR_hvm_op(HVMOP_get_param, &xhv);
	if (r < 0) {
		printk(KERN_ERR "cannot get hvm parameter %d: %d.\n",
		       idx, r);
		return 0;
	}
	return xhv.value;
}

#endif /* XEN_HVM_H__ */
