/******************************************************************************
 * xc_physdev.c
 * 
 * API for manipulating physical-device access permissions.
 * 
 * Copyright (c) 2004, Rolf Neugebauer (Intel Research Cambridge)
 * Copyright (c) 2004, K A Fraser (University of Cambridge)
 */

int xc_physdev_pci_access_modify(int xc_handle,
                                 u64 domid,
                                 int bus,
                                 int dev,
                                 int func,
                                 int enable)
{
    dom0_op_t op;

    op.cmd = DOM0_PCIDEV_ACCESS;
    op.u.pcidev_access.domain = (domid_t)domid;
    op.u.pcidev_access.bus    = bus;
    op.u.pcidev_access.dev    = dev;
    op.u.pcidev_access.func   = func;
    op.u.pcidev_access.enable = enable;

    return do_dom0_op(xc_handle, &op);
}
