/******************************************************************************
 * xc_misc.c
 *
 * Miscellaneous control interface functions.
 */

#include "xc_private.h"
#include <xen/hvm/hvm_op.h>

int xc_readconsolering(int xc_handle,
                       char **pbuffer,
                       unsigned int *pnr_chars,
                       int clear)
{
    int ret;
    DECLARE_SYSCTL;
    char *buffer = *pbuffer;
    unsigned int nr_chars = *pnr_chars;

    sysctl.cmd = XEN_SYSCTL_readconsole;
    set_xen_guest_handle(sysctl.u.readconsole.buffer, buffer);
    sysctl.u.readconsole.count  = nr_chars;
    sysctl.u.readconsole.clear  = clear;

    if ( (ret = lock_pages(buffer, nr_chars)) != 0 )
        return ret;

    if ( (ret = do_sysctl(xc_handle, &sysctl)) == 0 )
        *pnr_chars = sysctl.u.readconsole.count;

    unlock_pages(buffer, nr_chars);

    return ret;
}

int xc_physinfo(int xc_handle,
                xc_physinfo_t *put_info)
{
    int ret;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_physinfo;

    if ( (ret = do_sysctl(xc_handle, &sysctl)) != 0 )
        return ret;

    memcpy(put_info, &sysctl.u.physinfo, sizeof(*put_info));

    return 0;
}

int xc_sched_id(int xc_handle,
                int *sched_id)
{
    int ret;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_sched_id;

    if ( (ret = do_sysctl(xc_handle, &sysctl)) != 0 )
        return ret;

    *sched_id = sysctl.u.sched_id.sched_id;

    return 0;
}

int xc_perfc_control(int xc_handle,
                     uint32_t opcode,
                     xc_perfc_desc_t *desc,
                     xc_perfc_val_t *val,
                     int *nbr_desc,
                     int *nbr_val)
{
    int rc;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_perfc_op;
    sysctl.u.perfc_op.cmd = opcode;
    set_xen_guest_handle(sysctl.u.perfc_op.desc, desc);
    set_xen_guest_handle(sysctl.u.perfc_op.val, val);

    rc = do_sysctl(xc_handle, &sysctl);

    if (nbr_desc)
        *nbr_desc = sysctl.u.perfc_op.nr_counters;
    if (nbr_val)
        *nbr_val = sysctl.u.perfc_op.nr_vals;

    return rc;
}

int xc_hvm_set_pci_intx_level(
    int xc_handle, domid_t dom,
    uint8_t domain, uint8_t bus, uint8_t device, uint8_t intx,
    unsigned int level)
{
    DECLARE_HYPERCALL;
    struct xen_hvm_set_pci_intx_level arg;
    int rc;

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_set_pci_intx_level;
    hypercall.arg[1] = (unsigned long)&arg;

    arg.domid  = dom;
    arg.domain = domain;
    arg.bus    = bus;
    arg.device = device;
    arg.intx   = intx;
    arg.level  = level;

    if ( (rc = lock_pages(&arg, sizeof(arg))) != 0 )
    {
        PERROR("Could not lock memory");
        return rc;
    }

    rc = do_xen_hypercall(xc_handle, &hypercall);

    unlock_pages(&arg, sizeof(arg));

    return rc;
}

int xc_hvm_set_isa_irq_level(
    int xc_handle, domid_t dom,
    uint8_t isa_irq,
    unsigned int level)
{
    DECLARE_HYPERCALL;
    struct xen_hvm_set_isa_irq_level arg;
    int rc;

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_set_isa_irq_level;
    hypercall.arg[1] = (unsigned long)&arg;

    arg.domid   = dom;
    arg.isa_irq = isa_irq;
    arg.level   = level;

    if ( (rc = lock_pages(&arg, sizeof(arg))) != 0 )
    {
        PERROR("Could not lock memory");
        return rc;
    }

    rc = do_xen_hypercall(xc_handle, &hypercall);

    unlock_pages(&arg, sizeof(arg));

    return rc;
}

int xc_hvm_set_pci_link_route(
    int xc_handle, domid_t dom, uint8_t link, uint8_t isa_irq)
{
    DECLARE_HYPERCALL;
    struct xen_hvm_set_pci_link_route arg;
    int rc;

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_set_pci_link_route;
    hypercall.arg[1] = (unsigned long)&arg;

    arg.domid   = dom;
    arg.link    = link;
    arg.isa_irq = isa_irq;

    if ( (rc = lock_pages(&arg, sizeof(arg))) != 0 )
    {
        PERROR("Could not lock memory");
        return rc;
    }

    rc = do_xen_hypercall(xc_handle, &hypercall);

    unlock_pages(&arg, sizeof(arg));

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
