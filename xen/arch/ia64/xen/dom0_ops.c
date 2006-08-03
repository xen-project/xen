/******************************************************************************
 * Arch-specific dom0_ops.c
 * 
 * Process command requests from domain-0 guest OS.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <public/dom0_ops.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <asm/pdb.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/guest_access.h>
#include <public/sched_ctl.h>
#include <asm/vmx.h>
#include <asm/dom_fw.h>
#include <xen/iocap.h>

void build_physmap_table(struct domain *d);

extern unsigned long total_pages;
long arch_do_dom0_op(dom0_op_t *op, XEN_GUEST_HANDLE(dom0_op_t) u_dom0_op)
{
    long ret = 0;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    switch ( op->cmd )
    {
    case DOM0_GETMEMLIST:
    {
        unsigned long i;
        struct domain *d = find_domain_by_id(op->u.getmemlist.domain);
        unsigned long start_page = op->u.getmemlist.max_pfns >> 32;
        unsigned long nr_pages = op->u.getmemlist.max_pfns & 0xffffffff;
        unsigned long mfn;

        if ( d == NULL ) {
            ret = -EINVAL;
            break;
        }
        for (i = 0 ; i < nr_pages ; i++) {
            pte_t *pte;

            pte = (pte_t *)lookup_noalloc_domain_pte(d,
                                               (start_page + i) << PAGE_SHIFT);
            if (pte && pte_present(*pte))
                mfn = pte_pfn(*pte);
            else
                mfn = INVALID_MFN;

            if ( copy_to_guest_offset(op->u.getmemlist.buffer, i, &mfn, 1) ) {
                    ret = -EFAULT;
                    break;
            }
        }

        op->u.getmemlist.num_pfns = i;
        if (copy_to_guest(u_dom0_op, op, 1))
            ret = -EFAULT;

        put_domain(d);
    }
    break;

    case DOM0_PHYSINFO:
    {
        dom0_physinfo_t *pi = &op->u.physinfo;

        pi->threads_per_core =
            cpus_weight(cpu_sibling_map[0]);
        pi->cores_per_socket =
            cpus_weight(cpu_core_map[0]) / pi->threads_per_core;
        pi->sockets_per_node = 
            num_online_cpus() / cpus_weight(cpu_core_map[0]);
        pi->nr_nodes         = 1;
        pi->total_pages      = total_pages; 
        pi->free_pages       = avail_domheap_pages();
        pi->cpu_khz          = local_cpu_data->proc_freq / 1000;
        memset(pi->hw_cap, 0, sizeof(pi->hw_cap));
        //memcpy(pi->hw_cap, boot_cpu_data.x86_capability, NCAPINTS*4);
        ret = 0;
        if ( copy_to_guest(u_dom0_op, op, 1) )
            ret = -EFAULT;
    }
    break;

    case DOM0_DOMAIN_SETUP:
    {
        dom0_domain_setup_t *ds = &op->u.domain_setup;
        struct domain *d = find_domain_by_id(ds->domain);

        if ( d == NULL) {
            ret = -EINVAL;
            break;
        }

        if (ds->flags & XEN_DOMAINSETUP_query) {
            /* Set flags.  */
            if (d->arch.is_vti)
                ds->flags |= XEN_DOMAINSETUP_hvm_guest;
            /* Set params.  */
            ds->bp = 0;		/* unknown.  */
            ds->maxmem = 0; /* unknown.  */
            ds->xsi_va = d->arch.shared_info_va;
            ds->hypercall_imm = d->arch.breakimm;
            /* Copy back.  */
            if ( copy_to_guest(u_dom0_op, op, 1) )
                ret = -EFAULT;
        }
        else {
            if (ds->flags & XEN_DOMAINSETUP_hvm_guest) {
                if (!vmx_enabled) {
                    printk("No VMX hardware feature for vmx domain.\n");
                    ret = -EINVAL;
                    break;
                }
                if (!d->arch.is_vti) {
                    struct vcpu *v;
                    for_each_vcpu(d, v) {
                        BUG_ON(v->arch.privregs == NULL);
                        free_domheap_pages(virt_to_page(v->arch.privregs),
                                      get_order_from_shift(XMAPPEDREGS_SHIFT));
                        relinquish_vcpu_resources(v);
                    }
                }
                d->arch.is_vti = 1;
                vmx_setup_platform(d);
            }
            else {
                build_physmap_table(d);
                dom_fw_setup(d, ds->bp, ds->maxmem);
                if (ds->xsi_va)
                    d->arch.shared_info_va = ds->xsi_va;
                if (ds->hypercall_imm) {
                    struct vcpu *v;
                    d->arch.breakimm = ds->hypercall_imm;
                    for_each_vcpu (d, v)
                        v->arch.breakimm = d->arch.breakimm;
                }
            }
        }

        put_domain(d);
    }
    break;

    case DOM0_SHADOW_CONTROL:
    {
        struct domain *d; 
        ret = -ESRCH;
        d = find_domain_by_id(op->u.shadow_control.domain);
        if ( d != NULL )
        {
            ret = shadow_mode_control(d, &op->u.shadow_control);
            put_domain(d);
            copy_to_guest(u_dom0_op, op, 1);
        } 
    }
    break;

    case DOM0_IOPORT_PERMISSION:
    {
        struct domain *d;
        unsigned int fp = op->u.ioport_permission.first_port;
        unsigned int np = op->u.ioport_permission.nr_ports;
        unsigned int lp = fp + np - 1;

        ret = -ESRCH;
        d = find_domain_by_id(op->u.ioport_permission.domain);
        if (unlikely(d == NULL))
            break;

        if (np == 0)
            ret = 0;
        else {
            if (op->u.ioport_permission.allow_access)
                ret = ioports_permit_access(d, fp, lp);
            else
                ret = ioports_deny_access(d, fp, lp);
        }

        put_domain(d);
    }
    break;
    default:
        printf("arch_do_dom0_op: unrecognized dom0 op: %d!!!\n",op->cmd);
        ret = -ENOSYS;

    }

    return ret;
}

#ifdef CONFIG_XEN_IA64_DOM0_VP
static unsigned long
dom0vp_ioremap(struct domain *d, unsigned long mpaddr, unsigned long size)
{
    unsigned long end;

    /* Linux may use a 0 size!  */
    if (size == 0)
        size = PAGE_SIZE;

    end = PAGE_ALIGN(mpaddr + size);

    if (!iomem_access_permitted(d, mpaddr >> PAGE_SHIFT,
                                (end >> PAGE_SHIFT) - 1))
        return -EPERM;

    return assign_domain_mmio_page(d, mpaddr, size);
}

unsigned long
do_dom0vp_op(unsigned long cmd,
             unsigned long arg0, unsigned long arg1, unsigned long arg2,
             unsigned long arg3)
{
    unsigned long ret = 0;
    struct domain *d = current->domain;

    switch (cmd) {
    case IA64_DOM0VP_ioremap:
        ret = dom0vp_ioremap(d, arg0, arg1);
        break;
    case IA64_DOM0VP_phystomach:
        ret = ____lookup_domain_mpa(d, arg0 << PAGE_SHIFT);
        if (ret == INVALID_MFN) {
            DPRINTK("%s:%d INVALID_MFN ret: 0x%lx\n", __func__, __LINE__, ret);
        } else {
            ret = (ret & _PFN_MASK) >> PAGE_SHIFT;//XXX pte_pfn()
        }
        break;
    case IA64_DOM0VP_machtophys:
        if (!mfn_valid(arg0)) {
            ret = INVALID_M2P_ENTRY;
            break;
        }
        ret = get_gpfn_from_mfn(arg0);
        break;
    case IA64_DOM0VP_zap_physmap:
        ret = dom0vp_zap_physmap(d, arg0, (unsigned int)arg1);
        break;
    case IA64_DOM0VP_add_physmap:
        ret = dom0vp_add_physmap(d, arg0, arg1, (unsigned int)arg2,
                                 (domid_t)arg3);
        break;
    default:
        ret = -1;
		printf("unknown dom0_vp_op 0x%lx\n", cmd);
        break;
    }

    return ret;
}
#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
