/******************************************************************************
 * Arch-specific domctl.c
 *
 * Copyright (c) 2002-2006, K A Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/guest_access.h>
#include <xen/compat.h>
#include <xen/pci.h>
#include <public/domctl.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <asm/msr.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <xen/paging.h>
#include <asm/irq.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/cacheattr.h>
#include <asm/processor.h>
#include <asm/acpi.h> /* for hvm_acpi_power_button */
#include <xen/hypercall.h> /* for arch_do_domctl */
#include <xsm/xsm.h>
#include <xen/iommu.h>
#include <xen/vm_event.h>
#include <public/vm_event.h>
#include <asm/mem_sharing.h>
#include <asm/xstate.h>
#include <asm/debugger.h>
#include <asm/psr.h>

static int gdbsx_guest_mem_io(domid_t domid, struct xen_domctl_gdbsx_memio *iop)
{
    void * __user gva = (void *)iop->gva, * __user uva = (void *)iop->uva;

    iop->remain = dbg_rw_mem(gva, uva, iop->len, domid,
                             !!iop->gwr, iop->pgd3val);

    return iop->remain ? -EFAULT : 0;
}

#define MAX_IOPORTS 0x10000

long arch_do_domctl(
    struct xen_domctl *domctl, struct domain *d,
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    long ret = 0;
    bool_t copyback = 0;
    unsigned long i;

    switch ( domctl->cmd )
    {

    case XEN_DOMCTL_shadow_op:
        ret = paging_domctl(d, &domctl->u.shadow_op,
                            guest_handle_cast(u_domctl, void), 0);
        if ( ret == -ERESTART )
            return hypercall_create_continuation(__HYPERVISOR_arch_1,
                                                 "h", u_domctl);
        copyback = 1;
        break;

    case XEN_DOMCTL_ioport_permission:
    {
        unsigned int fp = domctl->u.ioport_permission.first_port;
        unsigned int np = domctl->u.ioport_permission.nr_ports;
        int allow = domctl->u.ioport_permission.allow_access;

        if ( (fp + np) <= fp || (fp + np) > MAX_IOPORTS )
            ret = -EINVAL;
        else if ( !ioports_access_permitted(currd, fp, fp + np - 1) ||
                  xsm_ioport_permission(XSM_HOOK, d, fp, fp + np - 1, allow) )
            ret = -EPERM;
        else if ( allow )
            ret = ioports_permit_access(d, fp, fp + np - 1);
        else
            ret = ioports_deny_access(d, fp, fp + np - 1);
        if ( !ret )
            memory_type_changed(d);
        break;
    }

    case XEN_DOMCTL_getmemlist:
    {
        unsigned long max_pfns = domctl->u.getmemlist.max_pfns;
        uint64_t mfn;
        struct page_info *page;

        if ( unlikely(d->is_dying) )
        {
            ret = -EINVAL;
            break;
        }

        /*
         * XSA-74: This sub-hypercall is broken in several ways:
         * - lock order inversion (p2m locks inside page_alloc_lock)
         * - no preemption on huge max_pfns input
         * - not (re-)checking d->is_dying with page_alloc_lock held
         * - not honoring start_pfn input (which libxc also doesn't set)
         * Additionally it is rather useless, as the result is stale by the
         * time the caller gets to look at it.
         * As it only has a single, non-production consumer (xen-mceinj),
         * rather than trying to fix it we restrict it for the time being.
         */
        if ( /* No nested locks inside copy_to_guest_offset(). */
             paging_mode_external(currd) ||
             /* Arbitrary limit capping processing time. */
             max_pfns > GB(4) / PAGE_SIZE )
        {
            ret = -EOPNOTSUPP;
            break;
        }

        spin_lock(&d->page_alloc_lock);

        ret = i = 0;
        page_list_for_each(page, &d->page_list)
        {
            if ( i >= max_pfns )
                break;
            mfn = page_to_mfn(page);
            if ( copy_to_guest_offset(domctl->u.getmemlist.buffer,
                                      i, &mfn, 1) )
            {
                ret = -EFAULT;
                break;
            }
			++i;
		}

        spin_unlock(&d->page_alloc_lock);

        domctl->u.getmemlist.num_pfns = i;
        copyback = 1;
        break;
    }

    case XEN_DOMCTL_getpageframeinfo3:
    {
        unsigned int num = domctl->u.getpageframeinfo3.num;
        unsigned int width = has_32bit_shinfo(currd) ? 4 : 8;

        /* Games to allow this code block to handle a compat guest. */
        void __user *guest_handle = domctl->u.getpageframeinfo3.array.p;

        if ( unlikely(num > 1024) ||
             unlikely(num != domctl->u.getpageframeinfo3.num) )
        {
            ret = -E2BIG;
            break;
        }

        for ( i = 0; i < num; ++i )
        {
            unsigned long gfn = 0, type = 0;
            struct page_info *page;
            p2m_type_t t;

            if ( raw_copy_from_guest(&gfn, guest_handle + (i * width), width) )
            {
                ret = -EFAULT;
                break;
            }

            page = get_page_from_gfn(d, gfn, &t, P2M_ALLOC);

            if ( unlikely(!page) ||
                 unlikely(is_xen_heap_page(page)) )
            {
                if ( unlikely(p2m_is_broken(t)) )
                    type = XEN_DOMCTL_PFINFO_BROKEN;
                else
                    type = XEN_DOMCTL_PFINFO_XTAB;
            }
            else
            {
                switch( page->u.inuse.type_info & PGT_type_mask )
                {
                case PGT_l1_page_table:
                    type = XEN_DOMCTL_PFINFO_L1TAB;
                    break;
                case PGT_l2_page_table:
                    type = XEN_DOMCTL_PFINFO_L2TAB;
                    break;
                case PGT_l3_page_table:
                    type = XEN_DOMCTL_PFINFO_L3TAB;
                    break;
                case PGT_l4_page_table:
                    type = XEN_DOMCTL_PFINFO_L4TAB;
                    break;
                }

                if ( page->u.inuse.type_info & PGT_pinned )
                    type |= XEN_DOMCTL_PFINFO_LPINTAB;

                if ( page->count_info & PGC_broken )
                    type = XEN_DOMCTL_PFINFO_BROKEN;
            }

            if ( page )
                put_page(page);

            if ( __raw_copy_to_guest(guest_handle + (i * width), &type, width) )
            {
                ret = -EFAULT;
                break;
            }
        }

        break;
    }

    case XEN_DOMCTL_hypercall_init:
    {
        unsigned long gmfn = domctl->u.hypercall_init.gmfn;
        struct page_info *page;
        void *hypercall_page;

        page = get_page_from_gfn(d, gmfn, NULL, P2M_ALLOC);

        if ( !page || !get_page_type(page, PGT_writable_page) )
        {
            if ( page )
            {
                ret = -EPERM;
                put_page(page);
            }
            else
                ret = -EINVAL;
            break;
        }

        hypercall_page = __map_domain_page(page);
        hypercall_page_initialise(d, hypercall_page);
        unmap_domain_page(hypercall_page);

        put_page_and_type(page);
        break;
    }

    case XEN_DOMCTL_sethvmcontext:
    {
        struct hvm_domain_context c = { .size = domctl->u.hvmcontext.size };

        ret = -EINVAL;
        if ( (d == currd) || /* no domain_pause() */
             !is_hvm_domain(d) )
            goto sethvmcontext_out;

        ret = -ENOMEM;
        if ( (c.data = xmalloc_bytes(c.size)) == NULL )
            goto sethvmcontext_out;

        ret = -EFAULT;
        if ( copy_from_guest(c.data, domctl->u.hvmcontext.buffer, c.size) != 0 )
            goto sethvmcontext_out;

        domain_pause(d);
        ret = hvm_load(d, &c);
        domain_unpause(d);

    sethvmcontext_out:
        xfree(c.data);
        break;
    }

    case XEN_DOMCTL_gethvmcontext:
    {
        struct hvm_domain_context c = { 0 };

        ret = -EINVAL;
        if ( (d == currd) || /* no domain_pause() */
             !is_hvm_domain(d) )
            goto gethvmcontext_out;

        c.size = hvm_save_size(d);

        if ( guest_handle_is_null(domctl->u.hvmcontext.buffer) )
        {
            /* Client is querying for the correct buffer size */
            domctl->u.hvmcontext.size = c.size;
            ret = 0;
            goto gethvmcontext_out;
        }

        /* Check that the client has a big enough buffer */
        ret = -ENOSPC;
        if ( domctl->u.hvmcontext.size < c.size )
            goto gethvmcontext_out;

        /* Allocate our own marshalling buffer */
        ret = -ENOMEM;
        if ( (c.data = xmalloc_bytes(c.size)) == NULL )
            goto gethvmcontext_out;

        domain_pause(d);
        ret = hvm_save(d, &c);
        domain_unpause(d);

        domctl->u.hvmcontext.size = c.cur;
        if ( copy_to_guest(domctl->u.hvmcontext.buffer, c.data, c.size) != 0 )
            ret = -EFAULT;

    gethvmcontext_out:
        copyback = 1;
        xfree(c.data);
        break;
    }

    case XEN_DOMCTL_gethvmcontext_partial:
        ret = -EINVAL;
        if ( (d == currd) || /* no domain_pause() */
             !is_hvm_domain(d) )
            break;

        domain_pause(d);
        ret = hvm_save_one(d, domctl->u.hvmcontext_partial.type,
                           domctl->u.hvmcontext_partial.instance,
                           domctl->u.hvmcontext_partial.buffer);
        domain_unpause(d);
        break;

    case XEN_DOMCTL_set_address_size:
        switch ( domctl->u.address_size.size )
        {
        case 32:
            ret = switch_compat(d);
            break;
        case 64:
            ret = switch_native(d);
            break;
        default:
            ret = (domctl->u.address_size.size == BITS_PER_LONG) ? 0 : -EINVAL;
            break;
        }
        break;

    case XEN_DOMCTL_get_address_size:
        domctl->u.address_size.size =
            is_pv_32bit_domain(d) ? 32 : BITS_PER_LONG;
        copyback = 1;
        break;

    case XEN_DOMCTL_set_machine_address_size:
        if ( d->tot_pages > 0 )
            ret = -EBUSY;
        else
            d->arch.physaddr_bitsize = domctl->u.address_size.size;
        break;

    case XEN_DOMCTL_get_machine_address_size:
        domctl->u.address_size.size = d->arch.physaddr_bitsize;
        copyback = 1;
        break;

    case XEN_DOMCTL_sendtrigger:
    {
        struct vcpu *v;

        ret = -ESRCH;
        if ( domctl->u.sendtrigger.vcpu >= d->max_vcpus ||
             (v = d->vcpu[domctl->u.sendtrigger.vcpu]) == NULL )
            break;

        switch ( domctl->u.sendtrigger.trigger )
        {
        case XEN_DOMCTL_SENDTRIGGER_NMI:
            ret = 0;
            if ( !test_and_set_bool(v->nmi_pending) )
                vcpu_kick(v);
            break;

        case XEN_DOMCTL_SENDTRIGGER_POWER:
            ret = -EINVAL;
            if ( is_hvm_domain(d) )
            {
                ret = 0;
                hvm_acpi_power_button(d);
            }
            break;

        case XEN_DOMCTL_SENDTRIGGER_SLEEP:
            ret = -EINVAL;
            if ( is_hvm_domain(d) )
            {
                ret = 0;
                hvm_acpi_sleep_button(d);
            }
            break;

        default:
            ret = -ENOSYS;
        }
        break;
    }

    case XEN_DOMCTL_bind_pt_irq:
    {
        xen_domctl_bind_pt_irq_t *bind = &domctl->u.bind_pt_irq;
        int irq;

        ret = -EINVAL;
        if ( !is_hvm_domain(d) )
            break;

        ret = xsm_bind_pt_irq(XSM_HOOK, d, bind);
        if ( ret )
            break;

        irq = domain_pirq_to_irq(d, bind->machine_irq);
        ret = -EPERM;
        if ( irq <= 0 || !irq_access_permitted(currd, irq) )
            break;

        ret = -ESRCH;
        if ( iommu_enabled )
        {
            spin_lock(&pcidevs_lock);
            ret = pt_irq_create_bind(d, bind);
            spin_unlock(&pcidevs_lock);
        }
        if ( ret < 0 )
            printk(XENLOG_G_ERR "pt_irq_create_bind failed (%ld) for dom%d\n",
                   ret, d->domain_id);
        break;
    }

    case XEN_DOMCTL_unbind_pt_irq:
    {
        xen_domctl_bind_pt_irq_t *bind = &domctl->u.bind_pt_irq;
        int irq = domain_pirq_to_irq(d, bind->machine_irq);

        ret = -EPERM;
        if ( irq <= 0 || !irq_access_permitted(currd, irq) )
            break;

        ret = xsm_unbind_pt_irq(XSM_HOOK, d, bind);
        if ( ret )
            break;

        if ( iommu_enabled )
        {
            spin_lock(&pcidevs_lock);
            ret = pt_irq_destroy_bind(d, bind);
            spin_unlock(&pcidevs_lock);
        }
        if ( ret < 0 )
            printk(XENLOG_G_ERR "pt_irq_destroy_bind failed (%ld) for dom%d\n",
                   ret, d->domain_id);
        break;
    }

    case XEN_DOMCTL_ioport_mapping:
    {
        struct hvm_iommu *hd;
        unsigned int fgp = domctl->u.ioport_mapping.first_gport;
        unsigned int fmp = domctl->u.ioport_mapping.first_mport;
        unsigned int np = domctl->u.ioport_mapping.nr_ports;
        unsigned int add = domctl->u.ioport_mapping.add_mapping;
        struct g2m_ioport *g2m_ioport;
        int found = 0;

        ret = -EINVAL;
        if ( ((fgp | fmp | (np - 1)) >= MAX_IOPORTS) ||
            ((fgp + np) > MAX_IOPORTS) || ((fmp + np) > MAX_IOPORTS) )
        {
            printk(XENLOG_G_ERR
                   "ioport_map:invalid:dom%d gport=%x mport=%x nr=%x\n",
                   domctl->domain, fgp, fmp, np);
            break;
        }

        ret = -EPERM;
        if ( !ioports_access_permitted(currd, fmp, fmp + np - 1) )
            break;

        ret = xsm_ioport_mapping(XSM_HOOK, d, fmp, fmp + np - 1, add);
        if ( ret )
            break;

        hd = domain_hvm_iommu(d);
        if ( add )
        {
            printk(XENLOG_G_INFO
                   "ioport_map:add: dom%d gport=%x mport=%x nr=%x\n",
                   d->domain_id, fgp, fmp, np);

            list_for_each_entry(g2m_ioport, &hd->arch.g2m_ioport_list, list)
                if (g2m_ioport->mport == fmp )
                {
                    g2m_ioport->gport = fgp;
                    g2m_ioport->np = np;
                    found = 1;
                    break;
                }
            if ( !found )
            {
                g2m_ioport = xmalloc(struct g2m_ioport);
                if ( !g2m_ioport )
                    ret = -ENOMEM;
            }
            if ( !found && !ret )
            {
                g2m_ioport->gport = fgp;
                g2m_ioport->mport = fmp;
                g2m_ioport->np = np;
                list_add_tail(&g2m_ioport->list, &hd->arch.g2m_ioport_list);
            }
            if ( !ret )
                ret = ioports_permit_access(d, fmp, fmp + np - 1);
            if ( ret && !found && g2m_ioport )
            {
                list_del(&g2m_ioport->list);
                xfree(g2m_ioport);
            }
        }
        else
        {
            printk(XENLOG_G_INFO
                   "ioport_map:remove: dom%d gport=%x mport=%x nr=%x\n",
                   d->domain_id, fgp, fmp, np);
            list_for_each_entry(g2m_ioport, &hd->arch.g2m_ioport_list, list)
                if ( g2m_ioport->mport == fmp )
                {
                    list_del(&g2m_ioport->list);
                    xfree(g2m_ioport);
                    break;
                }
            ret = ioports_deny_access(d, fmp, fmp + np - 1);
            if ( ret && is_hardware_domain(currd) )
                printk(XENLOG_ERR
                       "ioport_map: error %ld denying dom%d access to [%x,%x]\n",
                       ret, d->domain_id, fmp, fmp + np - 1);
        }
        if ( !ret )
            memory_type_changed(d);
        break;
    }

    case XEN_DOMCTL_pin_mem_cacheattr:
        ret = hvm_set_mem_pinned_cacheattr(
            d, domctl->u.pin_mem_cacheattr.start,
            domctl->u.pin_mem_cacheattr.end,
            domctl->u.pin_mem_cacheattr.type);
        break;

    case XEN_DOMCTL_set_ext_vcpucontext:
    case XEN_DOMCTL_get_ext_vcpucontext:
    {
        struct xen_domctl_ext_vcpucontext *evc = &domctl->u.ext_vcpucontext;
        struct vcpu *v;

        ret = -ESRCH;
        if ( (evc->vcpu >= d->max_vcpus) ||
             ((v = d->vcpu[evc->vcpu]) == NULL) )
            break;

        if ( domctl->cmd == XEN_DOMCTL_get_ext_vcpucontext )
        {
            if ( v == curr ) /* no vcpu_pause() */
                break;

            evc->size = sizeof(*evc);

            vcpu_pause(v);

            if ( is_pv_domain(d) )
            {
                evc->sysenter_callback_cs      =
                    v->arch.pv_vcpu.sysenter_callback_cs;
                evc->sysenter_callback_eip     =
                    v->arch.pv_vcpu.sysenter_callback_eip;
                evc->sysenter_disables_events  =
                    v->arch.pv_vcpu.sysenter_disables_events;
                evc->syscall32_callback_cs     =
                    v->arch.pv_vcpu.syscall32_callback_cs;
                evc->syscall32_callback_eip    =
                    v->arch.pv_vcpu.syscall32_callback_eip;
                evc->syscall32_disables_events =
                    v->arch.pv_vcpu.syscall32_disables_events;
            }
            else
            {
                evc->sysenter_callback_cs      = 0;
                evc->sysenter_callback_eip     = 0;
                evc->sysenter_disables_events  = 0;
                evc->syscall32_callback_cs     = 0;
                evc->syscall32_callback_eip    = 0;
                evc->syscall32_disables_events = 0;
            }
            evc->vmce.caps = v->arch.vmce.mcg_cap;
            evc->vmce.mci_ctl2_bank0 = v->arch.vmce.bank[0].mci_ctl2;
            evc->vmce.mci_ctl2_bank1 = v->arch.vmce.bank[1].mci_ctl2;

            ret = 0;
            vcpu_unpause(v);
            copyback = 1;
        }
        else
        {
            if ( d == currd ) /* no domain_pause() */
                break;
            ret = -EINVAL;
            if ( evc->size < offsetof(typeof(*evc), vmce) )
                break;
            if ( is_pv_domain(d) )
            {
                if ( !is_canonical_address(evc->sysenter_callback_eip) ||
                     !is_canonical_address(evc->syscall32_callback_eip) )
                    break;
                domain_pause(d);
                fixup_guest_code_selector(d, evc->sysenter_callback_cs);
                v->arch.pv_vcpu.sysenter_callback_cs      =
                    evc->sysenter_callback_cs;
                v->arch.pv_vcpu.sysenter_callback_eip     =
                    evc->sysenter_callback_eip;
                v->arch.pv_vcpu.sysenter_disables_events  =
                    evc->sysenter_disables_events;
                fixup_guest_code_selector(d, evc->syscall32_callback_cs);
                v->arch.pv_vcpu.syscall32_callback_cs     =
                    evc->syscall32_callback_cs;
                v->arch.pv_vcpu.syscall32_callback_eip    =
                    evc->syscall32_callback_eip;
                v->arch.pv_vcpu.syscall32_disables_events =
                    evc->syscall32_disables_events;
            }
            else if ( (evc->sysenter_callback_cs & ~3) ||
                      evc->sysenter_callback_eip ||
                      (evc->syscall32_callback_cs & ~3) ||
                      evc->syscall32_callback_eip )
                break;
            else
                domain_pause(d);

            BUILD_BUG_ON(offsetof(struct xen_domctl_ext_vcpucontext,
                                  mcg_cap) !=
                         offsetof(struct xen_domctl_ext_vcpucontext,
                                  vmce.caps));
            BUILD_BUG_ON(sizeof(evc->mcg_cap) != sizeof(evc->vmce.caps));
            if ( evc->size >= offsetof(typeof(*evc), vmce) +
                              sizeof(evc->vmce) )
                ret = vmce_restore_vcpu(v, &evc->vmce);
            else if ( evc->size >= offsetof(typeof(*evc), mcg_cap) +
                                   sizeof(evc->mcg_cap) )
            {
                struct hvm_vmce_vcpu vmce = { .caps = evc->mcg_cap };

                ret = vmce_restore_vcpu(v, &vmce);
            }
            else
                ret = 0;

            domain_unpause(d);
        }
        break;
    }

    case XEN_DOMCTL_set_cpuid:
    {
        xen_domctl_cpuid_t *ctl = &domctl->u.cpuid;
        cpuid_input_t *cpuid, *unused = NULL;

        for ( i = 0; i < MAX_CPUID_INPUT; i++ )
        {
            cpuid = &d->arch.cpuids[i];

            if ( cpuid->input[0] == XEN_CPUID_INPUT_UNUSED )
            {
                if ( !unused )
                    unused = cpuid;
                continue;
            }

            if ( (cpuid->input[0] == ctl->input[0]) &&
                 ((cpuid->input[1] == XEN_CPUID_INPUT_UNUSED) ||
                  (cpuid->input[1] == ctl->input[1])) )
                break;
        }

        if ( i < MAX_CPUID_INPUT )
            *cpuid = *ctl;
        else if ( unused )
            *unused = *ctl;
        else
            ret = -ENOENT;

        if ( !ret )
        {
            switch ( ctl->input[0] )
            {
            case 0: {
                union {
                    typeof(boot_cpu_data.x86_vendor_id) str;
                    struct {
                        uint32_t ebx, edx, ecx;
                    } reg;
                } vendor_id = {
                    .reg = {
                        .ebx = ctl->ebx,
                        .edx = ctl->edx,
                        .ecx = ctl->ecx
                    }
                };

                d->arch.x86_vendor = get_cpu_vendor(vendor_id.str, gcv_guest);
                break;
            }
            case 1:
                d->arch.x86 = (ctl->eax >> 8) & 0xf;
                if ( d->arch.x86 == 0xf )
                    d->arch.x86 += (ctl->eax >> 20) & 0xff;
                d->arch.x86_model = (ctl->eax >> 4) & 0xf;
                if ( d->arch.x86 >= 0x6 )
                    d->arch.x86_model |= (ctl->eax >> 12) & 0xf0;
                break;
            }
        }
        break;
    }

    case XEN_DOMCTL_gettscinfo:
        if ( d == currd ) /* no domain_pause() */
            ret = -EINVAL;
        else
        {
            domain_pause(d);
            tsc_get_info(d, &domctl->u.tsc_info.tsc_mode,
                         &domctl->u.tsc_info.elapsed_nsec,
                         &domctl->u.tsc_info.gtsc_khz,
                         &domctl->u.tsc_info.incarnation);
            domain_unpause(d);
            copyback = 1;
        }
        break;

    case XEN_DOMCTL_settscinfo:
        if ( d == currd ) /* no domain_pause() */
            ret = -EINVAL;
        else
        {
            domain_pause(d);
            tsc_set_info(d, domctl->u.tsc_info.tsc_mode,
                         domctl->u.tsc_info.elapsed_nsec,
                         domctl->u.tsc_info.gtsc_khz,
                         domctl->u.tsc_info.incarnation);
            domain_unpause(d);
        }
        break;

    case XEN_DOMCTL_suppress_spurious_page_faults:
        d->arch.suppress_spurious_page_faults = 1;
        break;

    case XEN_DOMCTL_debug_op:
    {
        struct vcpu *v;

        ret = -EINVAL;
        if ( (domctl->u.debug_op.vcpu >= d->max_vcpus) ||
             ((v = d->vcpu[domctl->u.debug_op.vcpu]) == NULL) )
            break;

        ret = -EINVAL;
        if ( (v == curr) || /* no vcpu_pause() */
             !is_hvm_domain(d) )
            break;

        ret = hvm_debug_op(v, domctl->u.debug_op.op);
        break;
    }

    case XEN_DOMCTL_gdbsx_guestmemio:
        domctl->u.gdbsx_guest_memio.remain = domctl->u.gdbsx_guest_memio.len;
        ret = gdbsx_guest_mem_io(domctl->domain, &domctl->u.gdbsx_guest_memio);
        if ( !ret )
           copyback = 1;
        break;

    case XEN_DOMCTL_gdbsx_pausevcpu:
    {
        struct vcpu *v;

        ret = -EBUSY;
        if ( !d->controller_pause_count )
            break;
        ret = -EINVAL;
        if ( domctl->u.gdbsx_pauseunp_vcpu.vcpu >= d->max_vcpus ||
             (v = d->vcpu[domctl->u.gdbsx_pauseunp_vcpu.vcpu]) == NULL )
            break;
        ret = vcpu_pause_by_systemcontroller(v);
        break;
    }

    case XEN_DOMCTL_gdbsx_unpausevcpu:
    {
        struct vcpu *v;

        ret = -EBUSY;
        if ( !d->controller_pause_count )
            break;
        ret = -EINVAL;
        if ( domctl->u.gdbsx_pauseunp_vcpu.vcpu >= d->max_vcpus ||
             (v = d->vcpu[domctl->u.gdbsx_pauseunp_vcpu.vcpu]) == NULL )
            break;
        ret = vcpu_unpause_by_systemcontroller(v);
        if ( ret == -EINVAL )
            printk(XENLOG_G_WARNING
                   "WARN: d%d attempting to unpause %pv which is not paused\n",
                   currd->domain_id, v);
        break;
    }

    case XEN_DOMCTL_gdbsx_domstatus:
    {
        struct vcpu *v;

        domctl->u.gdbsx_domstatus.vcpu_id = -1;
        domctl->u.gdbsx_domstatus.paused = d->controller_pause_count > 0;
        if ( domctl->u.gdbsx_domstatus.paused )
        {
            for_each_vcpu ( d, v )
            {
                if ( v->arch.gdbsx_vcpu_event )
                {
                    domctl->u.gdbsx_domstatus.vcpu_id = v->vcpu_id;
                    domctl->u.gdbsx_domstatus.vcpu_ev =
                        v->arch.gdbsx_vcpu_event;
                    v->arch.gdbsx_vcpu_event = 0;
                    break;
                }
            }
        }
        copyback = 1;
        break;
    }

    case XEN_DOMCTL_setvcpuextstate:
    case XEN_DOMCTL_getvcpuextstate:
    {
        struct xen_domctl_vcpuextstate *evc = &domctl->u.vcpuextstate;
        struct vcpu *v;
        uint32_t offset = 0;

#define PV_XSAVE_SIZE(xcr0) (2 * sizeof(uint64_t) + xstate_ctxt_size(xcr0))

        ret = -ESRCH;
        if ( (evc->vcpu >= d->max_vcpus) ||
             ((v = d->vcpu[evc->vcpu]) == NULL) )
            goto vcpuextstate_out;

        ret = -EINVAL;
        if ( v == curr ) /* no vcpu_pause() */
            goto vcpuextstate_out;

        if ( domctl->cmd == XEN_DOMCTL_getvcpuextstate )
        {
            unsigned int size;

            ret = 0;
            vcpu_pause(v);

            size = PV_XSAVE_SIZE(v->arch.xcr0_accum);
            if ( (!evc->size && !evc->xfeature_mask) ||
                 guest_handle_is_null(evc->buffer) )
            {
                evc->xfeature_mask = xfeature_mask;
                evc->size = size;
                vcpu_unpause(v);
                goto vcpuextstate_out;
            }

            if ( evc->size != size || evc->xfeature_mask != xfeature_mask )
                ret = -EINVAL;

            if ( !ret && copy_to_guest_offset(evc->buffer, offset,
                                              (void *)&v->arch.xcr0,
                                              sizeof(v->arch.xcr0)) )
                ret = -EFAULT;

            offset += sizeof(v->arch.xcr0);
            if ( !ret && copy_to_guest_offset(evc->buffer, offset,
                                              (void *)&v->arch.xcr0_accum,
                                              sizeof(v->arch.xcr0_accum)) )
                ret = -EFAULT;

            offset += sizeof(v->arch.xcr0_accum);
            if ( !ret && copy_to_guest_offset(evc->buffer, offset,
                                              (void *)v->arch.xsave_area,
                                              size - 2 * sizeof(uint64_t)) )
                ret = -EFAULT;

            vcpu_unpause(v);
        }
        else
        {
            void *receive_buf;
            uint64_t _xcr0, _xcr0_accum;
            const struct xsave_struct *_xsave_area;

            ret = -EINVAL;
            if ( evc->size < 2 * sizeof(uint64_t) ||
                 evc->size > 2 * sizeof(uint64_t) +
                             xstate_ctxt_size(xfeature_mask) )
                goto vcpuextstate_out;

            receive_buf = xmalloc_bytes(evc->size);
            if ( !receive_buf )
            {
                ret = -ENOMEM;
                goto vcpuextstate_out;
            }
            if ( copy_from_guest_offset(receive_buf, domctl->u.vcpuextstate.buffer,
                                        offset, evc->size) )
            {
                ret = -EFAULT;
                xfree(receive_buf);
                goto vcpuextstate_out;
            }

            _xcr0 = *(uint64_t *)receive_buf;
            _xcr0_accum = *(uint64_t *)(receive_buf + sizeof(uint64_t));
            _xsave_area = receive_buf + 2 * sizeof(uint64_t);

            if ( _xcr0_accum )
            {
                if ( evc->size >= 2 * sizeof(uint64_t) + XSTATE_AREA_MIN_SIZE )
                    ret = validate_xstate(_xcr0, _xcr0_accum,
                                          _xsave_area->xsave_hdr.xstate_bv);
            }
            else if ( !_xcr0 )
                ret = 0;
            if ( ret )
            {
                xfree(receive_buf);
                goto vcpuextstate_out;
            }

            if ( evc->size <= PV_XSAVE_SIZE(_xcr0_accum) )
            {
                vcpu_pause(v);
                v->arch.xcr0 = _xcr0;
                v->arch.xcr0_accum = _xcr0_accum;
                if ( _xcr0_accum & XSTATE_NONLAZY )
                    v->arch.nonlazy_xstate_used = 1;
                memcpy(v->arch.xsave_area, _xsave_area,
                       evc->size - 2 * sizeof(uint64_t));
                vcpu_unpause(v);
            }
            else
                ret = -EINVAL;

            xfree(receive_buf);
        }

    vcpuextstate_out:
        if ( domctl->cmd == XEN_DOMCTL_getvcpuextstate )
            copyback = 1;
        break;
    }

    case XEN_DOMCTL_mem_sharing_op:
        ret = mem_sharing_domctl(d, &domctl->u.mem_sharing_op);
        break;

#if P2M_AUDIT
    case XEN_DOMCTL_audit_p2m:
        if ( d == currd )
            ret = -EPERM;
        else
        {
            audit_p2m(d,
                      &domctl->u.audit_p2m.orphans,
                      &domctl->u.audit_p2m.m2p_bad,
                      &domctl->u.audit_p2m.p2m_bad);
            copyback = 1;
        }
        break;
#endif /* P2M_AUDIT */

    case XEN_DOMCTL_set_broken_page_p2m:
    {
        p2m_type_t pt;
        unsigned long pfn = domctl->u.set_broken_page_p2m.pfn;
        mfn_t mfn = get_gfn_query(d, pfn, &pt);

        if ( unlikely(!mfn_valid(mfn_x(mfn))) || unlikely(!p2m_is_ram(pt)) )
            ret = -EINVAL;
        else
            ret = p2m_change_type_one(d, pfn, pt, p2m_ram_broken);

        put_gfn(d, pfn);
        break;
    }

    case XEN_DOMCTL_get_vcpu_msrs:
    case XEN_DOMCTL_set_vcpu_msrs:
    {
        struct xen_domctl_vcpu_msrs *vmsrs = &domctl->u.vcpu_msrs;
        struct xen_domctl_vcpu_msr msr;
        struct vcpu *v;
        uint32_t nr_msrs = 0;

        ret = -ESRCH;
        if ( (vmsrs->vcpu >= d->max_vcpus) ||
             ((v = d->vcpu[vmsrs->vcpu]) == NULL) )
            break;

        ret = -EINVAL;
        if ( (v == curr) || /* no vcpu_pause() */
             !is_pv_domain(d) )
            break;

        /* Count maximum number of optional msrs. */
        if ( boot_cpu_has(X86_FEATURE_DBEXT) )
            nr_msrs += 4;

        if ( domctl->cmd == XEN_DOMCTL_get_vcpu_msrs )
        {
            ret = 0; copyback = 1;

            /* NULL guest handle is a request for max size. */
            if ( guest_handle_is_null(vmsrs->msrs) )
                vmsrs->msr_count = nr_msrs;
            else
            {
                i = 0;

                vcpu_pause(v);

                if ( boot_cpu_has(X86_FEATURE_DBEXT) )
                {
                    unsigned int j;

                    if ( v->arch.pv_vcpu.dr_mask[0] )
                    {
                        if ( i < vmsrs->msr_count && !ret )
                        {
                            msr.index = MSR_AMD64_DR0_ADDRESS_MASK;
                            msr.reserved = 0;
                            msr.value = v->arch.pv_vcpu.dr_mask[0];
                            if ( copy_to_guest_offset(vmsrs->msrs, i, &msr, 1) )
                                ret = -EFAULT;
                        }
                        ++i;
                    }

                    for ( j = 0; j < 3; ++j )
                    {
                        if ( !v->arch.pv_vcpu.dr_mask[1 + j] )
                            continue;
                        if ( i < vmsrs->msr_count && !ret )
                        {
                            msr.index = MSR_AMD64_DR1_ADDRESS_MASK + j;
                            msr.reserved = 0;
                            msr.value = v->arch.pv_vcpu.dr_mask[1 + j];
                            if ( copy_to_guest_offset(vmsrs->msrs, i, &msr, 1) )
                                ret = -EFAULT;
                        }
                        ++i;
                    }
                }

                vcpu_unpause(v);

                if ( i > vmsrs->msr_count && !ret )
                    ret = -ENOBUFS;
                vmsrs->msr_count = i;
            }
        }
        else
        {
            ret = -EINVAL;
            if ( vmsrs->msr_count > nr_msrs )
                break;

            vcpu_pause(v);

            for ( i = 0; i < vmsrs->msr_count; ++i )
            {
                ret = -EFAULT;
                if ( copy_from_guest_offset(&msr, vmsrs->msrs, i, 1) )
                    break;

                ret = -EINVAL;
                if ( msr.reserved )
                    break;

                switch ( msr.index )
                {
                case MSR_AMD64_DR0_ADDRESS_MASK:
                    if ( !boot_cpu_has(X86_FEATURE_DBEXT) ||
                         (msr.value >> 32) )
                        break;
                    v->arch.pv_vcpu.dr_mask[0] = msr.value;
                    continue;

                case MSR_AMD64_DR1_ADDRESS_MASK ...
                    MSR_AMD64_DR3_ADDRESS_MASK:
                    if ( !boot_cpu_has(X86_FEATURE_DBEXT) ||
                         (msr.value >> 32) )
                        break;
                    msr.index -= MSR_AMD64_DR1_ADDRESS_MASK - 1;
                    v->arch.pv_vcpu.dr_mask[msr.index] = msr.value;
                    continue;
                }
                break;
            }

            vcpu_unpause(v);

            if ( i == vmsrs->msr_count )
                ret = 0;
            else
            {
                vmsrs->msr_count = i;
                copyback = 1;
            }
        }
        break;
    }

    case XEN_DOMCTL_psr_cmt_op:
        if ( !psr_cmt_enabled() )
        {
            ret = -ENODEV;
            break;
        }

        switch ( domctl->u.psr_cmt_op.cmd )
        {
        case XEN_DOMCTL_PSR_CMT_OP_ATTACH:
            ret = psr_alloc_rmid(d);
            break;

        case XEN_DOMCTL_PSR_CMT_OP_DETACH:
            if ( d->arch.psr_rmid > 0 )
                psr_free_rmid(d);
            else
                ret = -ENOENT;
            break;

        case XEN_DOMCTL_PSR_CMT_OP_QUERY_RMID:
            domctl->u.psr_cmt_op.data = d->arch.psr_rmid;
            copyback = 1;
            break;

        default:
            ret = -ENOSYS;
            break;
        }
        break;

    case XEN_DOMCTL_psr_cat_op:
        switch ( domctl->u.psr_cat_op.cmd )
        {
        case XEN_DOMCTL_PSR_CAT_OP_SET_L3_CBM:
            ret = psr_set_l3_cbm(d, domctl->u.psr_cat_op.target,
                                 domctl->u.psr_cat_op.data);
            break;

        case XEN_DOMCTL_PSR_CAT_OP_GET_L3_CBM:
            ret = psr_get_l3_cbm(d, domctl->u.psr_cat_op.target,
                                 &domctl->u.psr_cat_op.data);
            copyback = 1;
            break;

        default:
            ret = -EOPNOTSUPP;
            break;
        }
        break;

    default:
        ret = iommu_do_domctl(domctl, d, u_domctl);
        break;
    }

    if ( copyback && __copy_to_guest(u_domctl, domctl, 1) )
        ret = -EFAULT;

    return ret;
}

#define xen_vcpu_guest_context vcpu_guest_context
#define fpu_ctxt fpu_ctxt.x
CHECK_FIELD_(struct, vcpu_guest_context, fpu_ctxt);
#undef fpu_ctxt
#undef xen_vcpu_guest_context

void arch_get_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
    unsigned int i;
    const struct domain *d = v->domain;
    bool_t compat = is_pv_32bit_domain(d);
#define c(fld) (!compat ? (c.nat->fld) : (c.cmp->fld))

    if ( !is_pv_domain(d) )
        memset(c.nat, 0, sizeof(*c.nat));
    memcpy(&c.nat->fpu_ctxt, v->arch.fpu_ctxt, sizeof(c.nat->fpu_ctxt));
    c(flags = v->arch.vgc_flags & ~(VGCF_i387_valid|VGCF_in_kernel));
    if ( v->fpu_initialised )
        c(flags |= VGCF_i387_valid);
    if ( !test_bit(_VPF_down, &v->pause_flags) )
        c(flags |= VGCF_online);
    if ( !compat )
    {
        memcpy(&c.nat->user_regs, &v->arch.user_regs, sizeof(c.nat->user_regs));
        if ( is_pv_domain(d) )
            memcpy(c.nat->trap_ctxt, v->arch.pv_vcpu.trap_ctxt,
                   sizeof(c.nat->trap_ctxt));
    }
    else
    {
        XLAT_cpu_user_regs(&c.cmp->user_regs, &v->arch.user_regs);
        if ( is_pv_domain(d) )
        {
            for ( i = 0; i < ARRAY_SIZE(c.cmp->trap_ctxt); ++i )
                XLAT_trap_info(c.cmp->trap_ctxt + i,
                               v->arch.pv_vcpu.trap_ctxt + i);
        }
    }

    for ( i = 0; i < ARRAY_SIZE(v->arch.debugreg); ++i )
        c(debugreg[i] = v->arch.debugreg[i]);

    if ( has_hvm_container_domain(d) )
    {
        struct segment_register sreg;

        c.nat->ctrlreg[0] = v->arch.hvm_vcpu.guest_cr[0];
        c.nat->ctrlreg[2] = v->arch.hvm_vcpu.guest_cr[2];
        c.nat->ctrlreg[3] = v->arch.hvm_vcpu.guest_cr[3];
        c.nat->ctrlreg[4] = v->arch.hvm_vcpu.guest_cr[4];
        hvm_get_segment_register(v, x86_seg_cs, &sreg);
        c.nat->user_regs.cs = sreg.sel;
        hvm_get_segment_register(v, x86_seg_ss, &sreg);
        c.nat->user_regs.ss = sreg.sel;
        hvm_get_segment_register(v, x86_seg_ds, &sreg);
        c.nat->user_regs.ds = sreg.sel;
        hvm_get_segment_register(v, x86_seg_es, &sreg);
        c.nat->user_regs.es = sreg.sel;
        hvm_get_segment_register(v, x86_seg_fs, &sreg);
        c.nat->user_regs.fs = sreg.sel;
        c.nat->fs_base = sreg.base;
        hvm_get_segment_register(v, x86_seg_gs, &sreg);
        c.nat->user_regs.gs = sreg.sel;
        if ( ring_0(&c.nat->user_regs) )
        {
            c.nat->gs_base_kernel = sreg.base;
            c.nat->gs_base_user = hvm_get_shadow_gs_base(v);
        }
        else
        {
            c.nat->gs_base_user = sreg.base;
            c.nat->gs_base_kernel = hvm_get_shadow_gs_base(v);
        }
    }
    else
    {
        c(ldt_base = v->arch.pv_vcpu.ldt_base);
        c(ldt_ents = v->arch.pv_vcpu.ldt_ents);
        for ( i = 0; i < ARRAY_SIZE(v->arch.pv_vcpu.gdt_frames); ++i )
            c(gdt_frames[i] = v->arch.pv_vcpu.gdt_frames[i]);
        BUILD_BUG_ON(ARRAY_SIZE(c.nat->gdt_frames) !=
                     ARRAY_SIZE(c.cmp->gdt_frames));
        for ( ; i < ARRAY_SIZE(c.nat->gdt_frames); ++i )
            c(gdt_frames[i] = 0);
        c(gdt_ents = v->arch.pv_vcpu.gdt_ents);
        c(kernel_ss = v->arch.pv_vcpu.kernel_ss);
        c(kernel_sp = v->arch.pv_vcpu.kernel_sp);
        for ( i = 0; i < ARRAY_SIZE(v->arch.pv_vcpu.ctrlreg); ++i )
            c(ctrlreg[i] = v->arch.pv_vcpu.ctrlreg[i]);
        c(event_callback_eip = v->arch.pv_vcpu.event_callback_eip);
        c(failsafe_callback_eip = v->arch.pv_vcpu.failsafe_callback_eip);
        if ( !compat )
        {
            c.nat->syscall_callback_eip = v->arch.pv_vcpu.syscall_callback_eip;
            c.nat->fs_base = v->arch.pv_vcpu.fs_base;
            c.nat->gs_base_kernel = v->arch.pv_vcpu.gs_base_kernel;
            c.nat->gs_base_user = v->arch.pv_vcpu.gs_base_user;
        }
        else
        {
            c(event_callback_cs = v->arch.pv_vcpu.event_callback_cs);
            c(failsafe_callback_cs = v->arch.pv_vcpu.failsafe_callback_cs);
        }

        /* IOPL privileges are virtualised: merge back into returned eflags. */
        BUG_ON((c(user_regs.eflags) & X86_EFLAGS_IOPL) != 0);
        c(user_regs.eflags |= v->arch.pv_vcpu.iopl << 12);

        if ( !compat )
        {
            c.nat->ctrlreg[3] = xen_pfn_to_cr3(
                pagetable_get_pfn(v->arch.guest_table));
            c.nat->ctrlreg[1] =
                pagetable_is_null(v->arch.guest_table_user) ? 0
                : xen_pfn_to_cr3(pagetable_get_pfn(v->arch.guest_table_user));

            /* Merge shadow DR7 bits into real DR7. */
            c.nat->debugreg[7] |= c.nat->debugreg[5];
            c.nat->debugreg[5] = 0;
        }
        else
        {
            const l4_pgentry_t *l4e =
                map_domain_page(_mfn(pagetable_get_pfn(v->arch.guest_table)));

            c.cmp->ctrlreg[3] = compat_pfn_to_cr3(l4e_get_pfn(*l4e));
            unmap_domain_page(l4e);

            /* Merge shadow DR7 bits into real DR7. */
            c.cmp->debugreg[7] |= c.cmp->debugreg[5];
            c.cmp->debugreg[5] = 0;
        }

        if ( guest_kernel_mode(v, &v->arch.user_regs) )
            c(flags |= VGCF_in_kernel);
    }

    c(vm_assist = d->vm_assist);
#undef c
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
