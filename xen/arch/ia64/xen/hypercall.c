/*
 * Hypercall implementations
 * 
 * Copyright (C) 2005 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/hypercall.h>
#include <xen/multicall.h>
#include <xen/guest_access.h>
#include <xen/mm.h>

#include <linux/efi.h>	/* FOR EFI_UNIMPLEMENTED */
#include <asm/sal.h>	/* FOR struct ia64_sal_retval */
#include <asm/fpswa.h>	/* FOR struct fpswa_ret_t */

#include <asm/vmx.h>
#include <asm/vmx_vcpu.h>
#include <asm/vcpu.h>
#include <asm/dom_fw.h>
#include <public/domctl.h>
#include <public/sysctl.h>
#include <public/event_channel.h>
#include <public/memory.h>
#include <public/sched.h>
#include <xen/irq.h>
#include <asm/hw_irq.h>
#include <public/physdev.h>
#include <xen/domain.h>
#include <public/callback.h>
#include <xen/event.h>
#include <xen/perfc.h>
#include <public/arch-ia64/debug_op.h>
#include <asm/sioemu.h>
#include <public/arch-ia64/sioemu.h>
#include <xen/pci.h>

static IA64FAULT
xen_hypercall (struct pt_regs *regs)
{
	uint32_t cmd = (uint32_t)regs->r2;
	printk("Warning %s should not be called %d\n", __FUNCTION__, cmd);
	return IA64_NO_FAULT;
}

static IA64FAULT
xen_fast_hypercall (struct pt_regs *regs)
{
	uint32_t cmd = (uint32_t)regs->r2;
	switch (cmd) {
	case __HYPERVISOR_ia64_fast_eoi:
		printk("Warning %s should not be called %d\n",
		       __FUNCTION__, cmd);
		break;
	default:
		regs->r8 = -ENOSYS;
	}
	return IA64_NO_FAULT;
}

static long __do_pirq_guest_eoi(struct domain *d, int pirq)
{
	if ( pirq < 0 || pirq >= NR_IRQS )
		return -EINVAL;
	if ( d->arch.auto_unmask ) {
		spin_lock(&d->event_lock);
		evtchn_unmask(pirq_to_evtchn(d, pirq));
		spin_unlock(&d->event_lock);
	}
	pirq_guest_eoi(pirq_info(d, pirq));
	return 0;
}

long do_pirq_guest_eoi(int pirq)
{
	return __do_pirq_guest_eoi(current->domain, pirq);
}

static void
fw_hypercall_ipi (struct pt_regs *regs)
{
	int cpu = regs->r14;
	int vector = regs->r15;
	struct vcpu *targ;
	struct domain *d = current->domain;

	/* Be sure the target exists.  */
	if (cpu >= d->max_vcpus)
		return;
	targ = d->vcpu[cpu];
	if (targ == NULL)
		return;

  	if (vector == XEN_SAL_BOOT_RENDEZ_VEC
	    && (!targ->is_initialised
		|| test_bit(_VPF_down, &targ->pause_flags))) {

		/* First start: initialize vpcu.  */
		if (!targ->is_initialised) {
			if (arch_set_info_guest (targ, NULL) != 0) {
				printk ("arch_boot_vcpu: failure\n");
				return;
			}
		}
			
		/* First or next rendez-vous: set registers.  */
		vcpu_init_regs (targ);
		vcpu_regs (targ)->cr_iip = d->arch.sal_data->boot_rdv_ip;
		vcpu_regs (targ)->r1 = d->arch.sal_data->boot_rdv_r1;
		vcpu_regs (targ)->b0 = FW_HYPERCALL_SAL_RETURN_PADDR;

		if (test_and_clear_bit(_VPF_down,
				       &targ->pause_flags)) {
			vcpu_wake(targ);
			printk(XENLOG_INFO "arch_boot_vcpu: vcpu %d awaken\n",
			       targ->vcpu_id);
		}
		else
			printk ("arch_boot_vcpu: huu, already awaken!\n");
	}
	else {
		int running = targ->is_running;
		vcpu_pend_interrupt(targ, vector);
		vcpu_unblock(targ);
		if (running)
			smp_send_event_check_cpu(targ->processor);
	}
	return;
}

static int
fpswa_get_domain_addr(struct vcpu *v, unsigned long gpaddr, size_t size,
		      void **virt, struct page_info **page, const char *name)
{
	int cross_page_boundary;

	if (gpaddr == 0) {
		*virt = 0;
		return 0;
	}

	cross_page_boundary = (((gpaddr & ~PAGE_MASK) + size) > PAGE_SIZE);
	if (unlikely(cross_page_boundary)) {
		/* this case isn't implemented */
		gdprintk(XENLOG_ERR,
			 "%s: fpswa hypercall is called with "
			 "page crossing argument %s 0x%lx\n",
			 __func__, name, gpaddr);
		return -ENOSYS;
	}

again:
        *virt = domain_mpa_to_imva(v->domain, gpaddr);
        *page = virt_to_page(*virt);
        if (get_page(*page, current->domain) == 0) {
                if (page_get_owner(*page) != current->domain) {
			*page = NULL;
			return -EFAULT;
		}
                goto again;
        }

	return 0;
}

static fpswa_ret_t
fw_hypercall_fpswa (struct vcpu *v, struct pt_regs *regs)
{
	fpswa_ret_t ret = {-1, 0, 0, 0};
	unsigned long bundle[2] = { regs->r15, regs->r16};
	fp_state_t fp_state;
	struct page_info *lp_page = NULL;
	struct page_info *lv_page = NULL;
	struct page_info *hp_page = NULL;
	struct page_info *hv_page = NULL;
	XEN_EFI_RR_DECLARE(rr6, rr7);

	if (unlikely(PSCBX(v, fpswa_ret).status != 0 && 
		     PSCBX(v, fpswa_ret).status != IA64_RETRY)) {
		ret = PSCBX(v, fpswa_ret);
		PSCBX(v, fpswa_ret) = (fpswa_ret_t){0, 0, 0, 0};
		return ret;
	}

	if (!fpswa_interface)
		goto error;

	memset(&fp_state, 0, sizeof(fp_state));
	fp_state.bitmask_low64 = regs->r22;
	fp_state.bitmask_high64 = regs->r23;

	/* bit6..bit11 */
	if ((fp_state.bitmask_low64 & 0xfc0) != 0xfc0) {
		/* other cases isn't supported yet */
		gdprintk(XENLOG_ERR, "%s unsupported bitmask_low64 0x%lx\n",
			 __func__, fp_state.bitmask_low64);
		goto error;
	}
	if (regs->r25 == 0)
		/* fp_state.fp_state_low_volatile must be supplied */
		goto error;

	/* eager save/lazy restore fpu: f32...f127 */
	if ((~fp_state.bitmask_low64 & ((1UL << 31) - 1)) != 0 ||
	    ~fp_state.bitmask_high64 != 0) {
		if (VMX_DOMAIN(v))
			vmx_lazy_load_fpu(v);
		else
			ia64_lazy_load_fpu(v);
	}

	if (fpswa_get_domain_addr(v, regs->r24,
				  sizeof(fp_state.fp_state_low_preserved), 
				  (void*)&fp_state.fp_state_low_preserved,
				  &lp_page, "fp_state_low_preserved") < 0)
		goto error;
	if (fpswa_get_domain_addr(v, regs->r25,
				  sizeof(fp_state.fp_state_low_volatile),
				  (void*)&fp_state.fp_state_low_volatile,
				  &lv_page, "fp_state_low_volatile") < 0)
		goto error;
	if (fpswa_get_domain_addr(v, regs->r26,
				  sizeof(fp_state.fp_state_high_preserved),
				  (void*)&fp_state.fp_state_high_preserved,
				  &hp_page, "fp_state_low_preserved") < 0)
		goto error;
	if (fpswa_get_domain_addr(v, regs->r27,
				  sizeof(fp_state.fp_state_high_volatile),
				  (void*)&fp_state.fp_state_high_volatile,
				  &hv_page, "fp_state_high_volatile") < 0)
		goto error;

	XEN_EFI_RR_ENTER(rr6, rr7);
	ret = (*fpswa_interface->fpswa)(regs->r14,
					bundle,
					&regs->r17,	/* pipsr */
					&regs->r18,	/* pfsr */
					&regs->r19,	/* pisr */
					&regs->r20,	/* ppreds */
					&regs->r21,	/* pifs	*/
					&fp_state);
	XEN_EFI_RR_LEAVE(rr6, rr7);

error:
	if (lp_page != NULL)
		put_page(lp_page);
	if (lv_page != NULL)
		put_page(lv_page);
	if (hp_page != NULL)
		put_page(hp_page);
	if (hv_page != NULL)
		put_page(hv_page);
	return ret;
}

static fpswa_ret_t
fw_hypercall_fpswa_error(void)
{
	return (fpswa_ret_t) {-1, 0, 0, 0};
}

IA64FAULT
ia64_hypercall(struct pt_regs *regs)
{
	struct vcpu *v = current;
	struct sal_ret_values x;
	efi_status_t efi_ret_value;
	fpswa_ret_t fpswa_ret;
	IA64FAULT fault; 
	unsigned long index = regs->r2 & FW_HYPERCALL_NUM_MASK_HIGH;

	perfc_incra(fw_hypercall, index >> 8);
	switch (index) {
	case FW_HYPERCALL_XEN:
		return xen_hypercall(regs);

	case FW_HYPERCALL_XEN_FAST:
		return xen_fast_hypercall(regs);

	case FW_HYPERCALL_PAL_CALL:
		//printk("*** PAL hypercall: index=%d\n",regs->r28);
		//FIXME: This should call a C routine
#if 0
		// This is very conservative, but avoids a possible
		// (and deadly) freeze in paravirtualized domains due
		// to a yet-to-be-found bug where pending_interruption
		// is zero when it shouldn't be. Since PAL is called
		// in the idle loop, this should resolve it
		VCPU(v,pending_interruption) = 1;
#endif
		if (regs->r28 == PAL_HALT_LIGHT) {
			if (vcpu_deliverable_interrupts(v) ||
				event_pending(v)) {
				perfc_incr(idle_when_pending);
				vcpu_pend_unspecified_interrupt(v);
//printk("idle w/int#%d pending!\n",pi);
//this shouldn't happen, but it apparently does quite a bit!  so don't
//allow it to happen... i.e. if a domain has an interrupt pending and
//it tries to halt itself because it thinks it is idle, just return here
//as deliver_pending_interrupt is called on the way out and will deliver it
			}
			else {
				perfc_incr(pal_halt_light);
				migrate_timer(&v->arch.hlt_timer,
				              v->processor);
				set_timer(&v->arch.hlt_timer,
				          vcpu_get_next_timer_ns(v));
				do_sched_op_compat(SCHEDOP_block, 0);
				/* do_block only pends a softirq */
				do_softirq();
				stop_timer(&v->arch.hlt_timer);
				/* do_block() calls
				 * local_event_delivery_enable(),
				 * but PAL CALL must be called with
				 * psr.i = 0 and psr.i is unchanged.
				 * SDM vol.2 Part I 11.10.2
				 * PAL Calling Conventions.
				 */
				local_event_delivery_disable();
			}
			regs->r8 = 0;
			regs->r9 = 0;
			regs->r10 = 0;
			regs->r11 = 0;
		}
		else {
			struct ia64_pal_retval y;

			if (regs->r28 >= PAL_COPY_PAL)
				y = xen_pal_emulator
					(regs->r28, vcpu_get_gr (v, 33),
					 vcpu_get_gr (v, 34),
					 vcpu_get_gr (v, 35));
			else
				y = xen_pal_emulator(regs->r28,regs->r29,
						     regs->r30,regs->r31);
			regs->r8 = y.status; regs->r9 = y.v0;
			regs->r10 = y.v1; regs->r11 = y.v2;
		}
		break;
	case FW_HYPERCALL_SAL_CALL:
		x = sal_emulator(vcpu_get_gr(v,32),vcpu_get_gr(v,33),
			vcpu_get_gr(v,34),vcpu_get_gr(v,35),
			vcpu_get_gr(v,36),vcpu_get_gr(v,37),
			vcpu_get_gr(v,38),vcpu_get_gr(v,39));
		regs->r8 = x.r8; regs->r9 = x.r9;
		regs->r10 = x.r10; regs->r11 = x.r11;
		break;
	case FW_HYPERCALL_SAL_RETURN:
	        if ( !test_and_set_bit(_VPF_down, &v->pause_flags) )
			vcpu_sleep_nosync(v);
		break;
	case FW_HYPERCALL_EFI_CALL:
		efi_ret_value = efi_emulator (regs, &fault);
		if (fault != IA64_NO_FAULT) return fault;
		regs->r8 = efi_ret_value;
		break;
	case FW_HYPERCALL_IPI:
		fw_hypercall_ipi (regs);
		break;
	case FW_HYPERCALL_SET_SHARED_INFO_VA:
	        regs->r8 = domain_set_shared_info_va (regs->r28);
		break;
	case FW_HYPERCALL_FPSWA_BASE:
		switch (regs->r2) {
		case FW_HYPERCALL_FPSWA_BROKEN:
			gdprintk(XENLOG_WARNING,
				 "Old fpswa hypercall was called (0x%lx).\n"
				 "Please update your domain builder. ip 0x%lx\n",
				 FW_HYPERCALL_FPSWA_BROKEN, regs->cr_iip);
			fpswa_ret = fw_hypercall_fpswa_error();
			break;
		case FW_HYPERCALL_FPSWA:
			fpswa_ret = fw_hypercall_fpswa(v, regs);
			break;
		default:
			gdprintk(XENLOG_ERR, "unknown fpswa hypercall %lx\n",
				 regs->r2);
			fpswa_ret = fw_hypercall_fpswa_error();
			break;
		}
		regs->r8  = fpswa_ret.status;
		regs->r9  = fpswa_ret.err0;
		regs->r10 = fpswa_ret.err1;
		regs->r11 = fpswa_ret.err2;
		break;
	case __HYPERVISOR_opt_feature:
	{
		XEN_GUEST_HANDLE(void) arg;
		struct xen_ia64_opt_feature optf;
		set_xen_guest_handle(arg, (void*)(vcpu_get_gr(v, 32)));
		if (copy_from_guest(&optf, arg, 1) == 0)
			regs->r8 = domain_opt_feature(v->domain, &optf);
		else
			regs->r8 = -EFAULT;
		break;
	}
	case FW_HYPERCALL_SIOEMU:
		sioemu_hypercall(regs);
		break;
	default:
		printk("unknown ia64 fw hypercall %lx\n", regs->r2);
		regs->r8 = do_ni_hypercall();
	}
	return IA64_NO_FAULT;
}

#define next_arg(fmt, args) ({                                              \
    unsigned long __arg;                                                    \
    switch ( *(fmt)++ )                                                     \
    {                                                                       \
    case 'i': __arg = (unsigned long)va_arg(args, unsigned int);  break;    \
    case 'l': __arg = (unsigned long)va_arg(args, unsigned long); break;    \
    case 'h': __arg = (unsigned long)va_arg(args, void *);        break;    \
    default:  __arg = 0; BUG();                                             \
    }                                                                       \
    __arg;                                                                  \
})

unsigned long hypercall_create_continuation(
	unsigned int op, const char *format, ...)
{
    struct mc_state *mcs = &current->mc_state;
    struct vcpu *v = current;
    const char *p = format;
    unsigned long arg;
    unsigned int i;
    va_list args;

    va_start(args, format);

    if (test_bit(_MCSF_in_multicall, &mcs->flags)) {
        dprintk(XENLOG_DEBUG, "PREEMPT happen in multicall\n");
        __set_bit(_MCSF_call_preempted, &mcs->flags);
        for (i = 0; *p != '\0'; i++)
            mcs->call.args[i] = next_arg(p, args);
    }
    else {
        vcpu_set_gr(v, 15, op, 0);

        for (i = 0; *p != '\0'; i++) {
            arg = next_arg(p, args);
            vcpu_set_gr(v, 16 + i, arg, 0);
        }
    
        if (i >= 6)
            panic("Too many args for hypercall continuation\n");

        // Clean other argument to 0
        while (i < 6) {
            vcpu_set_gr(v, 16 + i, 0, 0);
            i++;
        }

        // re-execute break;
        vcpu_decrement_iip(v);
    
        v->arch.hypercall_continuation = 1;
    }

    va_end(args);
    return op;
}

/* Need make this function common */
extern int
iosapic_guest_read(
    unsigned long physbase, unsigned int reg, u32 *pval);
extern int
iosapic_guest_write(
    unsigned long physbase, unsigned int reg, u32 pval);


/*
 * XXX: We don't support MSI for PCI passthrough at present, so make the
 * following 2 functions dummy for now. They shouldn't return -ENOSYS
 * because xend invokes them (the x86 version of them is necessary for
 * x86 Xen); if they return -ENOSYS, xend would disallow us to create
 * IPF HVM guest with devices assigned so here they can return 0.
 */
static int physdev_map_pirq(struct physdev_map_pirq *map)
{
	return 0;
}

static int physdev_unmap_pirq(struct physdev_unmap_pirq *unmap)
{
	return 0;
}


long do_physdev_op(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    int irq;
    long ret;

    switch ( cmd )
    {
    case PHYSDEVOP_eoi: {
        struct physdev_eoi eoi;
        ret = -EFAULT;
        if ( copy_from_guest(&eoi, arg, 1) != 0 )
            break;
        ret = __do_pirq_guest_eoi(current->domain, eoi.irq);
        break;
    }

    case PHYSDEVOP_pirq_eoi_gmfn_v1:
    case PHYSDEVOP_pirq_eoi_gmfn_v2: {
        struct physdev_pirq_eoi_gmfn info;
        unsigned long mfn;

        BUILD_BUG_ON(NR_IRQS > (PAGE_SIZE * 8));

        ret = -EFAULT;
        if ( copy_from_guest(&info, arg, 1) != 0 )
            break;

        ret = -EINVAL;
        mfn = gmfn_to_mfn(current->domain, info.gmfn);
        if ( !mfn_valid(mfn) || !get_page(mfn_to_page(mfn), current->domain) )
            break;

        if ( cmpxchg(&current->domain->arch.pirq_eoi_map_mfn, 0, mfn) != 0 )
        {
            put_page(mfn_to_page(mfn));
            ret = -EBUSY;
            break;
        }

        current->domain->arch.pirq_eoi_map = mfn_to_virt(mfn);
        if ( cmd == PHYSDEVOP_pirq_eoi_gmfn_v1 )
            current->domain->arch.auto_unmask = 1;
        ret = 0;
        break;
    }

    /* Legacy since 0x00030202. */
    case PHYSDEVOP_IRQ_UNMASK_NOTIFY: {
        ret = pirq_guest_unmask(current->domain);
        break;
    }

    case PHYSDEVOP_irq_status_query: {
        struct physdev_irq_status_query irq_status_query;
        ret = -EFAULT;
        if ( copy_from_guest(&irq_status_query, arg, 1) != 0 )
            break;
        irq = irq_status_query.irq;
        ret = -EINVAL;
        if ( (irq < 0) || (irq >= NR_IRQS) )
            break;
        irq_status_query.flags = 0;
        /* Edge-triggered interrupts don't need an explicit unmask downcall. */
        if ( !strstr(irq_descp(irq)->handler->typename, "edge") )
            irq_status_query.flags |= XENIRQSTAT_needs_eoi;
        ret = copy_to_guest(arg, &irq_status_query, 1) ? -EFAULT : 0;
        break;
    }

    case PHYSDEVOP_apic_read: {
        struct physdev_apic apic;
        ret = -EFAULT;
        if ( copy_from_guest(&apic, arg, 1) != 0 )
            break;
        ret = -EPERM;
        if ( !IS_PRIV(current->domain) )
            break;
        ret = iosapic_guest_read(apic.apic_physbase, apic.reg, &apic.value);
        if ( copy_to_guest(arg, &apic, 1) != 0 )
            ret = -EFAULT;
        break;
    }

    case PHYSDEVOP_apic_write: {
        struct physdev_apic apic;
        ret = -EFAULT;
        if ( copy_from_guest(&apic, arg, 1) != 0 )
            break;
        ret = -EPERM;
        if ( !IS_PRIV(current->domain) )
            break;
        ret = iosapic_guest_write(apic.apic_physbase, apic.reg, apic.value);
        break;
    }

    case PHYSDEVOP_alloc_irq_vector: {
        struct physdev_irq irq_op;

        ret = -EFAULT;
        if ( copy_from_guest(&irq_op, arg, 1) != 0 )
            break;

        ret = -EPERM;
        if ( !IS_PRIV(current->domain) )
            break;

        ret = -EINVAL;
        if ( (irq = irq_op.irq) >= NR_IRQS )
            break;
        
        irq_op.vector = assign_irq_vector(irq);
        ret = copy_to_guest(arg, &irq_op, 1) ? -EFAULT : 0;
        break;
    }

    case PHYSDEVOP_free_irq_vector: {
        struct physdev_irq irq_op;
        int vector;

        ret = -EFAULT;
        if ( copy_from_guest(&irq_op, arg, 1) != 0 )
            break;

        ret = -EPERM;
        if ( !IS_PRIV(current->domain) )
            break;

        ret = -EINVAL;
        vector = irq_op.vector;
        if (vector < IA64_FIRST_DEVICE_VECTOR ||
            vector > IA64_LAST_DEVICE_VECTOR)
            break;
        
        /* XXX This should be called, but causes a NAT consumption via the
	 * reboot notifier_call_chain in dom0 if a device is hidden for
	 * a driver domain using pciback.hide= (specifically, hiding function
	 * 1 of a 2 port e1000 card).
	 * free_irq_vector(vector);
	 */
        ret = 0;
        break;
    }

	case PHYSDEVOP_map_pirq: {
        struct physdev_map_pirq map;

        ret = -EFAULT;
        if ( copy_from_guest(&map, arg, 1) != 0 )
             break;

        ret = physdev_map_pirq(&map);

        if ( copy_to_guest(arg, &map, 1) != 0 )
             ret = -EFAULT;
        break;
    }

    case PHYSDEVOP_unmap_pirq: {
        struct physdev_unmap_pirq unmap;

        ret = -EFAULT;
        if ( copy_from_guest(&unmap, arg, 1) != 0 )
            break;

        ret = physdev_unmap_pirq(&unmap);
            break;
    }

    case PHYSDEVOP_manage_pci_add: {
        struct physdev_manage_pci manage_pci;
        ret = -EPERM;
        if ( !IS_PRIV(current->domain) )
            break;
        ret = -EFAULT;
        if ( copy_from_guest(&manage_pci, arg, 1) != 0 )
            break;

        ret = pci_add_device(0, manage_pci.bus, manage_pci.devfn, NULL);
        break;
    }

    case PHYSDEVOP_manage_pci_remove: {
        struct physdev_manage_pci manage_pci;
        ret = -EPERM;
        if ( !IS_PRIV(current->domain) )
            break;
        ret = -EFAULT;
        if ( copy_from_guest(&manage_pci, arg, 1) != 0 )
            break;

        ret = pci_remove_device(0, manage_pci.bus, manage_pci.devfn);
            break;
    }

    case PHYSDEVOP_manage_pci_add_ext: {
        struct physdev_manage_pci_ext manage_pci_ext;
        struct pci_dev_info pdev_info;

        ret = -EPERM;
        if ( !IS_PRIV(current->domain) )
            break;

        ret = -EFAULT;
        if ( copy_from_guest(&manage_pci_ext, arg, 1) != 0 )
            break;

        pdev_info.is_extfn = !!manage_pci_ext.is_extfn;
        pdev_info.is_virtfn = !!manage_pci_ext.is_virtfn;
        pdev_info.physfn.bus = manage_pci_ext.physfn.bus;
        pdev_info.physfn.devfn = manage_pci_ext.physfn.devfn;
        ret = pci_add_device(0, manage_pci_ext.bus,
                             manage_pci_ext.devfn,
                             &pdev_info);
        break;
    }

    default:
        ret = -ENOSYS;
        printk("not implemented do_physdev_op: %d\n", cmd);
        break;
    }

    return ret;
}

static long register_guest_callback(struct callback_register *reg)
{
    long ret = 0;
    struct vcpu *v = current;

    if (IS_VMM_ADDRESS(reg->address))
        return -EINVAL;

    switch ( reg->type )
    {
    case CALLBACKTYPE_event:
        v->arch.event_callback_ip    = reg->address;
        break;

    case CALLBACKTYPE_failsafe:
        v->arch.failsafe_callback_ip = reg->address;
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

static long unregister_guest_callback(struct callback_unregister *unreg)
{
    return -EINVAL;
}

/* First time to add callback to xen/ia64, so let's just stick to
 * the newer callback interface.
 */
long do_callback_op(int cmd, XEN_GUEST_HANDLE(const_void) arg)
{
    long ret;

    switch ( cmd )
    {
    case CALLBACKOP_register:
    {
        struct callback_register reg;

        ret = -EFAULT;
        if ( copy_from_guest(&reg, arg, 1) )
            break;

        ret = register_guest_callback(&reg);
    }
    break;

    case CALLBACKOP_unregister:
    {
        struct callback_unregister unreg;

        ret = -EFAULT;
        if ( copy_from_guest(&unreg, arg, 1) )
            break;

        ret = unregister_guest_callback(&unreg);
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

unsigned long
do_ia64_debug_op(unsigned long cmd, unsigned long domain,
		 XEN_GUEST_HANDLE(xen_ia64_debug_op_t) u_debug_op)
{
    xen_ia64_debug_op_t curop, *op = &curop;
    struct domain *d;
    long ret = 0;

    if (copy_from_guest(op, u_debug_op, 1))
        return -EFAULT;
    d = rcu_lock_domain_by_id(domain);
    if (d == NULL)
        return -ESRCH;
    if (!IS_PRIV_FOR(current->domain, d)) {
        ret = -EPERM;
        goto out;
    }

    switch (cmd) {
    case XEN_IA64_DEBUG_OP_SET_FLAGS:
        d->arch.debug_flags = op->flags;
        break;
    case XEN_IA64_DEBUG_OP_GET_FLAGS:
        op->flags = d->arch.debug_flags;
        if (copy_to_guest(u_debug_op, op, 1))
            ret = -EFAULT;
        break;
    default:
        ret = -ENOSYS;
    }
out:
    rcu_unlock_domain(d);
    return ret;
}
