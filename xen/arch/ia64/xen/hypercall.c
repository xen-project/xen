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

extern long do_physdev_op(int cmd, XEN_GUEST_HANDLE(void) arg);
extern long do_callback_op(int cmd, XEN_GUEST_HANDLE(void) arg);

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

long do_pirq_guest_eoi(int pirq)
{
	return pirq_guest_eoi(current->domain, pirq);
}
    

static void
fw_hypercall_ipi (struct pt_regs *regs)
{
	int cpu = regs->r14;
	int vector = regs->r15;
	struct vcpu *targ;
	struct domain *d = current->domain;

	/* Be sure the target exists.  */
	if (cpu > MAX_VIRT_CPUS)
		return;
	targ = d->vcpu[cpu];
	if (targ == NULL)
		return;

  	if (vector == XEN_SAL_BOOT_RENDEZ_VEC
	    && (!test_bit(_VCPUF_initialised, &targ->vcpu_flags)
		|| test_bit(_VCPUF_down, &targ->vcpu_flags))) {

		/* First start: initialize vpcu.  */
		if (!test_bit(_VCPUF_initialised, &targ->vcpu_flags)) {
			struct vcpu_guest_context c;
		
			memset (&c, 0, sizeof (c));

			if (arch_set_info_guest (targ, &c) != 0) {
				printk ("arch_boot_vcpu: failure\n");
				return;
			}
		}
			
		/* First or next rendez-vous: set registers.  */
		vcpu_init_regs (targ);
		vcpu_regs (targ)->cr_iip = d->arch.sal_data->boot_rdv_ip;
		vcpu_regs (targ)->r1 = d->arch.sal_data->boot_rdv_r1;
		vcpu_regs (targ)->b0 = FW_HYPERCALL_SAL_RETURN_PADDR;

		if (test_and_clear_bit(_VCPUF_down,
				       &targ->vcpu_flags)) {
			vcpu_wake(targ);
			printk(XENLOG_INFO "arch_boot_vcpu: vcpu %d awaken\n",
			       targ->vcpu_id);
		}
		else
			printk ("arch_boot_vcpu: huu, already awaken!\n");
	}
	else {
		int running = test_bit(_VCPUF_running,
				       &targ->vcpu_flags);
		
		vcpu_pend_interrupt(targ, vector);
		vcpu_unblock(targ);
		if (running)
			smp_send_event_check_cpu(targ->processor);
	}
	return;
}

static fpswa_ret_t
fw_hypercall_fpswa (struct vcpu *v)
{
	return PSCBX(v, fpswa_ret);
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
				perfc_incrc(idle_when_pending);
				vcpu_pend_unspecified_interrupt(v);
//printk("idle w/int#%d pending!\n",pi);
//this shouldn't happen, but it apparently does quite a bit!  so don't
//allow it to happen... i.e. if a domain has an interrupt pending and
//it tries to halt itself because it thinks it is idle, just return here
//as deliver_pending_interrupt is called on the way out and will deliver it
			}
			else {
				perfc_incrc(pal_halt_light);
				migrate_timer(&v->arch.hlt_timer,
				              v->processor);
				set_timer(&v->arch.hlt_timer,
				          vcpu_get_next_timer_ns(v));
				do_sched_op_compat(SCHEDOP_block, 0);
				/* do_block only pends a softirq */
				do_softirq();
				stop_timer(&v->arch.hlt_timer);
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
	        if ( !test_and_set_bit(_VCPUF_down, &v->vcpu_flags) )
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
	case FW_HYPERCALL_FPSWA:
		fpswa_ret = fw_hypercall_fpswa (v);
		regs->r8  = fpswa_ret.status;
		regs->r9  = fpswa_ret.err0;
		regs->r10 = fpswa_ret.err1;
		regs->r11 = fpswa_ret.err2;
		break;
	default:
		printk("unknown ia64 fw hypercall %lx\n", regs->r2);
		regs->r8 = do_ni_hypercall();
	}
	return IA64_NO_FAULT;
}

unsigned long hypercall_create_continuation(
	unsigned int op, const char *format, ...)
{
    struct mc_state *mcs = &this_cpu(mc_state);
    struct vcpu *v = current;
    const char *p = format;
    unsigned long arg;
    unsigned int i;
    va_list args;

    va_start(args, format);
    if (test_bit(_MCSF_in_multicall, &mcs->flags))
        panic("PREEMPT happen in multicall\n");	// Not support yet

    vcpu_set_gr(v, 15, op, 0);

    for (i = 0; *p != '\0'; i++) {
        switch ( *p++ )
        {
        case 'i':
            arg = (unsigned long)va_arg(args, unsigned int);
            break;
        case 'l':
            arg = (unsigned long)va_arg(args, unsigned long);
            break;
        case 'h':
            arg = (unsigned long)va_arg(args, void *);
            break;
        default:
            arg = 0;
            BUG();
        }
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
        ret = pirq_guest_eoi(current->domain, eoi.irq);
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
        if ( !strstr(irq_desc[irq_to_vector(irq)].handler->typename, "edge") )
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

    default:
        ret = -ENOSYS;
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
long do_callback_op(int cmd, XEN_GUEST_HANDLE(void) arg)
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
