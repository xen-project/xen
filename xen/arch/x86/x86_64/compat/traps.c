#include <xen/event.h>
#include <asm/regs.h>
#include <compat/callback.h>
#include <compat/arch-x86_32.h>

void compat_show_guest_stack(struct vcpu *v, const struct cpu_user_regs *regs,
                             int debug_stack_lines)
{
    unsigned int i, *stack, addr, mask = STACK_SIZE;

    stack = (unsigned int *)(unsigned long)regs->_esp;
    printk("Guest stack trace from esp=%08lx:\n ", (unsigned long)stack);

    if ( !__compat_access_ok(v->domain, stack, sizeof(*stack)) )
    {
        printk("Guest-inaccessible memory.\n");
        return;
    }

    if ( v != current )
    {
        struct vcpu *vcpu;
        unsigned long mfn;

        ASSERT(guest_kernel_mode(v, regs));
        mfn = read_cr3() >> PAGE_SHIFT;
        for_each_vcpu( v->domain, vcpu )
            if ( pagetable_get_pfn(vcpu->arch.guest_table) == mfn )
                break;
        if ( !vcpu )
        {
            stack = do_page_walk(v, (unsigned long)stack);
            if ( (unsigned long)stack < PAGE_SIZE )
            {
                printk("Inaccessible guest memory.\n");
                return;
            }
            mask = PAGE_SIZE;
        }
    }

    for ( i = 0; i < debug_stack_lines * 8; i++ )
    {
        if ( (((long)stack - 1) ^ ((long)(stack + 1) - 1)) & mask )
            break;
        if ( __get_user(addr, stack) )
        {
            if ( i != 0 )
                printk("\n    ");
            printk("Fault while accessing guest memory.");
            i = 1;
            break;
        }
        if ( (i != 0) && ((i % 8) == 0) )
            printk("\n ");
        printk(" %08x", addr);
        stack++;
    }
    if ( mask == PAGE_SIZE )
    {
        BUILD_BUG_ON(PAGE_SIZE == STACK_SIZE);
        unmap_domain_page(stack);
    }
    if ( i == 0 )
        printk("Stack empty.");
    printk("\n");
}

unsigned int compat_iret(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct vcpu *v = current;
    u32 eflags;

    /* Trim stack pointer to 32 bits. */
    regs->rsp = (u32)regs->rsp;

    /* Restore EAX (clobbered by hypercall). */
    if ( unlikely(__get_user(regs->_eax, (u32 *)regs->rsp)) )
        goto exit_and_crash;

    /* Restore CS and EIP. */
    if ( unlikely(__get_user(regs->_eip, (u32 *)regs->rsp + 1)) ||
        unlikely(__get_user(regs->cs, (u32 *)regs->rsp + 2)) )
        goto exit_and_crash;

    /*
     * Fix up and restore EFLAGS. We fix up in a local staging area
     * to avoid firing the BUG_ON(IOPL) check in arch_get_info_guest.
     */
    if ( unlikely(__get_user(eflags, (u32 *)regs->rsp + 3)) )
        goto exit_and_crash;
    regs->_eflags = (eflags & ~X86_EFLAGS_IOPL) | X86_EFLAGS_IF;

    if ( unlikely(eflags & X86_EFLAGS_VM) )
    {
        /*
         * Cannot return to VM86 mode: inject a GP fault instead. Note that
         * the GP fault is reported on the first VM86 mode instruction, not on
         * the IRET (which is why we can simply leave the stack frame as-is
         * (except for perhaps having to copy it), which in turn seems better
         * than teaching create_bounce_frame() to needlessly deal with vm86
         * mode frames).
         */
        const struct trap_info *ti;
        u32 x, ksp = v->arch.pv_vcpu.kernel_sp - 40;
        unsigned int i;
        int rc = 0;

        gdprintk(XENLOG_ERR, "VM86 mode unavailable (ksp:%08X->%08X)\n",
                 regs->_esp, ksp);
        if ( ksp < regs->_esp )
        {
            for (i = 1; i < 10; ++i)
            {
                rc |= __get_user(x, (u32 *)regs->rsp + i);
                rc |= __put_user(x, (u32 *)(unsigned long)ksp + i);
            }
        }
        else if ( ksp > regs->_esp )
        {
            for ( i = 9; i > 0; --i )
            {
                rc |= __get_user(x, (u32 *)regs->rsp + i);
                rc |= __put_user(x, (u32 *)(unsigned long)ksp + i);
            }
        }
        if ( rc )
            goto exit_and_crash;
        regs->_esp = ksp;
        regs->ss = v->arch.pv_vcpu.kernel_ss;

        ti = &v->arch.pv_vcpu.trap_ctxt[TRAP_gp_fault];
        if ( TI_GET_IF(ti) )
            eflags &= ~X86_EFLAGS_IF;
        regs->_eflags &= ~(X86_EFLAGS_VM|X86_EFLAGS_RF|
                           X86_EFLAGS_NT|X86_EFLAGS_TF);
        if ( unlikely(__put_user(0, (u32 *)regs->rsp)) )
            goto exit_and_crash;
        regs->_eip = ti->address;
        regs->cs = ti->cs;
    }
    else if ( unlikely(ring_0(regs)) )
        goto exit_and_crash;
    else if ( !ring_1(regs) )
    {
        /* Return to ring 2/3: restore ESP and SS. */
        if ( __get_user(regs->ss, (u32 *)regs->rsp + 5)
            || __get_user(regs->_esp, (u32 *)regs->rsp + 4))
            goto exit_and_crash;
    }
    else
        regs->_esp += 16;

    /* Restore upcall mask from supplied EFLAGS.IF. */
    vcpu_info(v, evtchn_upcall_mask) = !(eflags & X86_EFLAGS_IF);

    async_exception_cleanup(v);

    /*
     * The hypercall exit path will overwrite EAX with this return
     * value.
     */
    return regs->_eax;

 exit_and_crash:
    gdprintk(XENLOG_ERR, "Fatal error\n");
    domain_crash(v->domain);
    return 0;
}

static long compat_register_guest_callback(
    struct compat_callback_register *reg)
{
    long ret = 0;
    struct vcpu *v = current;

    fixup_guest_code_selector(v->domain, reg->address.cs);

    switch ( reg->type )
    {
    case CALLBACKTYPE_event:
        v->arch.pv_vcpu.event_callback_cs     = reg->address.cs;
        v->arch.pv_vcpu.event_callback_eip    = reg->address.eip;
        break;

    case CALLBACKTYPE_failsafe:
        v->arch.pv_vcpu.failsafe_callback_cs  = reg->address.cs;
        v->arch.pv_vcpu.failsafe_callback_eip = reg->address.eip;
        if ( reg->flags & CALLBACKF_mask_events )
            set_bit(_VGCF_failsafe_disables_events,
                    &v->arch.vgc_flags);
        else
            clear_bit(_VGCF_failsafe_disables_events,
                      &v->arch.vgc_flags);
        break;

    case CALLBACKTYPE_syscall32:
        v->arch.pv_vcpu.syscall32_callback_cs     = reg->address.cs;
        v->arch.pv_vcpu.syscall32_callback_eip    = reg->address.eip;
        v->arch.pv_vcpu.syscall32_disables_events =
            (reg->flags & CALLBACKF_mask_events) != 0;
        break;

    case CALLBACKTYPE_sysenter:
        v->arch.pv_vcpu.sysenter_callback_cs     = reg->address.cs;
        v->arch.pv_vcpu.sysenter_callback_eip    = reg->address.eip;
        v->arch.pv_vcpu.sysenter_disables_events =
            (reg->flags & CALLBACKF_mask_events) != 0;
        break;

    case CALLBACKTYPE_nmi:
        ret = register_guest_nmi_callback(reg->address.eip);
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

static long compat_unregister_guest_callback(
    struct compat_callback_unregister *unreg)
{
    long ret;

    switch ( unreg->type )
    {
    case CALLBACKTYPE_event:
    case CALLBACKTYPE_failsafe:
    case CALLBACKTYPE_syscall32:
    case CALLBACKTYPE_sysenter:
        ret = -EINVAL;
        break;

    case CALLBACKTYPE_nmi:
        ret = unregister_guest_nmi_callback();
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}


long compat_callback_op(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    long ret;

    switch ( cmd )
    {
    case CALLBACKOP_register:
    {
        struct compat_callback_register reg;

        ret = -EFAULT;
        if ( copy_from_guest(&reg, arg, 1) )
            break;

        ret = compat_register_guest_callback(&reg);
    }
    break;

    case CALLBACKOP_unregister:
    {
        struct compat_callback_unregister unreg;

        ret = -EFAULT;
        if ( copy_from_guest(&unreg, arg, 1) )
            break;

        ret = compat_unregister_guest_callback(&unreg);
    }
    break;

    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

long compat_set_callbacks(unsigned long event_selector,
                          unsigned long event_address,
                          unsigned long failsafe_selector,
                          unsigned long failsafe_address)
{
    struct compat_callback_register event = {
        .type = CALLBACKTYPE_event,
        .address = {
            .cs = event_selector,
            .eip = event_address
        }
    };
    struct compat_callback_register failsafe = {
        .type = CALLBACKTYPE_failsafe,
        .address = {
            .cs = failsafe_selector,
            .eip = failsafe_address
        }
    };

    compat_register_guest_callback(&event);
    compat_register_guest_callback(&failsafe);

    return 0;
}

DEFINE_XEN_GUEST_HANDLE(trap_info_compat_t);

int compat_set_trap_table(XEN_GUEST_HANDLE(trap_info_compat_t) traps)
{
    struct compat_trap_info cur;
    struct trap_info *dst = current->arch.pv_vcpu.trap_ctxt;
    long rc = 0;

    /* If no table is presented then clear the entire virtual IDT. */
    if ( guest_handle_is_null(traps) )
    {
        memset(dst, 0, NR_VECTORS * sizeof(*dst));
        return 0;
    }

    for ( ; ; )
    {
        if ( copy_from_guest(&cur, traps, 1) )
        {
            rc = -EFAULT;
            break;
        }

        if ( cur.address == 0 )
            break;

        fixup_guest_code_selector(current->domain, cur.cs);

        XLAT_trap_info(dst + cur.vector, &cur);

        if ( cur.vector == 0x80 )
            init_int80_direct_trap(current);

        guest_handle_add_offset(traps, 1);

        if ( hypercall_preempt_check() )
        {
            rc = hypercall_create_continuation(
                __HYPERVISOR_set_trap_table, "h", traps);
            break;
        }
    }

    return rc;
}

static void hypercall_page_initialise_ring1_kernel(void *hypercall_page)
{
    char *p;
    int i;

    /* Fill in all the transfer points with template machine code. */

    for ( i = 0; i < (PAGE_SIZE / 32); i++ )
    {
        if ( i == __HYPERVISOR_iret )
            continue;

        p = (char *)(hypercall_page + (i * 32));
        *(u8  *)(p+ 0) = 0xb8;    /* mov  $<i>,%eax */
        *(u32 *)(p+ 1) = i;
        *(u16 *)(p+ 5) = (HYPERCALL_VECTOR << 8) | 0xcd; /* int  $xx */
        *(u8  *)(p+ 7) = 0xc3;    /* ret */
    }

    /*
     * HYPERVISOR_iret is special because it doesn't return and expects a
     * special stack frame. Guests jump at this transfer point instead of
     * calling it.
     */
    p = (char *)(hypercall_page + (__HYPERVISOR_iret * 32));
    *(u8  *)(p+ 0) = 0x50;    /* push %eax */
    *(u8  *)(p+ 1) = 0xb8;    /* mov  $__HYPERVISOR_iret,%eax */
    *(u32 *)(p+ 2) = __HYPERVISOR_iret;
    *(u16 *)(p+ 6) = (HYPERCALL_VECTOR << 8) | 0xcd; /* int  $xx */
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
