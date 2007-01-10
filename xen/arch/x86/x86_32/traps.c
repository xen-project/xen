
#include <xen/config.h>
#include <xen/version.h>
#include <xen/domain_page.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/console.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/symbols.h>
#include <xen/shutdown.h>
#include <xen/nmi.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>

#include <public/callback.h>

/* All CPUs have their own IDT to allow int80 direct trap. */
idt_entry_t *idt_tables[NR_CPUS] __read_mostly;

static void print_xen_info(void)
{
    char taint_str[TAINT_STRING_MAX_LEN];
    char debug = 'n', *arch = "x86_32";

#ifndef NDEBUG
    debug = 'y';
#endif

#ifdef CONFIG_X86_PAE
    arch = "x86_32p";
#endif

    printk("----[ Xen-%d.%d%s  %s  debug=%c  %s ]----\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
           arch, debug, print_tainted(taint_str));
}

void show_registers(struct cpu_user_regs *regs)
{
    struct cpu_user_regs fault_regs = *regs;
    unsigned long fault_crs[8];
    const char *context;

    if ( is_hvm_vcpu(current) && guest_mode(regs) )
    {
        context = "hvm";
        hvm_store_cpu_guest_regs(current, &fault_regs, fault_crs);
    }
    else
    {
        if ( !guest_mode(regs) )
        {
            context = "hypervisor";
            fault_regs.esp = (unsigned long)&regs->esp;
            fault_regs.ss = read_segment_register(ss);
            fault_regs.ds = read_segment_register(ds);
            fault_regs.es = read_segment_register(es);
            fault_regs.fs = read_segment_register(fs);
            fault_regs.gs = read_segment_register(gs);
            fault_crs[2] = read_cr2();
        }
        else
        {
            context = "guest";
            fault_crs[2] = current->vcpu_info->arch.cr2;
        }

        fault_crs[0] = read_cr0();
        fault_crs[3] = read_cr3();
        fault_crs[4] = read_cr4();
    }

    print_xen_info();
    printk("CPU:    %d\nEIP:    %04x:[<%08x>]",
           smp_processor_id(), fault_regs.cs, fault_regs.eip);
    if ( !guest_mode(regs) )
        print_symbol(" %s", fault_regs.eip);
    printk("\nEFLAGS: %08x   CONTEXT: %s\n", fault_regs.eflags, context);
    printk("eax: %08x   ebx: %08x   ecx: %08x   edx: %08x\n",
           fault_regs.eax, fault_regs.ebx, fault_regs.ecx, fault_regs.edx);
    printk("esi: %08x   edi: %08x   ebp: %08x   esp: %08x\n",
           fault_regs.esi, fault_regs.edi, fault_regs.ebp, fault_regs.esp);
    printk("cr0: %08lx   cr4: %08lx   cr3: %08lx   cr2: %08lx\n",
           fault_crs[0], fault_crs[4], fault_crs[3], fault_crs[2]);
    printk("ds: %04x   es: %04x   fs: %04x   gs: %04x   "
           "ss: %04x   cs: %04x\n",
           fault_regs.ds, fault_regs.es, fault_regs.fs,
           fault_regs.gs, fault_regs.ss, fault_regs.cs);
}

void show_page_walk(unsigned long addr)
{
    unsigned long pfn, mfn, cr3 = read_cr3();
#ifdef CONFIG_X86_PAE
    l3_pgentry_t l3e, *l3t;
#endif
    l2_pgentry_t l2e, *l2t;
    l1_pgentry_t l1e, *l1t;

    printk("Pagetable walk from %08lx:\n", addr);

    mfn = cr3 >> PAGE_SHIFT;

#ifdef CONFIG_X86_PAE
    l3t  = map_domain_page(mfn);
    l3t += (cr3 & 0xFE0UL) >> 3;
    l3e = l3t[l3_table_offset(addr)];
    mfn = l3e_get_pfn(l3e);
    pfn = get_gpfn_from_mfn(mfn);
    printk(" L3[0x%03lx] = %"PRIpte" %08lx\n",
           l3_table_offset(addr), l3e_get_intpte(l3e), pfn);
    unmap_domain_page(l3t);
    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) )
        return;
#endif

    l2t = map_domain_page(mfn);
    l2e = l2t[l2_table_offset(addr)];
    mfn = l2e_get_pfn(l2e);
    pfn = get_gpfn_from_mfn(mfn);
    printk(" L2[0x%03lx] = %"PRIpte" %08lx %s\n",
           l2_table_offset(addr), l2e_get_intpte(l2e), pfn,
           (l2e_get_flags(l2e) & _PAGE_PSE) ? "(PSE)" : "");
    unmap_domain_page(l2t);
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) ||
         (l2e_get_flags(l2e) & _PAGE_PSE) )
        return;

    l1t = map_domain_page(mfn);
    l1e = l1t[l1_table_offset(addr)];
    mfn = l1e_get_pfn(l1e);
    pfn = get_gpfn_from_mfn(mfn);
    printk(" L1[0x%03lx] = %"PRIpte" %08lx\n",
           l1_table_offset(addr), l1e_get_intpte(l1e), pfn);
    unmap_domain_page(l1t);
}

#define DOUBLEFAULT_STACK_SIZE 1024
static struct tss_struct doublefault_tss;
static unsigned char doublefault_stack[DOUBLEFAULT_STACK_SIZE];

asmlinkage void do_double_fault(void)
{
    struct tss_struct *tss = &doublefault_tss;
    unsigned int cpu = ((tss->back_link>>3)-__FIRST_TSS_ENTRY)>>1;

    watchdog_disable();

    console_force_unlock();

    /* Find information saved during fault and dump it to the console. */
    tss = &init_tss[cpu];
    printk("*** DOUBLE FAULT ***\n");
    print_xen_info();
    printk("CPU:    %d\nEIP:    %04x:[<%08x>]",
           cpu, tss->cs, tss->eip);
    print_symbol(" %s\n", tss->eip);
    printk("EFLAGS: %08x\n", tss->eflags);
    printk("CR3:    %08x\n", tss->__cr3);
    printk("eax: %08x   ebx: %08x   ecx: %08x   edx: %08x\n",
           tss->eax, tss->ebx, tss->ecx, tss->edx);
    printk("esi: %08x   edi: %08x   ebp: %08x   esp: %08x\n",
           tss->esi, tss->edi, tss->ebp, tss->esp);
    printk("ds: %04x   es: %04x   fs: %04x   gs: %04x   ss: %04x\n",
           tss->ds, tss->es, tss->fs, tss->gs, tss->ss);
    show_stack_overflow(tss->esp);

    panic("DOUBLE FAULT -- system shutdown\n");
}

unsigned long do_iret(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    u32 eflags;

    /* Check worst-case stack frame for overlap with Xen protected area. */
    if ( unlikely(!access_ok(regs->esp, 40)) )
        goto exit_and_crash;

    /* Pop and restore EAX (clobbered by hypercall). */
    if ( unlikely(__copy_from_user(&regs->eax, (void __user *)regs->esp, 4)) )
        goto exit_and_crash;
    regs->esp += 4;

    /* Pop and restore CS and EIP. */
    if ( unlikely(__copy_from_user(&regs->eip, (void __user *)regs->esp, 8)) )
        goto exit_and_crash;
    regs->esp += 8;

    /*
     * Pop, fix up and restore EFLAGS. We fix up in a local staging area
     * to avoid firing the BUG_ON(IOPL) check in arch_get_info_guest.
     */
    if ( unlikely(__copy_from_user(&eflags, (void __user *)regs->esp, 4)) )
        goto exit_and_crash;
    regs->esp += 4;
    regs->eflags = (eflags & ~X86_EFLAGS_IOPL) | X86_EFLAGS_IF;

    if ( vm86_mode(regs) )
    {
        /* Return to VM86 mode: pop and restore ESP,SS,ES,DS,FS and GS. */
        if ( __copy_from_user(&regs->esp, (void __user *)regs->esp, 24) )
            goto exit_and_crash;
    }
    else if ( unlikely(ring_0(regs)) )
    {
        goto exit_and_crash;
    }
    else if ( !ring_1(regs) )
    {
        /* Return to ring 2/3: pop and restore ESP and SS. */
        if ( __copy_from_user(&regs->esp, (void __user *)regs->esp, 8) )
            goto exit_and_crash;
    }

    /* No longer in NMI context. */
    clear_bit(_VCPUF_nmi_masked, &current->vcpu_flags);

    /* Restore upcall mask from supplied EFLAGS.IF. */
    current->vcpu_info->evtchn_upcall_mask = !(eflags & X86_EFLAGS_IF);

    /*
     * The hypercall exit path will overwrite EAX with this return
     * value.
     */
    return regs->eax;

 exit_and_crash:
    gdprintk(XENLOG_ERR, "Fatal error\n");
    domain_crash(current->domain);
    return 0;
}

#include <asm/asm_defns.h>
BUILD_SMP_INTERRUPT(deferred_nmi, TRAP_deferred_nmi)
fastcall void smp_deferred_nmi(struct cpu_user_regs *regs)
{
    asmlinkage void do_nmi(struct cpu_user_regs *);
    ack_APIC_irq();
    do_nmi(regs);
}

void __init percpu_traps_init(void)
{
    struct tss_struct *tss = &doublefault_tss;
    asmlinkage int hypercall(void);

    if ( smp_processor_id() != 0 )
        return;

    /* CPU0 uses the master IDT. */
    idt_tables[0] = idt_table;

    /* The hypercall entry vector is only accessible from ring 1. */
    _set_gate(idt_table+HYPERCALL_VECTOR, 14, 1, &hypercall);

    set_intr_gate(TRAP_deferred_nmi, &deferred_nmi);

    /*
     * Make a separate task for double faults. This will get us debug output if
     * we blow the kernel stack.
     */
    memset(tss, 0, sizeof(*tss));
    tss->ds     = __HYPERVISOR_DS;
    tss->es     = __HYPERVISOR_DS;
    tss->ss     = __HYPERVISOR_DS;
    tss->esp    = (unsigned long)
        &doublefault_stack[DOUBLEFAULT_STACK_SIZE];
    tss->__cr3  = __pa(idle_pg_table);
    tss->cs     = __HYPERVISOR_CS;
    tss->eip    = (unsigned long)do_double_fault;
    tss->eflags = 2;
    tss->bitmap = IOBMP_INVALID_OFFSET;
    _set_tssldt_desc(
        gdt_table + __DOUBLEFAULT_TSS_ENTRY - FIRST_RESERVED_GDT_ENTRY,
        (unsigned long)tss, 235, 9);

    set_task_gate(TRAP_double_fault, __DOUBLEFAULT_TSS_ENTRY<<3);
}

void init_int80_direct_trap(struct vcpu *v)
{
    struct trap_info *ti = &v->arch.guest_context.trap_ctxt[0x80];

    /*
     * We can't virtualise interrupt gates, as there's no way to get
     * the CPU to automatically clear the events_mask variable. Also we
     * must ensure that the CS is safe to poke into an interrupt gate.
     *
     * When running with supervisor_mode_kernel enabled a direct trap
     * to the guest OS cannot be used because the INT instruction will
     * switch to the Xen stack and we need to swap back to the guest
     * kernel stack before passing control to the system call entry point.
     */
    if ( TI_GET_IF(ti) || !guest_gate_selector_okay(v->domain, ti->cs) ||
         supervisor_mode_kernel )
    {
        v->arch.int80_desc.a = v->arch.int80_desc.b = 0;
        return;
    }

    v->arch.int80_desc.a = (ti->cs << 16) | (ti->address & 0xffff);
    v->arch.int80_desc.b =
        (ti->address & 0xffff0000) | 0x8f00 | ((TI_GET_DPL(ti) & 3) << 13);

    if ( v == current )
        set_int80_direct_trap(v);
}

#ifdef CONFIG_X86_SUPERVISOR_MODE_KERNEL
static void do_update_sysenter(void *info)
{
    xen_callback_t *address = info;

    wrmsr(MSR_IA32_SYSENTER_CS, address->cs, 0);
    wrmsr(MSR_IA32_SYSENTER_EIP, address->eip, 0);
}
#endif

static long register_guest_callback(struct callback_register *reg)
{
    long ret = 0;
    struct vcpu *v = current;

    fixup_guest_code_selector(v->domain, reg->address.cs);

    switch ( reg->type )
    {
    case CALLBACKTYPE_event:
        v->arch.guest_context.event_callback_cs     = reg->address.cs;
        v->arch.guest_context.event_callback_eip    = reg->address.eip;
        break;

    case CALLBACKTYPE_failsafe:
        v->arch.guest_context.failsafe_callback_cs  = reg->address.cs;
        v->arch.guest_context.failsafe_callback_eip = reg->address.eip;
        if ( reg->flags & CALLBACKF_mask_events )
            set_bit(_VGCF_failsafe_disables_events,
                    &v->arch.guest_context.flags);
        else
            clear_bit(_VGCF_failsafe_disables_events,
                      &v->arch.guest_context.flags);
        break;

#ifdef CONFIG_X86_SUPERVISOR_MODE_KERNEL
    case CALLBACKTYPE_sysenter:
        if ( ! cpu_has_sep )
            ret = -EINVAL;
        else if ( on_each_cpu(do_update_sysenter, &reg->address, 1, 1) != 0 )
            ret = -EIO;
        break;
#endif

    case CALLBACKTYPE_nmi:
        ret = register_guest_nmi_callback(reg->address.eip);
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

static long unregister_guest_callback(struct callback_unregister *unreg)
{
    long ret;

    switch ( unreg->type )
    {
    case CALLBACKTYPE_event:
    case CALLBACKTYPE_failsafe:
#ifdef CONFIG_X86_SUPERVISOR_MODE_KERNEL
    case CALLBACKTYPE_sysenter:
#endif
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

long do_set_callbacks(unsigned long event_selector,
                      unsigned long event_address,
                      unsigned long failsafe_selector,
                      unsigned long failsafe_address)
{
    struct callback_register event = {
        .type = CALLBACKTYPE_event,
        .address = { event_selector, event_address },
    };
    struct callback_register failsafe = {
        .type = CALLBACKTYPE_failsafe,
        .address = { failsafe_selector, failsafe_address },
    };

    register_guest_callback(&event);
    register_guest_callback(&failsafe);

    return 0;
}

static void hypercall_page_initialise_ring0_kernel(void *hypercall_page)
{
    extern asmlinkage int hypercall(void);
    char *p;
    int i;

    /* Fill in all the transfer points with template machine code. */

    for ( i = 0; i < (PAGE_SIZE / 32); i++ )
    {
        p = (char *)(hypercall_page + (i * 32));

        *(u8  *)(p+ 0) = 0x9c;      /* pushf */
        *(u8  *)(p+ 1) = 0xfa;      /* cli */
        *(u8  *)(p+ 2) = 0xb8;      /* mov $<i>,%eax */
        *(u32 *)(p+ 3) = i;
        *(u8  *)(p+ 7) = 0x9a;      /* lcall $__HYPERVISOR_CS,&hypercall */
        *(u32 *)(p+ 8) = (u32)&hypercall;
        *(u16 *)(p+12) = (u16)__HYPERVISOR_CS;
        *(u8  *)(p+14) = 0xc3;      /* ret */
    }

    /*
     * HYPERVISOR_iret is special because it doesn't return and expects a
     * special stack frame. Guests jump at this transfer point instead of
     * calling it.
     */
    p = (char *)(hypercall_page + (__HYPERVISOR_iret * 32));
    *(u8  *)(p+ 0) = 0x50;      /* push %eax */
    *(u8  *)(p+ 1) = 0x9c;      /* pushf */
    *(u8  *)(p+ 2) = 0xfa;      /* cli */
    *(u8  *)(p+ 3) = 0xb8;      /* mov $<i>,%eax */
    *(u32 *)(p+ 4) = __HYPERVISOR_iret;
    *(u8  *)(p+ 8) = 0x9a;      /* lcall $__HYPERVISOR_CS,&hypercall */
    *(u32 *)(p+ 9) = (u32)&hypercall;
    *(u16 *)(p+13) = (u16)__HYPERVISOR_CS;
}

static void hypercall_page_initialise_ring1_kernel(void *hypercall_page)
{
    char *p;
    int i;

    /* Fill in all the transfer points with template machine code. */

    for ( i = 0; i < (PAGE_SIZE / 32); i++ )
    {
        p = (char *)(hypercall_page + (i * 32));
        *(u8  *)(p+ 0) = 0xb8;    /* mov  $<i>,%eax */
        *(u32 *)(p+ 1) = i;
        *(u16 *)(p+ 5) = 0x82cd;  /* int  $0x82 */
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
    *(u16 *)(p+ 6) = 0x82cd;  /* int  $0x82 */
}

void hypercall_page_initialise(struct domain *d, void *hypercall_page)
{
    if ( is_hvm_domain(d) )
        hvm_hypercall_page_initialise(d, hypercall_page);
    else if ( supervisor_mode_kernel )
        hypercall_page_initialise_ring0_kernel(hypercall_page);
    else
        hypercall_page_initialise_ring1_kernel(hypercall_page);
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
