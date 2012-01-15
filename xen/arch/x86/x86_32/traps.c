
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
#include <xen/cpu.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/traps.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>

#include <public/callback.h>

static void print_xen_info(void)
{
    char taint_str[TAINT_STRING_MAX_LEN];
    char debug = 'n', *arch = "x86_32p";

#ifndef NDEBUG
    debug = 'y';
#endif

    printk("----[ Xen-%d.%d%s  %s  debug=%c  %s ]----\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
           arch, debug, print_tainted(taint_str));
}

enum context { CTXT_hypervisor, CTXT_pv_guest, CTXT_hvm_guest };

static void _show_registers(
    const struct cpu_user_regs *regs, unsigned long crs[8],
    enum context context, const struct vcpu *v)
{
    const static char *context_names[] = {
        [CTXT_hypervisor] = "hypervisor",
        [CTXT_pv_guest]   = "pv guest",
        [CTXT_hvm_guest]  = "hvm guest"
    };

    printk("EIP:    %04x:[<%08x>]", regs->cs, regs->eip);
    if ( context == CTXT_hypervisor )
        print_symbol(" %s", regs->eip);
    printk("\nEFLAGS: %08x   ", regs->eflags);
    if ( (context == CTXT_pv_guest) && v && v->vcpu_info )
        printk("EM: %d   ", !!v->vcpu_info->evtchn_upcall_mask);
    printk("CONTEXT: %s\n", context_names[context]);

    printk("eax: %08x   ebx: %08x   ecx: %08x   edx: %08x\n",
           regs->eax, regs->ebx, regs->ecx, regs->edx);
    printk("esi: %08x   edi: %08x   ebp: %08x   esp: %08x\n",
           regs->esi, regs->edi, regs->ebp, regs->esp);
    printk("cr0: %08lx   cr4: %08lx   cr3: %08lx   cr2: %08lx\n",
           crs[0], crs[4], crs[3], crs[2]);
    printk("ds: %04x   es: %04x   fs: %04x   gs: %04x   "
           "ss: %04x   cs: %04x\n",
           regs->ds, regs->es, regs->fs,
           regs->gs, regs->ss, regs->cs);
}

void show_registers(struct cpu_user_regs *regs)
{
    struct cpu_user_regs fault_regs = *regs;
    unsigned long fault_crs[8];
    enum context context;
    struct vcpu *v = current;

    if ( is_hvm_vcpu(v) && guest_mode(regs) )
    {
        struct segment_register sreg;
        context = CTXT_hvm_guest;
        fault_crs[0] = v->arch.hvm_vcpu.guest_cr[0];
        fault_crs[2] = v->arch.hvm_vcpu.guest_cr[2];
        fault_crs[3] = v->arch.hvm_vcpu.guest_cr[3];
        fault_crs[4] = v->arch.hvm_vcpu.guest_cr[4];
        hvm_get_segment_register(v, x86_seg_cs, &sreg);
        fault_regs.cs = sreg.sel;
        hvm_get_segment_register(v, x86_seg_ds, &sreg);
        fault_regs.ds = sreg.sel;
        hvm_get_segment_register(v, x86_seg_es, &sreg);
        fault_regs.es = sreg.sel;
        hvm_get_segment_register(v, x86_seg_fs, &sreg);
        fault_regs.fs = sreg.sel;
        hvm_get_segment_register(v, x86_seg_gs, &sreg);
        fault_regs.gs = sreg.sel;
        hvm_get_segment_register(v, x86_seg_ss, &sreg);
        fault_regs.ss = sreg.sel;
    }
    else
    {
        if ( !guest_mode(regs) )
        {
            context = CTXT_hypervisor;
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
            context = CTXT_pv_guest;
            fault_crs[2] = v->vcpu_info->arch.cr2;
        }

        fault_crs[0] = read_cr0();
        fault_crs[3] = read_cr3();
        fault_crs[4] = read_cr4();
    }

    print_xen_info();
    printk("CPU:    %d\n", smp_processor_id());
    _show_registers(&fault_regs, fault_crs, context, v);

    if ( this_cpu(ler_msr) && !guest_mode(regs) )
    {
        u32 from, to, hi;
        rdmsr(this_cpu(ler_msr), from, hi);
        rdmsr(this_cpu(ler_msr) + 1, to, hi);
        printk("ler: %08x -> %08x\n", from, to);
    }
}

void vcpu_show_registers(const struct vcpu *v)
{
    unsigned long crs[8];

    /* No need to handle HVM for now. */
    if ( is_hvm_vcpu(v) )
        return;

    crs[0] = v->arch.pv_vcpu.ctrlreg[0];
    crs[2] = v->vcpu_info->arch.cr2;
    crs[3] = pagetable_get_paddr(v->arch.guest_table);
    crs[4] = v->arch.pv_vcpu.ctrlreg[4];

    _show_registers(&v->arch.user_regs, crs, CTXT_pv_guest, v);
}

void show_page_walk(unsigned long addr)
{
    unsigned long pfn, mfn, cr3 = read_cr3();
    l3_pgentry_t l3e, *l3t;
    l2_pgentry_t l2e, *l2t;
    l1_pgentry_t l1e, *l1t;

    printk("Pagetable walk from %08lx:\n", addr);

    mfn = cr3 >> PAGE_SHIFT;

    l3t  = map_domain_page(mfn);
    l3t += (cr3 & 0xFE0UL) >> 3;
    l3e = l3t[l3_table_offset(addr)];
    mfn = l3e_get_pfn(l3e);
    pfn = mfn_valid(mfn) && machine_to_phys_mapping_valid ?
          get_gpfn_from_mfn(mfn) : INVALID_M2P_ENTRY;
    printk(" L3[0x%03lx] = %"PRIpte" %08lx\n",
           l3_table_offset(addr), l3e_get_intpte(l3e), pfn);
    unmap_domain_page(l3t);
    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) ||
         !mfn_valid(mfn) )
        return;

    l2t = map_domain_page(mfn);
    l2e = l2t[l2_table_offset(addr)];
    mfn = l2e_get_pfn(l2e);
    pfn = mfn_valid(mfn) && machine_to_phys_mapping_valid ?
          get_gpfn_from_mfn(mfn) : INVALID_M2P_ENTRY;
    printk(" L2[0x%03lx] = %"PRIpte" %08lx %s\n",
           l2_table_offset(addr), l2e_get_intpte(l2e), pfn,
           (l2e_get_flags(l2e) & _PAGE_PSE) ? "(PSE)" : "");
    unmap_domain_page(l2t);
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) ||
         (l2e_get_flags(l2e) & _PAGE_PSE) ||
         !mfn_valid(mfn) )
        return;

    l1t = map_domain_page(mfn);
    l1e = l1t[l1_table_offset(addr)];
    mfn = l1e_get_pfn(l1e);
    pfn = mfn_valid(mfn) && machine_to_phys_mapping_valid ?
          get_gpfn_from_mfn(mfn) : INVALID_M2P_ENTRY;
    printk(" L1[0x%03lx] = %"PRIpte" %08lx\n",
           l1_table_offset(addr), l1e_get_intpte(l1e), pfn);
    unmap_domain_page(l1t);
}

static DEFINE_PER_CPU_READ_MOSTLY(struct tss_struct *, doublefault_tss);
static unsigned char __attribute__ ((__section__ (".bss.page_aligned")))
    boot_cpu_doublefault_space[PAGE_SIZE];

static int cpu_doublefault_tss_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    void *p;
    int rc = 0;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        per_cpu(doublefault_tss, cpu) = p = alloc_xenheap_page();
        if ( p == NULL )
            rc = -ENOMEM;
        else
            memset(p, 0, PAGE_SIZE);
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        free_xenheap_page(per_cpu(doublefault_tss, cpu));
        break;
    default:
        break;
    }

    return !rc ? NOTIFY_DONE : notifier_from_errno(rc);
}

static struct notifier_block cpu_doublefault_tss_nfb = {
    .notifier_call = cpu_doublefault_tss_callback
};

void do_double_fault(void)
{
    struct tss_struct *tss;
    unsigned int cpu;

    watchdog_disable();

    console_force_unlock();

    asm ( "lsll %1, %0" : "=r" (cpu) : "rm" (PER_CPU_GDT_ENTRY << 3) );

    /* Find information saved during fault and dump it to the console. */
    tss = &per_cpu(init_tss, cpu);
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
    show_stack_overflow(cpu, tss->esp);

    panic("DOUBLE FAULT -- system shutdown\n");
}

unsigned long do_iret(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct vcpu *v = current;
    u32 eflags;

    /* Check worst-case stack frame for overlap with Xen protected area. */
    if ( unlikely(!access_ok(regs->esp, 40)) )
        goto exit_and_crash;

    /* Pop and restore EAX (clobbered by hypercall). */
    if ( unlikely(__copy_from_user(&regs->eax, (void *)regs->esp, 4)) )
        goto exit_and_crash;
    regs->esp += 4;

    /* Pop and restore CS and EIP. */
    if ( unlikely(__copy_from_user(&regs->eip, (void *)regs->esp, 8)) )
        goto exit_and_crash;
    regs->esp += 8;

    /*
     * Pop, fix up and restore EFLAGS. We fix up in a local staging area
     * to avoid firing the BUG_ON(IOPL) check in arch_get_info_guest.
     */
    if ( unlikely(__copy_from_user(&eflags, (void *)regs->esp, 4)) )
        goto exit_and_crash;
    regs->esp += 4;
    regs->eflags = (eflags & ~X86_EFLAGS_IOPL) | X86_EFLAGS_IF;

    if ( vm86_mode(regs) )
    {
        /* Return to VM86 mode: pop and restore ESP,SS,ES,DS,FS and GS. */
        if ( __copy_from_user(&regs->esp, (void *)regs->esp, 24) )
            goto exit_and_crash;
    }
    else if ( unlikely(ring_0(regs)) )
    {
        goto exit_and_crash;
    }
    else if ( !ring_1(regs) )
    {
        /* Return to ring 2/3: pop and restore ESP and SS. */
        if ( __copy_from_user(&regs->esp, (void *)regs->esp, 8) )
            goto exit_and_crash;
    }

    /* Restore upcall mask from supplied EFLAGS.IF. */
    vcpu_info(v, evtchn_upcall_mask) = !(eflags & X86_EFLAGS_IF);

    async_exception_cleanup(v);

    /*
     * The hypercall exit path will overwrite EAX with this return
     * value.
     */
    return regs->eax;

 exit_and_crash:
    gdprintk(XENLOG_ERR, "Fatal error\n");
    domain_crash(v->domain);
    return 0;
}

static void set_task_gate(unsigned int n, unsigned int sel)
{
    idt_table[n].b = 0;
    wmb(); /* disable gate /then/ rewrite */
    idt_table[n].a = sel << 16;
    wmb(); /* rewrite /then/ enable gate */
    idt_table[n].b = 0x8500;
}

void __devinit subarch_percpu_traps_init(void)
{
    struct tss_struct *tss;
    int cpu = smp_processor_id();

    if ( cpu == 0 )
    {
        /* The hypercall entry vector is only accessible from ring 1. */
        _set_gate(idt_table+HYPERCALL_VECTOR, 14, 1, &hypercall);

        this_cpu(doublefault_tss) = (void *)boot_cpu_doublefault_space;

        register_cpu_notifier(&cpu_doublefault_tss_nfb);
    }

    tss = this_cpu(doublefault_tss);
    BUG_ON(tss == NULL);

    /*
     * Make a separate task for double faults. This will get us debug output if
     * we blow the kernel stack.
     */
    tss->ds     = __HYPERVISOR_DS;
    tss->es     = __HYPERVISOR_DS;
    tss->ss     = __HYPERVISOR_DS;
    tss->esp    = (unsigned long)tss + PAGE_SIZE;
    tss->__cr3  = __pa(idle_pg_table);
    tss->cs     = __HYPERVISOR_CS;
    tss->eip    = (unsigned long)do_double_fault;
    tss->eflags = 2;
    tss->bitmap = IOBMP_INVALID_OFFSET;
    _set_tssldt_desc(
        this_cpu(gdt_table) + DOUBLEFAULT_TSS_ENTRY - FIRST_RESERVED_GDT_ENTRY,
        (unsigned long)tss, 235, 9);

    set_task_gate(TRAP_double_fault, DOUBLEFAULT_TSS_ENTRY << 3);
}

void init_int80_direct_trap(struct vcpu *v)
{
    struct trap_info *ti = &v->arch.pv_vcpu.trap_ctxt[0x80];

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
        v->arch.pv_vcpu.int80_desc.a = v->arch.pv_vcpu.int80_desc.b = 0;
        return;
    }

    v->arch.pv_vcpu.int80_desc.a = (ti->cs << 16) | (ti->address & 0xffff);
    v->arch.pv_vcpu.int80_desc.b =
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

#ifdef CONFIG_X86_SUPERVISOR_MODE_KERNEL
    case CALLBACKTYPE_sysenter_deprecated:
        if ( !cpu_has_sep )
            ret = -EINVAL;
        else
            on_each_cpu(do_update_sysenter, &reg->address, 1);
        break;

    case CALLBACKTYPE_sysenter:
        if ( !cpu_has_sep )
            ret = -EINVAL;
        else
            do_update_sysenter(&reg->address);
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
    case CALLBACKTYPE_sysenter_deprecated:
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

void hypercall_page_initialise(struct domain *d, void *hypercall_page)
{
    memset(hypercall_page, 0xCC, PAGE_SIZE);
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
