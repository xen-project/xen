
#include <xen/config.h>
#include <xen/domain_page.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/console.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/symbols.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/vmx.h>

/* All CPUs have their own IDT to allow int80 direct trap. */
idt_entry_t *idt_tables[NR_CPUS] = { 0 };

void show_registers(struct cpu_user_regs *regs)
{
    unsigned long ss, ds, es, fs, gs, cs;
    unsigned long eip, esp, eflags, cr0, cr3;
    const char *context;

    if ( VMX_DOMAIN(current) && (regs->eflags == 0) )
    {
        __vmread(GUEST_RIP, &eip);
        __vmread(GUEST_RSP, &esp);
        __vmread(GUEST_RFLAGS, &eflags);
        __vmread(GUEST_SS_SELECTOR, &ss);
        __vmread(GUEST_DS_SELECTOR, &ds);
        __vmread(GUEST_ES_SELECTOR, &es);
        __vmread(GUEST_FS_SELECTOR, &fs);
        __vmread(GUEST_GS_SELECTOR, &gs);
        __vmread(GUEST_CS_SELECTOR, &cs);
        __vmread(CR0_READ_SHADOW, &cr0);
        __vmread(GUEST_CR3, &cr3);
        context = "vmx guest";
    }
    else
    {
        eip    = regs->eip;
        eflags = regs->eflags;
        cr0    = read_cr0();
        cr3    = read_cr3();

        __asm__ ( "movl %%fs,%0 ; movl %%gs,%1" : "=r" (fs), "=r" (gs) );

        if ( GUEST_MODE(regs) )
        {
            esp = regs->esp;
            ss  = regs->ss & 0xffff;
            ds  = regs->ds & 0xffff;
            es  = regs->es & 0xffff;
            cs  = regs->cs & 0xffff;
            context = "guest";
        }
        else
        {
            esp = (unsigned long)&regs->esp;
            ss  = __HYPERVISOR_DS;
            ds  = __HYPERVISOR_DS;
            es  = __HYPERVISOR_DS;
            cs  = __HYPERVISOR_CS;
            context = "hypervisor";
        }
    }

    printk("CPU:    %d\nEIP:    %04lx:[<%08lx>]",
           smp_processor_id(), (unsigned long)0xffff & regs->cs, eip);
    if ( !GUEST_MODE(regs) )
        print_symbol(" %s", eip);
    printk("\nEFLAGS: %08lx   CONTEXT: %s\n", eflags, context);
    printk("eax: %08x   ebx: %08x   ecx: %08x   edx: %08x\n",
           regs->eax, regs->ebx, regs->ecx, regs->edx);
    printk("esi: %08x   edi: %08x   ebp: %08x   esp: %08lx\n",
           regs->esi, regs->edi, regs->ebp, esp);
    printk("cr0: %08lx   cr3: %08lx\n", cr0, cr3);
    printk("ds: %04lx   es: %04lx   fs: %04lx   gs: %04lx   "
           "ss: %04lx   cs: %04lx\n",
           ds, es, fs, gs, ss, cs);

    show_stack(regs);
}

void show_page_walk(unsigned long addr)
{
    unsigned long mfn = read_cr3() >> PAGE_SHIFT;
    intpte_t *ptab, ent;
    unsigned long pfn; 

    printk("Pagetable walk from %08lx:\n", addr);

#ifdef CONFIG_X86_PAE
    ptab = map_domain_page(mfn);
    ent  = ptab[l3_table_offset(addr)];
    pfn  = get_pfn_from_mfn((u32)(ent >> PAGE_SHIFT)); 
    printk(" L3 = %"PRIpte" %08lx\n", ent, pfn);
    unmap_domain_page(ptab);
    if ( !(ent & _PAGE_PRESENT) )
        return;
    mfn = ent >> PAGE_SHIFT;
#endif

    ptab = map_domain_page(mfn);
    ent  = ptab[l2_table_offset(addr)];
    pfn  = get_pfn_from_mfn((u32)(ent >> PAGE_SHIFT));
    printk("  L2 = %"PRIpte" %08lx %s\n", ent, pfn, 
           (ent & _PAGE_PSE) ? "(PSE)" : "");
    unmap_domain_page(ptab);
    if ( !(ent & _PAGE_PRESENT) || (ent & _PAGE_PSE) )
        return;
    mfn = ent >> PAGE_SHIFT;

    ptab = map_domain_page(ent >> PAGE_SHIFT);
    ent  = ptab[l1_table_offset(addr)];
    pfn  = get_pfn_from_mfn((u32)(ent >> PAGE_SHIFT));
    printk("   L1 = %"PRIpte" %08lx\n", ent, pfn);
    unmap_domain_page(ptab);
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
    printk("************************************\n");
    printk("CPU%d DOUBLE FAULT -- system shutdown\n", cpu);
    printk("System needs manual reset.\n");
    printk("************************************\n");

    /* Lock up the console to prevent spurious output from other CPUs. */
    console_force_lock();

    /* Wait for manual reset. */
    for ( ; ; )
        __asm__ __volatile__ ( "hlt" );
}

BUILD_SMP_INTERRUPT(deferred_nmi, TRAP_deferred_nmi)
asmlinkage void smp_deferred_nmi(struct cpu_user_regs regs)
{
    asmlinkage void do_nmi(struct cpu_user_regs *, unsigned long);
    ack_APIC_irq();
    do_nmi(&regs, 0);
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
    trap_info_t *ti = &v->arch.guest_context.trap_ctxt[0x80];

    /*
     * We can't virtualise interrupt gates, as there's no way to get
     * the CPU to automatically clear the events_mask variable.
     */
    if ( TI_GET_IF(ti) )
        return;

    v->arch.int80_desc.a = (ti->cs << 16) | (ti->address & 0xffff);
    v->arch.int80_desc.b =
        (ti->address & 0xffff0000) | 0x8f00 | ((TI_GET_DPL(ti) & 3) << 13);

    if ( v == current )
        set_int80_direct_trap(v);
}

long do_set_callbacks(unsigned long event_selector,
                      unsigned long event_address,
                      unsigned long failsafe_selector,
                      unsigned long failsafe_address)
{
    struct vcpu *d = current;

    if ( !VALID_CODESEL(event_selector) || !VALID_CODESEL(failsafe_selector) )
        return -EPERM;

    d->arch.guest_context.event_callback_cs     = event_selector;
    d->arch.guest_context.event_callback_eip    = event_address;
    d->arch.guest_context.failsafe_callback_cs  = failsafe_selector;
    d->arch.guest_context.failsafe_callback_eip = failsafe_address;

    return 0;
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
