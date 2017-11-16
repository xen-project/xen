
#include <xen/config.h>
#include <xen/version.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/symbols.h>
#include <xen/console.h>
#include <xen/sched.h>
#include <xen/shutdown.h>
#include <xen/nmi.h>
#include <xen/guest_access.h>
#include <xen/watchdog.h>
#include <xen/hypercall.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/traps.h>
#include <asm/event.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/shared.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <public/callback.h>


static void print_xen_info(void)
{
    char taint_str[TAINT_STRING_MAX_LEN];

    printk("----[ Xen-%d.%d%s  x86_64  debug=%c " gcov_string "  %s ]----\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
           debug_build() ? 'y' : 'n', print_tainted(taint_str));
}

enum context { CTXT_hypervisor, CTXT_pv_guest, CTXT_hvm_guest };

/* (ab)use crs[5..7] for fs/gs bases. */
static void read_registers(struct cpu_user_regs *regs, unsigned long crs[8])
{
    crs[0] = read_cr0();
    crs[2] = read_cr2();
    crs[3] = read_cr3();
    crs[4] = read_cr4();
    regs->ds = read_sreg(ds);
    regs->es = read_sreg(es);
    regs->fs = read_sreg(fs);
    regs->gs = read_sreg(gs);
    crs[5] = rdfsbase();
    crs[6] = rdgsbase();
    rdmsrl(MSR_SHADOW_GS_BASE, crs[7]);
}

static void _show_registers(
    const struct cpu_user_regs *regs, unsigned long crs[8],
    enum context context, const struct vcpu *v)
{
    static const char *const context_names[] = {
        [CTXT_hypervisor] = "hypervisor",
        [CTXT_pv_guest]   = "pv guest",
        [CTXT_hvm_guest]  = "hvm guest"
    };

    printk("RIP:    %04x:[<%016lx>]", regs->cs, regs->rip);
    if ( context == CTXT_hypervisor )
        printk(" %pS", _p(regs->rip));
    printk("\nRFLAGS: %016lx   ", regs->rflags);
    if ( (context == CTXT_pv_guest) && v && v->vcpu_info )
        printk("EM: %d   ", !!vcpu_info(v, evtchn_upcall_mask));
    printk("CONTEXT: %s", context_names[context]);
    if ( v && !is_idle_vcpu(v) )
        printk(" (%pv)", v);

    printk("\nrax: %016lx   rbx: %016lx   rcx: %016lx\n",
           regs->rax, regs->rbx, regs->rcx);
    printk("rdx: %016lx   rsi: %016lx   rdi: %016lx\n",
           regs->rdx, regs->rsi, regs->rdi);
    printk("rbp: %016lx   rsp: %016lx   r8:  %016lx\n",
           regs->rbp, regs->rsp, regs->r8);
    printk("r9:  %016lx   r10: %016lx   r11: %016lx\n",
           regs->r9,  regs->r10, regs->r11);
    if ( !(regs->entry_vector & TRAP_regs_partial) )
    {
        printk("r12: %016lx   r13: %016lx   r14: %016lx\n",
               regs->r12, regs->r13, regs->r14);
        printk("r15: %016lx   cr0: %016lx   cr4: %016lx\n",
               regs->r15, crs[0], crs[4]);
    }
    else
        printk("cr0: %016lx   cr4: %016lx\n", crs[0], crs[4]);
    printk("cr3: %016lx   cr2: %016lx\n", crs[3], crs[2]);
    printk("fsb: %016lx   gsb: %016lx   gss: %016lx\n",
           crs[5], crs[6], crs[7]);
    printk("ds: %04x   es: %04x   fs: %04x   gs: %04x   "
           "ss: %04x   cs: %04x\n",
           regs->ds, regs->es, regs->fs,
           regs->gs, regs->ss, regs->cs);
}

void show_registers(const struct cpu_user_regs *regs)
{
    struct cpu_user_regs fault_regs = *regs;
    unsigned long fault_crs[8];
    enum context context;
    struct vcpu *v = system_state >= SYS_STATE_smp_boot ? current : NULL;

    if ( guest_mode(regs) && has_hvm_container_vcpu(v) )
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
        fault_crs[5] = sreg.base;
        hvm_get_segment_register(v, x86_seg_gs, &sreg);
        fault_regs.gs = sreg.sel;
        fault_crs[6] = sreg.base;
        hvm_get_segment_register(v, x86_seg_ss, &sreg);
        fault_regs.ss = sreg.sel;
        fault_crs[7] = hvm_get_shadow_gs_base(v);
    }
    else
    {
        read_registers(&fault_regs, fault_crs);

        if ( guest_mode(regs) )
        {
            context = CTXT_pv_guest;
            fault_crs[2] = arch_get_cr2(v);
        }
        else
        {
            context = CTXT_hypervisor;
            fault_crs[2] = read_cr2();
        }
    }

    print_xen_info();
    printk("CPU:    %d\n", smp_processor_id());
    _show_registers(&fault_regs, fault_crs, context, v);

    if ( this_cpu(ler_msr) && !guest_mode(regs) )
    {
        u64 from, to;
        rdmsrl(this_cpu(ler_msr), from);
        rdmsrl(this_cpu(ler_msr) + 1, to);
        printk("ler: %016lx -> %016lx\n", from, to);
    }
}

void vcpu_show_registers(const struct vcpu *v)
{
    const struct cpu_user_regs *regs = &v->arch.user_regs;
    bool kernel = guest_kernel_mode(v, regs);
    unsigned long crs[8];

    /* Only handle PV guests for now */
    if ( !is_pv_vcpu(v) )
        return;

    crs[0] = v->arch.pv_vcpu.ctrlreg[0];
    crs[2] = arch_get_cr2(v);
    crs[3] = pagetable_get_paddr(kernel ?
                                 v->arch.guest_table :
                                 v->arch.guest_table_user);
    crs[4] = v->arch.pv_vcpu.ctrlreg[4];
    crs[5] = v->arch.pv_vcpu.fs_base;
    crs[6 + !kernel] = v->arch.pv_vcpu.gs_base_kernel;
    crs[7 - !kernel] = v->arch.pv_vcpu.gs_base_user;

    _show_registers(regs, crs, CTXT_pv_guest, v);
}

void show_page_walk(unsigned long addr)
{
    unsigned long pfn, mfn = read_cr3() >> PAGE_SHIFT;
    l4_pgentry_t l4e, *l4t;
    l3_pgentry_t l3e, *l3t;
    l2_pgentry_t l2e, *l2t;
    l1_pgentry_t l1e, *l1t;

    printk("Pagetable walk from %016lx:\n", addr);
    if ( !is_canonical_address(addr) )
        return;

    l4t = map_domain_page(_mfn(mfn));
    l4e = l4t[l4_table_offset(addr)];
    unmap_domain_page(l4t);
    mfn = l4e_get_pfn(l4e);
    pfn = mfn_valid(mfn) && machine_to_phys_mapping_valid ?
          get_gpfn_from_mfn(mfn) : INVALID_M2P_ENTRY;
    printk(" L4[0x%03lx] = %"PRIpte" %016lx\n",
           l4_table_offset(addr), l4e_get_intpte(l4e), pfn);
    if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) ||
         !mfn_valid(mfn) )
        return;

    l3t = map_domain_page(_mfn(mfn));
    l3e = l3t[l3_table_offset(addr)];
    unmap_domain_page(l3t);
    mfn = l3e_get_pfn(l3e);
    pfn = mfn_valid(mfn) && machine_to_phys_mapping_valid ?
          get_gpfn_from_mfn(mfn) : INVALID_M2P_ENTRY;
    printk(" L3[0x%03lx] = %"PRIpte" %016lx%s\n",
           l3_table_offset(addr), l3e_get_intpte(l3e), pfn,
           (l3e_get_flags(l3e) & _PAGE_PSE) ? " (PSE)" : "");
    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) ||
         (l3e_get_flags(l3e) & _PAGE_PSE) ||
         !mfn_valid(mfn) )
        return;

    l2t = map_domain_page(_mfn(mfn));
    l2e = l2t[l2_table_offset(addr)];
    unmap_domain_page(l2t);
    mfn = l2e_get_pfn(l2e);
    pfn = mfn_valid(mfn) && machine_to_phys_mapping_valid ?
          get_gpfn_from_mfn(mfn) : INVALID_M2P_ENTRY;
    printk(" L2[0x%03lx] = %"PRIpte" %016lx %s\n",
           l2_table_offset(addr), l2e_get_intpte(l2e), pfn,
           (l2e_get_flags(l2e) & _PAGE_PSE) ? "(PSE)" : "");
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) ||
         (l2e_get_flags(l2e) & _PAGE_PSE) ||
         !mfn_valid(mfn) )
        return;

    l1t = map_domain_page(_mfn(mfn));
    l1e = l1t[l1_table_offset(addr)];
    unmap_domain_page(l1t);
    mfn = l1e_get_pfn(l1e);
    pfn = mfn_valid(mfn) && machine_to_phys_mapping_valid ?
          get_gpfn_from_mfn(mfn) : INVALID_M2P_ENTRY;
    printk(" L1[0x%03lx] = %"PRIpte" %016lx\n",
           l1_table_offset(addr), l1e_get_intpte(l1e), pfn);
}

void do_double_fault(struct cpu_user_regs *regs)
{
    unsigned int cpu;
    unsigned long crs[8];

    console_force_unlock();

    asm ( "lsll %1, %0" : "=r" (cpu) : "rm" (PER_CPU_GDT_ENTRY << 3) );

    /* Find information saved during fault and dump it to the console. */
    printk("*** DOUBLE FAULT ***\n");
    print_xen_info();

    read_registers(regs, crs);

    printk("CPU:    %d\n", cpu);
    _show_registers(regs, crs, CTXT_hypervisor, NULL);
    show_stack_overflow(cpu, regs);

    panic("DOUBLE FAULT -- system shutdown");
}

void toggle_guest_mode(struct vcpu *v)
{
    if ( is_pv_32bit_vcpu(v) )
        return;
    if ( cpu_has_fsgsbase )
    {
        if ( v->arch.flags & TF_kernel_mode )
            v->arch.pv_vcpu.gs_base_kernel = __rdgsbase();
        else
            v->arch.pv_vcpu.gs_base_user = __rdgsbase();
    }
    asm volatile ( "swapgs" );

    toggle_guest_pt(v);
}

void toggle_guest_pt(struct vcpu *v)
{
    if ( is_pv_32bit_vcpu(v) )
        return;

    v->arch.flags ^= TF_kernel_mode;
    update_cr3(v);
    /* Don't flush user global mappings from the TLB. Don't tick TLB clock. */
    asm volatile ( "mov %0, %%cr3" : : "r" (v->arch.cr3) : "memory" );

    if ( !(v->arch.flags & TF_kernel_mode) )
        return;

    if ( v->arch.pv_vcpu.need_update_runstate_area &&
         update_runstate_area(v) )
        v->arch.pv_vcpu.need_update_runstate_area = 0;

    if ( v->arch.pv_vcpu.pending_system_time.version &&
         update_secondary_system_time(v,
                                      &v->arch.pv_vcpu.pending_system_time) )
        v->arch.pv_vcpu.pending_system_time.version = 0;
}

unsigned long do_iret(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct iret_context iret_saved;
    struct vcpu *v = current;

    if ( unlikely(copy_from_user(&iret_saved, (void *)regs->rsp,
                                 sizeof(iret_saved))) )
    {
        gprintk(XENLOG_ERR,
                "Fault while reading IRET context from guest stack\n");
        goto exit_and_crash;
    }

    /* Returning to user mode? */
    if ( (iret_saved.cs & 3) == 3 )
    {
        if ( unlikely(pagetable_is_null(v->arch.guest_table_user)) )
        {
            gprintk(XENLOG_ERR,
                    "Guest switching to user mode with no user page tables\n");
            goto exit_and_crash;
        }
        toggle_guest_mode(v);
    }

    if ( VM_ASSIST(v->domain, architectural_iopl) )
        v->arch.pv_vcpu.iopl = iret_saved.rflags & X86_EFLAGS_IOPL;

    regs->rip    = iret_saved.rip;
    regs->cs     = iret_saved.cs | 3; /* force guest privilege */
    regs->rflags = ((iret_saved.rflags & ~(X86_EFLAGS_IOPL|X86_EFLAGS_VM))
                    | X86_EFLAGS_IF);
    regs->rsp    = iret_saved.rsp;
    regs->ss     = iret_saved.ss | 3; /* force guest privilege */

    if ( !(iret_saved.flags & VGCF_in_syscall) )
    {
        regs->entry_vector &= ~TRAP_syscall;
        regs->r11 = iret_saved.r11;
        regs->rcx = iret_saved.rcx;
    }

    /* Restore upcall mask from supplied EFLAGS.IF. */
    vcpu_info(v, evtchn_upcall_mask) = !(iret_saved.rflags & X86_EFLAGS_IF);

    async_exception_cleanup(v);

    /* Saved %rax gets written back to regs->rax in entry.S. */
    return iret_saved.rax;

 exit_and_crash:
    domain_crash(v->domain);
    return 0;
}

static unsigned int write_stub_trampoline(
    unsigned char *stub, unsigned long stub_va,
    unsigned long stack_bottom, unsigned long target_va)
{
    /* movabsq %rax, stack_bottom - 8 */
    stub[0] = 0x48;
    stub[1] = 0xa3;
    *(uint64_t *)&stub[2] = stack_bottom - 8;

    /* movq %rsp, %rax */
    stub[10] = 0x48;
    stub[11] = 0x89;
    stub[12] = 0xe0;

    /* movabsq $stack_bottom - 8, %rsp */
    stub[13] = 0x48;
    stub[14] = 0xbc;
    *(uint64_t *)&stub[15] = stack_bottom - 8;

    /* pushq %rax */
    stub[23] = 0x50;

    /* jmp target_va */
    stub[24] = 0xe9;
    *(int32_t *)&stub[25] = target_va - (stub_va + 29);

    /* Round up to a multiple of 16 bytes. */
    return 32;
}

DEFINE_PER_CPU(struct stubs, stubs);
void lstar_enter(void);
void cstar_enter(void);

void subarch_percpu_traps_init(void)
{
    unsigned long stack_bottom = get_stack_bottom();
    unsigned long stub_va = this_cpu(stubs.addr);
    unsigned char *stub_page;
    unsigned int offset;

    /* IST_MAX IST pages + 1 syscall page + 1 guard page + primary stack. */
    BUILD_BUG_ON((IST_MAX + 2) * PAGE_SIZE + PRIMARY_STACK_SIZE > STACK_SIZE);

    stub_page = map_domain_page(_mfn(this_cpu(stubs.mfn)));

    /* Trampoline for SYSCALL entry from 64-bit mode. */
    wrmsrl(MSR_LSTAR, stub_va);
    offset = write_stub_trampoline(stub_page + (stub_va & ~PAGE_MASK),
                                   stub_va, stack_bottom,
                                   (unsigned long)lstar_enter);
    stub_va += offset;

    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL ||
         boot_cpu_data.x86_vendor == X86_VENDOR_CENTAUR )
    {
        /* SYSENTER entry. */
        wrmsrl(MSR_IA32_SYSENTER_ESP, stack_bottom);
        wrmsrl(MSR_IA32_SYSENTER_EIP, (unsigned long)sysenter_entry);
        wrmsr(MSR_IA32_SYSENTER_CS, __HYPERVISOR_CS, 0);
    }

    /* Trampoline for SYSCALL entry from compatibility mode. */
    wrmsrl(MSR_CSTAR, stub_va);
    offset += write_stub_trampoline(stub_page + (stub_va & ~PAGE_MASK),
                                    stub_va, stack_bottom,
                                    (unsigned long)cstar_enter);

    /* Don't consume more than half of the stub space here. */
    ASSERT(offset <= STUB_BUF_SIZE / 2);

    unmap_domain_page(stub_page);

    /* Common SYSCALL parameters. */
    wrmsr(MSR_STAR, 0, ((unsigned int)FLAT_RING3_CS32 << 16) | __HYPERVISOR_CS);
    wrmsr(MSR_SYSCALL_MASK, XEN_SYSCALL_MASK, 0U);
}

void init_int80_direct_trap(struct vcpu *v)
{
    struct trap_info *ti = &v->arch.pv_vcpu.trap_ctxt[0x80];
    struct trap_bounce *tb = &v->arch.pv_vcpu.int80_bounce;

    tb->cs    = ti->cs;
    tb->eip   = ti->address;

    if ( null_trap_bounce(v, tb) )
        tb->flags = 0;
    else
        tb->flags = TBF_EXCEPTION | (TI_GET_IF(ti) ? TBF_INTERRUPT : 0);
}

static long register_guest_callback(struct callback_register *reg)
{
    long ret = 0;
    struct vcpu *v = current;

    if ( !is_canonical_address(reg->address) )
        return -EINVAL;

    switch ( reg->type )
    {
    case CALLBACKTYPE_event:
        v->arch.pv_vcpu.event_callback_eip    = reg->address;
        break;

    case CALLBACKTYPE_failsafe:
        v->arch.pv_vcpu.failsafe_callback_eip = reg->address;
        if ( reg->flags & CALLBACKF_mask_events )
            set_bit(_VGCF_failsafe_disables_events,
                    &v->arch.vgc_flags);
        else
            clear_bit(_VGCF_failsafe_disables_events,
                      &v->arch.vgc_flags);
        break;

    case CALLBACKTYPE_syscall:
        v->arch.pv_vcpu.syscall_callback_eip  = reg->address;
        if ( reg->flags & CALLBACKF_mask_events )
            set_bit(_VGCF_syscall_disables_events,
                    &v->arch.vgc_flags);
        else
            clear_bit(_VGCF_syscall_disables_events,
                      &v->arch.vgc_flags);
        break;

    case CALLBACKTYPE_syscall32:
        v->arch.pv_vcpu.syscall32_callback_eip = reg->address;
        v->arch.pv_vcpu.syscall32_disables_events =
            !!(reg->flags & CALLBACKF_mask_events);
        break;

    case CALLBACKTYPE_sysenter:
        v->arch.pv_vcpu.sysenter_callback_eip = reg->address;
        v->arch.pv_vcpu.sysenter_disables_events =
            !!(reg->flags & CALLBACKF_mask_events);
        break;

    case CALLBACKTYPE_nmi:
        ret = register_guest_nmi_callback(reg->address);
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
    case CALLBACKTYPE_syscall:
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


long do_callback_op(int cmd, XEN_GUEST_HANDLE_PARAM(const_void) arg)
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

long do_set_callbacks(unsigned long event_address,
                      unsigned long failsafe_address,
                      unsigned long syscall_address)
{
    struct callback_register event = {
        .type = CALLBACKTYPE_event,
        .address = event_address,
    };
    struct callback_register failsafe = {
        .type = CALLBACKTYPE_failsafe,
        .address = failsafe_address,
    };
    struct callback_register syscall = {
        .type = CALLBACKTYPE_syscall,
        .address = syscall_address,
    };

    register_guest_callback(&event);
    register_guest_callback(&failsafe);
    register_guest_callback(&syscall);

    return 0;
}

static void hypercall_page_initialise_ring3_kernel(void *hypercall_page)
{
    char *p;
    int i;

    /* Fill in all the transfer points with template machine code. */
    for ( i = 0; i < (PAGE_SIZE / 32); i++ )
    {
        if ( i == __HYPERVISOR_iret )
            continue;

        p = (char *)(hypercall_page + (i * 32));
        *(u8  *)(p+ 0) = 0x51;    /* push %rcx */
        *(u16 *)(p+ 1) = 0x5341;  /* push %r11 */
        *(u8  *)(p+ 3) = 0xb8;    /* mov  $<i>,%eax */
        *(u32 *)(p+ 4) = i;
        *(u16 *)(p+ 8) = 0x050f;  /* syscall */
        *(u16 *)(p+10) = 0x5b41;  /* pop  %r11 */
        *(u8  *)(p+12) = 0x59;    /* pop  %rcx */
        *(u8  *)(p+13) = 0xc3;    /* ret */
    }

    /*
     * HYPERVISOR_iret is special because it doesn't return and expects a
     * special stack frame. Guests jump at this transfer point instead of
     * calling it.
     */
    p = (char *)(hypercall_page + (__HYPERVISOR_iret * 32));
    *(u8  *)(p+ 0) = 0x51;    /* push %rcx */
    *(u16 *)(p+ 1) = 0x5341;  /* push %r11 */
    *(u8  *)(p+ 3) = 0x50;    /* push %rax */
    *(u8  *)(p+ 4) = 0xb8;    /* mov  $__HYPERVISOR_iret,%eax */
    *(u32 *)(p+ 5) = __HYPERVISOR_iret;
    *(u16 *)(p+ 9) = 0x050f;  /* syscall */
}

#include "compat/traps.c"

void hypercall_page_initialise(struct domain *d, void *hypercall_page)
{
    memset(hypercall_page, 0xCC, PAGE_SIZE);
    if ( has_hvm_container_domain(d) )
        hvm_hypercall_page_initialise(d, hypercall_page);
    else if ( !is_pv_32bit_domain(d) )
        hypercall_page_initialise_ring3_kernel(hypercall_page);
    else
        hypercall_page_initialise_ring1_kernel(hypercall_page);
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
