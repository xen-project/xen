/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/******************************************************************************
 * arch/x86/traps.c
 * 
 * Modifications to Linux original are copyright (c) 2002-2004, K A Fraser
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 * Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/console.h>
#include <asm/regs.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/spinlock.h>
#include <xen/irq.h>
#include <xen/perfc.h>
#include <xen/softirq.h>
#include <asm/shadow.h>
#include <asm/domain_page.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/atomic.h>
#include <asm/desc.h>
#include <asm/debugreg.h>
#include <asm/smp.h>
#include <asm/flushtlb.h>
#include <asm/uaccess.h>
#include <asm/i387.h>
#include <asm/debugger.h>
#include <asm/msr.h>

/*
 * opt_nmi: one of 'ignore', 'dom0', or 'fatal'.
 *  fatal:  Xen prints diagnostic message and then hangs.
 *  dom0:   The NMI is virtualised to DOM0.
 *  ignore: The NMI error is cleared and ignored.
 */
#ifdef NDEBUG
char opt_nmi[10] = "dom0";
#else
char opt_nmi[10] = "fatal";
#endif
string_param("nmi", opt_nmi);

/* Master table, used by all CPUs on x86/64, and by CPU0 on x86/32.*/
idt_entry_t idt_table[IDT_ENTRIES] = { {0, 0}, };

asmlinkage void divide_error(void);
asmlinkage void debug(void);
asmlinkage void nmi(void);
asmlinkage void int3(void);
asmlinkage void overflow(void);
asmlinkage void bounds(void);
asmlinkage void invalid_op(void);
asmlinkage void device_not_available(void);
asmlinkage void coprocessor_segment_overrun(void);
asmlinkage void invalid_TSS(void);
asmlinkage void segment_not_present(void);
asmlinkage void stack_segment(void);
asmlinkage void general_protection(void);
asmlinkage void page_fault(void);
asmlinkage void coprocessor_error(void);
asmlinkage void simd_coprocessor_error(void);
asmlinkage void alignment_check(void);
asmlinkage void spurious_interrupt_bug(void);
asmlinkage void machine_check(void);

/*
 * This is called for faults at very unexpected times (e.g., when interrupts
 * are disabled). In such situations we can't do much that is safe. We try to
 * print out some tracing and then we just spin.
 */
asmlinkage void fatal_trap(int trapnr, struct xen_regs *regs)
{
    int cpu = smp_processor_id();
    unsigned long cr2;
    static char *trapstr[] = { 
        "divide error", "debug", "nmi", "bkpt", "overflow", "bounds", 
        "invalid operation", "device not available", "double fault", 
        "coprocessor segment", "invalid tss", "segment not found", 
        "stack error", "general protection fault", "page fault", 
        "spurious interrupt", "coprocessor error", "alignment check", 
        "machine check", "simd error"
    };

    show_registers(regs);

    if ( trapnr == TRAP_page_fault )
    {
        __asm__ __volatile__ ("mov %%cr2,%0" : "=r" (cr2) : );
        printk("Faulting linear address might be %0lx %lx\n", cr2, cr2);
    }

    printk("************************************\n");
    printk("CPU%d FATAL TRAP %d (%s), ERROR_CODE %04x%s.\n",
           cpu, trapnr, trapstr[trapnr], regs->error_code,
           (regs->eflags & X86_EFLAGS_IF) ? "" : ", IN INTERRUPT CONTEXT");
    printk("System shutting down -- need manual reset.\n");
    printk("************************************\n");

    /* Lock up the console to prevent spurious output from other CPUs. */
    console_force_lock();

    /* Wait for manual reset. */
    for ( ; ; )
        __asm__ __volatile__ ( "hlt" );
}

static inline int do_trap(int trapnr, char *str,
                          struct xen_regs *regs, 
                          int use_error_code)
{
    struct exec_domain *ed = current;
    struct trap_bounce *tb = &ed->arch.trap_bounce;
    trap_info_t *ti;
    unsigned long fixup;

    DEBUGGER_trap_entry(trapnr, regs);

    if ( !GUEST_MODE(regs) )
        goto xen_fault;

#ifndef NDEBUG
    if ( (ed->arch.traps[trapnr].address == 0) && (ed->domain->id == 0) )
        goto xen_fault;
#endif

    ti = current->arch.traps + trapnr;
    tb->flags = TBF_EXCEPTION;
    tb->cs    = ti->cs;
    tb->eip   = ti->address;
    if ( use_error_code )
    {
        tb->flags |= TBF_EXCEPTION_ERRCODE;
        tb->error_code = regs->error_code;
    }
    if ( TI_GET_IF(ti) )
        ed->vcpu_info->evtchn_upcall_mask = 1;
    return 0;

 xen_fault:

    if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
    {
        DPRINTK("Trap %d: %p -> %p\n", trapnr, regs->eip, fixup);
        regs->eip = fixup;
        return 0;
    }

    DEBUGGER_trap_fatal(trapnr, regs);

    show_registers(regs);
    panic("CPU%d FATAL TRAP: vector = %d (%s)\n"
          "[error_code=%04x]\n",
          smp_processor_id(), trapnr, str, regs->error_code);
    return 0;
}

#define DO_ERROR_NOCODE(trapnr, str, name) \
asmlinkage int do_##name(struct xen_regs *regs) \
{ \
    return do_trap(trapnr, str, regs, 0); \
}

#define DO_ERROR(trapnr, str, name) \
asmlinkage int do_##name(struct xen_regs *regs) \
{ \
    return do_trap(trapnr, str, regs, 1); \
}

DO_ERROR_NOCODE( 0, "divide error", divide_error)
DO_ERROR_NOCODE( 4, "overflow", overflow)
DO_ERROR_NOCODE( 5, "bounds", bounds)
DO_ERROR_NOCODE( 6, "invalid operand", invalid_op)
DO_ERROR_NOCODE( 9, "coprocessor segment overrun", coprocessor_segment_overrun)
DO_ERROR(10, "invalid TSS", invalid_TSS)
DO_ERROR(11, "segment not present", segment_not_present)
DO_ERROR(12, "stack segment", stack_segment)
DO_ERROR_NOCODE(16, "fpu error", coprocessor_error)
DO_ERROR(17, "alignment check", alignment_check)
DO_ERROR_NOCODE(19, "simd error", simd_coprocessor_error)

asmlinkage int do_int3(struct xen_regs *regs)
{
    struct exec_domain *ed = current;
    struct trap_bounce *tb = &ed->arch.trap_bounce;
    trap_info_t *ti;

    DEBUGGER_trap_entry(TRAP_int3, regs);

    if ( !GUEST_MODE(regs) )
    {
        DEBUGGER_trap_fatal(TRAP_int3, regs);
        show_registers(regs);
        panic("CPU%d FATAL TRAP: vector = 3 (Int3)\n", smp_processor_id());
    }

    ti = current->arch.traps + 3;
    tb->flags = TBF_EXCEPTION;
    tb->cs    = ti->cs;
    tb->eip   = ti->address;
    if ( TI_GET_IF(ti) )
        ed->vcpu_info->evtchn_upcall_mask = 1;

    return 0;
}

asmlinkage void do_machine_check(struct xen_regs *regs)
{
    fatal_trap(TRAP_machine_check, regs);
}

void propagate_page_fault(unsigned long addr, u16 error_code)
{
    trap_info_t *ti;
    struct exec_domain *ed = current;
    struct trap_bounce *tb = &ed->arch.trap_bounce;

    ti = ed->arch.traps + 14;
    tb->flags = TBF_EXCEPTION | TBF_EXCEPTION_ERRCODE | TBF_EXCEPTION_CR2;
    tb->cr2        = addr;
    tb->error_code = error_code;
    tb->cs         = ti->cs;
    tb->eip        = ti->address;
    if ( TI_GET_IF(ti) )
        ed->vcpu_info->evtchn_upcall_mask = 1;

    ed->arch.guest_cr2 = addr;
}

asmlinkage int do_page_fault(struct xen_regs *regs)
{
    unsigned long off, addr, fixup;
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;
    extern int map_ldt_shadow_page(unsigned int);
    int cpu = ed->processor;
    int ret;

    __asm__ __volatile__ ("mov %%cr2,%0" : "=r" (addr) : );

    DEBUGGER_trap_entry(TRAP_page_fault, regs);

    perfc_incrc(page_faults);

    if ( likely(VM_ASSIST(d, VMASST_TYPE_writable_pagetables)) )
    {
        LOCK_BIGLOCK(d);
        if ( unlikely(ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l1va) &&
             unlikely((addr >> L2_PAGETABLE_SHIFT) ==
                      ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l2_idx) )
        {
            ptwr_flush(PTWR_PT_ACTIVE);
            UNLOCK_BIGLOCK(d);
            return EXCRET_fault_fixed;
        }

        if ( (addr < PAGE_OFFSET) &&
             ((regs->error_code & 3) == 3) && /* write-protection fault */
             ptwr_do_page_fault(addr) )
        {
            if ( unlikely(d->arch.shadow_mode) )
                (void)shadow_fault(addr, regs->error_code);
            UNLOCK_BIGLOCK(d);
            return EXCRET_fault_fixed;
        }
        UNLOCK_BIGLOCK(d);
    }

    if ( unlikely(d->arch.shadow_mode) && 
         (addr < PAGE_OFFSET) && shadow_fault(addr, regs->error_code) )
        return EXCRET_fault_fixed;

    if ( unlikely(addr >= LDT_VIRT_START(ed)) && 
         (addr < (LDT_VIRT_START(ed) + (ed->arch.ldt_ents*LDT_ENTRY_SIZE))) )
    {
        /*
         * Copy a mapping from the guest's LDT, if it is valid. Otherwise we
         * send the fault up to the guest OS to be handled.
         */
        LOCK_BIGLOCK(d);
        off  = addr - LDT_VIRT_START(ed);
        addr = ed->arch.ldt_base + off;
        ret = map_ldt_shadow_page(off >> PAGE_SHIFT);
        UNLOCK_BIGLOCK(d);
        if ( likely(ret) )
            return EXCRET_fault_fixed; /* successfully copied the mapping */
    }

    if ( !GUEST_MODE(regs) )
        goto xen_fault;

#ifndef NDEBUG
    if ( (ed->arch.traps[TRAP_page_fault].address == 0) && (d->id == 0) )
        goto xen_fault;
#endif

    propagate_page_fault(addr, regs->error_code);
    return 0; 

 xen_fault:

    if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
    {
        perfc_incrc(copy_user_faults);
        if ( !d->arch.shadow_mode )
            DPRINTK("Page fault: %p -> %p\n", regs->eip, fixup);
        regs->eip = fixup;
        return 0;
    }

    DEBUGGER_trap_fatal(TRAP_page_fault, regs);

    show_registers(regs);
    show_page_walk(addr);
    panic("CPU%d FATAL PAGE FAULT\n"
          "[error_code=%04x]\n"
          "Faulting linear address might be %p\n",
          smp_processor_id(), regs->error_code, addr);
    return 0;
}

static int emulate_privileged_op(struct xen_regs *regs)
{
    extern long do_fpu_taskswitch(void);
    extern void *decode_reg(struct xen_regs *regs, u8 b);

    struct exec_domain *ed = current;
    unsigned long *reg, eip = regs->eip;
    u8 opcode;

    if ( get_user(opcode, (u8 *)eip) )
        goto page_fault;
    eip += 1;
    if ( (opcode & 0xff) != 0x0f )
        goto fail;

    if ( get_user(opcode, (u8 *)eip) )
        goto page_fault;
    eip += 1;

    switch ( opcode )
    {
    case 0x06: /* CLTS */
        (void)do_fpu_taskswitch();
        break;

    case 0x09: /* WBINVD */
        if ( !IS_CAPABLE_PHYSDEV(ed->domain) )
        {
            DPRINTK("Non-physdev domain attempted WBINVD.\n");
            goto fail;
        }
        wbinvd();
        break;

    case 0x20: /* MOV CR?,<reg> */
        if ( get_user(opcode, (u8 *)eip) )
            goto page_fault;
        eip += 1;
        if ( (opcode & 0xc0) != 0xc0 )
            goto fail;
        reg = decode_reg(regs, opcode & 7);
        switch ( (opcode >> 3) & 7 )
        {
        case 0: /* Read CR0 */
            *reg = 
                (read_cr0() & ~X86_CR0_TS) | 
                (test_bit(EDF_GUEST_STTS, &ed->ed_flags) ? X86_CR0_TS : 0);
            break;

        case 2: /* Read CR2 */
            *reg = ed->arch.guest_cr2;
            break;
            
        case 3: /* Read CR3 */
            *reg = pagetable_val(ed->arch.pagetable);
            break;

        default:
            goto fail;
        }
        break;

    case 0x22: /* MOV <reg>,CR? */
        if ( get_user(opcode, (u8 *)eip) )
            goto page_fault;
        eip += 1;
        if ( (opcode & 0xc0) != 0xc0 )
            goto fail;
        reg = decode_reg(regs, opcode & 7);
        switch ( (opcode >> 3) & 7 )
        {
        case 0: /* Write CR0 */
            if ( *reg & X86_CR0_TS ) /* XXX ignore all but TS bit */
                (void)do_fpu_taskswitch;
            break;

        case 2: /* Write CR2 */
            ed->arch.guest_cr2 = *reg;
            break;
            
        case 3: /* Write CR3 */
            LOCK_BIGLOCK(ed->domain);
            (void)new_guest_cr3(*reg);
            UNLOCK_BIGLOCK(ed->domain);
            break;

        default:
            goto fail;
        }
        break;

    case 0x30: /* WRMSR */
        if ( !IS_PRIV(ed->domain) )
        {
            DPRINTK("Non-priv domain attempted WRMSR.\n");
            goto fail;
        }
        wrmsr(regs->ecx, regs->eax, regs->edx);
        break;

    case 0x32: /* RDMSR */
        if ( !IS_PRIV(ed->domain) )
        {
            DPRINTK("Non-priv domain attempted RDMSR.\n");
            goto fail;
        }
        rdmsr(regs->ecx, regs->eax, regs->edx);
        break;

    default:
        goto fail;
    }

    regs->eip = eip;
    return EXCRET_fault_fixed;

 fail:
    return 0;

 page_fault:
    propagate_page_fault(eip, 0);
    return EXCRET_fault_fixed;
}

asmlinkage int do_general_protection(struct xen_regs *regs)
{
    struct exec_domain *ed = current;
    struct trap_bounce *tb = &ed->arch.trap_bounce;
    trap_info_t *ti;
    unsigned long fixup;

    DEBUGGER_trap_entry(TRAP_gp_fault, regs);

    if ( regs->error_code & 1 )
        goto hardware_gp;

    if ( !GUEST_MODE(regs) )
        goto gp_in_kernel;

    /*
     * Cunning trick to allow arbitrary "INT n" handling.
     * 
     * We set DPL == 0 on all vectors in the IDT. This prevents any INT <n>
     * instruction from trapping to the appropriate vector, when that might not
     * be expected by Xen or the guest OS. For example, that entry might be for
     * a fault handler (unlike traps, faults don't increment EIP), or might
     * expect an error code on the stack (which a software trap never
     * provides), or might be a hardware interrupt handler that doesn't like
     * being called spuriously.
     * 
     * Instead, a GPF occurs with the faulting IDT vector in the error code.
     * Bit 1 is set to indicate that an IDT entry caused the fault. Bit 0 is 
     * clear to indicate that it's a software fault, not hardware.
     * 
     * NOTE: Vectors 3 and 4 are dealt with from their own handler. This is
     * okay because they can only be triggered by an explicit DPL-checked
     * instruction. The DPL specified by the guest OS for these vectors is NOT
     * CHECKED!!
     */
    if ( (regs->error_code & 3) == 2 )
    {
        /* This fault must be due to <INT n> instruction. */
        ti = current->arch.traps + (regs->error_code>>3);
        if ( TI_GET_DPL(ti) >= (VM86_MODE(regs) ? 3 : (regs->cs & 3)) )
        {
            tb->flags = TBF_EXCEPTION;
            regs->eip += 2;
            goto finish_propagation;
        }
    }

    /* Emulate some simple privileged instructions when exec'ed in ring 1. */
    if ( (regs->error_code == 0) &&
         KERNEL_MODE(ed, regs) &&
         emulate_privileged_op(regs) )
        return 0;

#if defined(__i386__)
    if ( VM_ASSIST(ed->domain, VMASST_TYPE_4gb_segments) && 
         (regs->error_code == 0) && 
         gpf_emulate_4gb(regs) )
        return 0;
#endif

#ifndef NDEBUG
    if ( (ed->arch.traps[TRAP_gp_fault].address == 0) &&
         (ed->domain->id == 0) )
        goto gp_in_kernel;
#endif

    /* Pass on GPF as is. */
    ti = current->arch.traps + 13;
    tb->flags      = TBF_EXCEPTION | TBF_EXCEPTION_ERRCODE;
    tb->error_code = regs->error_code;
 finish_propagation:
    tb->cs         = ti->cs;
    tb->eip        = ti->address;
    if ( TI_GET_IF(ti) )
        ed->vcpu_info->evtchn_upcall_mask = 1;
    return 0;

 gp_in_kernel:

    if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
    {
        DPRINTK("GPF (%04x): %p -> %p\n",
                regs->error_code, regs->eip, fixup);
        regs->eip = fixup;
        return 0;
    }

    DEBUGGER_trap_fatal(TRAP_gp_fault, regs);

 hardware_gp:
    show_registers(regs);
    panic("CPU%d GENERAL PROTECTION FAULT\n[error_code=%04x]\n",
          smp_processor_id(), regs->error_code);
    return 0;
}

unsigned long nmi_softirq_reason;
static void nmi_softirq(void)
{
    if ( dom0 == NULL )
        return;

    if ( test_and_clear_bit(0, &nmi_softirq_reason) )
        send_guest_virq(dom0->exec_domain[0], VIRQ_PARITY_ERR);

    if ( test_and_clear_bit(1, &nmi_softirq_reason) )
        send_guest_virq(dom0->exec_domain[0], VIRQ_IO_ERR);
}

asmlinkage void mem_parity_error(struct xen_regs *regs)
{
    /* Clear and disable the parity-error line. */
    outb((inb(0x61)&15)|4,0x61);

    switch ( opt_nmi[0] )
    {
    case 'd': /* 'dom0' */
        set_bit(0, &nmi_softirq_reason);
        raise_softirq(NMI_SOFTIRQ);
    case 'i': /* 'ignore' */
        break;
    default:  /* 'fatal' */
        console_force_unlock();
        printk("\n\nNMI - MEMORY ERROR\n");
        fatal_trap(TRAP_nmi, regs);
    }
}

asmlinkage void io_check_error(struct xen_regs *regs)
{
    /* Clear and disable the I/O-error line. */
    outb((inb(0x61)&15)|8,0x61);

    switch ( opt_nmi[0] )
    {
    case 'd': /* 'dom0' */
        set_bit(0, &nmi_softirq_reason);
        raise_softirq(NMI_SOFTIRQ);
    case 'i': /* 'ignore' */
        break;
    default:  /* 'fatal' */
        console_force_unlock();
        printk("\n\nNMI - I/O ERROR\n");
        fatal_trap(TRAP_nmi, regs);
    }
}

static void unknown_nmi_error(unsigned char reason)
{
    printk("Uhhuh. NMI received for unknown reason %02x.\n", reason);
    printk("Dazed and confused, but trying to continue\n");
    printk("Do you have a strange power saving mode enabled?\n");
}

asmlinkage void do_nmi(struct xen_regs *regs, unsigned long reason)
{
    ++nmi_count(smp_processor_id());

    if ( nmi_watchdog )
        nmi_watchdog_tick(regs);

    if ( reason & 0x80 )
        mem_parity_error(regs);
    else if ( reason & 0x40 )
        io_check_error(regs);
    else if ( !nmi_watchdog )
        unknown_nmi_error((unsigned char)(reason&0xff));
}

asmlinkage int math_state_restore(struct xen_regs *regs)
{
    /* Prevent recursion. */
    clts();

    if ( !test_bit(EDF_USEDFPU, &current->ed_flags) )
    {
        if ( test_bit(EDF_DONEFPUINIT, &current->ed_flags) )
            restore_fpu(current);
        else
            init_fpu();
        set_bit(EDF_USEDFPU, &current->ed_flags); /* so we fnsave on switch_to() */
    }

    if ( test_and_clear_bit(EDF_GUEST_STTS, &current->ed_flags) )
    {
        struct trap_bounce *tb = &current->arch.trap_bounce;
        tb->flags      = TBF_EXCEPTION;
        tb->cs         = current->arch.traps[7].cs;
        tb->eip        = current->arch.traps[7].address;
    }

    return EXCRET_fault_fixed;
}

asmlinkage int do_debug(struct xen_regs *regs)
{
    unsigned long condition;
    struct exec_domain *d = current;
    struct trap_bounce *tb = &d->arch.trap_bounce;

    DEBUGGER_trap_entry(TRAP_debug, regs);

    __asm__ __volatile__("mov %%db6,%0" : "=r" (condition));

    /* Mask out spurious debug traps due to lazy DR7 setting */
    if ( (condition & (DR_TRAP0|DR_TRAP1|DR_TRAP2|DR_TRAP3)) &&
         (d->arch.debugreg[7] == 0) )
    {
        __asm__("mov %0,%%db7" : : "r" (0UL));
        goto out;
    }

    if ( !GUEST_MODE(regs) )
    {
        /* Clear TF just for absolute sanity. */
        regs->eflags &= ~EF_TF;
        /*
         * We ignore watchpoints when they trigger within Xen. This may happen
         * when a buffer is passed to us which previously had a watchpoint set
         * on it. No need to bump EIP; the only faulting trap is an instruction
         * breakpoint, which can't happen to us.
         */
        goto out;
    }

    /* Save debug status register where guest OS can peek at it */
    d->arch.debugreg[6] = condition;

    tb->flags = TBF_EXCEPTION;
    tb->cs    = d->arch.traps[1].cs;
    tb->eip   = d->arch.traps[1].address;

 out:
    return EXCRET_not_a_fault;
}

asmlinkage int do_spurious_interrupt_bug(struct xen_regs *regs)
{
    return EXCRET_not_a_fault;
}

void set_intr_gate(unsigned int n, void *addr)
{
    _set_gate(idt_table+n,14,0,addr);
}

void set_system_gate(unsigned int n, void *addr)
{
    _set_gate(idt_table+n,14,3,addr);
}

void set_task_gate(unsigned int n, unsigned int sel)
{
    idt_table[n].a = sel << 16;
    idt_table[n].b = 0x8500;
}

void set_tss_desc(unsigned int n, void *addr)
{
    _set_tssldt_desc(
        gdt_table + __TSS(n),
        (unsigned long)addr,
        offsetof(struct tss_struct, __cacheline_filler) - 1,
        9);
}

void __init trap_init(void)
{
    extern void percpu_traps_init(void);
    extern void cpu_init(void);

    /*
     * Note that interrupt gates are always used, rather than trap gates. We 
     * must have interrupts disabled until DS/ES/FS/GS are saved because the 
     * first activation must have the "bad" value(s) for these registers and 
     * we may lose them if another activation is installed before they are 
     * saved. The page-fault handler also needs interrupts disabled until %cr2 
     * has been read and saved on the stack.
     */
    set_intr_gate(TRAP_divide_error,&divide_error);
    set_intr_gate(TRAP_debug,&debug);
    set_intr_gate(TRAP_nmi,&nmi);
    set_system_gate(TRAP_int3,&int3);         /* usable from all privileges */
    set_system_gate(TRAP_overflow,&overflow); /* usable from all privileges */
    set_intr_gate(TRAP_bounds,&bounds);
    set_intr_gate(TRAP_invalid_op,&invalid_op);
    set_intr_gate(TRAP_no_device,&device_not_available);
    set_intr_gate(TRAP_copro_seg,&coprocessor_segment_overrun);
    set_intr_gate(TRAP_invalid_tss,&invalid_TSS);
    set_intr_gate(TRAP_no_segment,&segment_not_present);
    set_intr_gate(TRAP_stack_error,&stack_segment);
    set_intr_gate(TRAP_gp_fault,&general_protection);
    set_intr_gate(TRAP_page_fault,&page_fault);
    set_intr_gate(TRAP_spurious_int,&spurious_interrupt_bug);
    set_intr_gate(TRAP_copro_error,&coprocessor_error);
    set_intr_gate(TRAP_alignment_check,&alignment_check);
    set_intr_gate(TRAP_machine_check,&machine_check);
    set_intr_gate(TRAP_simd_error,&simd_coprocessor_error);

    percpu_traps_init();

    cpu_init();

    open_softirq(NMI_SOFTIRQ, nmi_softirq);
}


long do_set_trap_table(trap_info_t *traps)
{
    trap_info_t cur;
    trap_info_t *dst = current->arch.traps;

    LOCK_BIGLOCK(current->domain);

    for ( ; ; )
    {
        if ( hypercall_preempt_check() )
        {
            UNLOCK_BIGLOCK(current->domain);
            return hypercall1_create_continuation(
                __HYPERVISOR_set_trap_table, traps);
        }

        if ( copy_from_user(&cur, traps, sizeof(cur)) ) return -EFAULT;

        if ( cur.address == 0 ) break;

        if ( !VALID_CODESEL(cur.cs) ) return -EPERM;

        memcpy(dst+cur.vector, &cur, sizeof(cur));
        traps++;
    }

    UNLOCK_BIGLOCK(current->domain);

    return 0;
}


long do_set_callbacks(unsigned long event_selector,
                      unsigned long event_address,
                      unsigned long failsafe_selector,
                      unsigned long failsafe_address)
{
    struct exec_domain *d = current;

    if ( !VALID_CODESEL(event_selector) || !VALID_CODESEL(failsafe_selector) )
        return -EPERM;

    d->arch.event_selector    = event_selector;
    d->arch.event_address     = event_address;
    d->arch.failsafe_selector = failsafe_selector;
    d->arch.failsafe_address  = failsafe_address;

    return 0;
}


long do_fpu_taskswitch(void)
{
    set_bit(EDF_GUEST_STTS, &current->ed_flags);
    stts();
    return 0;
}


#if defined(__i386__)
#define DB_VALID_ADDR(_a) \
    ((_a) <= (PAGE_OFFSET - 4))
#elif defined(__x86_64__)
#define DB_VALID_ADDR(_a) \
    ((_a) >= HYPERVISOR_VIRT_END) || ((_a) <= (HYPERVISOR_VIRT_START-8))
#endif
long set_debugreg(struct exec_domain *p, int reg, unsigned long value)
{
    int i;

    switch ( reg )
    {
    case 0: 
        if ( !DB_VALID_ADDR(value) ) return -EPERM;
        if ( p == current ) 
            __asm__ ( "mov %0, %%db0" : : "r" (value) );
        break;
    case 1: 
        if ( !DB_VALID_ADDR(value) ) return -EPERM;
        if ( p == current ) 
            __asm__ ( "mov %0, %%db1" : : "r" (value) );
        break;
    case 2: 
        if ( !DB_VALID_ADDR(value) ) return -EPERM;
        if ( p == current ) 
            __asm__ ( "mov %0, %%db2" : : "r" (value) );
        break;
    case 3:
        if ( !DB_VALID_ADDR(value) ) return -EPERM;
        if ( p == current ) 
            __asm__ ( "mov %0, %%db3" : : "r" (value) );
        break;
    case 6:
        /*
         * DR6: Bits 4-11,16-31 reserved (set to 1).
         *      Bit 12 reserved (set to 0).
         */
        value &= 0xffffefff; /* reserved bits => 0 */
        value |= 0xffff0ff0; /* reserved bits => 1 */
        if ( p == current ) 
            __asm__ ( "mov %0, %%db6" : : "r" (value) );
        break;
    case 7:
        /*
         * DR7: Bit 10 reserved (set to 1).
         *      Bits 11-12,14-15 reserved (set to 0).
         * Privileged bits:
         *      GD (bit 13): must be 0.
         *      R/Wn (bits 16-17,20-21,24-25,28-29): mustn't be 10.
         *      LENn (bits 18-19,22-23,26-27,30-31): mustn't be 10.
         */
        /* DR7 == 0 => debugging disabled for this domain. */
        if ( value != 0 )
        {
            value &= 0xffff27ff; /* reserved bits => 0 */
            value |= 0x00000400; /* reserved bits => 1 */
            if ( (value & (1<<13)) != 0 ) return -EPERM;
            for ( i = 0; i < 16; i += 2 )
                if ( ((value >> (i+16)) & 3) == 2 ) return -EPERM;
        }
        if ( p == current ) 
            __asm__ ( "mov %0, %%db7" : : "r" (value) );
        break;
    default:
        return -EINVAL;
    }

    p->arch.debugreg[reg] = value;
    return 0;
}

long do_set_debugreg(int reg, unsigned long value)
{
    return set_debugreg(current, reg, value);
}

unsigned long do_get_debugreg(int reg)
{
    if ( (reg < 0) || (reg > 7) ) return -EINVAL;
    return current->arch.debugreg[reg];
}
