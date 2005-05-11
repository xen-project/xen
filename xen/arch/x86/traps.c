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
#include <asm/x86_emulate.h>

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
idt_entry_t idt_table[IDT_ENTRIES];

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
asmlinkage void fatal_trap(int trapnr, struct cpu_user_regs *regs)
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

    watchdog_on = 0;

    show_registers(regs);

    if ( trapnr == TRAP_page_fault )
    {
        __asm__ __volatile__ ("mov %%cr2,%0" : "=r" (cr2) : );
        printk("Faulting linear address: %p\n", _p(cr2));
        show_page_walk(cr2);
    }

    printk("************************************\n");
    printk("CPU%d FATAL TRAP %d (%s), ERROR_CODE %04x%s.\n",
           cpu, trapnr, trapstr[trapnr], regs->error_code,
           (regs->eflags & X86_EFLAGS_IF) ? "" : ", IN INTERRUPT CONTEXT");
    printk("System shutting down -- need manual reset.\n");
    printk("************************************\n");

    (void)debugger_trap_fatal(trapnr, regs);

    /* Lock up the console to prevent spurious output from other CPUs. */
    console_force_lock();

    /* Wait for manual reset. */
    for ( ; ; )
        __asm__ __volatile__ ( "hlt" );
}

static inline int do_trap(int trapnr, char *str,
                          struct cpu_user_regs *regs, 
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
    if ( (ed->arch.guest_context.trap_ctxt[trapnr].address == 0) &&
         (ed->domain->id == 0) )
        goto xen_fault;
#endif

    ti = &current->arch.guest_context.trap_ctxt[trapnr];
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
        DPRINTK("Trap %d: %p -> %p\n", trapnr, _p(regs->eip), _p(fixup));
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
asmlinkage int do_##name(struct cpu_user_regs *regs) \
{ \
    return do_trap(trapnr, str, regs, 0); \
}

#define DO_ERROR(trapnr, str, name) \
asmlinkage int do_##name(struct cpu_user_regs *regs) \
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

asmlinkage int do_int3(struct cpu_user_regs *regs)
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

    ti = &current->arch.guest_context.trap_ctxt[TRAP_int3];
    tb->flags = TBF_EXCEPTION;
    tb->cs    = ti->cs;
    tb->eip   = ti->address;
    if ( TI_GET_IF(ti) )
        ed->vcpu_info->evtchn_upcall_mask = 1;

    return 0;
}

asmlinkage void do_machine_check(struct cpu_user_regs *regs)
{
    fatal_trap(TRAP_machine_check, regs);
}

void propagate_page_fault(unsigned long addr, u16 error_code)
{
    trap_info_t *ti;
    struct exec_domain *ed = current;
    struct trap_bounce *tb = &ed->arch.trap_bounce;

    ti = &ed->arch.guest_context.trap_ctxt[TRAP_page_fault];
    tb->flags = TBF_EXCEPTION | TBF_EXCEPTION_ERRCODE | TBF_EXCEPTION_CR2;
    tb->cr2        = addr;
    tb->error_code = error_code;
    tb->cs         = ti->cs;
    tb->eip        = ti->address;
    if ( TI_GET_IF(ti) )
        ed->vcpu_info->evtchn_upcall_mask = 1;

    ed->arch.guest_cr2 = addr;
}

asmlinkage int do_page_fault(struct cpu_user_regs *regs)
{
    unsigned long off, addr, fixup;
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;
    int ret;

    __asm__ __volatile__ ("mov %%cr2,%0" : "=r" (addr) : );

    DEBUGGER_trap_entry(TRAP_page_fault, regs);

    perfc_incrc(page_faults);

    if ( likely(VM_ASSIST(d, VMASST_TYPE_writable_pagetables) &&
                !shadow_mode_enabled(d)) )
    {
        LOCK_BIGLOCK(d);
        if ( unlikely(d->arch.ptwr[PTWR_PT_ACTIVE].l1va) &&
             unlikely((addr >> L2_PAGETABLE_SHIFT) ==
                      d->arch.ptwr[PTWR_PT_ACTIVE].l2_idx) )
        {
            ptwr_flush(d, PTWR_PT_ACTIVE);
            UNLOCK_BIGLOCK(d);
            return EXCRET_fault_fixed;
        }

        if ( (addr < HYPERVISOR_VIRT_START) &&
             ((regs->error_code & 3) == 3) && /* write-protection fault */
             ptwr_do_page_fault(d, addr) )
        {
            UNLOCK_BIGLOCK(d);
            return EXCRET_fault_fixed;
        }
        UNLOCK_BIGLOCK(d);
    }

    if ( unlikely(shadow_mode_enabled(d)) &&
         ((addr < HYPERVISOR_VIRT_START) ||
          (shadow_mode_external(d) && GUEST_CONTEXT(ed, regs))) &&
         shadow_fault(addr, regs) )
    {
        return EXCRET_fault_fixed;
    }

    if ( unlikely(addr >= LDT_VIRT_START(ed)) && 
         (addr < (LDT_VIRT_START(ed) + 
                  (ed->arch.guest_context.ldt_ents*LDT_ENTRY_SIZE))) )
    {
        /*
         * Copy a mapping from the guest's LDT, if it is valid. Otherwise we
         * send the fault up to the guest OS to be handled.
         */
        extern int map_ldt_shadow_page(unsigned int);
        LOCK_BIGLOCK(d);
        off  = addr - LDT_VIRT_START(ed);
        addr = ed->arch.guest_context.ldt_base + off;
        ret = map_ldt_shadow_page(off >> PAGE_SHIFT);
        UNLOCK_BIGLOCK(d);
        if ( likely(ret) )
            return EXCRET_fault_fixed; /* successfully copied the mapping */
    }

    if ( !GUEST_MODE(regs) )
        goto xen_fault;

#ifndef NDEBUG
    if ( (ed->arch.guest_context.trap_ctxt[TRAP_page_fault].address == 0) &&
         (d->id == 0) )
        goto xen_fault;
#endif

    propagate_page_fault(addr, regs->error_code);
    return 0; 

 xen_fault:

    if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
    {
        perfc_incrc(copy_user_faults);
        if ( !shadow_mode_enabled(d) )
            DPRINTK("Page fault: %p -> %p\n", _p(regs->eip), _p(fixup));
        regs->eip = fixup;
        return 0;
    }

    DEBUGGER_trap_fatal(TRAP_page_fault, regs);

    show_registers(regs);
    show_page_walk(addr);
    panic("CPU%d FATAL PAGE FAULT\n"
          "[error_code=%04x]\n"
          "Faulting linear address: %p\n",
          smp_processor_id(), regs->error_code, addr);
    return 0;
}

long do_fpu_taskswitch(int set)
{
    struct exec_domain *ed = current;

    if ( set )
    {
        set_bit(EDF_GUEST_STTS, &ed->flags);
        stts();
    }
    else
    {
        clear_bit(EDF_GUEST_STTS, &ed->flags);
        if ( test_bit(EDF_USEDFPU, &ed->flags) )
            clts();
    }

    return 0;
}

/* Has the guest requested sufficient permission for this I/O access? */
static inline int guest_io_okay(
    unsigned int port, unsigned int bytes,
    struct exec_domain *ed, struct cpu_user_regs *regs)
{
    u16 x;
#if defined(__x86_64__)
    /* If in user mode, switch to kernel mode just to read I/O bitmap. */
    extern void toggle_guest_mode(struct exec_domain *);
    int user_mode = !(ed->arch.flags & TF_kernel_mode);
#define TOGGLE_MODE() if ( user_mode ) toggle_guest_mode(ed)
#elif defined(__i386__)
#define TOGGLE_MODE() ((void)0)
#endif

    if ( ed->arch.iopl >= (KERNEL_MODE(ed, regs) ? 1 : 3) )
        return 1;

    if ( ed->arch.iobmp_limit > (port + bytes) )
    {
        TOGGLE_MODE();
        __get_user(x, (u16 *)(ed->arch.iobmp+(port>>3)));
        TOGGLE_MODE();
        if ( (x & (((1<<bytes)-1) << (port&7))) == 0 )
            return 1;
    }

    return 0;
}

/* Has the administrator granted sufficient permission for this I/O access? */
static inline int admin_io_okay(
    unsigned int port, unsigned int bytes,
    struct exec_domain *ed, struct cpu_user_regs *regs)
{
    struct domain *d = ed->domain;
    u16 x;

    if ( d->arch.iobmp_mask != NULL )
    {
        x = *(u16 *)(d->arch.iobmp_mask + (port >> 3));
        if ( (x & (((1<<bytes)-1) << (port&7))) == 0 )
            return 1;
    }

    return 0;
}

/* Check admin limits. Silently fail the access if it is disallowed. */
#define inb_user(_p, _d, _r) (admin_io_okay(_p, 1, _d, _r) ? inb(_p) : ~0)
#define inw_user(_p, _d, _r) (admin_io_okay(_p, 2, _d, _r) ? inw(_p) : ~0)
#define inl_user(_p, _d, _r) (admin_io_okay(_p, 4, _d, _r) ? inl(_p) : ~0)
#define outb_user(_v, _p, _d, _r) \
    (admin_io_okay(_p, 1, _d, _r) ? outb(_v, _p) : ((void)0))
#define outw_user(_v, _p, _d, _r) \
    (admin_io_okay(_p, 2, _d, _r) ? outw(_v, _p) : ((void)0))
#define outl_user(_v, _p, _d, _r) \
    (admin_io_okay(_p, 4, _d, _r) ? outl(_v, _p) : ((void)0))

#define insn_fetch(_type, _size, _ptr)          \
({  unsigned long _x;                           \
    if ( get_user(_x, (_type *)eip) )           \
        goto read_fault;                        \
    eip += _size; (_type)_x; })

static int emulate_privileged_op(struct cpu_user_regs *regs)
{
    struct exec_domain *ed = current;
    unsigned long *reg, eip = regs->eip;
    u8 opcode, modrm_reg = 0, rep_prefix = 0;
    unsigned int port, i, op_bytes = 4, data;

    /* Legacy prefixes. */
    for ( i = 0; i < 8; i++ )
    {
        switch ( opcode = insn_fetch(u8, 1, eip) )
        {
        case 0x66: /* operand-size override */
            op_bytes ^= 6; /* switch between 2/4 bytes */
            break;
        case 0x67: /* address-size override */
        case 0x2e: /* CS override */
        case 0x3e: /* DS override */
        case 0x26: /* ES override */
        case 0x64: /* FS override */
        case 0x65: /* GS override */
        case 0x36: /* SS override */
        case 0xf0: /* LOCK */
        case 0xf2: /* REPNE/REPNZ */
            break;
        case 0xf3: /* REP/REPE/REPZ */
            rep_prefix = 1;
            break;
        default:
            goto done_prefixes;
        }
    }
 done_prefixes:

#ifdef __x86_64__
    /* REX prefix. */
    if ( (opcode & 0xf0) == 0x40 )
    {
        modrm_reg = (opcode & 4) << 1;  /* REX.R */
        /* REX.W, REX.B and REX.X do not need to be decoded. */
        opcode = insn_fetch(u8, 1, eip);
    }
#endif
    
    /* Input/Output String instructions. */
    if ( (opcode >= 0x6c) && (opcode <= 0x6f) )
    {
        if ( rep_prefix && (regs->ecx == 0) )
            goto done;

    continue_io_string:
        switch ( opcode )
        {
        case 0x6c: /* INSB */
            op_bytes = 1;
        case 0x6d: /* INSW/INSL */
            if ( !guest_io_okay((u16)regs->edx, op_bytes, ed, regs) )
                goto fail;
            switch ( op_bytes )
            {
            case 1:
                data = (u8)inb_user((u16)regs->edx, ed, regs);
                if ( put_user((u8)data, (u8 *)regs->edi) )
                    goto write_fault;
                break;
            case 2:
                data = (u16)inw_user((u16)regs->edx, ed, regs);
                if ( put_user((u16)data, (u16 *)regs->edi) )
                    goto write_fault;
                break;
            case 4:
                data = (u32)inl_user((u16)regs->edx, ed, regs);
                if ( put_user((u32)data, (u32 *)regs->edi) )
                    goto write_fault;
                break;
            }
            regs->edi += (regs->eflags & EF_DF) ? -op_bytes : op_bytes;
            break;

        case 0x6e: /* OUTSB */
            op_bytes = 1;
        case 0x6f: /* OUTSW/OUTSL */
            if ( !guest_io_okay((u16)regs->edx, op_bytes, ed, regs) )
                goto fail;
            switch ( op_bytes )
            {
            case 1:
                if ( get_user(data, (u8 *)regs->esi) )
                    goto read_fault;
                outb_user((u8)data, (u16)regs->edx, ed, regs);
                break;
            case 2:
                if ( get_user(data, (u16 *)regs->esi) )
                    goto read_fault;
                outw_user((u16)data, (u16)regs->edx, ed, regs);
                break;
            case 4:
                if ( get_user(data, (u32 *)regs->esi) )
                    goto read_fault;
                outl_user((u32)data, (u16)regs->edx, ed, regs);
                break;
            }
            regs->esi += (regs->eflags & EF_DF) ? -op_bytes : op_bytes;
            break;
        }

        if ( rep_prefix && (--regs->ecx != 0) )
        {
            if ( !hypercall_preempt_check() )
                goto continue_io_string;
            eip = regs->eip;
        }

        goto done;
    }

    /* I/O Port and Interrupt Flag instructions. */
    switch ( opcode )
    {
    case 0xe4: /* IN imm8,%al */
        op_bytes = 1;
    case 0xe5: /* IN imm8,%eax */
        port = insn_fetch(u8, 1, eip);
    exec_in:
        if ( !guest_io_okay(port, op_bytes, ed, regs) )
            goto fail;
        switch ( op_bytes )
        {
        case 1:
            regs->eax &= ~0xffUL;
            regs->eax |= (u8)inb_user(port, ed, regs);
            break;
        case 2:
            regs->eax &= ~0xffffUL;
            regs->eax |= (u16)inw_user(port, ed, regs);
            break;
        case 4:
            regs->eax = (u32)inl_user(port, ed, regs);
            break;
        }
        goto done;

    case 0xec: /* IN %dx,%al */
        op_bytes = 1;
    case 0xed: /* IN %dx,%eax */
        port = (u16)regs->edx;
        goto exec_in;

    case 0xe6: /* OUT %al,imm8 */
        op_bytes = 1;
    case 0xe7: /* OUT %eax,imm8 */
        port = insn_fetch(u8, 1, eip);
    exec_out:
        if ( !guest_io_okay(port, op_bytes, ed, regs) )
            goto fail;
        switch ( op_bytes )
        {
        case 1:
            outb_user((u8)regs->eax, port, ed, regs);
            break;
        case 2:
            outw_user((u16)regs->eax, port, ed, regs);
            break;
        case 4:
            outl_user((u32)regs->eax, port, ed, regs);
            break;
        }
        goto done;

    case 0xee: /* OUT %al,%dx */
        op_bytes = 1;
    case 0xef: /* OUT %eax,%dx */
        port = (u16)regs->edx;
        goto exec_out;

    case 0xfa: /* CLI */
    case 0xfb: /* STI */
        if ( ed->arch.iopl < (KERNEL_MODE(ed, regs) ? 1 : 3) )
            goto fail;
        /*
         * This is just too dangerous to allow, in my opinion. Consider if the
         * caller then tries to reenable interrupts using POPF: we can't trap
         * that and we'll end up with hard-to-debug lockups. Fast & loose will
         * do for us. :-)
         */
        /*ed->vcpu_info->evtchn_upcall_mask = (opcode == 0xfa);*/
        goto done;

    case 0x0f: /* Two-byte opcode */
        break;

    default:
        goto fail;
    }

    /* Remaining instructions only emulated from guest kernel. */
    if ( !KERNEL_MODE(ed, regs) )
        goto fail;

    /* Privileged (ring 0) instructions. */
    opcode = insn_fetch(u8, 1, eip);
    switch ( opcode )
    {
    case 0x06: /* CLTS */
        (void)do_fpu_taskswitch(0);
        break;

    case 0x09: /* WBINVD */
        /* Ignore the instruction if unprivileged. */
        if ( !IS_CAPABLE_PHYSDEV(ed->domain) )
            DPRINTK("Non-physdev domain attempted WBINVD.\n");
        else
            wbinvd();
        break;

    case 0x20: /* MOV CR?,<reg> */
        opcode = insn_fetch(u8, 1, eip);
        if ( (opcode & 0xc0) != 0xc0 )
            goto fail;
        modrm_reg |= opcode & 7;
        reg = decode_register(modrm_reg, regs, 0);
        switch ( (opcode >> 3) & 7 )
        {
        case 0: /* Read CR0 */
            *reg = 
                (read_cr0() & ~X86_CR0_TS) | 
                (test_bit(EDF_GUEST_STTS, &ed->flags) ? X86_CR0_TS : 0);
            break;

        case 2: /* Read CR2 */
            *reg = ed->arch.guest_cr2;
            break;
            
        case 3: /* Read CR3 */
            *reg = pagetable_val(ed->arch.guest_table);
            break;

        default:
            goto fail;
        }
        break;

    case 0x22: /* MOV <reg>,CR? */
        opcode = insn_fetch(u8, 1, eip);
        if ( (opcode & 0xc0) != 0xc0 )
            goto fail;
        modrm_reg |= opcode & 7;
        reg = decode_register(modrm_reg, regs, 0);
        switch ( (opcode >> 3) & 7 )
        {
        case 0: /* Write CR0 */
            (void)do_fpu_taskswitch(!!(*reg & X86_CR0_TS));
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
        /* Ignore the instruction if unprivileged. */
        if ( !IS_PRIV(ed->domain) )
            DPRINTK("Non-priv domain attempted WRMSR(%p,%08lx,%08lx).\n",
                    _p(regs->ecx), (long)regs->eax, (long)regs->edx);
        else if ( wrmsr_user(regs->ecx, regs->eax, regs->edx) )
            goto fail;
        break;

    case 0x32: /* RDMSR */
        if ( !IS_PRIV(ed->domain) )
            DPRINTK("Non-priv domain attempted RDMSR(%p,%08lx,%08lx).\n",
                    _p(regs->ecx), (long)regs->eax, (long)regs->edx);
        /* Everyone can read the MSR space. */
        if ( rdmsr_user(regs->ecx, regs->eax, regs->edx) )
            goto fail;
        break;

    default:
        goto fail;
    }

 done:
    regs->eip = eip;
    return EXCRET_fault_fixed;

 fail:
    return 0;

 read_fault:
    propagate_page_fault(eip, 4); /* user mode, read fault */
    return EXCRET_fault_fixed;

 write_fault:
    propagate_page_fault(eip, 6); /* user mode, write fault */
    return EXCRET_fault_fixed;
}

asmlinkage int do_general_protection(struct cpu_user_regs *regs)
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
        ti = &current->arch.guest_context.trap_ctxt[regs->error_code>>3];
        if ( PERMIT_SOFTINT(TI_GET_DPL(ti), ed, regs) )
        {
            tb->flags = TBF_EXCEPTION;
            regs->eip += 2;
            goto finish_propagation;
        }
    }

    /* Emulate some simple privileged and I/O instructions. */
    if ( (regs->error_code == 0) &&
         emulate_privileged_op(regs) )
        return 0;

#if defined(__i386__)
    if ( VM_ASSIST(ed->domain, VMASST_TYPE_4gb_segments) && 
         (regs->error_code == 0) && 
         gpf_emulate_4gb(regs) )
        return 0;
#endif

#ifndef NDEBUG
    if ( (ed->arch.guest_context.trap_ctxt[TRAP_gp_fault].address == 0) &&
         (ed->domain->id == 0) )
        goto gp_in_kernel;
#endif

    /* Pass on GPF as is. */
    ti = &current->arch.guest_context.trap_ctxt[TRAP_gp_fault];
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
                regs->error_code, _p(regs->eip), _p(fixup));
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

asmlinkage void mem_parity_error(struct cpu_user_regs *regs)
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

asmlinkage void io_check_error(struct cpu_user_regs *regs)
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

asmlinkage void do_nmi(struct cpu_user_regs *regs, unsigned long reason)
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

asmlinkage int math_state_restore(struct cpu_user_regs *regs)
{
    /* Prevent recursion. */
    clts();

    setup_fpu(current);

    if ( test_and_clear_bit(EDF_GUEST_STTS, &current->flags) )
    {
        struct trap_bounce *tb = &current->arch.trap_bounce;
        tb->flags = TBF_EXCEPTION;
        tb->cs    = current->arch.guest_context.trap_ctxt[7].cs;
        tb->eip   = current->arch.guest_context.trap_ctxt[7].address;
    }

    return EXCRET_fault_fixed;
}

asmlinkage int do_debug(struct cpu_user_regs *regs)
{
    unsigned long condition;
    struct exec_domain *ed = current;
    struct trap_bounce *tb = &ed->arch.trap_bounce;

    __asm__ __volatile__("mov %%db6,%0" : "=r" (condition));

    /* Mask out spurious debug traps due to lazy DR7 setting */
    if ( (condition & (DR_TRAP0|DR_TRAP1|DR_TRAP2|DR_TRAP3)) &&
         (ed->arch.guest_context.debugreg[7] == 0) )
    {
        __asm__("mov %0,%%db7" : : "r" (0UL));
        goto out;
    }

    DEBUGGER_trap_entry(TRAP_debug, regs);

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
    ed->arch.guest_context.debugreg[6] = condition;

    tb->flags = TBF_EXCEPTION;
    tb->cs    = ed->arch.guest_context.trap_ctxt[TRAP_debug].cs;
    tb->eip   = ed->arch.guest_context.trap_ctxt[TRAP_debug].address;

 out:
    return EXCRET_not_a_fault;
}

asmlinkage int do_spurious_interrupt_bug(struct cpu_user_regs *regs)
{
    return EXCRET_not_a_fault;
}

void set_intr_gate(unsigned int n, void *addr)
{
#ifdef __i386__
    int i;
    /* Keep secondary tables in sync with IRQ updates. */
    for ( i = 1; i < NR_CPUS; i++ )
        if ( idt_tables[i] != NULL )
            _set_gate(&idt_tables[i][n], 14, 0, addr);
#endif
    _set_gate(&idt_table[n], 14, 0, addr);
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
    trap_info_t *dst = current->arch.guest_context.trap_ctxt;
    long rc = 0;

    LOCK_BIGLOCK(current->domain);

    for ( ; ; )
    {
        if ( hypercall_preempt_check() )
        {
            rc = hypercall1_create_continuation(
                __HYPERVISOR_set_trap_table, traps);
            break;
        }

        if ( copy_from_user(&cur, traps, sizeof(cur)) ) 
        {
            rc = -EFAULT;
            break;
        }

        if ( cur.address == 0 )
            break;

        if ( !VALID_CODESEL(cur.cs) )
        {
            rc = -EPERM;
            break;
        }

        memcpy(dst+cur.vector, &cur, sizeof(cur));
        traps++;
    }

    UNLOCK_BIGLOCK(current->domain);

    return rc;
}


long set_debugreg(struct exec_domain *p, int reg, unsigned long value)
{
    int i;

    switch ( reg )
    {
    case 0: 
        if ( !access_ok(value, sizeof(long)) )
            return -EPERM;
        if ( p == current ) 
            __asm__ ( "mov %0, %%db0" : : "r" (value) );
        break;
    case 1: 
        if ( !access_ok(value, sizeof(long)) )
            return -EPERM;
        if ( p == current ) 
            __asm__ ( "mov %0, %%db1" : : "r" (value) );
        break;
    case 2: 
        if ( !access_ok(value, sizeof(long)) )
            return -EPERM;
        if ( p == current ) 
            __asm__ ( "mov %0, %%db2" : : "r" (value) );
        break;
    case 3:
        if ( !access_ok(value, sizeof(long)) )
            return -EPERM;
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

    p->arch.guest_context.debugreg[reg] = value;
    return 0;
}

long do_set_debugreg(int reg, unsigned long value)
{
    return set_debugreg(current, reg, value);
}

unsigned long do_get_debugreg(int reg)
{
    if ( (reg < 0) || (reg > 7) ) return -EINVAL;
    return current->arch.guest_context.debugreg[reg];
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
