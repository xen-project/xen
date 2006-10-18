/*
 * vmx.c: handling VMX architecture-related VM exits
 * Copyright (c) 2004, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <xen/hypercall.h>
#include <xen/perfc.h>
#include <asm/current.h>
#include <asm/io.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/msr.h>
#include <asm/spinlock.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/vmx/cpu.h>
#include <asm/shadow.h>
#include <public/sched.h>
#include <public/hvm/ioreq.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>
#include <asm/x86_emulate.h>

extern uint32_t vlapic_update_ppr(struct vlapic *vlapic);

static DEFINE_PER_CPU(unsigned long, trace_values[5]);
#define TRACE_VMEXIT(index,value) this_cpu(trace_values)[index]=value

static void vmx_ctxt_switch_from(struct vcpu *v);
static void vmx_ctxt_switch_to(struct vcpu *v);

static int vmx_initialize_guest_resources(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct vcpu *vc;
    void *io_bitmap_a, *io_bitmap_b;
    int rc;

    v->arch.schedule_tail    = arch_vmx_do_launch;
    v->arch.ctxt_switch_from = vmx_ctxt_switch_from;
    v->arch.ctxt_switch_to   = vmx_ctxt_switch_to;

    if ( v->vcpu_id != 0 )
        return 1;

    if ( !shadow_mode_external(d) )
    {
        DPRINTK("Can't init HVM for dom %u vcpu %u: "
                "not in shadow external mode\n", 
                d->domain_id, v->vcpu_id);
        domain_crash(d);
    }

    for_each_vcpu ( d, vc )
    {
        memset(&vc->arch.hvm_vmx, 0, sizeof(struct arch_vmx_struct));

        if ( (rc = vmx_create_vmcs(vc)) != 0 )
        {
            DPRINTK("Failed to create VMCS for vcpu %d: err=%d.\n",
                    vc->vcpu_id, rc);
            return 0;
        }

        spin_lock_init(&vc->arch.hvm_vmx.vmcs_lock);

        if ( (io_bitmap_a = alloc_xenheap_pages(IO_BITMAP_ORDER)) == NULL )
        {
            DPRINTK("Failed to allocate io bitmap b for vcpu %d.\n",
                    vc->vcpu_id);
            return 0;
        }

        if ( (io_bitmap_b = alloc_xenheap_pages(IO_BITMAP_ORDER)) == NULL )
        {
            DPRINTK("Failed to allocate io bitmap b for vcpu %d.\n",
                    vc->vcpu_id);
            return 0;
        }

        memset(io_bitmap_a, 0xff, 0x1000);
        memset(io_bitmap_b, 0xff, 0x1000);

        /* don't bother debug port access */
        clear_bit(PC_DEBUG_PORT, io_bitmap_a);

        vc->arch.hvm_vmx.io_bitmap_a = io_bitmap_a;
        vc->arch.hvm_vmx.io_bitmap_b = io_bitmap_b;

    }

    /*
     * Required to do this once per domain XXX todo: add a seperate function 
     * to do these.
     */
    memset(&d->shared_info->evtchn_mask[0], 0xff,
           sizeof(d->shared_info->evtchn_mask));

    return 1;
}

static void vmx_relinquish_guest_resources(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
    {
        vmx_destroy_vmcs(v);
        if ( !test_bit(_VCPUF_initialised, &v->vcpu_flags) )
            continue;
        kill_timer(&v->arch.hvm_vcpu.hlt_timer);
        if ( VLAPIC(v) != NULL )
        {
            kill_timer(&VLAPIC(v)->vlapic_timer);
            unmap_domain_page_global(VLAPIC(v)->regs);
            free_domheap_page(VLAPIC(v)->regs_page);
            xfree(VLAPIC(v));
        }
        hvm_release_assist_channel(v);
    }

    kill_timer(&d->arch.hvm_domain.pl_time.periodic_tm.timer);

    if ( d->arch.hvm_domain.shared_page_va )
        unmap_domain_page_global(
            (void *)d->arch.hvm_domain.shared_page_va);

    if ( d->arch.hvm_domain.buffered_io_va )
        unmap_domain_page_global((void *)d->arch.hvm_domain.buffered_io_va);
}

#ifdef __x86_64__

static DEFINE_PER_CPU(struct vmx_msr_state, percpu_msr);

static u32 msr_data_index[VMX_MSR_COUNT] =
{
    MSR_LSTAR, MSR_STAR, MSR_CSTAR,
    MSR_SYSCALL_MASK, MSR_EFER,
};

static void vmx_save_segments(struct vcpu *v)
{
    rdmsrl(MSR_SHADOW_GS_BASE, v->arch.hvm_vmx.msr_content.shadow_gs);
}

/*
 * To avoid MSR save/restore at every VM exit/entry time, we restore
 * the x86_64 specific MSRs at domain switch time. Since those MSRs are
 * are not modified once set for generic domains, we don't save them,
 * but simply reset them to the values set at percpu_traps_init().
 */
static void vmx_load_msrs(void)
{
    struct vmx_msr_state *host_state = &this_cpu(percpu_msr);
    int i;

    while ( host_state->flags )
    {
        i = find_first_set_bit(host_state->flags);
        wrmsrl(msr_data_index[i], host_state->msr_items[i]);
        clear_bit(i, &host_state->flags);
    }
}

static void vmx_save_init_msrs(void)
{
    struct vmx_msr_state *host_state = &this_cpu(percpu_msr);
    int i;

    for ( i = 0; i < VMX_MSR_COUNT; i++ )
        rdmsrl(msr_data_index[i], host_state->msr_items[i]);
}

#define CASE_READ_MSR(address)              \
    case MSR_ ## address:                 \
    msr_content = msr->msr_items[VMX_INDEX_MSR_ ## address]; \
    break

#define CASE_WRITE_MSR(address)                                     \
    case MSR_ ## address:                                           \
    {                                                               \
        msr->msr_items[VMX_INDEX_MSR_ ## address] = msr_content;    \
        if (!test_bit(VMX_INDEX_MSR_ ## address, &msr->flags)) {    \
            set_bit(VMX_INDEX_MSR_ ## address, &msr->flags);        \
        }                                                           \
        wrmsrl(MSR_ ## address, msr_content);                       \
        set_bit(VMX_INDEX_MSR_ ## address, &host_state->flags);     \
    }                                                               \
    break

#define IS_CANO_ADDRESS(add) 1
static inline int long_mode_do_msr_read(struct cpu_user_regs *regs)
{
    u64 msr_content = 0;
    struct vcpu *v = current;
    struct vmx_msr_state *msr = &v->arch.hvm_vmx.msr_content;

    switch ( regs->ecx ) {
    case MSR_EFER:
        HVM_DBG_LOG(DBG_LEVEL_2, "EFER msr_content 0x%"PRIx64, msr_content);
        msr_content = msr->msr_items[VMX_INDEX_MSR_EFER];
        break;

    case MSR_FS_BASE:
        if ( !(vmx_long_mode_enabled(v)) )
            /* XXX should it be GP fault */
            domain_crash_synchronous();

        __vmread(GUEST_FS_BASE, &msr_content);
        break;

    case MSR_GS_BASE:
        if ( !(vmx_long_mode_enabled(v)) )
            domain_crash_synchronous();

        __vmread(GUEST_GS_BASE, &msr_content);
        break;

    case MSR_SHADOW_GS_BASE:
        msr_content = msr->shadow_gs;
        break;

    CASE_READ_MSR(STAR);
    CASE_READ_MSR(LSTAR);
    CASE_READ_MSR(CSTAR);
    CASE_READ_MSR(SYSCALL_MASK);

    default:
        return 0;
    }

    HVM_DBG_LOG(DBG_LEVEL_2, "msr_content: 0x%"PRIx64, msr_content);

    regs->eax = (u32)(msr_content >>  0);
    regs->edx = (u32)(msr_content >> 32);

    return 1;
}

static inline int long_mode_do_msr_write(struct cpu_user_regs *regs)
{
    u64 msr_content = (u32)regs->eax | ((u64)regs->edx << 32);
    struct vcpu *v = current;
    struct vmx_msr_state *msr = &v->arch.hvm_vmx.msr_content;
    struct vmx_msr_state *host_state = &this_cpu(percpu_msr);

    HVM_DBG_LOG(DBG_LEVEL_1, "msr 0x%lx msr_content 0x%"PRIx64"\n",
                (unsigned long)regs->ecx, msr_content);

    switch ( regs->ecx ) {
    case MSR_EFER:
        /* offending reserved bit will cause #GP */
        if ( msr_content & ~(EFER_LME | EFER_LMA | EFER_NX | EFER_SCE) )
        {
            printk("Trying to set reserved bit in EFER: %"PRIx64"\n",
                   msr_content);
            vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
            return 0;
        }

        if ( (msr_content & EFER_LME)
             &&  !(msr->msr_items[VMX_INDEX_MSR_EFER] & EFER_LME) )
        {
            if ( unlikely(vmx_paging_enabled(v)) )
            {
                printk("Trying to set EFER.LME with paging enabled\n");
                vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
                return 0;
            }
        }
        else if ( !(msr_content & EFER_LME)
                  && (msr->msr_items[VMX_INDEX_MSR_EFER] & EFER_LME) )
        {
            if ( unlikely(vmx_paging_enabled(v)) )
            {
                printk("Trying to clear EFER.LME with paging enabled\n");
                vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
                return 0;
            }
        }

        msr->msr_items[VMX_INDEX_MSR_EFER] = msr_content;
        break;

    case MSR_FS_BASE:
    case MSR_GS_BASE:
        if ( !(vmx_long_mode_enabled(v)) )
            domain_crash_synchronous();

        if ( !IS_CANO_ADDRESS(msr_content) )
        {
            HVM_DBG_LOG(DBG_LEVEL_1, "Not cano address of msr write\n");
            vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
            return 0;
        }

        if ( regs->ecx == MSR_FS_BASE )
            __vmwrite(GUEST_FS_BASE, msr_content);
        else
            __vmwrite(GUEST_GS_BASE, msr_content);

        break;

    case MSR_SHADOW_GS_BASE:
        if ( !(vmx_long_mode_enabled(v)) )
            domain_crash_synchronous();

        v->arch.hvm_vmx.msr_content.shadow_gs = msr_content;
        wrmsrl(MSR_SHADOW_GS_BASE, msr_content);
        break;

    CASE_WRITE_MSR(STAR);
    CASE_WRITE_MSR(LSTAR);
    CASE_WRITE_MSR(CSTAR);
    CASE_WRITE_MSR(SYSCALL_MASK);

    default:
        return 0;
    }

    return 1;
}

static void vmx_restore_msrs(struct vcpu *v)
{
    int i = 0;
    struct vmx_msr_state *guest_state;
    struct vmx_msr_state *host_state;
    unsigned long guest_flags ;

    guest_state = &v->arch.hvm_vmx.msr_content;;
    host_state = &this_cpu(percpu_msr);

    wrmsrl(MSR_SHADOW_GS_BASE, guest_state->shadow_gs);
    guest_flags = guest_state->flags;
    if (!guest_flags)
        return;

    while (guest_flags){
        i = find_first_set_bit(guest_flags);

        HVM_DBG_LOG(DBG_LEVEL_2,
                    "restore guest's index %d msr %lx with %lx\n",
                    i, (unsigned long)msr_data_index[i],
                    (unsigned long)guest_state->msr_items[i]);
        set_bit(i, &host_state->flags);
        wrmsrl(msr_data_index[i], guest_state->msr_items[i]);
        clear_bit(i, &guest_flags);
    }
}

#else  /* __i386__ */

#define vmx_save_segments(v)      ((void)0)
#define vmx_load_msrs()           ((void)0)
#define vmx_restore_msrs(v)       ((void)0)
#define vmx_save_init_msrs()      ((void)0)

static inline int long_mode_do_msr_read(struct cpu_user_regs *regs)
{
    return 0;
}

static inline int long_mode_do_msr_write(struct cpu_user_regs *regs)
{
    return 0;
}

#endif /* __i386__ */

#define loaddebug(_v,_reg) \
    __asm__ __volatile__ ("mov %0,%%db" #_reg : : "r" ((_v)->debugreg[_reg]))
#define savedebug(_v,_reg) \
    __asm__ __volatile__ ("mov %%db" #_reg ",%0" : : "r" ((_v)->debugreg[_reg]))

static inline void vmx_save_dr(struct vcpu *v)
{
    if ( v->arch.hvm_vcpu.flag_dr_dirty )
    {
        savedebug(&v->arch.guest_context, 0);
        savedebug(&v->arch.guest_context, 1);
        savedebug(&v->arch.guest_context, 2);
        savedebug(&v->arch.guest_context, 3);
        savedebug(&v->arch.guest_context, 6);
        
        v->arch.hvm_vcpu.flag_dr_dirty = 0;

        v->arch.hvm_vcpu.u.vmx.exec_control |= CPU_BASED_MOV_DR_EXITING;
        __vmwrite(CPU_BASED_VM_EXEC_CONTROL,
                  v->arch.hvm_vcpu.u.vmx.exec_control);
    }
}

static inline void __restore_debug_registers(struct vcpu *v)
{
    loaddebug(&v->arch.guest_context, 0);
    loaddebug(&v->arch.guest_context, 1);
    loaddebug(&v->arch.guest_context, 2);
    loaddebug(&v->arch.guest_context, 3);
    /* No 4 and 5 */
    loaddebug(&v->arch.guest_context, 6);
    /* DR7 is loaded from the vmcs. */
}

/*
 * DR7 is saved and restored on every vmexit.  Other debug registers only
 * need to be restored if their value is going to affect execution -- i.e.,
 * if one of the breakpoints is enabled.  So mask out all bits that don't
 * enable some breakpoint functionality.
 *
 * This is in part necessary because bit 10 of DR7 is hardwired to 1, so a
 * simple if( guest_dr7 ) will always return true.  As long as we're masking,
 * we might as well do it right.
 */
#define DR7_ACTIVE_MASK 0xff

static inline void vmx_restore_dr(struct vcpu *v)
{
    unsigned long guest_dr7;

    __vmread(GUEST_DR7, &guest_dr7);

    /* Assumes guest does not have DR access at time of context switch. */
    if ( unlikely(guest_dr7 & DR7_ACTIVE_MASK) )
        __restore_debug_registers(v);
}

static void vmx_freeze_time(struct vcpu *v)
{
    struct periodic_time *pt=&v->domain->arch.hvm_domain.pl_time.periodic_tm;
    
    if ( pt->enabled && pt->first_injected && !v->arch.hvm_vcpu.guest_time ) {
        v->arch.hvm_vcpu.guest_time = hvm_get_guest_time(v);
        stop_timer(&(pt->timer));
    }
}

static void vmx_ctxt_switch_from(struct vcpu *v)
{
    vmx_freeze_time(v);
    vmx_save_segments(v);
    vmx_load_msrs();
    vmx_save_dr(v);
}

static void vmx_ctxt_switch_to(struct vcpu *v)
{
    vmx_restore_msrs(v);
    vmx_restore_dr(v);
}

static void stop_vmx(void)
{
    if ( !(read_cr4() & X86_CR4_VMXE) )
        return;
    __vmxoff();
    clear_in_cr4(X86_CR4_VMXE);
}

void vmx_migrate_timers(struct vcpu *v)
{
    struct periodic_time *pt = &(v->domain->arch.hvm_domain.pl_time.periodic_tm);

    if ( pt->enabled )
    {
        migrate_timer(&pt->timer, v->processor);
        migrate_timer(&v->arch.hvm_vcpu.hlt_timer, v->processor);
    }
    if ( VLAPIC(v) != NULL )
        migrate_timer(&VLAPIC(v)->vlapic_timer, v->processor);
}

static void vmx_store_cpu_guest_regs(
    struct vcpu *v, struct cpu_user_regs *regs, unsigned long *crs)
{
    vmx_vmcs_enter(v);

    if ( regs != NULL )
    {
        __vmread(GUEST_RFLAGS, &regs->eflags);
        __vmread(GUEST_SS_SELECTOR, &regs->ss);
        __vmread(GUEST_CS_SELECTOR, &regs->cs);
        __vmread(GUEST_DS_SELECTOR, &regs->ds);
        __vmread(GUEST_ES_SELECTOR, &regs->es);
        __vmread(GUEST_GS_SELECTOR, &regs->gs);
        __vmread(GUEST_FS_SELECTOR, &regs->fs);
        __vmread(GUEST_RIP, &regs->eip);
        __vmread(GUEST_RSP, &regs->esp);
    }

    if ( crs != NULL )
    {
        __vmread(CR0_READ_SHADOW, &crs[0]);
        crs[2] = v->arch.hvm_vmx.cpu_cr2;
        __vmread(GUEST_CR3, &crs[3]);
        __vmread(CR4_READ_SHADOW, &crs[4]);
    }

    vmx_vmcs_exit(v);
}

/*
 * The VMX spec (section 4.3.1.2, Checks on Guest Segment
 * Registers) says that virtual-8086 mode guests' segment
 * base-address fields in the VMCS must be equal to their
 * corresponding segment selector field shifted right by
 * four bits upon vmentry.
 *
 * This function (called only for VM86-mode guests) fixes
 * the bases to be consistent with the selectors in regs
 * if they're not already.  Without this, we can fail the
 * vmentry check mentioned above.
 */
static void fixup_vm86_seg_bases(struct cpu_user_regs *regs)
{
    int err = 0;
    unsigned long base;

    err |= __vmread(GUEST_ES_BASE, &base);
    if (regs->es << 4 != base)
        err |= __vmwrite(GUEST_ES_BASE, regs->es << 4);
    err |= __vmread(GUEST_CS_BASE, &base);
    if (regs->cs << 4 != base)
        err |= __vmwrite(GUEST_CS_BASE, regs->cs << 4);
    err |= __vmread(GUEST_SS_BASE, &base);
    if (regs->ss << 4 != base)
        err |= __vmwrite(GUEST_SS_BASE, regs->ss << 4);
    err |= __vmread(GUEST_DS_BASE, &base);
    if (regs->ds << 4 != base)
        err |= __vmwrite(GUEST_DS_BASE, regs->ds << 4);
    err |= __vmread(GUEST_FS_BASE, &base);
    if (regs->fs << 4 != base)
        err |= __vmwrite(GUEST_FS_BASE, regs->fs << 4);
    err |= __vmread(GUEST_GS_BASE, &base);
    if (regs->gs << 4 != base)
        err |= __vmwrite(GUEST_GS_BASE, regs->gs << 4);

    BUG_ON(err);
}

static void vmx_load_cpu_guest_regs(struct vcpu *v, struct cpu_user_regs *regs)
{
    vmx_vmcs_enter(v);

    __vmwrite(GUEST_SS_SELECTOR, regs->ss);
    __vmwrite(GUEST_DS_SELECTOR, regs->ds);
    __vmwrite(GUEST_ES_SELECTOR, regs->es);
    __vmwrite(GUEST_GS_SELECTOR, regs->gs);
    __vmwrite(GUEST_FS_SELECTOR, regs->fs);

    __vmwrite(GUEST_RSP, regs->esp);

    __vmwrite(GUEST_RFLAGS, regs->eflags);
    if (regs->eflags & EF_TF)
        __vm_set_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_DB);
    else
        __vm_clear_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_DB);
    if (regs->eflags & EF_VM)
        fixup_vm86_seg_bases(regs);

    __vmwrite(GUEST_CS_SELECTOR, regs->cs);
    __vmwrite(GUEST_RIP, regs->eip);

    vmx_vmcs_exit(v);
}

static unsigned long vmx_get_ctrl_reg(struct vcpu *v, unsigned int num)
{
    switch ( num )
    {
    case 0:
        return v->arch.hvm_vmx.cpu_cr0;
    case 2:
        return v->arch.hvm_vmx.cpu_cr2;
    case 3:
        return v->arch.hvm_vmx.cpu_cr3;
    case 4:
        return v->arch.hvm_vmx.cpu_shadow_cr4;
    default:
        BUG();
    }
    return 0;                   /* dummy */
}



/* Make sure that xen intercepts any FP accesses from current */
static void vmx_stts(struct vcpu *v)
{
    unsigned long cr0;

    /* VMX depends on operating on the current vcpu */
    ASSERT(v == current);

    /*
     * If the guest does not have TS enabled then we must cause and handle an
     * exception on first use of the FPU. If the guest *does* have TS enabled
     * then this is not necessary: no FPU activity can occur until the guest
     * clears CR0.TS, and we will initialise the FPU when that happens.
     */
    __vmread_vcpu(v, CR0_READ_SHADOW, &cr0);
    if ( !(cr0 & X86_CR0_TS) )
    {
        __vmread_vcpu(v, GUEST_CR0, &cr0);
        __vmwrite(GUEST_CR0, cr0 | X86_CR0_TS);
        __vm_set_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_NM);
    }
}


static void vmx_set_tsc_offset(struct vcpu *v, u64 offset)
{
    /* VMX depends on operating on the current vcpu */
    ASSERT(v == current);

    __vmwrite(TSC_OFFSET, offset);
#if defined (__i386__)
    __vmwrite(TSC_OFFSET_HIGH, offset >> 32);
#endif
}



/* SMP VMX guest support */
static void vmx_init_ap_context(struct vcpu_guest_context *ctxt,
                         int vcpuid, int trampoline_vector)
{
    int i;

    memset(ctxt, 0, sizeof(*ctxt));

    /*
     * Initial register values:
     */
    ctxt->user_regs.eip = VMXASSIST_BASE;
    ctxt->user_regs.edx = vcpuid;
    ctxt->user_regs.ebx = trampoline_vector;

    ctxt->flags = VGCF_HVM_GUEST;

    /* Virtual IDT is empty at start-of-day. */
    for ( i = 0; i < 256; i++ )
    {
        ctxt->trap_ctxt[i].vector = i;
        ctxt->trap_ctxt[i].cs     = FLAT_KERNEL_CS;
    }

    /* No callback handlers. */
#if defined(__i386__)
    ctxt->event_callback_cs     = FLAT_KERNEL_CS;
    ctxt->failsafe_callback_cs  = FLAT_KERNEL_CS;
#endif
}

void do_nmi(struct cpu_user_regs *);

static void vmx_init_hypercall_page(struct domain *d, void *hypercall_page)
{
    char *p;
    int i;

    memset(hypercall_page, 0, PAGE_SIZE);

    for ( i = 0; i < (PAGE_SIZE / 32); i++ )
    {
        p = (char *)(hypercall_page + (i * 32));
        *(u8  *)(p + 0) = 0xb8; /* mov imm32, %eax */
        *(u32 *)(p + 1) = i;
        *(u8  *)(p + 5) = 0x0f; /* vmcall */
        *(u8  *)(p + 6) = 0x01;
        *(u8  *)(p + 7) = 0xc1;
        *(u8  *)(p + 8) = 0xc3; /* ret */
    }

    /* Don't support HYPERVISOR_iret at the moment */
    *(u16 *)(hypercall_page + (__HYPERVISOR_iret * 32)) = 0x0b0f; /* ud2 */
}

static int vmx_realmode(struct vcpu *v)
{
    unsigned long rflags;

    ASSERT(v == current);

    __vmread(GUEST_RFLAGS, &rflags);
    return rflags & X86_EFLAGS_VM;
}

static int vmx_guest_x86_mode(struct vcpu *v)
{
    unsigned long cs_ar_bytes;

    ASSERT(v == current);

    __vmread(GUEST_CS_AR_BYTES, &cs_ar_bytes);

    if ( vmx_long_mode_enabled(v) )
        return ((cs_ar_bytes & (1u<<13)) ?
                X86EMUL_MODE_PROT64 : X86EMUL_MODE_PROT32);

    if ( vmx_realmode(v) )
        return X86EMUL_MODE_REAL;

    return ((cs_ar_bytes & (1u<<14)) ?
            X86EMUL_MODE_PROT32 : X86EMUL_MODE_PROT16);
}

/* Setup HVM interfaces */
static void vmx_setup_hvm_funcs(void)
{
    if ( hvm_enabled )
        return;

    hvm_funcs.disable = stop_vmx;

    hvm_funcs.initialize_guest_resources = vmx_initialize_guest_resources;
    hvm_funcs.relinquish_guest_resources = vmx_relinquish_guest_resources;

    hvm_funcs.store_cpu_guest_regs = vmx_store_cpu_guest_regs;
    hvm_funcs.load_cpu_guest_regs = vmx_load_cpu_guest_regs;

    hvm_funcs.realmode = vmx_realmode;
    hvm_funcs.paging_enabled = vmx_paging_enabled;
    hvm_funcs.long_mode_enabled = vmx_long_mode_enabled;
    hvm_funcs.pae_enabled = vmx_pae_enabled;
    hvm_funcs.guest_x86_mode = vmx_guest_x86_mode;
    hvm_funcs.get_guest_ctrl_reg = vmx_get_ctrl_reg;

    hvm_funcs.update_host_cr3 = vmx_update_host_cr3;

    hvm_funcs.stts = vmx_stts;
    hvm_funcs.set_tsc_offset = vmx_set_tsc_offset;

    hvm_funcs.init_ap_context = vmx_init_ap_context;

    hvm_funcs.init_hypercall_page = vmx_init_hypercall_page;
}

int start_vmx(void)
{
    u32 eax, edx;
    struct vmcs_struct *vmcs;

    /*
     * Xen does not fill x86_capability words except 0.
     */
    boot_cpu_data.x86_capability[4] = cpuid_ecx(1);

    if ( !test_bit(X86_FEATURE_VMXE, &boot_cpu_data.x86_capability) )
        return 0;

    rdmsr(IA32_FEATURE_CONTROL_MSR, eax, edx);

    if ( eax & IA32_FEATURE_CONTROL_MSR_LOCK )
    {
        if ( (eax & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON) == 0x0 )
        {
            printk("VMX disabled by Feature Control MSR.\n");
            return 0;
        }
    }
    else
    {
        wrmsr(IA32_FEATURE_CONTROL_MSR,
              IA32_FEATURE_CONTROL_MSR_LOCK |
              IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON, 0);
    }

    set_in_cr4(X86_CR4_VMXE);

    vmx_init_vmcs_config();

    if ( smp_processor_id() == 0 )
        setup_vmcs_dump();

    if ( (vmcs = vmx_alloc_host_vmcs()) == NULL )
    {
        clear_in_cr4(X86_CR4_VMXE);
        printk("Failed to allocate host VMCS\n");
        return 0;
    }

    if ( __vmxon(virt_to_maddr(vmcs)) )
    {
        clear_in_cr4(X86_CR4_VMXE);
        printk("VMXON failed\n");
        vmx_free_host_vmcs(vmcs);
        return 0;
    }

    printk("VMXON is done\n");

    vmx_save_init_msrs();

    vmx_setup_hvm_funcs();

    hvm_enabled = 1;

    return 1;
}

/*
 * Not all cases receive valid value in the VM-exit instruction length field.
 * Callers must know what they're doing!
 */
static int __get_instruction_length(void)
{
    int len;
    __vmread(VM_EXIT_INSTRUCTION_LEN, &len); /* Safe: callers audited */
    if ( (len < 1) || (len > 15) )
        __hvm_bug(guest_cpu_user_regs());
    return len;
}

static void inline __update_guest_eip(unsigned long inst_len)
{
    unsigned long current_eip;

    __vmread(GUEST_RIP, &current_eip);
    __vmwrite(GUEST_RIP, current_eip + inst_len);
    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
}

static int vmx_do_page_fault(unsigned long va, struct cpu_user_regs *regs)
{
    int result;

#if 0 /* keep for debugging */
    {
        unsigned long eip, cs;

        __vmread(GUEST_CS_BASE, &cs);
        __vmread(GUEST_RIP, &eip);
        HVM_DBG_LOG(DBG_LEVEL_VMMU,
                    "vmx_do_page_fault = 0x%lx, cs_base=%lx, "
                    "eip = %lx, error_code = %lx\n",
                    va, cs, eip, (unsigned long)regs->error_code);
    }
#endif

    result = shadow_fault(va, regs);

    TRACE_VMEXIT (2,result);
#if 0
    if ( !result )
    {
        __vmread(GUEST_RIP, &eip);
        printk("vmx pgfault to guest va=%lx eip=%lx\n", va, eip);
    }
#endif

    return result;
}

static void vmx_do_no_device_fault(void)
{
    unsigned long cr0;
    struct vcpu *v = current;

    setup_fpu(current);
    __vm_clear_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_NM);

    /* Disable TS in guest CR0 unless the guest wants the exception too. */
    __vmread_vcpu(v, CR0_READ_SHADOW, &cr0);
    if ( !(cr0 & X86_CR0_TS) )
    {
        __vmread_vcpu(v, GUEST_CR0, &cr0);
        cr0 &= ~X86_CR0_TS;
        __vmwrite(GUEST_CR0, cr0);
    }
}

#define bitmaskof(idx) (1U << ((idx)&31))
static void vmx_vmexit_do_cpuid(struct cpu_user_regs *regs)
{
    unsigned int input = (unsigned int)regs->eax;
    unsigned int count = (unsigned int)regs->ecx;
    unsigned int eax, ebx, ecx, edx;
    unsigned long eip;
    struct vcpu *v = current;

    __vmread(GUEST_RIP, &eip);

    HVM_DBG_LOG(DBG_LEVEL_3, "(eax) 0x%08lx, (ebx) 0x%08lx, "
                "(ecx) 0x%08lx, (edx) 0x%08lx, (esi) 0x%08lx, (edi) 0x%08lx",
                (unsigned long)regs->eax, (unsigned long)regs->ebx,
                (unsigned long)regs->ecx, (unsigned long)regs->edx,
                (unsigned long)regs->esi, (unsigned long)regs->edi);

    if ( input == CPUID_LEAF_0x4 )
    {
        cpuid_count(input, count, &eax, &ebx, &ecx, &edx);
        eax &= NUM_CORES_RESET_MASK;  
    }
    else if ( !cpuid_hypervisor_leaves(input, &eax, &ebx, &ecx, &edx) )
    {
        cpuid(input, &eax, &ebx, &ecx, &edx);

        if ( input == CPUID_LEAF_0x1 )
        {
            /* mask off reserved bits */
            ecx &= ~VMX_VCPU_CPUID_L1_ECX_RESERVED;

            if ( !hvm_apic_support(v->domain) ||
                 !vlapic_global_enabled((VLAPIC(v))) )
            {
                /* Since the apic is disabled, avoid any 
                confusion about SMP cpus being available */

                clear_bit(X86_FEATURE_APIC, &edx);
            }
    
#if CONFIG_PAGING_LEVELS >= 3
            if ( !v->domain->arch.hvm_domain.params[HVM_PARAM_PAE_ENABLED] )
#endif
                clear_bit(X86_FEATURE_PAE, &edx);
            clear_bit(X86_FEATURE_PSE36, &edx);

            ebx &= NUM_THREADS_RESET_MASK;  

            /* Unsupportable for virtualised CPUs. */
            ecx &= ~(bitmaskof(X86_FEATURE_VMXE)  |
                     bitmaskof(X86_FEATURE_EST)   |
                     bitmaskof(X86_FEATURE_TM2)   |
                     bitmaskof(X86_FEATURE_CID)   |
                     bitmaskof(X86_FEATURE_MWAIT) );

            edx &= ~( bitmaskof(X86_FEATURE_HT)   |
                     bitmaskof(X86_FEATURE_ACPI)  |
                     bitmaskof(X86_FEATURE_ACC) );
        }
        else if (  ( input == CPUID_LEAF_0x6 ) 
                || ( input == CPUID_LEAF_0x9 )
                || ( input == CPUID_LEAF_0xA ))
        {
            eax = ebx = ecx = edx = 0x0;
        }
#ifdef __i386__
        else if ( input == CPUID_LEAF_0x80000001 )
        {
            clear_bit(X86_FEATURE_LAHF_LM & 31, &ecx);

            clear_bit(X86_FEATURE_LM & 31, &edx);
            clear_bit(X86_FEATURE_SYSCALL & 31, &edx);
        }
#endif
    }

    regs->eax = (unsigned long) eax;
    regs->ebx = (unsigned long) ebx;
    regs->ecx = (unsigned long) ecx;
    regs->edx = (unsigned long) edx;

    HVM_DBG_LOG(DBG_LEVEL_3, "eip@%lx, input: 0x%lx, "
                "output: eax = 0x%08lx, ebx = 0x%08lx, "
                "ecx = 0x%08lx, edx = 0x%08lx",
                (unsigned long)eip, (unsigned long)input,
                (unsigned long)eax, (unsigned long)ebx,
                (unsigned long)ecx, (unsigned long)edx);
}

#define CASE_GET_REG_P(REG, reg)    \
    case REG_ ## REG: reg_p = (unsigned long *)&(regs->reg); break

#ifdef __i386__
#define CASE_EXTEND_GET_REG_P
#else
#define CASE_EXTEND_GET_REG_P       \
    CASE_GET_REG_P(R8, r8);         \
    CASE_GET_REG_P(R9, r9);         \
    CASE_GET_REG_P(R10, r10);       \
    CASE_GET_REG_P(R11, r11);       \
    CASE_GET_REG_P(R12, r12);       \
    CASE_GET_REG_P(R13, r13);       \
    CASE_GET_REG_P(R14, r14);       \
    CASE_GET_REG_P(R15, r15)
#endif

static void vmx_dr_access(unsigned long exit_qualification,
                          struct cpu_user_regs *regs)
{
    struct vcpu *v = current;

    v->arch.hvm_vcpu.flag_dr_dirty = 1;

    /* We could probably be smarter about this */
    __restore_debug_registers(v);

    /* Allow guest direct access to DR registers */
    v->arch.hvm_vcpu.u.vmx.exec_control &= ~CPU_BASED_MOV_DR_EXITING;
    __vmwrite(CPU_BASED_VM_EXEC_CONTROL,
              v->arch.hvm_vcpu.u.vmx.exec_control);
}

/*
 * Invalidate the TLB for va. Invalidate the shadow page corresponding
 * the address va.
 */
static void vmx_vmexit_do_invlpg(unsigned long va)
{
    unsigned long eip;
    struct vcpu *v = current;

    __vmread(GUEST_RIP, &eip);

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "vmx_vmexit_do_invlpg: eip=%lx, va=%lx",
                eip, va);

    /*
     * We do the safest things first, then try to update the shadow
     * copying from guest
     */
    shadow_invlpg(v, va);
}


static int check_for_null_selector(unsigned long eip, int inst_len, int dir)
{
    unsigned char inst[MAX_INST_LEN];
    unsigned long sel;
    int i;
    int inst_copy_from_guest(unsigned char *, unsigned long, int);

    /* INS can only use ES segment register, and it can't be overridden */
    if ( dir == IOREQ_READ )
    {
        __vmread(GUEST_ES_SELECTOR, &sel);
        return sel == 0 ? 1 : 0;
    }

    memset(inst, 0, MAX_INST_LEN);
    if ( inst_copy_from_guest(inst, eip, inst_len) != inst_len )
    {
        printf("check_for_null_selector: get guest instruction failed\n");
        domain_crash_synchronous();
    }

    for ( i = 0; i < inst_len; i++ )
    {
        switch ( inst[i] )
        {
        case 0xf3: /* REPZ */
        case 0xf2: /* REPNZ */
        case 0xf0: /* LOCK */
        case 0x66: /* data32 */
        case 0x67: /* addr32 */
            continue;
        case 0x2e: /* CS */
            __vmread(GUEST_CS_SELECTOR, &sel);
            break;
        case 0x36: /* SS */
            __vmread(GUEST_SS_SELECTOR, &sel);
            break;
        case 0x26: /* ES */
            __vmread(GUEST_ES_SELECTOR, &sel);
            break;
        case 0x64: /* FS */
            __vmread(GUEST_FS_SELECTOR, &sel);
            break;
        case 0x65: /* GS */
            __vmread(GUEST_GS_SELECTOR, &sel);
            break;
        case 0x3e: /* DS */
            /* FALLTHROUGH */
        default:
            /* DS is the default */
            __vmread(GUEST_DS_SELECTOR, &sel);
        }
        return sel == 0 ? 1 : 0;
    }

    return 0;
}

static void vmx_io_instruction(unsigned long exit_qualification,
                               unsigned long inst_len)
{
    struct cpu_user_regs *regs;
    struct hvm_io_op *pio_opp;
    unsigned long port, size;
    int dir, df, vm86;

    pio_opp = &current->arch.hvm_vcpu.io_op;
    pio_opp->instr = INSTR_PIO;
    pio_opp->flags = 0;

    regs = &pio_opp->io_context;

    /* Copy current guest state into io instruction state structure. */
    memcpy(regs, guest_cpu_user_regs(), HVM_CONTEXT_STACK_BYTES);
    hvm_store_cpu_guest_regs(current, regs, NULL);

    vm86 = regs->eflags & X86_EFLAGS_VM ? 1 : 0;
    df = regs->eflags & X86_EFLAGS_DF ? 1 : 0;

    HVM_DBG_LOG(DBG_LEVEL_IO, "vm86 %d, eip=%x:%lx, "
                "exit_qualification = %lx",
                vm86, regs->cs, (unsigned long)regs->eip, exit_qualification);

    if ( test_bit(6, &exit_qualification) )
        port = (exit_qualification >> 16) & 0xFFFF;
    else
        port = regs->edx & 0xffff;

    TRACE_VMEXIT(1,port);

    size = (exit_qualification & 7) + 1;
    dir = test_bit(3, &exit_qualification); /* direction */

    if ( test_bit(4, &exit_qualification) ) { /* string instruction */
        unsigned long addr, count = 1;
        int sign = regs->eflags & X86_EFLAGS_DF ? -1 : 1;

        __vmread(GUEST_LINEAR_ADDRESS, &addr);

        /*
         * In protected mode, guest linear address is invalid if the
         * selector is null.
         */
        if ( !vm86 && check_for_null_selector(regs->eip, inst_len, dir) )
            addr = dir == IOREQ_WRITE ? regs->esi : regs->edi;

        if ( test_bit(5, &exit_qualification) ) { /* "rep" prefix */
            pio_opp->flags |= REPZ;
            count = vm86 ? regs->ecx & 0xFFFF : regs->ecx;
        }

        /*
         * Handle string pio instructions that cross pages or that
         * are unaligned. See the comments in hvm_domain.c/handle_mmio()
         */
        if ( (addr & PAGE_MASK) != ((addr + size - 1) & PAGE_MASK) ) {
            unsigned long value = 0;

            pio_opp->flags |= OVERLAP;

            if ( dir == IOREQ_WRITE )   /* OUTS */
            {
                if ( hvm_paging_enabled(current) )
                    (void)hvm_copy_from_guest_virt(&value, addr, size);
                else
                    (void)hvm_copy_from_guest_phys(&value, addr, size);
            } else
                pio_opp->addr = addr;

            if ( count == 1 )
                regs->eip += inst_len;

            send_pio_req(port, 1, size, value, dir, df, 0);
        } else {
            unsigned long last_addr = sign > 0 ? addr + count * size - 1
                                               : addr - (count - 1) * size;

            if ( (addr & PAGE_MASK) != (last_addr & PAGE_MASK) )
            {
                if ( sign > 0 )
                    count = (PAGE_SIZE - (addr & ~PAGE_MASK)) / size;
                else
                    count = (addr & ~PAGE_MASK) / size + 1;
            } else
                regs->eip += inst_len;

            send_pio_req(port, count, size, addr, dir, df, 1);
        }
    } else {
        if ( port == 0xe9 && dir == IOREQ_WRITE && size == 1 )
            hvm_print_line(current, regs->eax); /* guest debug output */

        regs->eip += inst_len;
        send_pio_req(port, 1, size, regs->eax, dir, df, 0);
    }
}

static int vmx_world_save(struct vcpu *v, struct vmx_assist_context *c)
{
    int error = 0;

    /* NB. Skip transition instruction. */
    error |= __vmread(GUEST_RIP, &c->eip);
    c->eip += __get_instruction_length(); /* Safe: MOV Cn, LMSW, CLTS */

    error |= __vmread(GUEST_RSP, &c->esp);
    error |= __vmread(GUEST_RFLAGS, &c->eflags);

    error |= __vmread(CR0_READ_SHADOW, &c->cr0);
    c->cr3 = v->arch.hvm_vmx.cpu_cr3;
    error |= __vmread(CR4_READ_SHADOW, &c->cr4);

    error |= __vmread(GUEST_IDTR_LIMIT, &c->idtr_limit);
    error |= __vmread(GUEST_IDTR_BASE, &c->idtr_base);

    error |= __vmread(GUEST_GDTR_LIMIT, &c->gdtr_limit);
    error |= __vmread(GUEST_GDTR_BASE, &c->gdtr_base);

    error |= __vmread(GUEST_CS_SELECTOR, &c->cs_sel);
    error |= __vmread(GUEST_CS_LIMIT, &c->cs_limit);
    error |= __vmread(GUEST_CS_BASE, &c->cs_base);
    error |= __vmread(GUEST_CS_AR_BYTES, &c->cs_arbytes.bytes);

    error |= __vmread(GUEST_DS_SELECTOR, &c->ds_sel);
    error |= __vmread(GUEST_DS_LIMIT, &c->ds_limit);
    error |= __vmread(GUEST_DS_BASE, &c->ds_base);
    error |= __vmread(GUEST_DS_AR_BYTES, &c->ds_arbytes.bytes);

    error |= __vmread(GUEST_ES_SELECTOR, &c->es_sel);
    error |= __vmread(GUEST_ES_LIMIT, &c->es_limit);
    error |= __vmread(GUEST_ES_BASE, &c->es_base);
    error |= __vmread(GUEST_ES_AR_BYTES, &c->es_arbytes.bytes);

    error |= __vmread(GUEST_SS_SELECTOR, &c->ss_sel);
    error |= __vmread(GUEST_SS_LIMIT, &c->ss_limit);
    error |= __vmread(GUEST_SS_BASE, &c->ss_base);
    error |= __vmread(GUEST_SS_AR_BYTES, &c->ss_arbytes.bytes);

    error |= __vmread(GUEST_FS_SELECTOR, &c->fs_sel);
    error |= __vmread(GUEST_FS_LIMIT, &c->fs_limit);
    error |= __vmread(GUEST_FS_BASE, &c->fs_base);
    error |= __vmread(GUEST_FS_AR_BYTES, &c->fs_arbytes.bytes);

    error |= __vmread(GUEST_GS_SELECTOR, &c->gs_sel);
    error |= __vmread(GUEST_GS_LIMIT, &c->gs_limit);
    error |= __vmread(GUEST_GS_BASE, &c->gs_base);
    error |= __vmread(GUEST_GS_AR_BYTES, &c->gs_arbytes.bytes);

    error |= __vmread(GUEST_TR_SELECTOR, &c->tr_sel);
    error |= __vmread(GUEST_TR_LIMIT, &c->tr_limit);
    error |= __vmread(GUEST_TR_BASE, &c->tr_base);
    error |= __vmread(GUEST_TR_AR_BYTES, &c->tr_arbytes.bytes);

    error |= __vmread(GUEST_LDTR_SELECTOR, &c->ldtr_sel);
    error |= __vmread(GUEST_LDTR_LIMIT, &c->ldtr_limit);
    error |= __vmread(GUEST_LDTR_BASE, &c->ldtr_base);
    error |= __vmread(GUEST_LDTR_AR_BYTES, &c->ldtr_arbytes.bytes);

    return !error;
}

static int vmx_world_restore(struct vcpu *v, struct vmx_assist_context *c)
{
    unsigned long mfn, old_base_mfn;
    int error = 0;

    error |= __vmwrite(GUEST_RIP, c->eip);
    error |= __vmwrite(GUEST_RSP, c->esp);
    error |= __vmwrite(GUEST_RFLAGS, c->eflags);

    error |= __vmwrite(CR0_READ_SHADOW, c->cr0);

    if (!vmx_paging_enabled(v))
        goto skip_cr3;

    if (c->cr3 == v->arch.hvm_vmx.cpu_cr3) {
        /*
         * This is simple TLB flush, implying the guest has
         * removed some translation or changed page attributes.
         * We simply invalidate the shadow.
         */
        mfn = get_mfn_from_gpfn(c->cr3 >> PAGE_SHIFT);
        if (mfn != pagetable_get_pfn(v->arch.guest_table)) {
            printk("Invalid CR3 value=%x", c->cr3);
            domain_crash_synchronous();
            return 0;
        }
    } else {
        /*
         * If different, make a shadow. Check if the PDBR is valid
         * first.
         */
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR3 c->cr3 = %x", c->cr3);
        if ((c->cr3 >> PAGE_SHIFT) > v->domain->max_pages) {
            printk("Invalid CR3 value=%x", c->cr3);
            domain_crash_synchronous();
            return 0;
        }
        mfn = get_mfn_from_gpfn(c->cr3 >> PAGE_SHIFT);
        if(!get_page(mfn_to_page(mfn), v->domain))
                return 0;
        old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
        v->arch.guest_table = pagetable_from_pfn(mfn);
        if (old_base_mfn)
             put_page(mfn_to_page(old_base_mfn));
        /*
         * arch.shadow_table should now hold the next CR3 for shadow
         */
        v->arch.hvm_vmx.cpu_cr3 = c->cr3;
    }

 skip_cr3:

    if (!vmx_paging_enabled(v))
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "switching to vmxassist. use phys table");
    else
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %x", c->cr3);

    error |= __vmwrite(GUEST_CR4, (c->cr4 | VMX_CR4_HOST_MASK));
    error |= __vmwrite(CR4_READ_SHADOW, c->cr4);

    error |= __vmwrite(GUEST_IDTR_LIMIT, c->idtr_limit);
    error |= __vmwrite(GUEST_IDTR_BASE, c->idtr_base);

    error |= __vmwrite(GUEST_GDTR_LIMIT, c->gdtr_limit);
    error |= __vmwrite(GUEST_GDTR_BASE, c->gdtr_base);

    error |= __vmwrite(GUEST_CS_SELECTOR, c->cs_sel);
    error |= __vmwrite(GUEST_CS_LIMIT, c->cs_limit);
    error |= __vmwrite(GUEST_CS_BASE, c->cs_base);
    error |= __vmwrite(GUEST_CS_AR_BYTES, c->cs_arbytes.bytes);

    error |= __vmwrite(GUEST_DS_SELECTOR, c->ds_sel);
    error |= __vmwrite(GUEST_DS_LIMIT, c->ds_limit);
    error |= __vmwrite(GUEST_DS_BASE, c->ds_base);
    error |= __vmwrite(GUEST_DS_AR_BYTES, c->ds_arbytes.bytes);

    error |= __vmwrite(GUEST_ES_SELECTOR, c->es_sel);
    error |= __vmwrite(GUEST_ES_LIMIT, c->es_limit);
    error |= __vmwrite(GUEST_ES_BASE, c->es_base);
    error |= __vmwrite(GUEST_ES_AR_BYTES, c->es_arbytes.bytes);

    error |= __vmwrite(GUEST_SS_SELECTOR, c->ss_sel);
    error |= __vmwrite(GUEST_SS_LIMIT, c->ss_limit);
    error |= __vmwrite(GUEST_SS_BASE, c->ss_base);
    error |= __vmwrite(GUEST_SS_AR_BYTES, c->ss_arbytes.bytes);

    error |= __vmwrite(GUEST_FS_SELECTOR, c->fs_sel);
    error |= __vmwrite(GUEST_FS_LIMIT, c->fs_limit);
    error |= __vmwrite(GUEST_FS_BASE, c->fs_base);
    error |= __vmwrite(GUEST_FS_AR_BYTES, c->fs_arbytes.bytes);

    error |= __vmwrite(GUEST_GS_SELECTOR, c->gs_sel);
    error |= __vmwrite(GUEST_GS_LIMIT, c->gs_limit);
    error |= __vmwrite(GUEST_GS_BASE, c->gs_base);
    error |= __vmwrite(GUEST_GS_AR_BYTES, c->gs_arbytes.bytes);

    error |= __vmwrite(GUEST_TR_SELECTOR, c->tr_sel);
    error |= __vmwrite(GUEST_TR_LIMIT, c->tr_limit);
    error |= __vmwrite(GUEST_TR_BASE, c->tr_base);
    error |= __vmwrite(GUEST_TR_AR_BYTES, c->tr_arbytes.bytes);

    error |= __vmwrite(GUEST_LDTR_SELECTOR, c->ldtr_sel);
    error |= __vmwrite(GUEST_LDTR_LIMIT, c->ldtr_limit);
    error |= __vmwrite(GUEST_LDTR_BASE, c->ldtr_base);
    error |= __vmwrite(GUEST_LDTR_AR_BYTES, c->ldtr_arbytes.bytes);

    shadow_update_paging_modes(v);
    __vmwrite(GUEST_CR3, v->arch.hvm_vcpu.hw_cr3);

    return !error;
}

enum { VMX_ASSIST_INVOKE = 0, VMX_ASSIST_RESTORE };

static int vmx_assist(struct vcpu *v, int mode)
{
    struct vmx_assist_context c;
    u32 magic;
    u32 cp;

    /* make sure vmxassist exists (this is not an error) */
    if (hvm_copy_from_guest_phys(&magic, VMXASSIST_MAGIC_OFFSET,
                                 sizeof(magic)))
        return 0;
    if (magic != VMXASSIST_MAGIC)
        return 0;

    switch (mode) {
        /*
         * Transfer control to vmxassist.
         * Store the current context in VMXASSIST_OLD_CONTEXT and load
         * the new VMXASSIST_NEW_CONTEXT context. This context was created
         * by vmxassist and will transfer control to it.
         */
    case VMX_ASSIST_INVOKE:
        /* save the old context */
        if (hvm_copy_from_guest_phys(&cp, VMXASSIST_OLD_CONTEXT, sizeof(cp)))
            goto error;
        if (cp != 0) {
            if (!vmx_world_save(v, &c))
                goto error;
            if (hvm_copy_to_guest_phys(cp, &c, sizeof(c)))
                goto error;
        }

        /* restore the new context, this should activate vmxassist */
        if (hvm_copy_from_guest_phys(&cp, VMXASSIST_NEW_CONTEXT, sizeof(cp)))
            goto error;
        if (cp != 0) {
            if (hvm_copy_from_guest_phys(&c, cp, sizeof(c)))
                goto error;
            if (!vmx_world_restore(v, &c))
                goto error;
            v->arch.hvm_vmx.vmxassist_enabled = 1;            
            return 1;
        }
        break;

        /*
         * Restore the VMXASSIST_OLD_CONTEXT that was saved by
         * VMX_ASSIST_INVOKE above.
         */
    case VMX_ASSIST_RESTORE:
        /* save the old context */
        if (hvm_copy_from_guest_phys(&cp, VMXASSIST_OLD_CONTEXT, sizeof(cp)))
            goto error;
        if (cp != 0) {
            if (hvm_copy_from_guest_phys(&c, cp, sizeof(c)))
                goto error;
            if (!vmx_world_restore(v, &c))
                goto error;
            v->arch.hvm_vmx.vmxassist_enabled = 0;
            return 1;
        }
        break;
    }

 error:
    printf("Failed to transfer to vmxassist\n");
    domain_crash_synchronous();
    return 0;
}

static int vmx_set_cr0(unsigned long value)
{
    struct vcpu *v = current;
    unsigned long mfn;
    unsigned long eip;
    int paging_enabled;
    unsigned long vm_entry_value;
    unsigned long old_cr0;
    unsigned long old_base_mfn;

    /*
     * CR0: We don't want to lose PE and PG.
     */
    __vmread_vcpu(v, CR0_READ_SHADOW, &old_cr0);
    paging_enabled = (old_cr0 & X86_CR0_PE) && (old_cr0 & X86_CR0_PG);

    /* TS cleared? Then initialise FPU now. */
    if ( !(value & X86_CR0_TS) )
    {
        setup_fpu(v);
        __vm_clear_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_NM);
    }

    __vmwrite(GUEST_CR0, value | X86_CR0_PE | X86_CR0_PG | X86_CR0_NE);
    __vmwrite(CR0_READ_SHADOW, value);

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR0 value = %lx\n", value);

    if ( (value & X86_CR0_PE) && (value & X86_CR0_PG) && !paging_enabled )
    {
        /*
         * Trying to enable guest paging.
         * The guest CR3 must be pointing to the guest physical.
         */
        if ( !VALID_MFN(mfn = get_mfn_from_gpfn(
            v->arch.hvm_vmx.cpu_cr3 >> PAGE_SHIFT)) ||
             !get_page(mfn_to_page(mfn), v->domain) )
        {
            printk("Invalid CR3 value = %lx (mfn=%lx)\n", 
                   v->arch.hvm_vmx.cpu_cr3, mfn);
            domain_crash_synchronous(); /* need to take a clean path */
        }

#if defined(__x86_64__)
        if ( vmx_lme_is_set(v) )
        {
            if ( !(v->arch.hvm_vmx.cpu_shadow_cr4 & X86_CR4_PAE) )
            {
                HVM_DBG_LOG(DBG_LEVEL_1, "Guest enabled paging "
                            "with EFER.LME set but not CR4.PAE\n");
                vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
            }
            else 
            {
                HVM_DBG_LOG(DBG_LEVEL_1, "Enabling long mode\n");
                v->arch.hvm_vmx.msr_content.msr_items[VMX_INDEX_MSR_EFER]
                    |= EFER_LMA;
                __vmread(VM_ENTRY_CONTROLS, &vm_entry_value);
                vm_entry_value |= VM_ENTRY_IA32E_MODE;
                __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);
            }
        }
#endif

        /*
         * Now arch.guest_table points to machine physical.
         */
        old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
        v->arch.guest_table = pagetable_from_pfn(mfn);
        if (old_base_mfn)
            put_page(mfn_to_page(old_base_mfn));
        shadow_update_paging_modes(v);

        HVM_DBG_LOG(DBG_LEVEL_VMMU, "New arch.guest_table = %lx",
                    (unsigned long) (mfn << PAGE_SHIFT));

        __vmwrite(GUEST_CR3, v->arch.hvm_vcpu.hw_cr3);
        /*
         * arch->shadow_table should hold the next CR3 for shadow
         */
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx, mfn = %lx",
                    v->arch.hvm_vmx.cpu_cr3, mfn);
    }

    if ( !((value & X86_CR0_PE) && (value & X86_CR0_PG)) && paging_enabled )
        if ( v->arch.hvm_vmx.cpu_cr3 ) {
            put_page(mfn_to_page(get_mfn_from_gpfn(
                      v->arch.hvm_vmx.cpu_cr3 >> PAGE_SHIFT)));
            v->arch.guest_table = pagetable_null();
        }

    /*
     * VMX does not implement real-mode virtualization. We emulate
     * real-mode by performing a world switch to VMXAssist whenever
     * a partition disables the CR0.PE bit.
     */
    if ( (value & X86_CR0_PE) == 0 )
    {
        if ( value & X86_CR0_PG ) {
            /* inject GP here */
            vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
            return 0;
        } else {
            /*
             * Disable paging here.
             * Same to PE == 1 && PG == 0
             */
            if ( vmx_long_mode_enabled(v) )
            {
                v->arch.hvm_vmx.msr_content.msr_items[VMX_INDEX_MSR_EFER]
                    &= ~EFER_LMA;
                __vmread(VM_ENTRY_CONTROLS, &vm_entry_value);
                vm_entry_value &= ~VM_ENTRY_IA32E_MODE;
                __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);
            }
        }

        if ( vmx_assist(v, VMX_ASSIST_INVOKE) )
        {
            __vmread(GUEST_RIP, &eip);
            HVM_DBG_LOG(DBG_LEVEL_1,
                        "Transfering control to vmxassist %%eip 0x%lx\n", eip);
            return 0; /* do not update eip! */
        }
    }
    else if ( v->arch.hvm_vmx.vmxassist_enabled )
    {
        __vmread(GUEST_RIP, &eip);
        HVM_DBG_LOG(DBG_LEVEL_1,
                    "Enabling CR0.PE at %%eip 0x%lx\n", eip);
        if ( vmx_assist(v, VMX_ASSIST_RESTORE) )
        {
            __vmread(GUEST_RIP, &eip);
            HVM_DBG_LOG(DBG_LEVEL_1,
                        "Restoring to %%eip 0x%lx\n", eip);
            return 0; /* do not update eip! */
        }
    }
    else if ( (value & (X86_CR0_PE | X86_CR0_PG)) == X86_CR0_PE )
    {
        shadow_update_paging_modes(v);
        __vmwrite(GUEST_CR3, v->arch.hvm_vcpu.hw_cr3);
    }

    return 1;
}

#define CASE_SET_REG(REG, reg)      \
    case REG_ ## REG: regs->reg = value; break
#define CASE_GET_REG(REG, reg)      \
    case REG_ ## REG: value = regs->reg; break

#define CASE_EXTEND_SET_REG         \
    CASE_EXTEND_REG(S)
#define CASE_EXTEND_GET_REG         \
    CASE_EXTEND_REG(G)

#ifdef __i386__
#define CASE_EXTEND_REG(T)
#else
#define CASE_EXTEND_REG(T)          \
    CASE_ ## T ## ET_REG(R8, r8);   \
    CASE_ ## T ## ET_REG(R9, r9);   \
    CASE_ ## T ## ET_REG(R10, r10); \
    CASE_ ## T ## ET_REG(R11, r11); \
    CASE_ ## T ## ET_REG(R12, r12); \
    CASE_ ## T ## ET_REG(R13, r13); \
    CASE_ ## T ## ET_REG(R14, r14); \
    CASE_ ## T ## ET_REG(R15, r15)
#endif

/*
 * Write to control registers
 */
static int mov_to_cr(int gp, int cr, struct cpu_user_regs *regs)
{
    unsigned long value;
    unsigned long old_cr;
    struct vcpu *v = current;
    struct vlapic *vlapic = VLAPIC(v);

    switch ( gp ) {
    CASE_GET_REG(EAX, eax);
    CASE_GET_REG(ECX, ecx);
    CASE_GET_REG(EDX, edx);
    CASE_GET_REG(EBX, ebx);
    CASE_GET_REG(EBP, ebp);
    CASE_GET_REG(ESI, esi);
    CASE_GET_REG(EDI, edi);
    CASE_EXTEND_GET_REG;
    case REG_ESP:
        __vmread(GUEST_RSP, &value);
        break;
    default:
        printk("invalid gp: %d\n", gp);
        __hvm_bug(regs);
    }

    HVM_DBG_LOG(DBG_LEVEL_1, "CR%d, value = %lx", cr, value);

    switch ( cr ) {
    case 0:
        return vmx_set_cr0(value);
    case 3:
    {
        unsigned long old_base_mfn, mfn;

        /*
         * If paging is not enabled yet, simply copy the value to CR3.
         */
        if (!vmx_paging_enabled(v)) {
            v->arch.hvm_vmx.cpu_cr3 = value;
            break;
        }

        /*
         * We make a new one if the shadow does not exist.
         */
        if (value == v->arch.hvm_vmx.cpu_cr3) {
            /*
             * This is simple TLB flush, implying the guest has
             * removed some translation or changed page attributes.
             * We simply invalidate the shadow.
             */
            mfn = get_mfn_from_gpfn(value >> PAGE_SHIFT);
            if (mfn != pagetable_get_pfn(v->arch.guest_table))
                __hvm_bug(regs);
            shadow_update_cr3(v);
        } else {
            /*
             * If different, make a shadow. Check if the PDBR is valid
             * first.
             */
            HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR3 value = %lx", value);
            if ( ((value >> PAGE_SHIFT) > v->domain->max_pages ) ||
                 !VALID_MFN(mfn = get_mfn_from_gpfn(value >> PAGE_SHIFT)) ||
                 !get_page(mfn_to_page(mfn), v->domain) )
            {
                printk("Invalid CR3 value=%lx", value);
                domain_crash_synchronous(); /* need to take a clean path */
            }
            old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
            v->arch.guest_table = pagetable_from_pfn(mfn);
            if (old_base_mfn)
                put_page(mfn_to_page(old_base_mfn));
            /*
             * arch.shadow_table should now hold the next CR3 for shadow
             */
            v->arch.hvm_vmx.cpu_cr3 = value;
            update_cr3(v);
            HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx",
                        value);
            __vmwrite(GUEST_CR3, v->arch.hvm_vcpu.hw_cr3);
        }
        break;
    }
    case 4: /* CR4 */
    {
        __vmread(CR4_READ_SHADOW, &old_cr);

        if ( value & X86_CR4_PAE && !(old_cr & X86_CR4_PAE) )
        {
            if ( vmx_pgbit_test(v) )
            {
                /* The guest is a 32-bit PAE guest. */
#if CONFIG_PAGING_LEVELS >= 3
                unsigned long mfn, old_base_mfn;

                if ( !VALID_MFN(mfn = get_mfn_from_gpfn(
                                    v->arch.hvm_vmx.cpu_cr3 >> PAGE_SHIFT)) ||
                     !get_page(mfn_to_page(mfn), v->domain) )
                {
                    printk("Invalid CR3 value = %lx", v->arch.hvm_vmx.cpu_cr3);
                    domain_crash_synchronous(); /* need to take a clean path */
                }


                /*
                 * Now arch.guest_table points to machine physical.
                 */

                old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
                v->arch.guest_table = pagetable_from_pfn(mfn);
                if ( old_base_mfn )
                    put_page(mfn_to_page(old_base_mfn));

                HVM_DBG_LOG(DBG_LEVEL_VMMU, "New arch.guest_table = %lx",
                            (unsigned long) (mfn << PAGE_SHIFT));

                __vmwrite(GUEST_CR3, v->arch.hvm_vcpu.hw_cr3);

                /*
                 * arch->shadow_table should hold the next CR3 for shadow
                 */

                HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx, mfn = %lx",
                            v->arch.hvm_vmx.cpu_cr3, mfn);
#endif
            }
        }
        else if ( !(value & X86_CR4_PAE) )
        {
            if ( unlikely(vmx_long_mode_enabled(v)) )
            {
                HVM_DBG_LOG(DBG_LEVEL_1, "Guest cleared CR4.PAE while "
                            "EFER.LMA is set\n");
                vmx_inject_hw_exception(v, TRAP_gp_fault, 0);
            }
        }

        __vmwrite(GUEST_CR4, value| VMX_CR4_HOST_MASK);
        __vmwrite(CR4_READ_SHADOW, value);

        /*
         * Writing to CR4 to modify the PSE, PGE, or PAE flag invalidates
         * all TLB entries except global entries.
         */
        if ( (old_cr ^ value) & (X86_CR4_PSE | X86_CR4_PGE | X86_CR4_PAE) )
            shadow_update_paging_modes(v);
        break;
    }
    case 8:
    {
        if ( vlapic == NULL )
            break;
        vlapic_set_reg(vlapic, APIC_TASKPRI, ((value & 0x0F) << 4));
        vlapic_update_ppr(vlapic);
        break;
    }
    default:
        printk("invalid cr: %d\n", gp);
        __hvm_bug(regs);
    }

    return 1;
}

/*
 * Read from control registers. CR0 and CR4 are read from the shadow.
 */
static void mov_from_cr(int cr, int gp, struct cpu_user_regs *regs)
{
    unsigned long value = 0;
    struct vcpu *v = current;
    struct vlapic *vlapic = VLAPIC(v);

    switch ( cr )
    {
    case 3:
        value = (unsigned long)v->arch.hvm_vmx.cpu_cr3;
        break;
    case 8:
        if ( vlapic == NULL )
            break;
        value = (unsigned long)vlapic_get_reg(vlapic, APIC_TASKPRI);
        value = (value & 0xF0) >> 4;
        break;
    default:
        __hvm_bug(regs);
    }

    switch ( gp ) {
    CASE_SET_REG(EAX, eax);
    CASE_SET_REG(ECX, ecx);
    CASE_SET_REG(EDX, edx);
    CASE_SET_REG(EBX, ebx);
    CASE_SET_REG(EBP, ebp);
    CASE_SET_REG(ESI, esi);
    CASE_SET_REG(EDI, edi);
    CASE_EXTEND_SET_REG;
    case REG_ESP:
        __vmwrite(GUEST_RSP, value);
        regs->esp = value;
        break;
    default:
        printk("invalid gp: %d\n", gp);
        __hvm_bug(regs);
    }

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR%d, value = %lx", cr, value);
}

static int vmx_cr_access(unsigned long exit_qualification,
                         struct cpu_user_regs *regs)
{
    unsigned int gp, cr;
    unsigned long value;
    struct vcpu *v = current;

    switch (exit_qualification & CONTROL_REG_ACCESS_TYPE) {
    case TYPE_MOV_TO_CR:
        gp = exit_qualification & CONTROL_REG_ACCESS_REG;
        cr = exit_qualification & CONTROL_REG_ACCESS_NUM;
        TRACE_VMEXIT(1,TYPE_MOV_TO_CR);
        TRACE_VMEXIT(2,cr);
        TRACE_VMEXIT(3,gp);
        return mov_to_cr(gp, cr, regs);
    case TYPE_MOV_FROM_CR:
        gp = exit_qualification & CONTROL_REG_ACCESS_REG;
        cr = exit_qualification & CONTROL_REG_ACCESS_NUM;
        TRACE_VMEXIT(1,TYPE_MOV_FROM_CR);
        TRACE_VMEXIT(2,cr);
        TRACE_VMEXIT(3,gp);
        mov_from_cr(cr, gp, regs);
        break;
    case TYPE_CLTS:
        TRACE_VMEXIT(1,TYPE_CLTS);

        /* We initialise the FPU now, to avoid needing another vmexit. */
        setup_fpu(v);
        __vm_clear_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_NM);

        __vmread_vcpu(v, GUEST_CR0, &value);
        value &= ~X86_CR0_TS; /* clear TS */
        __vmwrite(GUEST_CR0, value);

        __vmread_vcpu(v, CR0_READ_SHADOW, &value);
        value &= ~X86_CR0_TS; /* clear TS */
        __vmwrite(CR0_READ_SHADOW, value);
        break;
    case TYPE_LMSW:
        TRACE_VMEXIT(1,TYPE_LMSW);
        __vmread_vcpu(v, CR0_READ_SHADOW, &value);
        value = (value & ~0xF) |
            (((exit_qualification & LMSW_SOURCE_DATA) >> 16) & 0xF);
        return vmx_set_cr0(value);
        break;
    default:
        __hvm_bug(regs);
        break;
    }
    return 1;
}

static inline void vmx_do_msr_read(struct cpu_user_regs *regs)
{
    u64 msr_content = 0;
    u32 eax, edx;
    struct vcpu *v = current;

    HVM_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_read: ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);
    switch (regs->ecx) {
    case MSR_IA32_TIME_STAMP_COUNTER:
        msr_content = hvm_get_guest_time(v);
        break;
    case MSR_IA32_SYSENTER_CS:
        __vmread(GUEST_SYSENTER_CS, (u32 *)&msr_content);
        break;
    case MSR_IA32_SYSENTER_ESP:
        __vmread(GUEST_SYSENTER_ESP, &msr_content);
        break;
    case MSR_IA32_SYSENTER_EIP:
        __vmread(GUEST_SYSENTER_EIP, &msr_content);
        break;
    case MSR_IA32_APICBASE:
        msr_content = VLAPIC(v) ? VLAPIC(v)->apic_base_msr : 0;
        break;
    default:
        if (long_mode_do_msr_read(regs))
            return;

        if ( rdmsr_hypervisor_regs(regs->ecx, &eax, &edx) )
        {
            regs->eax = eax;
            regs->edx = edx;
            return;
        }

        rdmsr_safe(regs->ecx, regs->eax, regs->edx);
        return;
    }

    regs->eax = msr_content & 0xFFFFFFFF;
    regs->edx = msr_content >> 32;

    HVM_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_read returns: "
                "ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);
}

static inline void vmx_do_msr_write(struct cpu_user_regs *regs)
{
    u64 msr_content;
    struct vcpu *v = current;

    HVM_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_write: ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);

    msr_content = (u32)regs->eax | ((u64)regs->edx << 32);

    switch (regs->ecx) {
    case MSR_IA32_TIME_STAMP_COUNTER:
        hvm_set_guest_time(v, msr_content);
        break;
    case MSR_IA32_SYSENTER_CS:
        __vmwrite(GUEST_SYSENTER_CS, msr_content);
        break;
    case MSR_IA32_SYSENTER_ESP:
        __vmwrite(GUEST_SYSENTER_ESP, msr_content);
        break;
    case MSR_IA32_SYSENTER_EIP:
        __vmwrite(GUEST_SYSENTER_EIP, msr_content);
        break;
    case MSR_IA32_APICBASE:
        vlapic_msr_set(VLAPIC(v), msr_content);
        break;
    default:
        if ( !long_mode_do_msr_write(regs) )
            wrmsr_hypervisor_regs(regs->ecx, regs->eax, regs->edx);
        break;
    }

    HVM_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_write returns: "
                "ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);
}

void vmx_vmexit_do_hlt(void)
{
    unsigned long rflags;
    __vmread(GUEST_RFLAGS, &rflags);
    hvm_hlt(rflags);
}

static inline void vmx_vmexit_do_extint(struct cpu_user_regs *regs)
{
    unsigned int vector;
    int error;

    asmlinkage void do_IRQ(struct cpu_user_regs *);
    fastcall void smp_apic_timer_interrupt(struct cpu_user_regs *);
    fastcall void smp_event_check_interrupt(void);
    fastcall void smp_invalidate_interrupt(void);
    fastcall void smp_call_function_interrupt(void);
    fastcall void smp_spurious_interrupt(struct cpu_user_regs *regs);
    fastcall void smp_error_interrupt(struct cpu_user_regs *regs);
#ifdef CONFIG_X86_MCE_P4THERMAL
    fastcall void smp_thermal_interrupt(struct cpu_user_regs *regs);
#endif

    if ((error = __vmread(VM_EXIT_INTR_INFO, &vector))
        && !(vector & INTR_INFO_VALID_MASK))
        __hvm_bug(regs);

    vector &= INTR_INFO_VECTOR_MASK;
    TRACE_VMEXIT(1,vector);

    switch(vector) {
    case LOCAL_TIMER_VECTOR:
        smp_apic_timer_interrupt(regs);
        break;
    case EVENT_CHECK_VECTOR:
        smp_event_check_interrupt();
        break;
    case INVALIDATE_TLB_VECTOR:
        smp_invalidate_interrupt();
        break;
    case CALL_FUNCTION_VECTOR:
        smp_call_function_interrupt();
        break;
    case SPURIOUS_APIC_VECTOR:
        smp_spurious_interrupt(regs);
        break;
    case ERROR_APIC_VECTOR:
        smp_error_interrupt(regs);
        break;
#ifdef CONFIG_X86_MCE_P4THERMAL
    case THERMAL_APIC_VECTOR:
        smp_thermal_interrupt(regs);
        break;
#endif
    default:
        regs->entry_vector = vector;
        do_IRQ(regs);
        break;
    }
}

#if defined (__x86_64__)
void store_cpu_user_regs(struct cpu_user_regs *regs)
{
    __vmread(GUEST_SS_SELECTOR, &regs->ss);
    __vmread(GUEST_RSP, &regs->rsp);
    __vmread(GUEST_RFLAGS, &regs->rflags);
    __vmread(GUEST_CS_SELECTOR, &regs->cs);
    __vmread(GUEST_DS_SELECTOR, &regs->ds);
    __vmread(GUEST_ES_SELECTOR, &regs->es);
    __vmread(GUEST_RIP, &regs->rip);
}
#elif defined (__i386__)
void store_cpu_user_regs(struct cpu_user_regs *regs)
{
    __vmread(GUEST_SS_SELECTOR, &regs->ss);
    __vmread(GUEST_RSP, &regs->esp);
    __vmread(GUEST_RFLAGS, &regs->eflags);
    __vmread(GUEST_CS_SELECTOR, &regs->cs);
    __vmread(GUEST_DS_SELECTOR, &regs->ds);
    __vmread(GUEST_ES_SELECTOR, &regs->es);
    __vmread(GUEST_RIP, &regs->eip);
}
#endif 

#ifdef XEN_DEBUGGER
void save_cpu_user_regs(struct cpu_user_regs *regs)
{
    __vmread(GUEST_SS_SELECTOR, &regs->xss);
    __vmread(GUEST_RSP, &regs->esp);
    __vmread(GUEST_RFLAGS, &regs->eflags);
    __vmread(GUEST_CS_SELECTOR, &regs->xcs);
    __vmread(GUEST_RIP, &regs->eip);

    __vmread(GUEST_GS_SELECTOR, &regs->xgs);
    __vmread(GUEST_FS_SELECTOR, &regs->xfs);
    __vmread(GUEST_ES_SELECTOR, &regs->xes);
    __vmread(GUEST_DS_SELECTOR, &regs->xds);
}

void restore_cpu_user_regs(struct cpu_user_regs *regs)
{
    __vmwrite(GUEST_SS_SELECTOR, regs->xss);
    __vmwrite(GUEST_RSP, regs->esp);
    __vmwrite(GUEST_RFLAGS, regs->eflags);
    __vmwrite(GUEST_CS_SELECTOR, regs->xcs);
    __vmwrite(GUEST_RIP, regs->eip);

    __vmwrite(GUEST_GS_SELECTOR, regs->xgs);
    __vmwrite(GUEST_FS_SELECTOR, regs->xfs);
    __vmwrite(GUEST_ES_SELECTOR, regs->xes);
    __vmwrite(GUEST_DS_SELECTOR, regs->xds);
}
#endif

static void vmx_reflect_exception(struct vcpu *v)
{
    int error_code, intr_info, vector;

    __vmread(VM_EXIT_INTR_INFO, &intr_info);
    vector = intr_info & 0xff;
    if ( intr_info & INTR_INFO_DELIVER_CODE_MASK )
        __vmread(VM_EXIT_INTR_ERROR_CODE, &error_code);
    else
        error_code = VMX_DELIVER_NO_ERROR_CODE;

#ifndef NDEBUG
    {
        unsigned long rip;

        __vmread(GUEST_RIP, &rip);
        HVM_DBG_LOG(DBG_LEVEL_1, "rip = %lx, error_code = %x",
                    rip, error_code);
    }
#endif /* NDEBUG */

    /*
     * According to Intel Virtualization Technology Specification for
     * the IA-32 Intel Architecture (C97063-002 April 2005), section
     * 2.8.3, SW_EXCEPTION should be used for #BP and #OV, and
     * HW_EXCEPTION used for everything else.  The main difference
     * appears to be that for SW_EXCEPTION, the EIP/RIP is incremented
     * by VM_ENTER_INSTRUCTION_LEN bytes, whereas for HW_EXCEPTION,
     * it is not.
     */
    if ( (intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_SW_EXCEPTION )
    {
        int ilen = __get_instruction_length(); /* Safe: software exception */
        vmx_inject_sw_exception(v, vector, ilen);
    }
    else
    {
        vmx_inject_hw_exception(v, vector, error_code);
    }
}

asmlinkage void vmx_vmexit_handler(struct cpu_user_regs *regs)
{
    unsigned int exit_reason;
    unsigned long exit_qualification, rip, inst_len = 0;
    struct vcpu *v = current;

    __vmread(VM_EXIT_REASON, &exit_reason);

    perfc_incra(vmexits, exit_reason);

    if ( (exit_reason != EXIT_REASON_EXTERNAL_INTERRUPT) &&
         (exit_reason != EXIT_REASON_VMCALL) &&
         (exit_reason != EXIT_REASON_IO_INSTRUCTION) )
        HVM_DBG_LOG(DBG_LEVEL_0, "exit reason = %x", exit_reason);

    if ( exit_reason != EXIT_REASON_EXTERNAL_INTERRUPT )
        local_irq_enable();

    if ( unlikely(exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) )
    {
        unsigned int failed_vmentry_reason = exit_reason & 0xFFFF;

        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        printk("Failed vm entry (exit reason 0x%x) ", exit_reason);
        switch ( failed_vmentry_reason ) {
        case EXIT_REASON_INVALID_GUEST_STATE:
            printk("caused by invalid guest state (%ld).\n", exit_qualification);
            break;
        case EXIT_REASON_MSR_LOADING:
            printk("caused by MSR entry %ld loading.\n", exit_qualification);
            break;
        case EXIT_REASON_MACHINE_CHECK:
            printk("caused by machine check.\n");
            break;
        default:
            printk("reason not known yet!");
            break;
        }

        printk("************* VMCS Area **************\n");
        vmcs_dump_vcpu();
        printk("**************************************\n");
        domain_crash_synchronous();
    }

    TRACE_VMEXIT(0,exit_reason);

    switch ( exit_reason )
    {
    case EXIT_REASON_EXCEPTION_NMI:
    {
        /*
         * We don't set the software-interrupt exiting (INT n).
         * (1) We can get an exception (e.g. #PG) in the guest, or
         * (2) NMI
         */
        unsigned int vector;
        unsigned long va;

        if ( __vmread(VM_EXIT_INTR_INFO, &vector) ||
             !(vector & INTR_INFO_VALID_MASK) )
            domain_crash_synchronous();
        vector &= INTR_INFO_VECTOR_MASK;

        TRACE_VMEXIT(1,vector);
        perfc_incra(cause_vector, vector);

        switch ( vector ) {
#ifdef XEN_DEBUGGER
        case TRAP_debug:
        {
            save_cpu_user_regs(regs);
            pdb_handle_exception(1, regs, 1);
            restore_cpu_user_regs(regs);
            break;
        }
        case TRAP_int3:
        {
            save_cpu_user_regs(regs);
            pdb_handle_exception(3, regs, 1);
            restore_cpu_user_regs(regs);
            break;
        }
#else
        case TRAP_debug:
        {
            void store_cpu_user_regs(struct cpu_user_regs *regs);

            if ( test_bit(_DOMF_debugging, &v->domain->domain_flags) )
            {
                store_cpu_user_regs(regs);
                domain_pause_for_debugger();
                __vm_clear_bit(GUEST_PENDING_DBG_EXCEPTIONS,
                               PENDING_DEBUG_EXC_BS);
            }
            else
            {
                vmx_reflect_exception(v);
                __vm_clear_bit(GUEST_PENDING_DBG_EXCEPTIONS,
                               PENDING_DEBUG_EXC_BS);
            }

            break;
        }
        case TRAP_int3:
        {
            if ( test_bit(_DOMF_debugging, &v->domain->domain_flags) )
                domain_pause_for_debugger();
            else
                vmx_reflect_exception(v);
            break;
        }
#endif
        case TRAP_no_device:
        {
            vmx_do_no_device_fault();
            break;
        }
        case TRAP_page_fault:
        {
            __vmread(EXIT_QUALIFICATION, &va);
            __vmread(VM_EXIT_INTR_ERROR_CODE, &regs->error_code);

            TRACE_VMEXIT(3, regs->error_code);
            TRACE_VMEXIT(4, va);

            HVM_DBG_LOG(DBG_LEVEL_VMMU,
                        "eax=%lx, ebx=%lx, ecx=%lx, edx=%lx, esi=%lx, edi=%lx",
                        (unsigned long)regs->eax, (unsigned long)regs->ebx,
                        (unsigned long)regs->ecx, (unsigned long)regs->edx,
                        (unsigned long)regs->esi, (unsigned long)regs->edi);

            if ( !vmx_do_page_fault(va, regs) )
            {
                /* Inject #PG using Interruption-Information Fields. */
                vmx_inject_hw_exception(v, TRAP_page_fault, regs->error_code);
                v->arch.hvm_vmx.cpu_cr2 = va;
                TRACE_3D(TRC_VMX_INT, v->domain->domain_id,
                         TRAP_page_fault, va);
            }
            break;
        }
        case TRAP_nmi:
            do_nmi(regs);
            break;
        default:
            vmx_reflect_exception(v);
            break;
        }
        break;
    }
    case EXIT_REASON_EXTERNAL_INTERRUPT:
        vmx_vmexit_do_extint(regs);
        break;
    case EXIT_REASON_TRIPLE_FAULT:
        domain_crash_synchronous();
        break;
    case EXIT_REASON_PENDING_INTERRUPT:
        /* Disable the interrupt window. */
        v->arch.hvm_vcpu.u.vmx.exec_control &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
        __vmwrite(CPU_BASED_VM_EXEC_CONTROL,
                  v->arch.hvm_vcpu.u.vmx.exec_control);
        break;
    case EXIT_REASON_TASK_SWITCH:
        domain_crash_synchronous();
        break;
    case EXIT_REASON_CPUID:
        inst_len = __get_instruction_length(); /* Safe: CPUID */
        __update_guest_eip(inst_len);
        vmx_vmexit_do_cpuid(regs);
        break;
    case EXIT_REASON_HLT:
        inst_len = __get_instruction_length(); /* Safe: HLT */
        __update_guest_eip(inst_len);
        vmx_vmexit_do_hlt();
        break;
    case EXIT_REASON_INVLPG:
    {
        unsigned long va;
        inst_len = __get_instruction_length(); /* Safe: INVLPG */
        __update_guest_eip(inst_len);
        __vmread(EXIT_QUALIFICATION, &va);
        vmx_vmexit_do_invlpg(va);
        break;
    }
    case EXIT_REASON_VMCALL:
    {
        inst_len = __get_instruction_length(); /* Safe: VMCALL */
        __update_guest_eip(inst_len);
        __vmread(GUEST_RIP, &rip);
        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        hvm_do_hypercall(regs);
        break;
    }
    case EXIT_REASON_CR_ACCESS:
    {
        __vmread(GUEST_RIP, &rip);
        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        inst_len = __get_instruction_length(); /* Safe: MOV Cn, LMSW, CLTS */
        if ( vmx_cr_access(exit_qualification, regs) )
            __update_guest_eip(inst_len);
        TRACE_VMEXIT(3, regs->error_code);
        TRACE_VMEXIT(4, exit_qualification);
        break;
    }
    case EXIT_REASON_DR_ACCESS:
        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        vmx_dr_access(exit_qualification, regs);
        break;
    case EXIT_REASON_IO_INSTRUCTION:
        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        inst_len = __get_instruction_length(); /* Safe: IN, INS, OUT, OUTS */
        vmx_io_instruction(exit_qualification, inst_len);
        TRACE_VMEXIT(4,exit_qualification);
        break;
    case EXIT_REASON_MSR_READ:
        inst_len = __get_instruction_length(); /* Safe: RDMSR */
        __update_guest_eip(inst_len);
        vmx_do_msr_read(regs);
        break;
    case EXIT_REASON_MSR_WRITE:
        inst_len = __get_instruction_length(); /* Safe: WRMSR */
        __update_guest_eip(inst_len);
        vmx_do_msr_write(regs);
        break;
    case EXIT_REASON_MWAIT_INSTRUCTION:
    case EXIT_REASON_MONITOR_INSTRUCTION:
    case EXIT_REASON_PAUSE_INSTRUCTION:
        domain_crash_synchronous();
        break;
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
        /* Report invalid opcode exception when a VMX guest tries to execute
            any of the VMX instructions */
        vmx_inject_hw_exception(v, TRAP_invalid_op, VMX_DELIVER_NO_ERROR_CODE);
        break;

    default:
        domain_crash_synchronous();     /* should not happen */
    }
}

asmlinkage void vmx_load_cr2(void)
{
    struct vcpu *v = current;

    local_irq_disable();
    asm volatile("mov %0,%%cr2": :"r" (v->arch.hvm_vmx.cpu_cr2));
}

asmlinkage void vmx_trace_vmentry (void)
{
    TRACE_5D(TRC_VMX_VMENTRY,
             this_cpu(trace_values)[0],
             this_cpu(trace_values)[1],
             this_cpu(trace_values)[2],
             this_cpu(trace_values)[3],
             this_cpu(trace_values)[4]);
    TRACE_VMEXIT(0,9);
    TRACE_VMEXIT(1,9);
    TRACE_VMEXIT(2,9);
    TRACE_VMEXIT(3,9);
    TRACE_VMEXIT(4,9);
    return;
}

asmlinkage void vmx_trace_vmexit (void)
{
    TRACE_3D(TRC_VMX_VMEXIT,0,0,0);
    return;
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
