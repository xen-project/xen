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
#include <asm/current.h>
#include <asm/io.h>
#include <asm/shadow.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/msr.h>
#include <asm/spinlock.h>
#include <asm/vmx.h>
#include <asm/vmx_vmcs.h>
#include <asm/vmx_intercept.h>
#include <asm/shadow.h>
#if CONFIG_PAGING_LEVELS >= 3
#include <asm/shadow_64.h>
#endif
#include <public/sched.h>
#include <public/io/ioreq.h>
#include <asm/vmx_vpic.h>
#include <asm/vmx_vlapic.h>

int hvm_enabled;

#ifdef CONFIG_VMX
unsigned int opt_vmx_debug_level = 0;
integer_param("vmx_debug", opt_vmx_debug_level);

static unsigned long trace_values[NR_CPUS][4];
#define TRACE_VMEXIT(index,value) trace_values[current->processor][index]=value

static int vmx_switch_on;

void vmx_final_setup_guest(struct vcpu *v)
{
    v->arch.schedule_tail = arch_vmx_do_launch;

    if ( v->vcpu_id == 0 )
    {
        struct domain *d = v->domain;
        struct vcpu *vc;

        d->arch.vmx_platform.lapic_enable = v->arch.guest_context.user_regs.ecx;
        v->arch.guest_context.user_regs.ecx = 0;
        VMX_DBG_LOG(DBG_LEVEL_VLAPIC, "lapic enable is %d.\n",
                    d->arch.vmx_platform.lapic_enable);

        /* Initialize monitor page table */
        for_each_vcpu(d, vc)
            vc->arch.monitor_table = mk_pagetable(0);

        /*
         * Required to do this once per domain
         * XXX todo: add a seperate function to do these.
         */
        memset(&d->shared_info->evtchn_mask[0], 0xff,
               sizeof(d->shared_info->evtchn_mask));

        /* Put the domain in shadow mode even though we're going to be using
         * the shared 1:1 page table initially. It shouldn't hurt */
        shadow_mode_enable(d,
                           SHM_enable|SHM_refcounts|
                           SHM_translate|SHM_external|SHM_wr_pt_pte);
    }

    vmx_switch_on = 1;
}

void vmx_relinquish_resources(struct vcpu *v)
{
    struct vmx_virpit *vpit;
    
    if ( !VMX_DOMAIN(v) )
        return;

    if (v->vcpu_id == 0) {
        /* unmap IO shared page */
        struct domain *d = v->domain;
        unmap_domain_page((void *)d->arch.vmx_platform.shared_page_va);
    }

    destroy_vmcs(&v->arch.arch_vmx);
    free_monitor_pagetable(v);
    vpit = &v->domain->arch.vmx_platform.vmx_pit;
    if ( active_ac_timer(&(vpit->pit_timer)) )
        rem_ac_timer(&vpit->pit_timer);
    if ( active_ac_timer(&v->arch.arch_vmx.hlt_timer) ) {
        rem_ac_timer(&v->arch.arch_vmx.hlt_timer);
    }
    if ( vmx_apic_support(v->domain) ) {
        rem_ac_timer( &(VLAPIC(v)->vlapic_timer) );
        xfree( VLAPIC(v) );
    }
}

#ifdef __x86_64__
static struct msr_state percpu_msr[NR_CPUS];

static u32 msr_data_index[VMX_MSR_COUNT] =
{
    MSR_LSTAR, MSR_STAR, MSR_CSTAR,
    MSR_SYSCALL_MASK, MSR_EFER,
};

/*
 * To avoid MSR save/restore at every VM exit/entry time, we restore
 * the x86_64 specific MSRs at domain switch time. Since those MSRs are
 * are not modified once set for generic domains, we don't save them,
 * but simply reset them to the values set at percpu_traps_init().
 */
void vmx_load_msrs(struct vcpu *n)
{
    struct msr_state *host_state = &percpu_msr[smp_processor_id()];
    int i;

    if ( !vmx_switch_on )
        return;

    while ( host_state->flags )
    {
        i = find_first_set_bit(host_state->flags);
        wrmsrl(msr_data_index[i], host_state->msr_items[i]);
        clear_bit(i, &host_state->flags);
    }
}

static void vmx_save_init_msrs(void)
{
    struct msr_state *host_state = &percpu_msr[smp_processor_id()];
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
    u64     msr_content = 0;
    struct vcpu *vc = current;
    struct msr_state * msr = &vc->arch.arch_vmx.msr_content;
    switch(regs->ecx){
    case MSR_EFER:
        msr_content = msr->msr_items[VMX_INDEX_MSR_EFER];
        VMX_DBG_LOG(DBG_LEVEL_2, "EFER msr_content %llx\n", (unsigned long long)msr_content);
        if (test_bit(VMX_CPU_STATE_LME_ENABLED,
                     &vc->arch.arch_vmx.cpu_state))
            msr_content |= 1 << _EFER_LME;

        if (VMX_LONG_GUEST(vc))
            msr_content |= 1 << _EFER_LMA;
        break;
    case MSR_FS_BASE:
        if (!(VMX_LONG_GUEST(vc)))
            /* XXX should it be GP fault */
            domain_crash(vc->domain);
        __vmread(GUEST_FS_BASE, &msr_content);
        break;
    case MSR_GS_BASE:
        if (!(VMX_LONG_GUEST(vc)))
            domain_crash(vc->domain);
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
    VMX_DBG_LOG(DBG_LEVEL_2, "mode_do_msr_read: msr_content: %lx\n", msr_content);
    regs->eax = msr_content & 0xffffffff;
    regs->edx = msr_content >> 32;
    return 1;
}

static inline int long_mode_do_msr_write(struct cpu_user_regs *regs)
{
    u64     msr_content = regs->eax | ((u64)regs->edx << 32);
    struct vcpu *vc = current;
    struct msr_state * msr = &vc->arch.arch_vmx.msr_content;
    struct msr_state * host_state =
        &percpu_msr[smp_processor_id()];

    VMX_DBG_LOG(DBG_LEVEL_1, " mode_do_msr_write msr %lx msr_content %lx\n",
                regs->ecx, msr_content);

    switch (regs->ecx){
    case MSR_EFER:
        if ((msr_content & EFER_LME) ^
            test_bit(VMX_CPU_STATE_LME_ENABLED,
                     &vc->arch.arch_vmx.cpu_state)){
            if (test_bit(VMX_CPU_STATE_PG_ENABLED,
                         &vc->arch.arch_vmx.cpu_state) ||
                !test_bit(VMX_CPU_STATE_PAE_ENABLED,
                          &vc->arch.arch_vmx.cpu_state)){
                vmx_inject_exception(vc, TRAP_gp_fault, 0);
            }
        }
        if (msr_content & EFER_LME)
            set_bit(VMX_CPU_STATE_LME_ENABLED,
                    &vc->arch.arch_vmx.cpu_state);
        /* No update for LME/LMA since it have no effect */
        msr->msr_items[VMX_INDEX_MSR_EFER] =
            msr_content;
        if (msr_content & ~(EFER_LME | EFER_LMA)){
            msr->msr_items[VMX_INDEX_MSR_EFER] = msr_content;
            if (!test_bit(VMX_INDEX_MSR_EFER, &msr->flags)){
                rdmsrl(MSR_EFER,
                       host_state->msr_items[VMX_INDEX_MSR_EFER]);
                set_bit(VMX_INDEX_MSR_EFER, &host_state->flags);
                set_bit(VMX_INDEX_MSR_EFER, &msr->flags);
                wrmsrl(MSR_EFER, msr_content);
            }
        }
        break;

    case MSR_FS_BASE:
    case MSR_GS_BASE:
        if (!(VMX_LONG_GUEST(vc)))
            domain_crash(vc->domain);
        if (!IS_CANO_ADDRESS(msr_content)){
            VMX_DBG_LOG(DBG_LEVEL_1, "Not cano address of msr write\n");
            vmx_inject_exception(vc, TRAP_gp_fault, 0);
        }
        if (regs->ecx == MSR_FS_BASE)
            __vmwrite(GUEST_FS_BASE, msr_content);
        else
            __vmwrite(GUEST_GS_BASE, msr_content);
        break;

    case MSR_SHADOW_GS_BASE:
        if (!(VMX_LONG_GUEST(vc)))
            domain_crash(vc->domain);
        vc->arch.arch_vmx.msr_content.shadow_gs = msr_content;
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

void
vmx_restore_msrs(struct vcpu *v)
{
    int i = 0;
    struct msr_state *guest_state;
    struct msr_state *host_state;
    unsigned long guest_flags ;

    guest_state = &v->arch.arch_vmx.msr_content;;
    host_state = &percpu_msr[smp_processor_id()];

    wrmsrl(MSR_SHADOW_GS_BASE, guest_state->shadow_gs);
    guest_flags = guest_state->flags;
    if (!guest_flags)
        return;

    while (guest_flags){
        i = find_first_set_bit(guest_flags);

        VMX_DBG_LOG(DBG_LEVEL_2,
                    "restore guest's index %d msr %lx with %lx\n",
                    i, (unsigned long) msr_data_index[i], (unsigned long) guest_state->msr_items[i]);
        set_bit(i, &host_state->flags);
        wrmsrl(msr_data_index[i], guest_state->msr_items[i]);
        clear_bit(i, &guest_flags);
    }
}

#else  /* __i386__ */
#define  vmx_save_init_msrs()   ((void)0)

static inline int  long_mode_do_msr_read(struct cpu_user_regs *regs){
    return 0;
}
static inline int  long_mode_do_msr_write(struct cpu_user_regs *regs){
    return 0;
}
#endif

extern long evtchn_send(int lport);
extern long do_block(void);
void do_nmi(struct cpu_user_regs *, unsigned long);

static int check_vmx_controls(ctrls, msr)
{
    u32 vmx_msr_low, vmx_msr_high;

    rdmsr(msr, vmx_msr_low, vmx_msr_high);
    if (ctrls < vmx_msr_low || ctrls > vmx_msr_high) {
        printk("Insufficient VMX capability 0x%x, "
               "msr=0x%x,low=0x%8x,high=0x%x\n",
               ctrls, msr, vmx_msr_low, vmx_msr_high);
        return 0;
    }
    return 1;
}

int start_vmx(void)
{
    struct vmcs_struct *vmcs;
    u32 ecx;
    u32 eax, edx;
    u64 phys_vmcs;      /* debugging */

    /*
     * Xen does not fill x86_capability words except 0.
     */
    ecx = cpuid_ecx(1);
    boot_cpu_data.x86_capability[4] = ecx;

    if (!(test_bit(X86_FEATURE_VMXE, &boot_cpu_data.x86_capability)))
        return 0;

    rdmsr(IA32_FEATURE_CONTROL_MSR, eax, edx);

    if (eax & IA32_FEATURE_CONTROL_MSR_LOCK) {
        if ((eax & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON) == 0x0) {
            printk("VMX disabled by Feature Control MSR.\n");
            return 0;
        }
    }
    else {
        wrmsr(IA32_FEATURE_CONTROL_MSR,
              IA32_FEATURE_CONTROL_MSR_LOCK |
              IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON, 0);
    }

    if (!check_vmx_controls(MONITOR_PIN_BASED_EXEC_CONTROLS,
                            MSR_IA32_VMX_PINBASED_CTLS_MSR))
        return 0;
    if (!check_vmx_controls(MONITOR_CPU_BASED_EXEC_CONTROLS,
                            MSR_IA32_VMX_PROCBASED_CTLS_MSR))
        return 0;
    if (!check_vmx_controls(MONITOR_VM_EXIT_CONTROLS,
                            MSR_IA32_VMX_EXIT_CTLS_MSR))
        return 0;
    if (!check_vmx_controls(MONITOR_VM_ENTRY_CONTROLS,
                            MSR_IA32_VMX_ENTRY_CTLS_MSR))
        return 0;

    set_in_cr4(X86_CR4_VMXE);   /* Enable VMXE */

    if (!(vmcs = alloc_vmcs())) {
        printk("Failed to allocate VMCS\n");
        return 0;
    }

    phys_vmcs = (u64) virt_to_phys(vmcs);

    if (!(__vmxon(phys_vmcs))) {
        printk("VMXON is done\n");
    }

    vmx_save_init_msrs();

    hvm_enabled = 1;

    return 1;
}

void stop_vmx(void)
{
    if (read_cr4() & X86_CR4_VMXE)
        __vmxoff();
}

/*
 * Not all cases receive valid value in the VM-exit instruction length field.
 */
#define __get_instruction_length(len) \
    __vmread(VM_EXIT_INSTRUCTION_LEN, &(len)); \
     if ((len) < 1 || (len) > 15) \
        __vmx_bug(&regs);

static void inline __update_guest_eip(unsigned long inst_len)
{
    unsigned long current_eip;

    __vmread(GUEST_RIP, &current_eip);
    __vmwrite(GUEST_RIP, current_eip + inst_len);
}


static int vmx_do_page_fault(unsigned long va, struct cpu_user_regs *regs)
{
    unsigned long gpa; /* FIXME: PAE */
    int result;

#if 0 /* keep for debugging */
    {
        unsigned long eip;

        __vmread(GUEST_RIP, &eip);
        VMX_DBG_LOG(DBG_LEVEL_VMMU,
                    "vmx_do_page_fault = 0x%lx, eip = %lx, error_code = %lx",
                    va, eip, (unsigned long)regs->error_code);
    }
#endif

    if (!vmx_paging_enabled(current)){
        handle_mmio(va, va);
        TRACE_VMEXIT (2,2);
        return 1;
    }
    gpa = gva_to_gpa(va);

    /* Use 1:1 page table to identify MMIO address space */
    if ( mmio_space(gpa) ){
        struct vcpu *v = current;
        /* No support for APIC */
        if (!vmx_apic_support(v->domain) && gpa >= 0xFEC00000) { 
            u32 inst_len;
            __vmread(VM_EXIT_INSTRUCTION_LEN, &(inst_len));
            __update_guest_eip(inst_len);
            return 1;
        }
        TRACE_VMEXIT (2,2);
        handle_mmio(va, gpa);
        return 1;
    }

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

    clts();
    setup_fpu(current);
    __vmread_vcpu(v, CR0_READ_SHADOW, &cr0);
    if (!(cr0 & X86_CR0_TS)) {
        __vmread_vcpu(v, GUEST_CR0, &cr0);
        cr0 &= ~X86_CR0_TS;
        __vmwrite(GUEST_CR0, cr0);
    }
    __vm_clear_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_NM);
}


static void vmx_vmexit_do_cpuid(unsigned long input, struct cpu_user_regs *regs)
{
    unsigned int eax, ebx, ecx, edx;
    unsigned long eip;
    struct vcpu *v = current;

    __vmread(GUEST_RIP, &eip);

    VMX_DBG_LOG(DBG_LEVEL_1,
                "do_cpuid: (eax) %lx, (ebx) %lx, (ecx) %lx, (edx) %lx,"
                " (esi) %lx, (edi) %lx",
                (unsigned long)regs->eax, (unsigned long)regs->ebx,
                (unsigned long)regs->ecx, (unsigned long)regs->edx,
                (unsigned long)regs->esi, (unsigned long)regs->edi);

    cpuid(input, &eax, &ebx, &ecx, &edx);

    if ( input == 1 )
    {
        if ( vmx_apic_support(v->domain) &&
             !vlapic_global_enabled((VLAPIC(v))) )
            clear_bit(X86_FEATURE_APIC, &edx);

#ifdef __x86_64__
        if ( v->domain->arch.ops->guest_paging_levels == PAGING_L2 )
#endif
        {
            clear_bit(X86_FEATURE_PSE, &edx);
            clear_bit(X86_FEATURE_PAE, &edx);
            clear_bit(X86_FEATURE_PSE36, &edx);
        }

        /* Unsupportable for virtualised CPUs. */
        clear_bit(X86_FEATURE_VMXE & 31, &ecx);
        clear_bit(X86_FEATURE_MWAIT & 31, &ecx);
    }

    regs->eax = (unsigned long) eax;
    regs->ebx = (unsigned long) ebx;
    regs->ecx = (unsigned long) ecx;
    regs->edx = (unsigned long) edx;

    VMX_DBG_LOG(DBG_LEVEL_1,
                "vmx_vmexit_do_cpuid: eip: %lx, input: %lx, out:eax=%x, ebx=%x, ecx=%x, edx=%x",
                eip, input, eax, ebx, ecx, edx);

}

#define CASE_GET_REG_P(REG, reg)    \
    case REG_ ## REG: reg_p = (unsigned long *)&(regs->reg); break

static void vmx_dr_access (unsigned long exit_qualification, struct cpu_user_regs *regs)
{
    unsigned int reg;
    unsigned long *reg_p = 0;
    struct vcpu *v = current;
    unsigned long eip;

    __vmread(GUEST_RIP, &eip);

    reg = exit_qualification & DEBUG_REG_ACCESS_NUM;

    VMX_DBG_LOG(DBG_LEVEL_1,
                "vmx_dr_access : eip=%lx, reg=%d, exit_qualification = %lx",
                eip, reg, exit_qualification);

    switch(exit_qualification & DEBUG_REG_ACCESS_REG) {
        CASE_GET_REG_P(EAX, eax);
        CASE_GET_REG_P(ECX, ecx);
        CASE_GET_REG_P(EDX, edx);
        CASE_GET_REG_P(EBX, ebx);
        CASE_GET_REG_P(EBP, ebp);
        CASE_GET_REG_P(ESI, esi);
        CASE_GET_REG_P(EDI, edi);
    case REG_ESP:
        break;
    default:
        __vmx_bug(regs);
    }

    switch (exit_qualification & DEBUG_REG_ACCESS_TYPE) {
    case TYPE_MOV_TO_DR:
        /* don't need to check the range */
        if (reg != REG_ESP)
            v->arch.guest_context.debugreg[reg] = *reg_p;
        else {
            unsigned long value;
            __vmread(GUEST_RSP, &value);
            v->arch.guest_context.debugreg[reg] = value;
        }
        break;
    case TYPE_MOV_FROM_DR:
        if (reg != REG_ESP)
            *reg_p = v->arch.guest_context.debugreg[reg];
        else {
            __vmwrite(GUEST_RSP, v->arch.guest_context.debugreg[reg]);
        }
        break;
    }
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

    VMX_DBG_LOG(DBG_LEVEL_VMMU, "vmx_vmexit_do_invlpg: eip=%lx, va=%lx",
                eip, va);

    /*
     * We do the safest things first, then try to update the shadow
     * copying from guest
     */
    shadow_invlpg(v, va);
}

static int check_for_null_selector(unsigned long eip)
{
    unsigned char inst[MAX_INST_LEN];
    unsigned long sel;
    int i, inst_len;
    int inst_copy_from_guest(unsigned char *, unsigned long, int);

    __vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len);
    memset(inst, 0, MAX_INST_LEN);
    if (inst_copy_from_guest(inst, eip, inst_len) != inst_len) {
        printf("check_for_null_selector: get guest instruction failed\n");
        domain_crash_synchronous();
    }

    for (i = 0; i < inst_len; i++) {
        switch (inst[i]) {
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

void send_pio_req(struct cpu_user_regs *regs, unsigned long port,
                  unsigned long count, int size, long value, int dir, int pvalid)
{
    struct vcpu *v = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;

    vio = get_vio(v->domain, v->vcpu_id);
    if (vio == NULL) {
        printk("bad shared page: %lx\n", (unsigned long) vio);
        domain_crash_synchronous();
    }

    if (test_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags)) {
        printf("VMX I/O has not yet completed\n");
        domain_crash_synchronous();
    }
    set_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags);

    p = &vio->vp_ioreq;
    p->dir = dir;
    p->pdata_valid = pvalid;

    p->type = IOREQ_TYPE_PIO;
    p->size = size;
    p->addr = port;
    p->count = count;
    p->df = regs->eflags & EF_DF ? 1 : 0;

    if (pvalid) {
        if (vmx_paging_enabled(current))
            p->u.pdata = (void *) gva_to_gpa(value);
        else
            p->u.pdata = (void *) value; /* guest VA == guest PA */
    } else
        p->u.data = value;

    if (vmx_portio_intercept(p)) {
        p->state = STATE_IORESP_READY;
        vmx_io_assist(v);
        return;
    }

    p->state = STATE_IOREQ_READY;

    evtchn_send(iopacket_port(v->domain));
    vmx_wait_io();
}

static void vmx_io_instruction(struct cpu_user_regs *regs,
                               unsigned long exit_qualification, unsigned long inst_len)
{
    struct mmio_op *mmio_opp;
    unsigned long eip, cs, eflags;
    unsigned long port, size, dir;
    int vm86;

    mmio_opp = &current->arch.arch_vmx.mmio_op;
    mmio_opp->instr = INSTR_PIO;
    mmio_opp->flags = 0;

    __vmread(GUEST_RIP, &eip);
    __vmread(GUEST_CS_SELECTOR, &cs);
    __vmread(GUEST_RFLAGS, &eflags);
    vm86 = eflags & X86_EFLAGS_VM ? 1 : 0;

    VMX_DBG_LOG(DBG_LEVEL_1,
                "vmx_io_instruction: vm86 %d, eip=%lx:%lx, "
                "exit_qualification = %lx",
                vm86, cs, eip, exit_qualification);

    if (test_bit(6, &exit_qualification))
        port = (exit_qualification >> 16) & 0xFFFF;
    else
        port = regs->edx & 0xffff;
    TRACE_VMEXIT(2, port);
    size = (exit_qualification & 7) + 1;
    dir = test_bit(3, &exit_qualification); /* direction */

    if (test_bit(4, &exit_qualification)) { /* string instruction */
        unsigned long addr, count = 1;
        int sign = regs->eflags & EF_DF ? -1 : 1;

        __vmread(GUEST_LINEAR_ADDRESS, &addr);

        /*
         * In protected mode, guest linear address is invalid if the
         * selector is null.
         */
        if (!vm86 && check_for_null_selector(eip))
            addr = dir == IOREQ_WRITE ? regs->esi : regs->edi;

        if (test_bit(5, &exit_qualification)) { /* "rep" prefix */
            mmio_opp->flags |= REPZ;
            count = vm86 ? regs->ecx & 0xFFFF : regs->ecx;
        }

        /*
         * Handle string pio instructions that cross pages or that
         * are unaligned. See the comments in vmx_platform.c/handle_mmio()
         */
        if ((addr & PAGE_MASK) != ((addr + size - 1) & PAGE_MASK)) {
            unsigned long value = 0;

            mmio_opp->flags |= OVERLAP;
            if (dir == IOREQ_WRITE)
                vmx_copy(&value, addr, size, VMX_COPY_IN);
            send_pio_req(regs, port, 1, size, value, dir, 0);
        } else {
            if ((addr & PAGE_MASK) != ((addr + count * size - 1) & PAGE_MASK)) {
                if (sign > 0)
                    count = (PAGE_SIZE - (addr & ~PAGE_MASK)) / size;
                else
                    count = (addr & ~PAGE_MASK) / size;
            } else
                __update_guest_eip(inst_len);

            send_pio_req(regs, port, count, size, addr, dir, 1);
        }
    } else {
        __update_guest_eip(inst_len);
        send_pio_req(regs, port, 1, size, regs->eax, dir, 0);
    }
}

int
vmx_copy(void *buf, unsigned long laddr, int size, int dir)
{
    unsigned long gpa, mfn;
    char *addr;
    int count;

    while (size > 0) {
        count = PAGE_SIZE - (laddr & ~PAGE_MASK);
        if (count > size)
            count = size;

        if (vmx_paging_enabled(current)) {
            gpa = gva_to_gpa(laddr);
            mfn = get_mfn_from_pfn(gpa >> PAGE_SHIFT);
        } else
            mfn = get_mfn_from_pfn(laddr >> PAGE_SHIFT);
        if (mfn == INVALID_MFN)
            return 0;

        addr = (char *)map_domain_page(mfn) + (laddr & ~PAGE_MASK);

        if (dir == VMX_COPY_IN)
            memcpy(buf, addr, count);
        else
            memcpy(addr, buf, count);

        unmap_domain_page(addr);

        laddr += count;
        buf += count;
        size -= count;
    }

    return 1;
}

int
vmx_world_save(struct vcpu *v, struct vmx_assist_context *c)
{
    unsigned long inst_len;
    int error = 0;

    error |= __vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len);
    error |= __vmread(GUEST_RIP, &c->eip);
    c->eip += inst_len; /* skip transition instruction */
    error |= __vmread(GUEST_RSP, &c->esp);
    error |= __vmread(GUEST_RFLAGS, &c->eflags);

    error |= __vmread(CR0_READ_SHADOW, &c->cr0);
    c->cr3 = v->arch.arch_vmx.cpu_cr3;
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

int
vmx_world_restore(struct vcpu *v, struct vmx_assist_context *c)
{
    unsigned long mfn, old_cr4, old_base_mfn;
    int error = 0;

    error |= __vmwrite(GUEST_RIP, c->eip);
    error |= __vmwrite(GUEST_RSP, c->esp);
    error |= __vmwrite(GUEST_RFLAGS, c->eflags);

    error |= __vmwrite(CR0_READ_SHADOW, c->cr0);

    if (!vmx_paging_enabled(v)) {
        VMX_DBG_LOG(DBG_LEVEL_VMMU, "switching to vmxassist. use phys table");
        __vmwrite(GUEST_CR3, pagetable_get_paddr(v->domain->arch.phys_table));
        goto skip_cr3;
    }

    if (c->cr3 == v->arch.arch_vmx.cpu_cr3) {
        /*
         * This is simple TLB flush, implying the guest has
         * removed some translation or changed page attributes.
         * We simply invalidate the shadow.
         */
        mfn = get_mfn_from_pfn(c->cr3 >> PAGE_SHIFT);
        if (mfn != pagetable_get_pfn(v->arch.guest_table)) {
            printk("Invalid CR3 value=%x", c->cr3);
            domain_crash_synchronous();
            return 0;
        }
        shadow_sync_all(v->domain);
    } else {
        /*
         * If different, make a shadow. Check if the PDBR is valid
         * first.
         */
        VMX_DBG_LOG(DBG_LEVEL_VMMU, "CR3 c->cr3 = %x", c->cr3);
        if ((c->cr3 >> PAGE_SHIFT) > v->domain->max_pages) {
            printk("Invalid CR3 value=%x", c->cr3);
            domain_crash_synchronous();
            return 0;
        }
        mfn = get_mfn_from_pfn(c->cr3 >> PAGE_SHIFT);
        if(!get_page(pfn_to_page(mfn), v->domain))
                return 0;
        old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
        v->arch.guest_table = mk_pagetable(mfn << PAGE_SHIFT);
        if (old_base_mfn)
             put_page(pfn_to_page(old_base_mfn));
        update_pagetables(v);
        /*
         * arch.shadow_table should now hold the next CR3 for shadow
         */
        v->arch.arch_vmx.cpu_cr3 = c->cr3;
        VMX_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %x", c->cr3);
        __vmwrite(GUEST_CR3, pagetable_get_paddr(v->arch.shadow_table));
    }

 skip_cr3:

    error |= __vmread(CR4_READ_SHADOW, &old_cr4);
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

    return !error;
}

enum { VMX_ASSIST_INVOKE = 0, VMX_ASSIST_RESTORE };

int
vmx_assist(struct vcpu *v, int mode)
{
    struct vmx_assist_context c;
    u32 magic;
    u32 cp;

    /* make sure vmxassist exists (this is not an error) */
    if (!vmx_copy(&magic, VMXASSIST_MAGIC_OFFSET, sizeof(magic), VMX_COPY_IN))
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
        if (!vmx_copy(&cp, VMXASSIST_OLD_CONTEXT, sizeof(cp), VMX_COPY_IN))
            goto error;
        if (cp != 0) {
            if (!vmx_world_save(v, &c))
                goto error;
            if (!vmx_copy(&c, cp, sizeof(c), VMX_COPY_OUT))
                goto error;
        }

        /* restore the new context, this should activate vmxassist */
        if (!vmx_copy(&cp, VMXASSIST_NEW_CONTEXT, sizeof(cp), VMX_COPY_IN))
            goto error;
        if (cp != 0) {
            if (!vmx_copy(&c, cp, sizeof(c), VMX_COPY_IN))
                goto error;
            if (!vmx_world_restore(v, &c))
                goto error;
            return 1;
        }
        break;

        /*
         * Restore the VMXASSIST_OLD_CONTEXT that was saved by VMX_ASSIST_INVOKE
         * above.
         */
    case VMX_ASSIST_RESTORE:
        /* save the old context */
        if (!vmx_copy(&cp, VMXASSIST_OLD_CONTEXT, sizeof(cp), VMX_COPY_IN))
            goto error;
        if (cp != 0) {
            if (!vmx_copy(&c, cp, sizeof(c), VMX_COPY_IN))
                goto error;
            if (!vmx_world_restore(v, &c))
                goto error;
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

    /*
     * CR0: We don't want to lose PE and PG.
     */
    paging_enabled = vmx_paging_enabled(v);
    __vmwrite(GUEST_CR0, value | X86_CR0_PE | X86_CR0_PG | X86_CR0_NE);
    __vmwrite(CR0_READ_SHADOW, value);

    VMX_DBG_LOG(DBG_LEVEL_VMMU, "Update CR0 value = %lx\n", value);

    if ((value & X86_CR0_PE) && (value & X86_CR0_PG) && !paging_enabled) {
        /*
         * The guest CR3 must be pointing to the guest physical.
         */
        if ( !VALID_MFN(mfn = get_mfn_from_pfn(
            v->arch.arch_vmx.cpu_cr3 >> PAGE_SHIFT)) ||
             !get_page(pfn_to_page(mfn), v->domain) )
        {
            printk("Invalid CR3 value = %lx", v->arch.arch_vmx.cpu_cr3);
            domain_crash_synchronous(); /* need to take a clean path */
        }

#if defined(__x86_64__)
        if (test_bit(VMX_CPU_STATE_LME_ENABLED,
                     &v->arch.arch_vmx.cpu_state) &&
            !test_bit(VMX_CPU_STATE_PAE_ENABLED,
                      &v->arch.arch_vmx.cpu_state)){
            VMX_DBG_LOG(DBG_LEVEL_1, "Enable paging before PAE enable\n");
            vmx_inject_exception(v, TRAP_gp_fault, 0);
        }
        if (test_bit(VMX_CPU_STATE_LME_ENABLED,
                     &v->arch.arch_vmx.cpu_state)){
            /* Here the PAE is should to be opened */
            VMX_DBG_LOG(DBG_LEVEL_1, "Enable the Long mode\n");
            set_bit(VMX_CPU_STATE_LMA_ENABLED,
                    &v->arch.arch_vmx.cpu_state);
            __vmread(VM_ENTRY_CONTROLS, &vm_entry_value);
            vm_entry_value |= VM_ENTRY_CONTROLS_IA32E_MODE;
            __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);

#if CONFIG_PAGING_LEVELS >= 4
            if(!shadow_set_guest_paging_levels(v->domain, 4)) {
                printk("Unsupported guest paging levels\n");
                domain_crash_synchronous(); /* need to take a clean path */
            }
#endif
        }
        else
        {
#if CONFIG_PAGING_LEVELS >= 4
            if(!shadow_set_guest_paging_levels(v->domain, 2)) {
                printk("Unsupported guest paging levels\n");
                domain_crash_synchronous(); /* need to take a clean path */
            }
#endif
        }

        {
            unsigned long crn;
            /* update CR4's PAE if needed */
            __vmread(GUEST_CR4, &crn);
            if ( (!(crn & X86_CR4_PAE)) &&
                 test_bit(VMX_CPU_STATE_PAE_ENABLED,
                          &v->arch.arch_vmx.cpu_state) )
            {
                VMX_DBG_LOG(DBG_LEVEL_1, "enable PAE on cr4\n");
                __vmwrite(GUEST_CR4, crn | X86_CR4_PAE);
            }
        }
#endif
        /*
         * Now arch.guest_table points to machine physical.
         */
        v->arch.guest_table = mk_pagetable(mfn << PAGE_SHIFT);
        update_pagetables(v);

        VMX_DBG_LOG(DBG_LEVEL_VMMU, "New arch.guest_table = %lx",
                    (unsigned long) (mfn << PAGE_SHIFT));

        __vmwrite(GUEST_CR3, pagetable_get_paddr(v->arch.shadow_table));
        /*
         * arch->shadow_table should hold the next CR3 for shadow
         */
        VMX_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx, mfn = %lx",
                    v->arch.arch_vmx.cpu_cr3, mfn);
    }

    if(!((value & X86_CR0_PE) && (value & X86_CR0_PG)) && paging_enabled)
        if(v->arch.arch_vmx.cpu_cr3){
            put_page(pfn_to_page(get_mfn_from_pfn(
                      v->arch.arch_vmx.cpu_cr3 >> PAGE_SHIFT)));
            v->arch.guest_table = mk_pagetable(0);
        }

    /*
     * VMX does not implement real-mode virtualization. We emulate
     * real-mode by performing a world switch to VMXAssist whenever
     * a partition disables the CR0.PE bit.
     */
    if ((value & X86_CR0_PE) == 0) {
        if ( value & X86_CR0_PG ) {
            /* inject GP here */
            vmx_inject_exception(v, TRAP_gp_fault, 0);
            return 0;
        } else {
            /*
             * Disable paging here.
             * Same to PE == 1 && PG == 0
             */
            if (test_bit(VMX_CPU_STATE_LMA_ENABLED,
                         &v->arch.arch_vmx.cpu_state)){
                clear_bit(VMX_CPU_STATE_LMA_ENABLED,
                          &v->arch.arch_vmx.cpu_state);
                __vmread(VM_ENTRY_CONTROLS, &vm_entry_value);
                vm_entry_value &= ~VM_ENTRY_CONTROLS_IA32E_MODE;
                __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);
            }
        }

        if (vmx_assist(v, VMX_ASSIST_INVOKE)) {
            set_bit(VMX_CPU_STATE_ASSIST_ENABLED, &v->arch.arch_vmx.cpu_state);
            __vmread(GUEST_RIP, &eip);
            VMX_DBG_LOG(DBG_LEVEL_1,
                        "Transfering control to vmxassist %%eip 0x%lx\n", eip);
            return 0; /* do not update eip! */
        }
    } else if (test_bit(VMX_CPU_STATE_ASSIST_ENABLED,
                        &v->arch.arch_vmx.cpu_state)) {
        __vmread(GUEST_RIP, &eip);
        VMX_DBG_LOG(DBG_LEVEL_1,
                    "Enabling CR0.PE at %%eip 0x%lx\n", eip);
        if (vmx_assist(v, VMX_ASSIST_RESTORE)) {
            clear_bit(VMX_CPU_STATE_ASSIST_ENABLED,
                      &v->arch.arch_vmx.cpu_state);
            __vmread(GUEST_RIP, &eip);
            VMX_DBG_LOG(DBG_LEVEL_1,
                        "Restoring to %%eip 0x%lx\n", eip);
            return 0; /* do not update eip! */
        }
    }

    return 1;
}

#define CASE_GET_REG(REG, reg)  \
    case REG_ ## REG: value = regs->reg; break

#define CASE_EXTEND_SET_REG \
      CASE_EXTEND_REG(S)
#define CASE_EXTEND_GET_REG \
      CASE_EXTEND_REG(G)

#ifdef __i386__
#define CASE_EXTEND_REG(T)
#else
#define CASE_EXTEND_REG(T)    \
    CASE_ ## T ## ET_REG(R8, r8); \
    CASE_ ## T ## ET_REG(R9, r9); \
    CASE_ ## T ## ET_REG(R10, r10); \
    CASE_ ## T ## ET_REG(R11, r11); \
    CASE_ ## T ## ET_REG(R12, r12); \
    CASE_ ## T ## ET_REG(R13, r13); \
    CASE_ ## T ## ET_REG(R14, r14); \
    CASE_ ## T ## ET_REG(R15, r15);
#endif


/*
 * Write to control registers
 */
static int mov_to_cr(int gp, int cr, struct cpu_user_regs *regs)
{
    unsigned long value;
    unsigned long old_cr;
    struct vcpu *v = current;

    switch (gp) {
        CASE_GET_REG(EAX, eax);
        CASE_GET_REG(ECX, ecx);
        CASE_GET_REG(EDX, edx);
        CASE_GET_REG(EBX, ebx);
        CASE_GET_REG(EBP, ebp);
        CASE_GET_REG(ESI, esi);
        CASE_GET_REG(EDI, edi);
        CASE_EXTEND_GET_REG
            case REG_ESP:
                __vmread(GUEST_RSP, &value);
        break;
    default:
        printk("invalid gp: %d\n", gp);
        __vmx_bug(regs);
    }

    VMX_DBG_LOG(DBG_LEVEL_1, "mov_to_cr: CR%d, value = %lx,", cr, value);
    VMX_DBG_LOG(DBG_LEVEL_1, "current = %lx,", (unsigned long) current);

    switch(cr) {
    case 0:
    {
        return vmx_set_cr0(value);
    }
    case 3:
    {
        unsigned long old_base_mfn, mfn;

        /*
         * If paging is not enabled yet, simply copy the value to CR3.
         */
        if (!vmx_paging_enabled(v)) {
            v->arch.arch_vmx.cpu_cr3 = value;
            break;
        }

        /*
         * We make a new one if the shadow does not exist.
         */
        if (value == v->arch.arch_vmx.cpu_cr3) {
            /*
             * This is simple TLB flush, implying the guest has
             * removed some translation or changed page attributes.
             * We simply invalidate the shadow.
             */
            mfn = get_mfn_from_pfn(value >> PAGE_SHIFT);
            if (mfn != pagetable_get_pfn(v->arch.guest_table))
                __vmx_bug(regs);
            shadow_sync_all(v->domain);
        } else {
            /*
             * If different, make a shadow. Check if the PDBR is valid
             * first.
             */
            VMX_DBG_LOG(DBG_LEVEL_VMMU, "CR3 value = %lx", value);
            if ( ((value >> PAGE_SHIFT) > v->domain->max_pages ) ||
                 !VALID_MFN(mfn = get_mfn_from_pfn(value >> PAGE_SHIFT)) ||
                 !get_page(pfn_to_page(mfn), v->domain) )
            {
                printk("Invalid CR3 value=%lx", value);
                domain_crash_synchronous(); /* need to take a clean path */
            }
            old_base_mfn = pagetable_get_pfn(v->arch.guest_table);
            v->arch.guest_table = mk_pagetable(mfn << PAGE_SHIFT);
            if (old_base_mfn)
                put_page(pfn_to_page(old_base_mfn));
            update_pagetables(v);
            /*
             * arch.shadow_table should now hold the next CR3 for shadow
             */
            v->arch.arch_vmx.cpu_cr3 = value;
            VMX_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx",
                        value);
            __vmwrite(GUEST_CR3, pagetable_get_paddr(v->arch.shadow_table));
        }
        break;
    }
    case 4:
    {
        /* CR4 */
        unsigned long old_guest_cr;

        __vmread(GUEST_CR4, &old_guest_cr);
        if (value & X86_CR4_PAE){
            set_bit(VMX_CPU_STATE_PAE_ENABLED, &v->arch.arch_vmx.cpu_state);
        } else {
            if (test_bit(VMX_CPU_STATE_LMA_ENABLED,
                         &v->arch.arch_vmx.cpu_state)){
                vmx_inject_exception(v, TRAP_gp_fault, 0);
            }
            clear_bit(VMX_CPU_STATE_PAE_ENABLED, &v->arch.arch_vmx.cpu_state);
        }

        __vmread(CR4_READ_SHADOW, &old_cr);

        __vmwrite(GUEST_CR4, value| VMX_CR4_HOST_MASK);
        __vmwrite(CR4_READ_SHADOW, value);

        /*
         * Writing to CR4 to modify the PSE, PGE, or PAE flag invalidates
         * all TLB entries except global entries.
         */
        if ((old_cr ^ value) & (X86_CR4_PSE | X86_CR4_PGE | X86_CR4_PAE)) {
            shadow_sync_all(v->domain);
        }
        break;
    }
    default:
        printk("invalid cr: %d\n", gp);
        __vmx_bug(regs);
    }

    return 1;
}

#define CASE_SET_REG(REG, reg)      \
    case REG_ ## REG:       \
    regs->reg = value;      \
    break

/*
 * Read from control registers. CR0 and CR4 are read from the shadow.
 */
static void mov_from_cr(int cr, int gp, struct cpu_user_regs *regs)
{
    unsigned long value;
    struct vcpu *v = current;

    if (cr != 3)
        __vmx_bug(regs);

    value = (unsigned long) v->arch.arch_vmx.cpu_cr3;

    switch (gp) {
        CASE_SET_REG(EAX, eax);
        CASE_SET_REG(ECX, ecx);
        CASE_SET_REG(EDX, edx);
        CASE_SET_REG(EBX, ebx);
        CASE_SET_REG(EBP, ebp);
        CASE_SET_REG(ESI, esi);
        CASE_SET_REG(EDI, edi);
        CASE_EXTEND_SET_REG
            case REG_ESP:
                __vmwrite(GUEST_RSP, value);
        regs->esp = value;
        break;
    default:
        printk("invalid gp: %d\n", gp);
        __vmx_bug(regs);
    }

    VMX_DBG_LOG(DBG_LEVEL_VMMU, "mov_from_cr: CR%d, value = %lx,", cr, value);
}

static int vmx_cr_access(unsigned long exit_qualification, struct cpu_user_regs *regs)
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
        clts();
        setup_fpu(current);

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
        __vmx_bug(regs);
        break;
    }
    return 1;
}

static inline void vmx_do_msr_read(struct cpu_user_regs *regs)
{
    u64 msr_content = 0;
    struct vcpu *v = current;

    VMX_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_read: ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);
    switch (regs->ecx) {
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
        if(long_mode_do_msr_read(regs))
            return;
        rdmsr_user(regs->ecx, regs->eax, regs->edx);
        break;
    }

    regs->eax = msr_content & 0xFFFFFFFF;
    regs->edx = msr_content >> 32;

    VMX_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_read returns: "
                "ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);
}

static inline void vmx_do_msr_write(struct cpu_user_regs *regs)
{
    u64 msr_content;
    struct vcpu *v = current;

    VMX_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_write: ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);

    msr_content = (regs->eax & 0xFFFFFFFF) | ((u64)regs->edx << 32);

    switch (regs->ecx) {
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
        long_mode_do_msr_write(regs);
        break;
    }

    VMX_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_write returns: "
                "ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);
}

/*
 * Need to use this exit to reschedule
 */
void vmx_vmexit_do_hlt(void)
{
    struct vcpu *v=current;
    struct vmx_virpit *vpit = &(v->domain->arch.vmx_platform.vmx_pit);
    s_time_t   next_pit=-1,next_wakeup;

    if ( !v->vcpu_id ) {
        next_pit = get_pit_scheduled(v,vpit);
    }
    next_wakeup = get_apictime_scheduled(v);
    if ( (next_pit != -1 && next_pit < next_wakeup) || next_wakeup == -1 ) {
        next_wakeup = next_pit;
    }
    if ( next_wakeup != - 1 ) 
        set_ac_timer(&current->arch.arch_vmx.hlt_timer, next_wakeup);
    do_block();
}

static inline void vmx_vmexit_do_extint(struct cpu_user_regs *regs)
{
    unsigned int vector;
    int error;

    asmlinkage void do_IRQ(struct cpu_user_regs *);
    void smp_apic_timer_interrupt(struct cpu_user_regs *);
    void timer_interrupt(int, void *, struct cpu_user_regs *);
    void smp_event_check_interrupt(void);
    void smp_invalidate_interrupt(void);
    void smp_call_function_interrupt(void);
    void smp_spurious_interrupt(struct cpu_user_regs *regs);
    void smp_error_interrupt(struct cpu_user_regs *regs);

    if ((error = __vmread(VM_EXIT_INTR_INFO, &vector))
        && !(vector & INTR_INFO_VALID_MASK))
        __vmx_bug(regs);

    vector &= 0xff;
    local_irq_disable();

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
    default:
        regs->entry_vector = vector;
        do_IRQ(regs);
        break;
    }
}

#define BUF_SIZ     256
#define MAX_LINE    80
char print_buf[BUF_SIZ];
static int index;

static void vmx_print_line(const char c, struct vcpu *v)
{

    if (index == MAX_LINE || c == '\n') {
        if (index == MAX_LINE) {
            print_buf[index++] = c;
        }
        print_buf[index] = '\0';
        printk("(GUEST: %u) %s\n", v->domain->domain_id, (char *) &print_buf);
        index = 0;
    }
    else
        print_buf[index++] = c;
}

void save_vmx_cpu_user_regs(struct cpu_user_regs *ctxt)
{
    __vmread(GUEST_SS_SELECTOR, &ctxt->ss);
    __vmread(GUEST_RSP, &ctxt->esp);
    __vmread(GUEST_RFLAGS, &ctxt->eflags);
    __vmread(GUEST_CS_SELECTOR, &ctxt->cs);
    __vmread(GUEST_RIP, &ctxt->eip);

    __vmread(GUEST_GS_SELECTOR, &ctxt->gs);
    __vmread(GUEST_FS_SELECTOR, &ctxt->fs);
    __vmread(GUEST_ES_SELECTOR, &ctxt->es);
    __vmread(GUEST_DS_SELECTOR, &ctxt->ds);
}

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

asmlinkage void vmx_vmexit_handler(struct cpu_user_regs regs)
{
    unsigned int exit_reason, idtv_info_field;
    unsigned long exit_qualification, eip, inst_len = 0;
    struct vcpu *v = current;
    int error;

    if ((error = __vmread(VM_EXIT_REASON, &exit_reason)))
        __vmx_bug(&regs);

    perfc_incra(vmexits, exit_reason);

    __vmread(IDT_VECTORING_INFO_FIELD, &idtv_info_field);
    if (idtv_info_field & INTR_INFO_VALID_MASK) {
        __vmwrite(VM_ENTRY_INTR_INFO_FIELD, idtv_info_field);

        __vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len);
        if (inst_len >= 1 && inst_len <= 15)
            __vmwrite(VM_ENTRY_INSTRUCTION_LEN, inst_len);

        if (idtv_info_field & 0x800) { /* valid error code */
            unsigned long error_code;
            __vmread(IDT_VECTORING_ERROR_CODE, &error_code);
            __vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
        }

        VMX_DBG_LOG(DBG_LEVEL_1, "idtv_info_field=%x", idtv_info_field);
    }

    /* don't bother H/W interrutps */
    if (exit_reason != EXIT_REASON_EXTERNAL_INTERRUPT &&
        exit_reason != EXIT_REASON_VMCALL &&
        exit_reason != EXIT_REASON_IO_INSTRUCTION)
        VMX_DBG_LOG(DBG_LEVEL_0, "exit reason = %x", exit_reason);

    if (exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) {
        printk("Failed vm entry\n");
        domain_crash_synchronous();
        return;
    }

    {
        __vmread(GUEST_RIP, &eip);
        TRACE_3D(TRC_VMX_VMEXIT, v->domain->domain_id, eip, exit_reason);
        TRACE_VMEXIT(0,exit_reason);
    }

    switch (exit_reason) {
    case EXIT_REASON_EXCEPTION_NMI:
    {
        /*
         * We don't set the software-interrupt exiting (INT n).
         * (1) We can get an exception (e.g. #PG) in the guest, or
         * (2) NMI
         */
        int error;
        unsigned int vector;
        unsigned long va;

        if ((error = __vmread(VM_EXIT_INTR_INFO, &vector))
            || !(vector & INTR_INFO_VALID_MASK))
            __vmx_bug(&regs);
        vector &= 0xff;

        TRACE_VMEXIT(1,vector);
        perfc_incra(cause_vector, vector);

        TRACE_3D(TRC_VMX_VECTOR, v->domain->domain_id, eip, vector);
        switch (vector) {
#ifdef XEN_DEBUGGER
        case TRAP_debug:
        {
            save_cpu_user_regs(&regs);
            pdb_handle_exception(1, &regs, 1);
            restore_cpu_user_regs(&regs);
            break;
        }
        case TRAP_int3:
        {
            save_cpu_user_regs(&regs);
            pdb_handle_exception(3, &regs, 1);
            restore_cpu_user_regs(&regs);
            break;
        }
#else
        case TRAP_debug:
        {
            void store_cpu_user_regs(struct cpu_user_regs *regs);
            long do_sched_op(unsigned long op);


            store_cpu_user_regs(&regs);
            __vm_clear_bit(GUEST_PENDING_DBG_EXCEPTIONS, PENDING_DEBUG_EXC_BS);

            domain_pause_for_debugger();
            do_sched_op(SCHEDOP_yield);

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
            __vmread(VM_EXIT_INTR_ERROR_CODE, &regs.error_code);

            TRACE_VMEXIT(3,regs.error_code);
            TRACE_VMEXIT(4,va);

            VMX_DBG_LOG(DBG_LEVEL_VMMU,
                        "eax=%lx, ebx=%lx, ecx=%lx, edx=%lx, esi=%lx, edi=%lx",
                        (unsigned long)regs.eax, (unsigned long)regs.ebx,
                        (unsigned long)regs.ecx, (unsigned long)regs.edx,
                        (unsigned long)regs.esi, (unsigned long)regs.edi);
            v->arch.arch_vmx.mmio_op.inst_decoder_regs = &regs;

            if (!(error = vmx_do_page_fault(va, &regs))) {
                /*
                 * Inject #PG using Interruption-Information Fields
                 */
                vmx_inject_exception(v, TRAP_page_fault, regs.error_code);
                v->arch.arch_vmx.cpu_cr2 = va;
                TRACE_3D(TRC_VMX_INT, v->domain->domain_id, TRAP_page_fault, va);
            }
            break;
        }
        case TRAP_nmi:
            do_nmi(&regs, 0);
            break;
        default:
            vmx_reflect_exception(v);
            break;
        }
        break;
    }
    case EXIT_REASON_EXTERNAL_INTERRUPT:
        vmx_vmexit_do_extint(&regs);
        break;
    case EXIT_REASON_PENDING_INTERRUPT:
        __vmwrite(CPU_BASED_VM_EXEC_CONTROL,
                  MONITOR_CPU_BASED_EXEC_CONTROLS);
        break;
    case EXIT_REASON_TASK_SWITCH:
        __vmx_bug(&regs);
        break;
    case EXIT_REASON_CPUID:
        __get_instruction_length(inst_len);
        vmx_vmexit_do_cpuid(regs.eax, &regs);
        __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_HLT:
        __get_instruction_length(inst_len);
        __update_guest_eip(inst_len);
        vmx_vmexit_do_hlt();
        break;
    case EXIT_REASON_INVLPG:
    {
        unsigned long   va;

        __vmread(EXIT_QUALIFICATION, &va);
        vmx_vmexit_do_invlpg(va);
        __get_instruction_length(inst_len);
        __update_guest_eip(inst_len);
        break;
    }
    case EXIT_REASON_VMCALL:
        __get_instruction_length(inst_len);
        __vmread(GUEST_RIP, &eip);
        __vmread(EXIT_QUALIFICATION, &exit_qualification);

        vmx_print_line(regs.eax, v); /* provides the current domain */
        __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_CR_ACCESS:
    {
        __vmread(GUEST_RIP, &eip);
        __get_instruction_length(inst_len);
        __vmread(EXIT_QUALIFICATION, &exit_qualification);

        VMX_DBG_LOG(DBG_LEVEL_1, "eip = %lx, inst_len =%lx, exit_qualification = %lx",
                    eip, inst_len, exit_qualification);
        if (vmx_cr_access(exit_qualification, &regs))
            __update_guest_eip(inst_len);
        TRACE_VMEXIT(3,regs.error_code);
        TRACE_VMEXIT(4,exit_qualification);
        break;
    }
    case EXIT_REASON_DR_ACCESS:
        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        vmx_dr_access(exit_qualification, &regs);
        __get_instruction_length(inst_len);
        __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_IO_INSTRUCTION:
        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        __get_instruction_length(inst_len);
        vmx_io_instruction(&regs, exit_qualification, inst_len);
        TRACE_VMEXIT(4,exit_qualification);
        break;
    case EXIT_REASON_MSR_READ:
        __get_instruction_length(inst_len);
        vmx_do_msr_read(&regs);
        __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_MSR_WRITE:
        __vmread(GUEST_RIP, &eip);
        vmx_do_msr_write(&regs);
        __get_instruction_length(inst_len);
        __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_MWAIT_INSTRUCTION:
        __vmx_bug(&regs);
        break;
    default:
        __vmx_bug(&regs);       /* should not happen */
    }
}

asmlinkage void load_cr2(void)
{
    struct vcpu *v = current;

    local_irq_disable();
#ifdef __i386__
    asm volatile("movl %0,%%cr2": :"r" (v->arch.arch_vmx.cpu_cr2));
#else
    asm volatile("movq %0,%%cr2": :"r" (v->arch.arch_vmx.cpu_cr2));
#endif
}

asmlinkage void trace_vmentry (void)
{
    TRACE_5D(TRC_VMENTRY,trace_values[current->processor][0],
             trace_values[current->processor][1],trace_values[current->processor][2],
             trace_values[current->processor][3],trace_values[current->processor][4]);
    TRACE_VMEXIT(0,9);
    TRACE_VMEXIT(1,9);
    TRACE_VMEXIT(2,9);
    TRACE_VMEXIT(3,9);
    TRACE_VMEXIT(4,9);
    return;
}
asmlinkage void trace_vmexit (void)
{
    TRACE_3D(TRC_VMEXIT,0,0,0);
    return;
}
#endif /* CONFIG_VMX */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
