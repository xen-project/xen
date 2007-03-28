/*
 * vmcs.c: VMCS management
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
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/domain_page.h>
#include <asm/current.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/flushtlb.h>
#include <xen/event.h>
#include <xen/kernel.h>
#include <xen/keyhandler.h>
#include <asm/shadow.h>

/* Basic flags for Pin-based VM-execution controls. */
#define MONITOR_PIN_BASED_EXEC_CONTROLS                 \
    ( PIN_BASED_EXT_INTR_MASK |                         \
      PIN_BASED_NMI_EXITING )

/* Basic flags for CPU-based VM-execution controls. */
#ifdef __x86_64__
#define MONITOR_CPU_BASED_EXEC_CONTROLS_SUBARCH         \
    ( CPU_BASED_CR8_LOAD_EXITING |                      \
      CPU_BASED_CR8_STORE_EXITING )
#else
#define MONITOR_CPU_BASED_EXEC_CONTROLS_SUBARCH 0
#endif
#define MONITOR_CPU_BASED_EXEC_CONTROLS                 \
    ( MONITOR_CPU_BASED_EXEC_CONTROLS_SUBARCH |         \
      CPU_BASED_HLT_EXITING |                           \
      CPU_BASED_INVDPG_EXITING |                        \
      CPU_BASED_MWAIT_EXITING |                         \
      CPU_BASED_MOV_DR_EXITING |                        \
      CPU_BASED_ACTIVATE_IO_BITMAP |                    \
      CPU_BASED_USE_TSC_OFFSETING )

/* Basic flags for VM-Exit controls. */
#ifdef __x86_64__
#define MONITOR_VM_EXIT_CONTROLS_SUBARCH VM_EXIT_IA32E_MODE
#else
#define MONITOR_VM_EXIT_CONTROLS_SUBARCH 0
#endif
#define MONITOR_VM_EXIT_CONTROLS                        \
    ( MONITOR_VM_EXIT_CONTROLS_SUBARCH |                \
      VM_EXIT_ACK_INTR_ON_EXIT )

/* Basic flags for VM-Entry controls. */
#define MONITOR_VM_ENTRY_CONTROLS                       0x00000000

/* Dynamic (run-time adjusted) execution control flags. */
static u32 vmx_pin_based_exec_control;
static u32 vmx_cpu_based_exec_control;
static u32 vmx_vmexit_control;
static u32 vmx_vmentry_control;

static u32 vmcs_revision_id;

static u32 adjust_vmx_controls(u32 ctrls, u32 msr)
{
    u32 vmx_msr_low, vmx_msr_high;

    rdmsr(msr, vmx_msr_low, vmx_msr_high);

    /* Bit == 0 means must be zero. */
    BUG_ON(ctrls & ~vmx_msr_high);

    /* Bit == 1 means must be one. */
    ctrls |= vmx_msr_low;

    return ctrls;
}

void vmx_init_vmcs_config(void)
{
    u32 vmx_msr_low, vmx_msr_high;
    u32 _vmx_pin_based_exec_control;
    u32 _vmx_cpu_based_exec_control;
    u32 _vmx_vmexit_control;
    u32 _vmx_vmentry_control;

    _vmx_pin_based_exec_control =
        adjust_vmx_controls(MONITOR_PIN_BASED_EXEC_CONTROLS,
                            MSR_IA32_VMX_PINBASED_CTLS_MSR);
    _vmx_cpu_based_exec_control =
        adjust_vmx_controls(MONITOR_CPU_BASED_EXEC_CONTROLS,
                            MSR_IA32_VMX_PROCBASED_CTLS_MSR);
    _vmx_vmexit_control =
        adjust_vmx_controls(MONITOR_VM_EXIT_CONTROLS,
                            MSR_IA32_VMX_EXIT_CTLS_MSR);
    _vmx_vmentry_control =
        adjust_vmx_controls(MONITOR_VM_ENTRY_CONTROLS,
                            MSR_IA32_VMX_ENTRY_CTLS_MSR);

    rdmsr(MSR_IA32_VMX_BASIC_MSR, vmx_msr_low, vmx_msr_high);

    if ( smp_processor_id() == 0 )
    {
        vmcs_revision_id = vmx_msr_low;
        vmx_pin_based_exec_control = _vmx_pin_based_exec_control;
        vmx_cpu_based_exec_control = _vmx_cpu_based_exec_control;
        vmx_vmexit_control         = _vmx_vmexit_control;
        vmx_vmentry_control        = _vmx_vmentry_control;
    }
    else
    {
        BUG_ON(vmcs_revision_id != vmx_msr_low);
        BUG_ON(vmx_pin_based_exec_control != _vmx_pin_based_exec_control);
        BUG_ON(vmx_cpu_based_exec_control != _vmx_cpu_based_exec_control);
        BUG_ON(vmx_vmexit_control != _vmx_vmexit_control);
        BUG_ON(vmx_vmentry_control != _vmx_vmentry_control);
    }

    /* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
    BUG_ON((vmx_msr_high & 0x1fff) > PAGE_SIZE);
}

static struct vmcs_struct *vmx_alloc_vmcs(void)
{
    struct vmcs_struct *vmcs;

    if ( (vmcs = alloc_xenheap_page()) == NULL )
    {
        gdprintk(XENLOG_WARNING, "Failed to allocate VMCS.\n");
        return NULL;
    }

    memset(vmcs, 0, PAGE_SIZE);
    vmcs->vmcs_revision_id = vmcs_revision_id;

    return vmcs;
}

static void vmx_free_vmcs(struct vmcs_struct *vmcs)
{
    free_xenheap_page(vmcs);
}

static void __vmx_clear_vmcs(void *info)
{
    struct vcpu *v = info;

    __vmpclear(virt_to_maddr(v->arch.hvm_vmx.vmcs));

    v->arch.hvm_vmx.active_cpu = -1;
    v->arch.hvm_vmx.launched   = 0;
}

static void vmx_clear_vmcs(struct vcpu *v)
{
    int cpu = v->arch.hvm_vmx.active_cpu;

    if ( cpu == -1 )
        return;

    if ( cpu == smp_processor_id() )
        return __vmx_clear_vmcs(v);

    on_selected_cpus(cpumask_of_cpu(cpu), __vmx_clear_vmcs, v, 1, 1);
}

static void vmx_load_vmcs(struct vcpu *v)
{
    __vmptrld(virt_to_maddr(v->arch.hvm_vmx.vmcs));
    v->arch.hvm_vmx.active_cpu = smp_processor_id();
}

void vmx_vmcs_enter(struct vcpu *v)
{
    /*
     * NB. We must *always* run an HVM VCPU on its own VMCS, except for
     * vmx_vmcs_enter/exit critical regions.
     */
    if ( v == current )
        return;

    vcpu_pause(v);
    spin_lock(&v->arch.hvm_vmx.vmcs_lock);

    vmx_clear_vmcs(v);
    vmx_load_vmcs(v);
}

void vmx_vmcs_exit(struct vcpu *v)
{
    if ( v == current )
        return;

    /* Don't confuse vmx_do_resume (for @v or @current!) */
    vmx_clear_vmcs(v);
    if ( is_hvm_vcpu(current) )
        vmx_load_vmcs(current);

    spin_unlock(&v->arch.hvm_vmx.vmcs_lock);
    vcpu_unpause(v);
}

struct vmcs_struct *vmx_alloc_host_vmcs(void)
{
    return vmx_alloc_vmcs();
}

void vmx_free_host_vmcs(struct vmcs_struct *vmcs)
{
    vmx_free_vmcs(vmcs);
}

#define GUEST_SEGMENT_LIMIT     0xffffffff

struct host_execution_env {
    /* selectors */
    unsigned short ldtr_selector;
    unsigned short tr_selector;
    unsigned short ds_selector;
    unsigned short cs_selector;
    /* limits */
    unsigned short gdtr_limit;
    unsigned short ldtr_limit;
    unsigned short idtr_limit;
    unsigned short tr_limit;
    /* base */
    unsigned long gdtr_base;
    unsigned long ldtr_base;
    unsigned long idtr_base;
    unsigned long tr_base;
    unsigned long ds_base;
    unsigned long cs_base;
#ifdef __x86_64__
    unsigned long fs_base;
    unsigned long gs_base;
#endif
};

static void vmx_set_host_env(struct vcpu *v)
{
    unsigned int tr, cpu;
    struct host_execution_env host_env;
    struct Xgt_desc_struct desc;

    cpu = smp_processor_id();
    __asm__ __volatile__ ("sidt  (%0) \n" :: "a"(&desc) : "memory");
    host_env.idtr_limit = desc.size;
    host_env.idtr_base = desc.address;
    __vmwrite(HOST_IDTR_BASE, host_env.idtr_base);

    __asm__ __volatile__ ("sgdt  (%0) \n" :: "a"(&desc) : "memory");
    host_env.gdtr_limit = desc.size;
    host_env.gdtr_base = desc.address;
    __vmwrite(HOST_GDTR_BASE, host_env.gdtr_base);

    __asm__ __volatile__ ("str  (%0) \n" :: "a"(&tr) : "memory");
    host_env.tr_selector = tr;
    host_env.tr_limit = sizeof(struct tss_struct);
    host_env.tr_base = (unsigned long) &init_tss[cpu];
    __vmwrite(HOST_TR_SELECTOR, host_env.tr_selector);
    __vmwrite(HOST_TR_BASE, host_env.tr_base);

    /*
     * Skip end of cpu_user_regs when entering the hypervisor because the
     * CPU does not save context onto the stack. SS,RSP,CS,RIP,RFLAGS,etc
     * all get saved into the VMCS instead.
     */
    __vmwrite(HOST_RSP,
              (unsigned long)&get_cpu_info()->guest_cpu_user_regs.error_code);
}

static void construct_vmcs(struct vcpu *v)
{
    unsigned long cr0, cr4;
    union vmcs_arbytes arbytes;

    vmx_vmcs_enter(v);

    v->arch.hvm_vmx.cpu_cr2 = 0;
    v->arch.hvm_vmx.cpu_cr3 = 0;
    memset(&v->arch.hvm_vmx.msr_state, 0, sizeof(v->arch.hvm_vmx.msr_state));
    v->arch.hvm_vmx.vmxassist_enabled = 0;

    /* VMCS controls. */
    __vmwrite(PIN_BASED_VM_EXEC_CONTROL, vmx_pin_based_exec_control);
    __vmwrite(VM_EXIT_CONTROLS, vmx_vmexit_control);
    __vmwrite(VM_ENTRY_CONTROLS, vmx_vmentry_control);
    __vmwrite(CPU_BASED_VM_EXEC_CONTROL, vmx_cpu_based_exec_control);
    v->arch.hvm_vcpu.u.vmx.exec_control = vmx_cpu_based_exec_control;

    /* I/O access bitmap. */
    __vmwrite(IO_BITMAP_A, virt_to_maddr(hvm_io_bitmap));
    __vmwrite(IO_BITMAP_B, virt_to_maddr(hvm_io_bitmap + PAGE_SIZE));

    /* Host data selectors. */
    __vmwrite(HOST_SS_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_DS_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_ES_SELECTOR, __HYPERVISOR_DS);
#if defined(__i386__)
    __vmwrite(HOST_FS_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_GS_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_FS_BASE, 0);
    __vmwrite(HOST_GS_BASE, 0);
#elif defined(__x86_64__)
    {
        unsigned long msr;
        rdmsrl(MSR_FS_BASE, msr); __vmwrite(HOST_FS_BASE, msr);
        rdmsrl(MSR_GS_BASE, msr); __vmwrite(HOST_GS_BASE, msr);
    }
#endif

    /* Host control registers. */
    __vmwrite(HOST_CR0, read_cr0());
    __vmwrite(HOST_CR4, read_cr4());

    /* Host CS:RIP. */
    __vmwrite(HOST_CS_SELECTOR, __HYPERVISOR_CS);
    __vmwrite(HOST_RIP, (unsigned long)vmx_asm_vmexit_handler);

    /* MSR intercepts. */
    __vmwrite(VM_EXIT_MSR_LOAD_ADDR, 0);
    __vmwrite(VM_EXIT_MSR_STORE_ADDR, 0);
    __vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
    __vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
    __vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);

    __vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

    __vmwrite(CR0_GUEST_HOST_MASK, ~0UL);
    __vmwrite(CR4_GUEST_HOST_MASK, ~0UL);

    __vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
    __vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

    __vmwrite(CR3_TARGET_COUNT, 0);

    __vmwrite(GUEST_ACTIVITY_STATE, 0);

    /* Guest segment bases. */
    __vmwrite(GUEST_ES_BASE, 0);
    __vmwrite(GUEST_SS_BASE, 0);
    __vmwrite(GUEST_DS_BASE, 0);
    __vmwrite(GUEST_FS_BASE, 0);
    __vmwrite(GUEST_GS_BASE, 0);
    __vmwrite(GUEST_CS_BASE, 0);

    /* Guest segment limits. */
    __vmwrite(GUEST_ES_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_SS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_DS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_FS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_GS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_CS_LIMIT, GUEST_SEGMENT_LIMIT);

    /* Guest segment AR bytes. */
    arbytes.bytes = 0;
    arbytes.fields.seg_type = 0x3;          /* type = 3 */
    arbytes.fields.s = 1;                   /* code or data, i.e. not system */
    arbytes.fields.dpl = 0;                 /* DPL = 3 */
    arbytes.fields.p = 1;                   /* segment present */
    arbytes.fields.default_ops_size = 1;    /* 32-bit */
    arbytes.fields.g = 1;
    arbytes.fields.null_bit = 0;            /* not null */
    __vmwrite(GUEST_ES_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_SS_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_DS_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_FS_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_GS_AR_BYTES, arbytes.bytes);
    arbytes.fields.seg_type = 0xb;          /* type = 0xb */
    __vmwrite(GUEST_CS_AR_BYTES, arbytes.bytes);

    /* Guest GDT. */
    __vmwrite(GUEST_GDTR_BASE, 0);
    __vmwrite(GUEST_GDTR_LIMIT, 0);

    /* Guest IDT. */
    __vmwrite(GUEST_IDTR_BASE, 0);
    __vmwrite(GUEST_IDTR_LIMIT, 0);

    /* Guest LDT and TSS. */
    arbytes.fields.s = 0;                   /* not code or data segement */
    arbytes.fields.seg_type = 0x2;          /* LTD */
    arbytes.fields.default_ops_size = 0;    /* 16-bit */
    arbytes.fields.g = 0;
    __vmwrite(GUEST_LDTR_AR_BYTES, arbytes.bytes);
    arbytes.fields.seg_type = 0xb;          /* 32-bit TSS (busy) */
    __vmwrite(GUEST_TR_AR_BYTES, arbytes.bytes);

    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    __vmwrite(GUEST_DR7, 0);
    __vmwrite(VMCS_LINK_POINTER, ~0UL);
#if defined(__i386__)
    __vmwrite(VMCS_LINK_POINTER_HIGH, ~0UL);
#endif

    __vmwrite(EXCEPTION_BITMAP, 1U << TRAP_page_fault);

    /* Guest CR0. */
    cr0 = read_cr0();
    v->arch.hvm_vmx.cpu_cr0 = cr0;
    __vmwrite(GUEST_CR0, v->arch.hvm_vmx.cpu_cr0);
    v->arch.hvm_vmx.cpu_shadow_cr0 = cr0 & ~(X86_CR0_PG | X86_CR0_TS);
    __vmwrite(CR0_READ_SHADOW, v->arch.hvm_vmx.cpu_shadow_cr0);

    /* Guest CR4. */
    cr4 = read_cr4();
    __vmwrite(GUEST_CR4, cr4 & ~X86_CR4_PSE);
    v->arch.hvm_vmx.cpu_shadow_cr4 =
        cr4 & ~(X86_CR4_PGE | X86_CR4_VMXE | X86_CR4_PAE);
    __vmwrite(CR4_READ_SHADOW, v->arch.hvm_vmx.cpu_shadow_cr4);

#ifdef __x86_64__ 
    /* VLAPIC TPR optimisation. */
    v->arch.hvm_vcpu.u.vmx.exec_control |= CPU_BASED_TPR_SHADOW;
    v->arch.hvm_vcpu.u.vmx.exec_control &=
        ~(CPU_BASED_CR8_STORE_EXITING | CPU_BASED_CR8_LOAD_EXITING);
    __vmwrite(CPU_BASED_VM_EXEC_CONTROL, v->arch.hvm_vcpu.u.vmx.exec_control);
    __vmwrite(VIRTUAL_APIC_PAGE_ADDR,
              page_to_maddr(vcpu_vlapic(v)->regs_page));
    __vmwrite(TPR_THRESHOLD, 0);
#endif

    __vmwrite(GUEST_LDTR_SELECTOR, 0);
    __vmwrite(GUEST_LDTR_BASE, 0);
    __vmwrite(GUEST_LDTR_LIMIT, 0);

    __vmwrite(GUEST_TR_BASE, 0);
    __vmwrite(GUEST_TR_LIMIT, 0xff);

    vmx_vmcs_exit(v);

    paging_update_paging_modes(v); /* will update HOST & GUEST_CR3 as reqd */
}

int vmx_create_vmcs(struct vcpu *v)
{
    if ( v->arch.hvm_vmx.vmcs == NULL )
    {
        if ( (v->arch.hvm_vmx.vmcs = vmx_alloc_vmcs()) == NULL )
            return -ENOMEM;

        __vmx_clear_vmcs(v);
    }

    construct_vmcs(v);

    return 0;
}

void vmx_destroy_vmcs(struct vcpu *v)
{
    struct arch_vmx_struct *arch_vmx = &v->arch.hvm_vmx;

    if ( arch_vmx->vmcs == NULL )
        return;

    vmx_clear_vmcs(v);

    vmx_free_vmcs(arch_vmx->vmcs);
    arch_vmx->vmcs = NULL;
}

void vm_launch_fail(unsigned long eflags)
{
    unsigned long error = __vmread(VM_INSTRUCTION_ERROR);
    printk("<vm_launch_fail> error code %lx\n", error);
    domain_crash_synchronous();
}

void vm_resume_fail(unsigned long eflags)
{
    unsigned long error = __vmread(VM_INSTRUCTION_ERROR);
    printk("<vm_resume_fail> error code %lx\n", error);
    domain_crash_synchronous();
}

void vmx_do_resume(struct vcpu *v)
{
    bool_t debug_state;

    if ( v->arch.hvm_vmx.active_cpu == smp_processor_id() )
    {
        vmx_load_vmcs(v);
    }
    else
    {
        vmx_clear_vmcs(v);
        vmx_load_vmcs(v);
        hvm_migrate_timers(v);
        vmx_set_host_env(v);
    }

    debug_state = v->domain->debugger_attached;
    if ( unlikely(v->arch.hvm_vcpu.debug_state_latch != debug_state) )
    {
        unsigned long intercepts = __vmread(EXCEPTION_BITMAP);
        unsigned long mask = (1U << TRAP_debug) | (1U << TRAP_int3);
        v->arch.hvm_vcpu.debug_state_latch = debug_state;
        if ( debug_state )
            intercepts |= mask;
        else
            intercepts &= ~mask;
        __vmwrite(EXCEPTION_BITMAP, intercepts);
    }

    hvm_do_resume(v);
    reset_stack_and_jump(vmx_asm_do_vmentry);
}

/* Dump a section of VMCS */
static void print_section(char *header, uint32_t start, 
                          uint32_t end, int incr)
{
    uint32_t addr, j;
    unsigned long val;
    int code, rc;
    char *fmt[4] = {"0x%04lx ", "0x%016lx ", "0x%08lx ", "0x%016lx "};
    char *err[4] = {"------ ", "------------------ ", 
                    "---------- ", "------------------ "};

    /* Find width of the field (encoded in bits 14:13 of address) */
    code = (start>>13)&3;

    if (header)
        printk("\t %s", header);

    for (addr=start, j=0; addr<=end; addr+=incr, j++) {

        if (!(j&3))
            printk("\n\t\t0x%08x: ", addr);

        val = __vmread_safe(addr, &rc);
        if (rc == 0)
            printk(fmt[code], val);
        else
            printk("%s", err[code]);
    }

    printk("\n");
}

/* Dump current VMCS */
void vmcs_dump_vcpu(void)
{
    print_section("16-bit Guest-State Fields", 0x800, 0x80e, 2);
    print_section("16-bit Host-State Fields", 0xc00, 0xc0c, 2);
    print_section("64-bit Control Fields", 0x2000, 0x2013, 1);
    print_section("64-bit Guest-State Fields", 0x2800, 0x2803, 1);
    print_section("32-bit Control Fields", 0x4000, 0x401c, 2);
    print_section("32-bit RO Data Fields", 0x4400, 0x440e, 2);
    print_section("32-bit Guest-State Fields", 0x4800, 0x482a, 2);
    print_section("32-bit Host-State Fields", 0x4c00, 0x4c00, 2);
    print_section("Natural 64-bit Control Fields", 0x6000, 0x600e, 2);
    print_section("64-bit RO Data Fields", 0x6400, 0x640A, 2);
    print_section("Natural 64-bit Guest-State Fields", 0x6800, 0x6826, 2);
    print_section("Natural 64-bit Host-State Fields", 0x6c00, 0x6c16, 2);
}


static void vmcs_dump(unsigned char ch)
{
    struct domain *d;
    struct vcpu *v;
    
    printk("*********** VMCS Areas **************\n");

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
    {
        if ( !is_hvm_domain(d) )
            continue;
        printk("\n>>> Domain %d <<<\n", d->domain_id);
        for_each_vcpu ( d, v )
        {
            printk("\tVCPU %d\n", v->vcpu_id);
            vmx_vmcs_enter(v);
            vmcs_dump_vcpu();
            vmx_vmcs_exit(v);
        }
    }

    rcu_read_unlock(&domlist_read_lock);

    printk("**************************************\n");
}

void setup_vmcs_dump(void)
{
    register_keyhandler('v', vmcs_dump, "dump Intel's VMCS");
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
