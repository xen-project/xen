#include <asm/page.h>
#include <asm/asm_defns.h>
#include <public/xen.h>

        .section ".text.page_aligned", "ax", @progbits
        .p2align PAGE_SHIFT

GLOBAL(hypercall_page)
         /* Poisoned with `ret` for safety before hypercalls are set up. */
        .fill PAGE_SIZE, 1, 0xc3
        .type hypercall_page, STT_OBJECT
        .size hypercall_page, PAGE_SIZE

/*
 * Identify a specific hypercall in the hypercall page
 * @param name Hypercall name.
 */
#define DECLARE_HYPERCALL(name)                                                 \
        .globl HYPERCALL_ ## name;                                              \
        .set   HYPERCALL_ ## name, hypercall_page + __HYPERVISOR_ ## name * 32; \
        .type  HYPERCALL_ ## name, STT_FUNC;                                    \
        .size  HYPERCALL_ ## name, 32

DECLARE_HYPERCALL(set_trap_table)
DECLARE_HYPERCALL(mmu_update)
DECLARE_HYPERCALL(set_gdt)
DECLARE_HYPERCALL(stack_switch)
DECLARE_HYPERCALL(set_callbacks)
DECLARE_HYPERCALL(fpu_taskswitch)
DECLARE_HYPERCALL(sched_op_compat)
DECLARE_HYPERCALL(platform_op)
DECLARE_HYPERCALL(set_debugreg)
DECLARE_HYPERCALL(get_debugreg)
DECLARE_HYPERCALL(update_descriptor)
DECLARE_HYPERCALL(memory_op)
DECLARE_HYPERCALL(multicall)
DECLARE_HYPERCALL(update_va_mapping)
DECLARE_HYPERCALL(set_timer_op)
DECLARE_HYPERCALL(event_channel_op_compat)
DECLARE_HYPERCALL(xen_version)
DECLARE_HYPERCALL(console_io)
DECLARE_HYPERCALL(physdev_op_compat)
DECLARE_HYPERCALL(grant_table_op)
DECLARE_HYPERCALL(vm_assist)
DECLARE_HYPERCALL(update_va_mapping_otherdomain)
DECLARE_HYPERCALL(iret)
DECLARE_HYPERCALL(vcpu_op)
DECLARE_HYPERCALL(set_segment_base)
DECLARE_HYPERCALL(mmuext_op)
DECLARE_HYPERCALL(xsm_op)
DECLARE_HYPERCALL(nmi_op)
DECLARE_HYPERCALL(sched_op)
DECLARE_HYPERCALL(callback_op)
DECLARE_HYPERCALL(xenoprof_op)
DECLARE_HYPERCALL(event_channel_op)
DECLARE_HYPERCALL(physdev_op)
DECLARE_HYPERCALL(hvm_op)
DECLARE_HYPERCALL(sysctl)
DECLARE_HYPERCALL(domctl)
DECLARE_HYPERCALL(kexec_op)
DECLARE_HYPERCALL(argo_op)
DECLARE_HYPERCALL(xenpmu_op)

DECLARE_HYPERCALL(arch_0)
DECLARE_HYPERCALL(arch_1)
DECLARE_HYPERCALL(arch_2)
DECLARE_HYPERCALL(arch_3)
DECLARE_HYPERCALL(arch_4)
DECLARE_HYPERCALL(arch_5)
DECLARE_HYPERCALL(arch_6)
DECLARE_HYPERCALL(arch_7)

/*
 * Local variables:
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 */
