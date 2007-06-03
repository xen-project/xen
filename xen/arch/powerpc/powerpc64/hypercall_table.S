#include <asm/config.h>

        .data
        .align 3
        .globl __hypercall_table
__hypercall_table:
        .quad 0 /* do_set_trap_table */    /*  0 */
        .quad 0 /* do_mmu_update */
        .quad 0 /* do_set_gdt */
        .quad 0 /* do_stack_switch */
        .quad 0 /* do_set_callbacks */
        .quad 0 /* do_fpu_taskswitch */     /*  5 */
        .quad do_sched_op
        .quad 0 /* do_platform_op */
        .quad 0 /* do_set_debugreg */
        .quad 0 /* do_get_debugreg */
        .quad 0 /* do_update_descriptor */  /* 10 */
        .quad do_ni_hypercall
        .quad do_memory_op
        .quad 0 /* do_multicall */
        .quad 0 /* do_update_va_mapping */
        .quad do_set_timer_op       /* 15 */
        .quad 0 /* do_event_channel_op_compat */
        .quad do_xen_version
        .quad do_console_io
        .quad 0 /* do_physdev_op_compat */
        .quad do_grant_table_op     /* 20 */
        .quad do_vm_assist
        .quad 0 /* do_update_va_mapping_otherdomain */
        .quad do_rtas_proxy /* do_switch_vm86 */
        .quad do_vcpu_op
        .quad do_ni_hypercall       /* 25 */
        .quad 0 /* do_mmuext_op */
        .quad do_acm_op
        .quad do_nmi_op
        .quad do_sched_op /* do_arch_sched_op */
        .quad 0 /* do_callback_op */        /* 30 */
        .quad 0 /* do_xenoprof_op */
        .quad do_event_channel_op
        .quad do_physdev_op
        .quad 0 /* do_hvm_op */
        .quad do_sysctl             /* 35 */
        .quad do_domctl
        .rept NR_hypercalls-((.-__hypercall_table)/8)
        .quad do_ni_hypercall
        .endr
