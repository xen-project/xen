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
        .quad do_dom0_op
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
        .quad 0 /* do_switch_vm86 */
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
        .rept NR_hypercalls-((.-__hypercall_table)/8)
        .quad do_ni_hypercall
        .endr

        .globl hypercall_args_table
hypercall_args_table:	
        .byte 1 /* do_set_trap_table    */  /*  0 */
        .byte 4 /* do_mmu_update        */
        .byte 2 /* do_set_gdt           */
        .byte 2 /* do_stack_switch      */
        .byte 4 /* do_set_callbacks     */
        .byte 1 /* do_fpu_taskswitch    */  /*  5 */
        .byte 2 /* do_arch_sched_op     */
        .byte 1 /* do_dom0_op           */
        .byte 2 /* do_set_debugreg      */
        .byte 1 /* do_get_debugreg      */
        .byte 4 /* do_update_descriptor */  /* 10 */
        .byte 0 /* do_ni_hypercall      */
        .byte 2 /* do_memory_op         */
        .byte 2 /* do_multicall         */
        .byte 4 /* do_update_va_mapping */
        .byte 2 /* do_set_timer_op      */  /* 15 */
        .byte 1 /* do_event_channel_op  */
        .byte 2 /* do_xen_version       */
        .byte 3 /* do_console_io        */
        .byte 1 /* do_physdev_op        */
        .byte 3 /* do_grant_table_op    */  /* 20 */
        .byte 2 /* do_vm_assist         */
        .byte 5 /* do_update_va_mapping_otherdomain */
        .byte 0 /* do_switch_vm86       */
        .byte 2 /* do_boot_vcpu         */
        .byte 0 /* do_ni_hypercall      */  /* 25 */
        .byte 4 /* do_mmuext_op         */
        .byte 1 /* do_acm_op            */
        .byte 2 /* do_nmi_op            */
        .byte 2 /* do_arch_sched_op     */
        .byte 2 /* do_callback_op       */  /* 30 */
        .byte 2 /* do_xenoprof_op       */
        .byte 2 /* do_event_channel_op  */
        .byte 2 /* do_physdev_op        */
        .rept NR_hypercalls-(.-hypercall_args_table)
        .byte 0 /* do_ni_hypercall      */
        .endr
