#ifndef __ASM_DEFNS_H__
#define __ASM_DEFNS_H__

/* Offsets in 'struct xen_regs' --- AUTO-GENERATE ME! */
#define XREGS_ebx      0x00
#define XREGS_ecx      0x04
#define XREGS_edx      0x08
#define XREGS_esi      0x0C
#define XREGS_edi      0x10
#define XREGS_ebp      0x14
#define XREGS_eax      0x18
#define XREGS_orig_eax 0x1C
#define XREGS_eip      0x20
#define XREGS_cs       0x24
#define XREGS_eflags   0x28
#define XREGS_esp      0x2C
#define XREGS_ss       0x30
#define XREGS_es       0x34
#define XREGS_ds       0x38
#define XREGS_fs       0x3C
#define XREGS_gs       0x40

/* Offsets in 'struct domain' --- AUTO-GENERATE ME! */
#define DOMAIN_processor       0
#define DOMAIN_shared_info     4
#define DOMAIN_event_sel       8
#define DOMAIN_event_addr     12
#define DOMAIN_failsafe_sel   16
#define DOMAIN_failsafe_addr  20

/* Offsets in shared_info_t --- AUTO-GENERATE ME! */
#define SHINFO_upcall_pending /* 0 */
#define SHINFO_upcall_mask       1

/* Offsets in 'struct guest_trap_bounce' --- AUTO-GENERATE ME! */
#define GTB_error_code    0
#define GTB_cr2           4
#define GTB_flags         8
#define GTB_cs           10
#define GTB_eip          12
#define GTBF_TRAP         1
#define GTBF_TRAP_NOCODE  2
#define GTBF_TRAP_CR2     4

/* EFLAGS masks. */
#define CF_MASK 0x00000001
#define IF_MASK 0x00000200
#define NT_MASK 0x00004000

#define __STR(x) #x
#define STR(x) __STR(x)

/* AUTO-GENERATE the following two cases (quoted vs. unquoted). */
#ifndef __ASSEMBLY__

#define __SAVE_ALL_PRE(_reg) \
        "cld;" \
        "pushl %eax;" \
        "pushl %ebp;" \
        "pushl %edi;" \
        "pushl %esi;" \
        "pushl %edx;" \
        "pushl %ecx;" \
        "pushl %ebx;" \
        "movb "STR(XREGS_cs)"(%esp),%"STR(_reg)"l;" \
        "testb $3,%"STR(_reg)"l;" \
        "je 1f;" \
        "movl %ds,"STR(XREGS_ds)"(%esp);" \
        "movl %es,"STR(XREGS_es)"(%esp);" \
        "movl %fs,"STR(XREGS_fs)"(%esp);" \
        "movl %gs,"STR(XREGS_gs)"(%esp);"

#define SAVE_ALL_NOSEGREGS(_reg) \
        __SAVE_ALL_PRE(_reg) \
        "1:"

#define SET_XEN_SEGMENTS(_reg) \
        "movl $("STR(__HYPERVISOR_DS)"),%e"STR(_reg)"x;" \
        "movl %e"STR(_reg)"x,%ds;" \
        "movl %e"STR(_reg)"x,%es;"

#define SAVE_ALL(_reg) \
        __SAVE_ALL_PRE(_reg) \
        SET_XEN_SEGMENTS(_reg) \
        "1:"

#else

#define __SAVE_ALL_PRE(_reg) \
        cld; \
        pushl %eax; \
        pushl %ebp; \
        pushl %edi; \
        pushl %esi; \
        pushl %edx; \
        pushl %ecx; \
        pushl %ebx; \
        movb XREGS_cs(%esp),% ## _reg ## l; \
        testb $3,% ## _reg ## l; \
        je 1f; \
        movl %ds,XREGS_ds(%esp); \
        movl %es,XREGS_es(%esp); \
        movl %fs,XREGS_fs(%esp); \
        movl %gs,XREGS_gs(%esp);

#define SAVE_ALL_NOSEGREGS(_reg) \
        __SAVE_ALL_PRE(_reg) \
        1:

#define SET_XEN_SEGMENTS(_reg) \
        movl $(__HYPERVISOR_DS),%e ## _reg ## x; \
        movl %e ## _reg ## x,%ds; \
        movl %e ## _reg ## x,%es;

#define SAVE_ALL(_reg) \
        __SAVE_ALL_PRE(_reg) \
        SET_XEN_SEGMENTS(_reg) \
        1:

#endif

#endif /* __ASM_DEFNS_H__ */
