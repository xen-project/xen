#ifndef __ASM_DEFNS_H__
#define __ASM_DEFNS_H__

/* NB. Auto-generated from arch/.../asm-offsets.c */
#include <asm/asm-offsets.h>
#include <asm/processor.h>

#define __STR(x) #x
#define STR(x) __STR(x)

/* Maybe auto-generate the following two cases (quoted vs. unquoted). */
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
