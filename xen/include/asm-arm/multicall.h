#ifndef __ASM_ARM_MULTICALL_H__
#define __ASM_ARM_MULTICALL_H__

#define do_multicall_call(_call)                             \
    do {                                                     \
        __asm__ __volatile__ (                               \
            ".word 0xe7f000f0@; do_multicall_call\n"         \
            "    mov r0,#0; @ do_multicall_call\n"           \
            "    str r0, [r0];\n"                            \
            :                                                \
            :                                                \
            : );                                             \
    } while ( 0 )

#endif /* __ASM_ARM_MULTICALL_H__ */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
