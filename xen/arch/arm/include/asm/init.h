#ifndef _XEN_ASM_INIT_H
#define _XEN_ASM_INIT_H

struct init_info
{
    /* Pointer to the stack, used by head.S when entering in C */
    unsigned char *stack;
    /* Logical CPU ID, used by start_secondary */
    unsigned int cpuid;
};

#endif /* _XEN_ASM_INIT_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
