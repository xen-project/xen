
#ifndef __ARCH_SCHED_H__
#define __ARCH_SCHED_H__


static inline struct thread* get_current(void)
{
    struct thread **current;
#ifdef __i386__    
    register unsigned long sp asm("esp");
#else
    register unsigned long sp asm("rsp");
#endif 
    current = (void *)(sp & ~8191UL);
    return *current;
}

#ifdef __i386__
#define arch_switch_threads(prev, next) do {                            \
    unsigned long esi,edi;                                              \
    __asm__ __volatile__("pushfl\n\t"                                   \
                         "pushl %%ebp\n\t"                              \
                         "movl %%esp,%0\n\t"         /* save ESP */     \
                         "movl %4,%%esp\n\t"        /* restore ESP */   \
                         "movl $1f,%1\n\t"          /* save EIP */      \
                         "pushl %5\n\t"             /* restore EIP */   \
                         "ret\n\t"                                      \
                         "1:\t"                                         \
                         "popl %%ebp\n\t"                               \
                         "popfl"                                        \
                         :"=m" (prev->sp),"=m" (prev->ip),            \
                          "=S" (esi),"=D" (edi)             \
                         :"m" (next->sp),"m" (next->ip),              \
                          "2" (prev), "d" (next));                      \
} while (0)
#elif __x86_64__
#define arch_switch_threads(prev, next) do {                                 \
    unsigned long rsi,rdi;                                              \
    __asm__ __volatile__("pushfq\n\t"                                   \
                         "pushq %%rbp\n\t"                              \
                         "movq %%rsp,%0\n\t"         /* save RSP */     \
                         "movq %4,%%rsp\n\t"        /* restore RSP */   \
                         "movq $1f,%1\n\t"          /* save RIP */      \
                         "pushq %5\n\t"             /* restore RIP */   \
                         "ret\n\t"                                      \
                         "1:\t"                                         \
                         "popq %%rbp\n\t"                               \
                         "popfq"                                        \
                         :"=m" (prev->sp),"=m" (prev->ip),            \
                          "=S" (rsi),"=D" (rdi)             \
                         :"m" (next->sp),"m" (next->ip),              \
                          "2" (prev), "d" (next));                      \
} while (0)
#endif



          
#endif /* __ARCH_SCHED_H__ */
