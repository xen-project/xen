#ifndef __X86_64_ELF_H__
#define __X86_64_ELF_H__

#include <asm/msr.h>
#include <asm/regs.h>

typedef struct {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long orig_rax;
    unsigned long rip;
    unsigned long cs;
    unsigned long rflags;
    unsigned long rsp;
    unsigned long ss;
    unsigned long thread_fs;
    unsigned long thread_gs;
    unsigned long ds;
    unsigned long es;
    unsigned long fs;
    unsigned long gs;
} ELF_Gregset;

static inline void elf_core_save_regs(ELF_Gregset *core_regs,
                                      crash_xen_core_t *xen_core_regs)
{
    asm ( "movq %%r15, %0" : "=m" (core_regs->r15) );
    asm ( "movq %%r14, %0" : "=m" (core_regs->r14) );
    asm ( "movq %%r13, %0" : "=m" (core_regs->r13) );
    asm ( "movq %%r12, %0" : "=m" (core_regs->r12) );
    asm ( "movq %%rbp, %0" : "=m" (core_regs->rbp) );
    asm ( "movq %%rbx, %0" : "=m" (core_regs->rbx) );
    asm ( "movq %%r11, %0" : "=m" (core_regs->r11) );
    asm ( "movq %%r10, %0" : "=m" (core_regs->r10) );
    asm ( "movq %%r9, %0" : "=m" (core_regs->r9) );
    asm ( "movq %%r8, %0" : "=m" (core_regs->r8) );
    asm ( "movq %%rax, %0" : "=m" (core_regs->rax) );
    asm ( "movq %%rcx, %0" : "=m" (core_regs->rcx) );
    asm ( "movq %%rdx, %0" : "=m" (core_regs->rdx) );
    asm ( "movq %%rsi, %0" : "=m" (core_regs->rsi) );
    asm ( "movq %%rdi, %0" : "=m" (core_regs->rdi) );

    /* orig_rax not filled in for now */
    asm ( "lea (%%rip), %0" : "=r" (core_regs->rip) );
    asm ( "mov %%cs, %0" : "=m" (core_regs->cs) );
    asm ( "pushfq; popq %0" : "=m" (core_regs->rflags) ASM_CALL_CONSTRAINT );
    asm ( "movq %%rsp, %0" : "=m" (core_regs->rsp) );
    asm ( "mov %%ss, %0" : "=m" (core_regs->ss) );
    rdmsrl(MSR_FS_BASE, core_regs->thread_fs);
    rdmsrl(MSR_GS_BASE, core_regs->thread_gs);
    asm ( "mov %%ds, %0" : "=m" (core_regs->ds) );
    asm ( "mov %%es, %0" : "=m" (core_regs->es) );
    asm ( "mov %%fs, %0" : "=m" (core_regs->fs) );
    asm ( "mov %%gs, %0" : "=m" (core_regs->gs) );

    asm ( "mov %%cr0, %0" : "=r" (xen_core_regs->cr0) );
    asm ( "mov %%cr2, %0" : "=r" (xen_core_regs->cr2) );
    asm ( "mov %%cr3, %0" : "=r" (xen_core_regs->cr3) );
    asm ( "mov %%cr4, %0" : "=r" (xen_core_regs->cr4) );
}

#endif /* __X86_64_ELF_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
