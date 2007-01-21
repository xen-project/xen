/* from xen/arch/x86/x86_32/asm-offsets.c */

/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */

#include <xen/sched.h>
#include <public/xen.h>
#include <asm/powerpc64/procarea.h>
#include <asm/hardirq.h>

#define DEFINE(_sym, _val) \
    __asm__ __volatile__ ( "\n->" #_sym " %0 " #_val : : "i" (_val) )
#define BLANK() \
    __asm__ __volatile__ ( "\n->" : : )
#define OFFSET(_sym, _str, _mem) \
    DEFINE(_sym, offsetof(_str, _mem));

/* base-2 logarithm */
#define __L2(_x)  (((_x) & 0x00000002) ?   1 : 0)
#define __L4(_x)  (((_x) & 0x0000000c) ? ( 2 + __L2( (_x)>> 2)) : __L2( _x))
#define __L8(_x)  (((_x) & 0x000000f0) ? ( 4 + __L4( (_x)>> 4)) : __L4( _x))
#define __L16(_x) (((_x) & 0x0000ff00) ? ( 8 + __L8( (_x)>> 8)) : __L8( _x))
#define LOG_2(_x) (((_x) & 0xffff0000) ? (16 + __L16((_x)>>16)) : __L16(_x))

extern void __dummy__(void);
void __dummy__(void) 
{
    DEFINE(GPR_WIDTH, sizeof(unsigned long));
    DEFINE(FPR_WIDTH, sizeof(double));

    OFFSET(PAREA_vcpu, struct processor_area, cur_vcpu);
    OFFSET(PAREA_stack, struct processor_area, hyp_stack_base);
    OFFSET(PAREA_r1, struct processor_area, saved_regs[0]);
    OFFSET(PAREA_cr, struct processor_area, saved_regs[1]);

    OFFSET(UREGS_gprs, struct cpu_user_regs, gprs);
    OFFSET(UREGS_r0, struct cpu_user_regs, gprs[0]);
    OFFSET(UREGS_r1, struct cpu_user_regs, gprs[1]);
    OFFSET(UREGS_r13, struct cpu_user_regs, gprs[13]);
    OFFSET(UREGS_srr0, struct cpu_user_regs, srr0);
    OFFSET(UREGS_srr1, struct cpu_user_regs, srr1);
    OFFSET(UREGS_pc, struct cpu_user_regs, pc);
    OFFSET(UREGS_msr, struct cpu_user_regs, msr);
    OFFSET(UREGS_lr, struct cpu_user_regs, lr);
    OFFSET(UREGS_ctr, struct cpu_user_regs, ctr);
    OFFSET(UREGS_xer, struct cpu_user_regs, xer);
    OFFSET(UREGS_hid4, struct cpu_user_regs, hid4);
    OFFSET(UREGS_dar, struct cpu_user_regs, dar);
    OFFSET(UREGS_dsisr, struct cpu_user_regs, dsisr);
    OFFSET(UREGS_cr, struct cpu_user_regs, cr);
    OFFSET(UREGS_fpscr, struct cpu_user_regs, fpscr);
    DEFINE(UREGS_sizeof, sizeof(struct cpu_user_regs));

    OFFSET(VCPU_fprs, struct vcpu, arch.fprs);
    OFFSET(VCPU_fpscr, struct vcpu, arch.ctxt.fpscr);
    OFFSET(VCPU_vrs, struct vcpu, arch.vrs);
    OFFSET(VCPU_vscr, struct vcpu, arch.vscr);
    OFFSET(VCPU_vrsave, struct vcpu, arch.vrsave);
    OFFSET(VCPU_dec, struct vcpu, arch.dec);
    OFFSET(VCPU_processor, struct vcpu, processor);

    DEFINE(IRQSTAT_shift, LOG_2(sizeof(irq_cpustat_t)));
    OFFSET(IRQSTAT_pending, irq_cpustat_t, __softirq_pending);
}
