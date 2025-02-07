#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/processor.h>
#include <asm/riscv_encoding.h>
#include <asm/traps.h>

/* WIP: only works while interrupting Xen context */
FUNC(handle_trap)

    /* Exceptions from xen */
save_to_stack:
        /* Save context to stack */
        REG_S   sp, (CPU_USER_REGS_SP - CPU_USER_REGS_SIZE) (sp)
        addi    sp, sp, -CPU_USER_REGS_SIZE
        REG_S   t0, CPU_USER_REGS_T0(sp)

        /* Save registers */
        REG_S   ra, CPU_USER_REGS_RA(sp)
        REG_S   gp, CPU_USER_REGS_GP(sp)
        REG_S   t1, CPU_USER_REGS_T1(sp)
        REG_S   t2, CPU_USER_REGS_T2(sp)
        REG_S   s0, CPU_USER_REGS_S0(sp)
        REG_S   s1, CPU_USER_REGS_S1(sp)
        REG_S   a0, CPU_USER_REGS_A0(sp)
        REG_S   a1, CPU_USER_REGS_A1(sp)
        REG_S   a2, CPU_USER_REGS_A2(sp)
        REG_S   a3, CPU_USER_REGS_A3(sp)
        REG_S   a4, CPU_USER_REGS_A4(sp)
        REG_S   a5, CPU_USER_REGS_A5(sp)
        REG_S   a6, CPU_USER_REGS_A6(sp)
        REG_S   a7, CPU_USER_REGS_A7(sp)
        REG_S   s2, CPU_USER_REGS_S2(sp)
        REG_S   s3, CPU_USER_REGS_S3(sp)
        REG_S   s4, CPU_USER_REGS_S4(sp)
        REG_S   s5, CPU_USER_REGS_S5(sp)
        REG_S   s6, CPU_USER_REGS_S6(sp)
        REG_S   s7, CPU_USER_REGS_S7(sp)
        REG_S   s8, CPU_USER_REGS_S8(sp)
        REG_S   s9, CPU_USER_REGS_S9(sp)
        REG_S   s10,CPU_USER_REGS_S10(sp)
        REG_S   s11,CPU_USER_REGS_S11(sp)
        REG_S   t3, CPU_USER_REGS_T3(sp)
        REG_S   t4, CPU_USER_REGS_T4(sp)
        REG_S   t5, CPU_USER_REGS_T5(sp)
        REG_S   t6, CPU_USER_REGS_T6(sp)
        csrr    t0, CSR_SEPC
        REG_S   t0, CPU_USER_REGS_SEPC(sp)
        csrr    t0, CSR_SSTATUS
        REG_S   t0, CPU_USER_REGS_SSTATUS(sp)

        mv      a0, sp
        call    do_trap

restore_registers:
        /* Restore stack_cpu_regs */
        REG_L   t0, CPU_USER_REGS_SEPC(sp)
        csrw    CSR_SEPC, t0
        REG_L   t0, CPU_USER_REGS_SSTATUS(sp)
        csrw    CSR_SSTATUS, t0

        REG_L   ra, CPU_USER_REGS_RA(sp)
        REG_L   gp, CPU_USER_REGS_GP(sp)
        REG_L   t0, CPU_USER_REGS_T0(sp)
        REG_L   t1, CPU_USER_REGS_T1(sp)
        REG_L   t2, CPU_USER_REGS_T2(sp)
        REG_L   s0, CPU_USER_REGS_S0(sp)
        REG_L   s1, CPU_USER_REGS_S1(sp)
        REG_L   a0, CPU_USER_REGS_A0(sp)
        REG_L   a1, CPU_USER_REGS_A1(sp)
        REG_L   a2, CPU_USER_REGS_A2(sp)
        REG_L   a3, CPU_USER_REGS_A3(sp)
        REG_L   a4, CPU_USER_REGS_A4(sp)
        REG_L   a5, CPU_USER_REGS_A5(sp)
        REG_L   a6, CPU_USER_REGS_A6(sp)
        REG_L   a7, CPU_USER_REGS_A7(sp)
        REG_L   s2, CPU_USER_REGS_S2(sp)
        REG_L   s3, CPU_USER_REGS_S3(sp)
        REG_L   s4, CPU_USER_REGS_S4(sp)
        REG_L   s5, CPU_USER_REGS_S5(sp)
        REG_L   s6, CPU_USER_REGS_S6(sp)
        REG_L   s7, CPU_USER_REGS_S7(sp)
        REG_L   s8, CPU_USER_REGS_S8(sp)
        REG_L   s9, CPU_USER_REGS_S9(sp)
        REG_L   s10, CPU_USER_REGS_S10(sp)
        REG_L   s11, CPU_USER_REGS_S11(sp)
        REG_L   t3, CPU_USER_REGS_T3(sp)
        REG_L   t4, CPU_USER_REGS_T4(sp)
        REG_L   t5, CPU_USER_REGS_T5(sp)
        REG_L   t6, CPU_USER_REGS_T6(sp)

        /* Restore sp */
        REG_L   sp, CPU_USER_REGS_SP(sp)

        sret
END(handle_trap)
