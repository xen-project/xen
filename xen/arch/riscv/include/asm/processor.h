/* SPDX-License-Identifier: MIT */
/******************************************************************************
 *
 * Copyright 2019 (C) Alistair Francis <alistair.francis@wdc.com>
 * Copyright 2021 (C) Bobby Eshleman <bobby.eshleman@gmail.com>
 * Copyright 2023 (C) Vates
 *
 */

#ifndef _ASM_RISCV_PROCESSOR_H
#define _ASM_RISCV_PROCESSOR_H

#ifndef __ASSEMBLY__

/* On stack VCPU state */
struct cpu_user_regs
{
    unsigned long zero;
    unsigned long ra;
    unsigned long sp;
    unsigned long gp;
    unsigned long tp;
    unsigned long t0;
    unsigned long t1;
    unsigned long t2;
    unsigned long s0;
    unsigned long s1;
    unsigned long a0;
    unsigned long a1;
    unsigned long a2;
    unsigned long a3;
    unsigned long a4;
    unsigned long a5;
    unsigned long a6;
    unsigned long a7;
    unsigned long s2;
    unsigned long s3;
    unsigned long s4;
    unsigned long s5;
    unsigned long s6;
    unsigned long s7;
    unsigned long s8;
    unsigned long s9;
    unsigned long s10;
    unsigned long s11;
    unsigned long t3;
    unsigned long t4;
    unsigned long t5;
    unsigned long t6;
    unsigned long sepc;
    unsigned long sstatus;
    /* pointer to previous stack_cpu_regs */
    unsigned long pregs;
};

static inline void wfi(void)
{
    __asm__ __volatile__ ("wfi");
}

/*
 * panic() isn't available at the moment so an infinite loop will be
 * used temporarily.
 * TODO: change it to panic()
 */
static inline void die(void)
{
    for ( ;; )
        wfi();
}

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_PROCESSOR_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
