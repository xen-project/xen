/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Taken and modified from the xvisor project with the copyright Copyright (c)
 * 2019 Western Digital Corporation or its affiliates and author Anup Patel
 * (anup.patel@wdc.com).
 *
 * Modified by Bobby Eshleman (bobby.eshleman@gmail.com).
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 * Copyright (c) 2021-2023 Vates SAS.
 */

#include <asm/sbi.h>

struct sbiret sbi_ecall(unsigned long ext, unsigned long fid,
                        unsigned long arg0, unsigned long arg1,
                        unsigned long arg2, unsigned long arg3,
                        unsigned long arg4, unsigned long arg5)
{
    struct sbiret ret;

    register unsigned long a0 asm ("a0") = arg0;
    register unsigned long a1 asm ("a1") = arg1;
    register unsigned long a2 asm ("a2") = arg2;
    register unsigned long a3 asm ("a3") = arg3;
    register unsigned long a4 asm ("a4") = arg4;
    register unsigned long a5 asm ("a5") = arg5;
    register unsigned long a6 asm ("a6") = fid;
    register unsigned long a7 asm ("a7") = ext;

    asm volatile (  "ecall"
                    : "+r" (a0), "+r" (a1)
                    : "r" (a2), "r" (a3), "r" (a4), "r" (a5), "r" (a6), "r" (a7)
                    : "memory");
    ret.error = a0;
    ret.value = a1;

    return ret;
}

void sbi_console_putchar(int ch)
{
    sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, ch, 0, 0, 0, 0, 0);
}
