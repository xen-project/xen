/* SPDX-License-Identifier: (GPL-2.0-or-later) */
/*
 * Copyright (c) 2021-2023 Vates SAS.
 *
 * Taken from xvisor, modified by Bobby Eshleman (bobby.eshleman@gmail.com).
 *
 * Taken/modified from Xvisor project with the following copyright:
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 */

#ifndef __ASM_RISCV_SBI_H__
#define __ASM_RISCV_SBI_H__

#define SBI_EXT_0_1_CONSOLE_PUTCHAR		0x1

struct sbiret {
    long error;
    long value;
};

struct sbiret sbi_ecall(unsigned long ext, unsigned long fid,
                        unsigned long arg0, unsigned long arg1,
                        unsigned long arg2, unsigned long arg3,
                        unsigned long arg4, unsigned long arg5);

/**
 * Writes given character to the console device.
 *
 * @param ch The data to be written to the console.
 */
void sbi_console_putchar(int ch);

#endif /* __ASM_RISCV_SBI_H__ */
