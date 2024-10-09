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

#ifndef ASM__RISCV__SBI_H
#define ASM__RISCV__SBI_H

#include <xen/cpumask.h>

#define SBI_EXT_0_1_CONSOLE_PUTCHAR		0x1
#define SBI_EXT_0_1_SHUTDOWN			0x8

#define SBI_EXT_BASE                    0x10
#define SBI_EXT_RFENCE                  0x52464E43

/* SBI function IDs for BASE extension */
#define SBI_EXT_BASE_GET_SPEC_VERSION   0x0
#define SBI_EXT_BASE_GET_IMP_ID         0x1
#define SBI_EXT_BASE_GET_IMP_VERSION    0x2
#define SBI_EXT_BASE_PROBE_EXT          0x3

/* SBI function IDs for RFENCE extension */
#define SBI_EXT_RFENCE_REMOTE_FENCE_I           0x0
#define SBI_EXT_RFENCE_REMOTE_SFENCE_VMA        0x1
#define SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID   0x2
#define SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA       0x3
#define SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA_VMID  0x4
#define SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA       0x5
#define SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA_ASID  0x6

#define SBI_SPEC_VERSION_MAJOR_MASK     0x7f000000
#define SBI_SPEC_VERSION_MINOR_MASK     0x00ffffff

/* SBI return error codes */
#define SBI_SUCCESS             0
#define SBI_ERR_FAILURE         (-1)
#define SBI_ERR_NOT_SUPPORTED   (-2)
#define SBI_ERR_INVALID_PARAM   (-3)
#define SBI_ERR_DENIED          (-4)
#define SBI_ERR_INVALID_ADDRESS (-5)

#define SBI_SPEC_VERSION_DEFAULT 0x1

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

void sbi_shutdown(void);

/*
 * Check underlying SBI implementation has RFENCE
 *
 * @return true for supported AND false for not-supported
 */
bool sbi_has_rfence(void);

/*
 * Instructs the remote harts to execute one or more SFENCE.VMA
 * instructions, covering the range of virtual addresses between
 * [start_addr, start_addr + size).
 *
 * Returns 0 if IPI was sent to all the targeted harts successfully
 * or negative value if start_addr or size is not valid.
 *
 * @hart_mask a cpu mask containing all the target harts.
 * @param start virtual address start
 * @param size virtual address range size
 */
int sbi_remote_sfence_vma(const cpumask_t *cpu_mask, vaddr_t start,
                          size_t size);

/*
 * Initialize SBI library
 *
 * @return 0 on success, otherwise negative errno on failure
 */
int sbi_init(void);

#endif /* ASM__RISCV__SBI_H */
