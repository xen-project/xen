/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ASM__RISCV__CPUFEATURE_H
#define ASM__RISCV__CPUFEATURE_H

#ifndef __ASSEMBLY__

#include <xen/stdbool.h>

/*
 * These macros represent the logical IDs of each multi-letter RISC-V ISA
 * extension and are used in the ISA bitmap. The logical IDs start from
 * RISCV_ISA_EXT_BASE, which allows the 0-25 range to be reserved for single
 * letter extensions and are used in enum riscv_isa_ext_id.
 *
 * New extensions should just be added to the bottom, rather than added
 * alphabetically, in order to avoid unnecessary shuffling.
 */
#define RISCV_ISA_EXT_BASE  26

enum riscv_isa_ext_id {
    RISCV_ISA_EXT_a,
    RISCV_ISA_EXT_c,
    RISCV_ISA_EXT_d,
    RISCV_ISA_EXT_f,
    RISCV_ISA_EXT_h,
    RISCV_ISA_EXT_i,
    RISCV_ISA_EXT_m,
    RISCV_ISA_EXT_q,
    RISCV_ISA_EXT_v,
    RISCV_ISA_EXT_zicntr = RISCV_ISA_EXT_BASE,
    RISCV_ISA_EXT_zicsr,
    RISCV_ISA_EXT_zifencei,
    RISCV_ISA_EXT_zihintpause,
    RISCV_ISA_EXT_zihpm,
    RISCV_ISA_EXT_zba,
    RISCV_ISA_EXT_zbb,
    RISCV_ISA_EXT_zbs,
    RISCV_ISA_EXT_smaia,
    RISCV_ISA_EXT_ssaia,
    RISCV_ISA_EXT_MAX
};

void riscv_fill_hwcap(void);

bool riscv_isa_extension_available(const unsigned long *isa_bitmap,
                                   enum riscv_isa_ext_id id);

#endif /* __ASSEMBLY__ */

#endif /* ASM__RISCV__CPUFEATURE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
