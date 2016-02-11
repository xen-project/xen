/*
 * MCA implementation for AMD CPUs
 * Copyright (c) 2007-2012 Advanced Micro Devices, Inc. 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef X86_MCA_H
#define X86_MCA_H

#include <public/arch-x86/xen-mca.h>

/* The MCA/MCE MSRs should not be used anywhere else.
 * They are cpu family/model specific and are only for use
 * in terms of machine check handling.
 * So we define them here rather in <asm/msr.h>.
 */


/* Bitfield of the MSR_IA32_MCG_CAP register */
#define MCG_CAP_COUNT           0x00000000000000ffULL
#define MCG_CTL_P               (1ULL<<8)
#define MCG_EXT_P               (1ULL<<9)  /* Intel specific */
#define MCG_CMCI_P              (1ULL<<10) /* Intel specific */
#define MCG_TES_P               (1ULL<<11) /* Intel specific */
#define MCG_EXT_CNT             16         /* Intel specific */
#define MCG_SER_P               (1ULL<<24) /* Intel specific */
/* Other bits are reserved */

/* Bitfield of the MSR_IA32_MCG_STATUS register */
#define MCG_STATUS_RIPV         0x0000000000000001ULL
#define MCG_STATUS_EIPV         0x0000000000000002ULL
#define MCG_STATUS_MCIP         0x0000000000000004ULL
/* Bits 3-63 are reserved */

/* Bitfield of MSR_K8_MCi_STATUS registers */
/* MCA error code */
#define MCi_STATUS_MCA          0x000000000000ffffULL
/* model-specific error code */
#define MCi_STATUS_MSEC         0x00000000ffff0000ULL
/* Other information */
#define MCi_STATUS_OTHER        0x01ffffff00000000ULL
/* Action Required flag */
#define MCi_STATUS_AR           0x0080000000000000ULL  /* Intel specific */
/* Signaling flag */
#define MCi_STATUS_S            0x0100000000000000ULL  /* Intel specific */
/* processor context corrupt */
#define MCi_STATUS_PCC          0x0200000000000000ULL
/* MSR_K8_MCi_ADDR register valid */
#define MCi_STATUS_ADDRV        0x0400000000000000ULL
/* MSR_K8_MCi_MISC register valid */
#define MCi_STATUS_MISCV        0x0800000000000000ULL
/* error condition enabled */
#define MCi_STATUS_EN           0x1000000000000000ULL
/* uncorrected error */
#define MCi_STATUS_UC           0x2000000000000000ULL
/* status register overflow */
#define MCi_STATUS_OVER         0x4000000000000000ULL
/* valid */
#define MCi_STATUS_VAL          0x8000000000000000ULL

/* Bitfield of MSi_STATUS_OTHER field */
/* reserved bits */
#define MCi_STATUS_OTHER_RESERVED1      0x00001fff00000000ULL
/* uncorrectable ECC error */
#define MCi_STATUS_OTEHR_UC_ECC         0x0000200000000000ULL
/* correctable ECC error */
#define MCi_STATUS_OTHER_C_ECC          0x0000400000000000ULL
/* ECC syndrome of an ECC error */
#define MCi_STATUS_OTHER_ECC_SYNDROME   0x007f800000000000ULL
/* reserved bits */
#define MCi_STATUS_OTHER_RESERVED2      0x0180000000000000ULL

/* Bitfield of MSR_K8_HWCR register */
#define K8_HWCR_MCi_STATUS_WREN		(1ULL << 18)

/*Intel Specific bitfield*/
#define MCi_MISC_ADDRMOD_MASK (0x7UL << 6)
#define MCi_MISC_PHYSMOD    (0x2UL << 6)

#include <asm/domain.h>

struct mca_banks
{
    int num;
    unsigned long *bank_map;
};

static inline void mcabanks_clear(int bit, struct mca_banks *banks)
{
    if (!banks || !banks->bank_map || bit >= banks->num)
        return ;
    clear_bit(bit, banks->bank_map);
}

static inline void mcabanks_set(int bit, struct mca_banks* banks)
{
    if (!banks || !banks->bank_map || bit >= banks->num)
        return;
    set_bit(bit, banks->bank_map);
}

static inline int mcabanks_test(int bit, struct mca_banks* banks)
{
    if (!banks || !banks->bank_map || bit >= banks->num)
        return 0;
    return test_bit(bit, banks->bank_map);
}

struct mca_banks *mcabanks_alloc(void);
void mcabanks_free(struct mca_banks *banks);
extern struct mca_banks *mca_allbanks;

/* Keep bank so that we can get status even if mib is NULL */
struct mca_binfo {
    int bank;
    struct mcinfo_global *mig;
    struct mcinfo_bank *mib;
    struct mc_info *mi;
    struct cpu_user_regs *regs;
};

enum mce_result
{
    MCER_NOERROR,
    MCER_RECOVERED,
    /* Not recovered, but can continue */
    MCER_CONTINUE,
    MCER_RESET,
};

struct mca_error_handler
{
    /* Assume corresponding recovery action could be uniquely
     * identified by mca_code. Otherwise, we might need to have
     * a seperate function to decode the corresponding actions
     * for the particular mca error later.
     */
    int (*owned_error)(uint64_t status);
    void (*recovery_handler)(struct mca_binfo *binfo,
                    enum mce_result *result, const struct cpu_user_regs *regs);
};

/* Global variables */
extern bool_t opt_mce;

#endif /* X86_MCA_H */
