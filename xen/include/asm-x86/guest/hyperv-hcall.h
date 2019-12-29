/******************************************************************************
 * asm-x86/guest/hyperv-hcall.h
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2019 Microsoft.
 */

#ifndef __X86_HYPERV_HCALL_H__
#define __X86_HYPERV_HCALL_H__

#include <xen/lib.h>
#include <xen/types.h>

#include <asm/asm_defns.h>
#include <asm/fixmap.h>
#include <asm/guest/hyperv-tlfs.h>
#include <asm/page.h>

static inline uint64_t hv_do_hypercall(uint64_t control, paddr_t input_addr,
                                       paddr_t output_addr)
{
    uint64_t status;
    register unsigned long r8 asm ( "r8" ) = output_addr;

    /* See TLFS for volatile registers */
    asm volatile ( "call hv_hcall_page"
                   : "=a" (status), "+c" (control),
                     "+d" (input_addr) ASM_CALL_CONSTRAINT
                   : "r" (r8)
                   : "memory" );

    return status;
}

static inline uint64_t hv_do_fast_hypercall(uint16_t code,
                                            uint64_t input1, uint64_t input2)
{
    uint64_t status;
    uint64_t control = code | HV_HYPERCALL_FAST_BIT;
    register unsigned long r8 asm ( "r8" ) = input2;

    /* See TLFS for volatile registers */
    asm volatile ( "call hv_hcall_page"
                   : "=a" (status), "+c" (control),
                     "+d" (input1) ASM_CALL_CONSTRAINT
                   : "r" (r8) );

    return status;
}

static inline uint64_t hv_do_rep_hypercall(uint16_t code, uint16_t rep_count,
                                           uint16_t varhead_size,
                                           paddr_t input, paddr_t output)
{
    uint64_t control = code;
    uint64_t status;
    uint16_t rep_comp;

    control |= (uint64_t)varhead_size << HV_HYPERCALL_VARHEAD_OFFSET;
    control |= (uint64_t)rep_count << HV_HYPERCALL_REP_COMP_OFFSET;

    do {
        status = hv_do_hypercall(control, input, output);
        if ( (status & HV_HYPERCALL_RESULT_MASK) != HV_STATUS_SUCCESS )
            break;

        rep_comp = MASK_EXTR(status, HV_HYPERCALL_REP_COMP_MASK);

        control &= ~HV_HYPERCALL_REP_START_MASK;
        control |= MASK_INSR(rep_comp, HV_HYPERCALL_REP_START_MASK);
    } while ( rep_comp < rep_count );

    return status;
}

#endif /* __X86_HYPERV_HCALL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
