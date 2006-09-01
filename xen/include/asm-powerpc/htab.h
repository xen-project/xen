/*
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
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ASM_HTAB_H_
#define _ASM_HTAB_H_

#include <xen/config.h>
#include <xen/types.h>

/***** general PowerPC architecture limits ******/

/* 256KB, from PowerPC Architecture specification */
#define HTAB_MIN_LOG_SIZE 18

#define LOG_NUM_PTES_IN_PTEG    3
#define NUM_PTES_IN_PTEG        (1 << LOG_NUM_PTES_IN_PTEG)
#define LOG_PTE_SIZE            4
#define LOG_PTEG_SIZE           (LOG_NUM_PTES_IN_PTEG + LOG_PTE_SIZE)
#define LOG_HTAB_HASH           (LOG_HTAB_SIZE - LOG_PTEG_SIZE)

/* real page number shift to create the rpn field of the pte */
#define RPN_SHIFT 12

/* page protection bits in pp1 (name format: MSR:PR=0 | MSR:PR=1) */
#define PP_RWxx 0x0UL
#define PP_RWRW 0x2UL
#define PP_RWRx 0x4UL
#define PP_RxRx 0x6UL

/***** 64-bit PowerPC architecture limits ******/

#define SDR1_HTABORG_MASK   0xfffffffffff80000ULL
#define SDR1_HTABSIZE_MASK  0x1fUL
#define SDR1_HTABSIZE_MAX   46
#define SDR1_HTABSIZE_BASEBITS 11

/* used to turn a vsid into a number usable in the hash function */
#define VSID_HASH_MASK 0x0000007fffffffffUL

/* used to turn a vaddr into an api for a pte */
#define VADDR_TO_API(vaddr) (((vaddr) & API_MASK) >> API_SHIFT)
#define API_VEC   0x1fUL
#define API_SHIFT 23
#define API_MASK  (API_VEC << API_SHIFT)

/***** hypervisor internals ******/

/* 64M: reasonable hypervisor limit? */
#define HTAB_MAX_LOG_SIZE 26

#define GET_HTAB(domain) ((domain)->arch.htab.sdr1 & SDR1_HTABORG_MASK)

union pte {
    struct pte_words {
        ulong vsid;
        ulong rpn;
    } words;
    struct pte_bits {
        /* *INDENT-OFF* */
        /* high word */
        ulong avpn:     57; /* [0-56] abbreviated virtual page number */
        ulong lock:     1;  /* [57] hypervisor lock bit */
        ulong res:      1;  /* [58] reserved for hypervisor */
        ulong bolted:   1;  /* [59] XXX software-reserved; temp hack */
        ulong sw:       1;  /* [60] reserved for software */
        ulong l:        1;  /* [61] Large Page */
        ulong h:        1;  /* [62] hash function id */
        ulong v:        1;  /* [63] valid */

        /* low word */
        ulong pp0:  1;  /* [0] page protection bit 0 (current PowerPC
                         *     specification says it can always be 0) */
        ulong ts:   1;  /* [1] tag select */
        ulong rpn:  50; /* [2-51] real page number */
        ulong res2: 2;  /* [52,53] reserved */
        ulong ac:   1;  /* [54] address compare */
        ulong r:    1;  /* [55] referenced */
        ulong c:    1;  /* [56] changed */
        ulong w:    1;  /* [57] write through */
        ulong i:    1;  /* [58] cache inhibited */
        ulong m:    1;  /* [59] memory coherent */
        ulong g:    1;  /* [60] guarded */
        ulong n:    1;  /* [61] no-execute */
        ulong pp1:  2;  /* [62,63] page protection bits 1:2 */
        /* *INDENT-ON* */
    } bits;
};

union ptel {
    ulong word;
    struct ptel_bits {
        /* *INDENT-OFF* */

        ulong pp0:  1;  /* page protection bit 0 (current PPC
                         *   AS says it can always be 0) */
        ulong ts:   1;  /* tag select */
        ulong rpn:  50; /* real page number */
        ulong res2: 2;  /* reserved */
        ulong ac:   1;  /* address compare */
        ulong r:    1;  /* referenced */
        ulong c:    1;  /* changed */
        ulong w:    1;  /* write through */
        ulong i:    1;  /* cache inhibited */
        ulong m:    1;  /* memory coherent */
        ulong g:    1;  /* guarded */
        ulong n:    1;  /* no-execute */
        ulong pp1:  2;  /* page protection bits 1:2 */
        /* *INDENT-ON* */
    } bits;
};

struct domain_htab {
    ulong sdr1;
    uint log_num_ptes;  /* log number of PTEs in HTAB. */
    uint order;         /* order for freeing. */
    union pte *map;     /* access the htab like an array */
    ulong *shadow;      /* idx -> logical translation array */
};
#endif
