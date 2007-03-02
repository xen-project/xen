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
 * Copyright IBM Corp. 2005, 2007
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ASM_DOMAIN_H_
#define _ASM_DOMAIN_H_

#include <xen/cache.h>
#include <xen/sched.h>
#include <xen/list.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <public/arch-powerpc.h>
#include <asm/htab.h>
#include <asm/powerpc64/ppc970.h>

struct arch_domain {
    struct domain_htab htab;

    /* The Real Mode area is fixed to the domain and is accessible while the
     * processor is in real mode */
    struct page_info *rma_page;
    uint rma_order;

    /* list of extents beyond RMA */
    struct list_head extent_list;

    uint foreign_mfn_count;
    uint *foreign_mfns;

    /* I/O-port access bitmap mask. */
    u8 *iobmp_mask;       /* Address of IO bitmap mask, or NULL.      */

    u32 *p2m; /* Array of 32-bit MFNs supports 44 bits of physical memory. */
    ulong p2m_entries;

    uint large_page_sizes;
    uint large_page_order[4];
} __cacheline_aligned;

struct slb_entry {
    ulong slb_vsid;
    ulong slb_esid;
};
#define SLB_ESID_VALID (1ULL << (63 - 36))
#define SLB_ESID_CLASS (1ULL << (63 - 56))
#define SLB_ESID_MASK  (~0ULL << (63 - 35))
#define SLBIE_CLASS_LOG (63-36)
#define SLBMTE_ENTRY_MASK ((0x1UL << (63 - 52 + 1)) - 1)

struct xencomm;

typedef struct {
    u32 u[4];
} __attribute__((aligned(16))) vector128;

struct arch_vcpu {
    cpu_user_regs_t ctxt; /* User-level CPU registers */

#ifdef HAS_FLOAT
    double fprs[NUM_FPRS];
#endif
#ifdef HAS_VMX
    vector128 vrs[32];
    vector128 vscr;
    u32 vrsave;
#endif

    /* Special-Purpose Registers */
    ulong sprg[4];
    ulong timebase;
    ulong dar;
    ulong dsisr;
    
    /* Segment Lookaside Buffer */
    struct slb_entry slb_entries[NUM_SLB_ENTRIES];

    /* I/O-port access bitmap. */
    XEN_GUEST_HANDLE(uint8_t) iobmp; /* Guest kernel virtual address of the bitmap. */
    int iobmp_limit;  /* Number of ports represented in the bitmap.  */
    int iopl;         /* Current IOPL for this VCPU. */

    u32 dec;
    struct cpu_vcpu cpu; /* CPU-specific bits */
    struct xencomm *xencomm;
} __cacheline_aligned;

extern void full_resume(void);

extern void save_sprs(struct vcpu *);
extern void load_sprs(struct vcpu *);
extern void save_segments(struct vcpu *);
extern void load_segments(struct vcpu *);
extern void save_float(struct vcpu *);
extern void load_float(struct vcpu *);

#define rma_size(rma_order) (1UL << ((rma_order) + PAGE_SHIFT))

#endif
