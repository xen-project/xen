/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef XG_PRIVATE_H
#define XG_PRIVATE_H

#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "xc_private.h"
#include "xc_bitops.h"
#include "xenguest.h"

#include <xen/memory.h>
#include <xen/elfnote.h>
#include <xen/libelf/libelf.h>

#ifndef ELFSIZE
#include <limits.h>
#if UINT_MAX == ULONG_MAX
#define ELFSIZE 32
#else
#define ELFSIZE 64
#endif
#endif

#define GET_FIELD(_p, _f, _w) (((_w) == 8) ? ((_p)->x64._f) : ((_p)->x32._f))

#define SET_FIELD(_p, _f, _v, _w) do {          \
    if ((_w) == 8)                              \
        (_p)->x64._f = (_v);                    \
    else                                        \
        (_p)->x32._f = (_v);                    \
} while (0)

struct domain_info_context {
    unsigned int guest_width;
    unsigned int p2m_frames;
    unsigned long p2m_size;
};

struct xc_dom_loader {
    const char *name;
    /* Sadly the error returns from these functions are not consistent: */
    elf_negerrnoval (*probe) (struct xc_dom_image * dom);
    elf_negerrnoval (*parser) (struct xc_dom_image * dom);
    elf_errorstatus (*loader) (struct xc_dom_image * dom);

    struct xc_dom_loader *next;
};

#define __init __attribute__ ((constructor))
void xc_dom_register_loader(struct xc_dom_loader *loader);

char *xc_read_image(xc_interface *xch,
                    const char *filename, unsigned long *size);
char *xc_inflate_buffer(xc_interface *xch,
                        const char *in_buf,
                        unsigned long in_size,
                        unsigned long *out_size);

#if !defined(__MINIOS__) || defined(XG_NEED_UNALIGNED)

static inline unsigned int get_unaligned_le32(const uint8_t *buf)
{
    return ((unsigned int)buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0];
}

#endif /* !__MINIOS__ || XG_NEED_UNALIGNED */

unsigned long csum_page (void * page);

#define _PAGE_PRESENT   0x001
#define _PAGE_RW        0x002
#define _PAGE_USER      0x004
#define _PAGE_PWT       0x008
#define _PAGE_PCD       0x010
#define _PAGE_ACCESSED  0x020
#define _PAGE_DIRTY     0x040
#define _PAGE_PAT       0x080
#define _PAGE_PSE       0x080
#define _PAGE_GLOBAL    0x100

#define VIRT_BITS_I386     32
#define VIRT_BITS_X86_64   48

#define PGTBL_LEVELS_I386       3
#define PGTBL_LEVELS_X86_64     4

#define PGTBL_LEVEL_SHIFT_X86   9

#define L1_PAGETABLE_SHIFT_PAE        12
#define L2_PAGETABLE_SHIFT_PAE        21
#define L3_PAGETABLE_SHIFT_PAE        30
#define L1_PAGETABLE_ENTRIES_PAE     512
#define L2_PAGETABLE_ENTRIES_PAE     512
#define L3_PAGETABLE_ENTRIES_PAE       4

#define L1_PAGETABLE_SHIFT_X86_64     12
#define L2_PAGETABLE_SHIFT_X86_64     21
#define L3_PAGETABLE_SHIFT_X86_64     30
#define L4_PAGETABLE_SHIFT_X86_64     39
#define L1_PAGETABLE_ENTRIES_X86_64  512
#define L2_PAGETABLE_ENTRIES_X86_64  512
#define L3_PAGETABLE_ENTRIES_X86_64  512
#define L4_PAGETABLE_ENTRIES_X86_64  512

typedef uint64_t x86_pgentry_t;

#define PAGE_SHIFT_ARM          12
#define PAGE_SIZE_ARM           (1UL << PAGE_SHIFT_ARM)
#define PAGE_MASK_ARM           (~(PAGE_SIZE_ARM-1))

#define PAGE_SHIFT_X86          12
#define PAGE_SIZE_X86           (1UL << PAGE_SHIFT_X86)
#define PAGE_MASK_X86           (~(PAGE_SIZE_X86-1))

#define NRPAGES(x) (ROUNDUP(x, PAGE_SHIFT) >> PAGE_SHIFT)

static inline xen_pfn_t xc_pfn_to_mfn(xen_pfn_t pfn, xen_pfn_t *p2m,
                                      unsigned gwidth)
{
    if ( gwidth == sizeof(uint64_t) )
        /* 64 bit guest.  Need to truncate their pfns for 32 bit toolstacks. */
        return ((uint64_t *)p2m)[pfn];
    else
    {
        /* 32 bit guest.  Need to expand INVALID_MFN for 64 bit toolstacks. */
        uint32_t mfn = ((uint32_t *)p2m)[pfn];

        return mfn == ~0U ? INVALID_MFN : mfn;
    }
}


/* Masks for PTE<->PFN conversions */
#define MADDR_BITS_X86  ((dinfo->guest_width == 8) ? 52 : 44)
#define MFN_MASK_X86    ((1ULL << (MADDR_BITS_X86 - PAGE_SHIFT_X86)) - 1)

int pin_table(xc_interface *xch, unsigned int type, unsigned long mfn,
              uint32_t dom);

/*
 * The M2P is made up of some number of 'chunks' of at least 2MB in size.
 * The below definitions and utility function(s) deal with mapping the M2P
 * regarldess of the underlying machine memory size or architecture.
 */
#define M2P_SHIFT       L2_PAGETABLE_SHIFT_PAE
#define M2P_CHUNK_SIZE  (1 << M2P_SHIFT)
#define M2P_SIZE(_m)    ROUNDUP(((_m) * sizeof(xen_pfn_t)), M2P_SHIFT)
#define M2P_CHUNKS(_m)  (M2P_SIZE((_m)) >> M2P_SHIFT)

#if defined(__x86_64__) || defined(__i386__)
#include <xen/lib/x86/cpu-policy.h>

struct xc_cpu_policy {
    struct cpu_policy policy;
    xen_cpuid_leaf_t leaves[CPUID_MAX_SERIALISED_LEAVES];
    xen_msr_entry_t msrs[MSR_MAX_SERIALISED_ENTRIES];
};
#endif /* x86 */

#endif /* XG_PRIVATE_H */
