#ifndef __ARCH_DESC_H
#define __ARCH_DESC_H

#include <asm/page.h>

/*
 * Xen reserves a memory page of GDT entries.
 * No guest GDT entries exist beyond the Xen reserved area.
 */
#define NR_RESERVED_GDT_PAGES   1
#define NR_RESERVED_GDT_BYTES   (NR_RESERVED_GDT_PAGES * PAGE_SIZE)
#define NR_RESERVED_GDT_ENTRIES (NR_RESERVED_GDT_BYTES / 8)

#define LAST_RESERVED_GDT_PAGE  \
    (FIRST_RESERVED_GDT_PAGE + NR_RESERVED_GDT_PAGES - 1)
#define LAST_RESERVED_GDT_BYTE  \
    (FIRST_RESERVED_GDT_BYTE + NR_RESERVED_GDT_BYTES - 1)
#define LAST_RESERVED_GDT_ENTRY \
    (FIRST_RESERVED_GDT_ENTRY + NR_RESERVED_GDT_ENTRIES - 1)

#define LDT_ENTRY_SIZE 8

#define FLAT_COMPAT_RING1_CS 0xe019  /* GDT index 259 */
#define FLAT_COMPAT_RING1_DS 0xe021  /* GDT index 260 */
#define FLAT_COMPAT_RING1_SS 0xe021  /* GDT index 260 */
#define FLAT_COMPAT_RING3_CS 0xe02b  /* GDT index 261 */
#define FLAT_COMPAT_RING3_DS 0xe033  /* GDT index 262 */
#define FLAT_COMPAT_RING3_SS 0xe033  /* GDT index 262 */

#define FLAT_COMPAT_KERNEL_DS FLAT_COMPAT_RING1_DS
#define FLAT_COMPAT_KERNEL_CS FLAT_COMPAT_RING1_CS
#define FLAT_COMPAT_KERNEL_SS FLAT_COMPAT_RING1_SS
#define FLAT_COMPAT_USER_DS   FLAT_COMPAT_RING3_DS
#define FLAT_COMPAT_USER_CS   FLAT_COMPAT_RING3_CS
#define FLAT_COMPAT_USER_SS   FLAT_COMPAT_RING3_SS

#define TSS_ENTRY (FIRST_RESERVED_GDT_ENTRY + 8)
#define LDT_ENTRY (TSS_ENTRY + 2)
#define PER_CPU_GDT_ENTRY (LDT_ENTRY + 2)

#define TSS_SELECTOR     (TSS_ENTRY << 3)
#define LDT_SELECTOR     (LDT_ENTRY << 3)
#define PER_CPU_SELECTOR (PER_CPU_GDT_ENTRY << 3)

#ifndef __ASSEMBLY__

#define GUEST_KERNEL_RPL(d) (is_pv_32bit_domain(d) ? 1 : 3)

/* Fix up the RPL of a guest segment selector. */
#define __fixup_guest_selector(d, sel)                             \
({                                                                 \
    uint16_t _rpl = GUEST_KERNEL_RPL(d);                           \
    (sel) = (((sel) & 3) >= _rpl) ? (sel) : (((sel) & ~3) | _rpl); \
})

#define fixup_guest_stack_selector(d, ss) __fixup_guest_selector(d, ss)
#define fixup_guest_code_selector(d, cs)  __fixup_guest_selector(d, cs)

/*
 * We need this function because enforcing the correct guest kernel RPL is
 * unsufficient if the selector is poked into an interrupt, trap or call gate.
 * The selector RPL is ignored when a gate is accessed. We must therefore make
 * sure that the selector does not reference a Xen-private segment.
 * 
 * Note that selectors used only by IRET do not need to be checked. If the
 * descriptor DPL fiffers from CS RPL then we'll #GP.
 * 
 * Stack and data selectors do not need to be checked. If DS, ES, FS, GS are
 * DPL < CPL then they'll be cleared automatically. If SS RPL or DPL differs
 * from CS RPL then we'll #GP.
 */
#define guest_gate_selector_okay(d, sel)                                \
    ((((sel)>>3) < FIRST_RESERVED_GDT_ENTRY) || /* Guest seg? */        \
     ((sel) == (!is_pv_32bit_domain(d) ?                                \
                FLAT_KERNEL_CS :                /* Xen default seg? */  \
                FLAT_COMPAT_KERNEL_CS)) ||                              \
     ((sel) & 4))                               /* LDT seg? */

#endif /* __ASSEMBLY__ */

/* These are bitmasks for the high 32 bits of a descriptor table entry. */
#define _SEGMENT_TYPE    (15<< 8)
#define _SEGMENT_WR      ( 1<< 9) /* Writeable (data) or Readable (code)
                                     segment */
#define _SEGMENT_EC      ( 1<<10) /* Expand-down or Conforming segment */
#define _SEGMENT_CODE    ( 1<<11) /* Code (vs data) segment for non-system
                                     segments */
#define _SEGMENT_S       ( 1<<12) /* System descriptor (yes iff S==0) */
#define _SEGMENT_DPL     ( 3<<13) /* Descriptor Privilege Level */
#define _SEGMENT_P       ( 1<<15) /* Segment Present */
#define _SEGMENT_L       ( 1<<21) /* 64-bit segment */
#define _SEGMENT_DB      ( 1<<22) /* 16- or 32-bit segment */
#define _SEGMENT_G       ( 1<<23) /* Granularity */

#ifndef __ASSEMBLY__

/* System Descriptor types for GDT and IDT entries. */
#define SYS_DESC_tss16_avail  1
#define SYS_DESC_ldt          2
#define SYS_DESC_tss16_busy   3
#define SYS_DESC_call_gate16  4
#define SYS_DESC_task_gate    5
#define SYS_DESC_irq_gate16   6
#define SYS_DESC_trap_gate16  7
#define SYS_DESC_tss_avail    9
#define SYS_DESC_tss_busy     11
#define SYS_DESC_call_gate    12
#define SYS_DESC_irq_gate     14
#define SYS_DESC_trap_gate    15

typedef union {
    uint64_t raw;
    struct {
        uint32_t a, b;
    };
} seg_desc_t;

#define _set_tssldt_desc(desc,addr,limit,type)           \
do {                                                     \
    (desc)[0].b = (desc)[1].b = 0;                       \
    smp_wmb(); /* disable entry /then/ rewrite */        \
    (desc)[0].a =                                        \
        ((u32)(addr) << 16) | ((u32)(limit) & 0xFFFF);   \
    (desc)[1].a = (u32)(((unsigned long)(addr)) >> 32);  \
    smp_wmb(); /* rewrite /then/ enable entry */         \
    (desc)[0].b =                                        \
        ((u32)(addr) & 0xFF000000U) |                    \
        ((u32)(type) << 8) | 0x8000U |                   \
        (((u32)(addr) & 0x00FF0000U) >> 16);             \
} while (0)

struct __packed desc_ptr {
	unsigned short limit;
	unsigned long base;
};

extern seg_desc_t boot_gdt[];
DECLARE_PER_CPU(seg_desc_t *, gdt);
DECLARE_PER_CPU(l1_pgentry_t, gdt_l1e);
extern seg_desc_t boot_compat_gdt[];
DECLARE_PER_CPU(seg_desc_t *, compat_gdt);
DECLARE_PER_CPU(l1_pgentry_t, compat_gdt_l1e);
DECLARE_PER_CPU(bool, full_gdt_loaded);

static inline void lgdt(const struct desc_ptr *gdtr)
{
    __asm__ __volatile__ ( "lgdt %0" :: "m" (*gdtr) : "memory" );
}

static inline void lidt(const struct desc_ptr *idtr)
{
    __asm__ __volatile__ ( "lidt %0" :: "m" (*idtr) : "memory" );
}

static inline void lldt(unsigned int sel)
{
    __asm__ __volatile__ ( "lldt %w0" :: "rm" (sel) : "memory" );
}

static inline void ltr(unsigned int sel)
{
    __asm__ __volatile__ ( "ltr %w0" :: "rm" (sel) : "memory" );
}

#endif /* !__ASSEMBLY__ */

#endif /* __ARCH_DESC_H */
