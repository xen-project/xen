#ifndef __ARCH_DESC_H
#define __ARCH_DESC_H

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

#if defined(__x86_64__)

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

#define __FIRST_TSS_ENTRY (FIRST_RESERVED_GDT_ENTRY + 8)
#define __FIRST_LDT_ENTRY (__FIRST_TSS_ENTRY + 2)

#define __TSS(n) (((n)<<2) + __FIRST_TSS_ENTRY)
#define __LDT(n) (((n)<<2) + __FIRST_LDT_ENTRY)

#elif defined(__i386__)

#define FLAT_COMPAT_KERNEL_CS FLAT_KERNEL_CS
#define FLAT_COMPAT_KERNEL_DS FLAT_KERNEL_DS
#define FLAT_COMPAT_KERNEL_SS FLAT_KERNEL_SS
#define FLAT_COMPAT_USER_CS   FLAT_USER_CS
#define FLAT_COMPAT_USER_DS   FLAT_USER_DS
#define FLAT_COMPAT_USER_SS   FLAT_USER_SS

#define __DOUBLEFAULT_TSS_ENTRY FIRST_RESERVED_GDT_ENTRY

#define __FIRST_TSS_ENTRY (FIRST_RESERVED_GDT_ENTRY + 8)
#define __FIRST_LDT_ENTRY (__FIRST_TSS_ENTRY + 1)

#define __TSS(n) (((n)<<1) + __FIRST_TSS_ENTRY)
#define __LDT(n) (((n)<<1) + __FIRST_LDT_ENTRY)

#endif

#ifndef __ASSEMBLY__

#define load_TR(n)  __asm__ __volatile__ ("ltr  %%ax" : : "a" (__TSS(n)<<3) )

#if defined(__x86_64__)
#define GUEST_KERNEL_RPL(d) (is_pv_32bit_domain(d) ? 1 : 3)
#elif defined(__i386__)
#define GUEST_KERNEL_RPL(d) ((void)(d), 1)
#endif

/* Fix up the RPL of a guest segment selector. */
#define __fixup_guest_selector(d, sel)                             \
({                                                                 \
    uint16_t _rpl = GUEST_KERNEL_RPL(d);                           \
    (sel) = (((sel) & 3) >= _rpl) ? (sel) : (((sel) & ~3) | _rpl); \
})

/* Stack selectors don't need fixing up if the kernel runs in ring 0. */
#ifdef CONFIG_X86_SUPERVISOR_MODE_KERNEL
#define fixup_guest_stack_selector(d, ss) ((void)0)
#else
#define fixup_guest_stack_selector(d, ss) __fixup_guest_selector(d, ss)
#endif

/*
 * Code selectors are always fixed up. It allows the Xen exit stub to detect
 * return to guest context, even when the guest kernel runs in ring 0.
 */
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
     ((sel) == (!is_pv_32on64_domain(d) ?                               \
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
#ifdef __x86_64
#define _SEGMENT_L       ( 1<<21) /* 64-bit segment */
#else
#define _SEGMENT_L       0
#endif
#define _SEGMENT_DB      ( 1<<22) /* 16- or 32-bit segment */
#define _SEGMENT_G       ( 1<<23) /* Granularity */

#ifndef __ASSEMBLY__

struct desc_struct {
    u32 a, b;
};

#if defined(__x86_64__)

typedef struct {
    u64 a, b;
} idt_entry_t;

#define _set_gate(gate_addr,type,dpl,addr)               \
do {                                                     \
    (gate_addr)->a =                                     \
        (((unsigned long)(addr) & 0xFFFF0000UL) << 32) | \
        ((unsigned long)(dpl) << 45) |                   \
        ((unsigned long)(type) << 40) |                  \
        ((unsigned long)(addr) & 0xFFFFUL) |             \
        ((unsigned long)__HYPERVISOR_CS64 << 16) |       \
        (1UL << 47);                                     \
    (gate_addr)->b =                                     \
        ((unsigned long)(addr) >> 32);                   \
} while (0)

#define _set_tssldt_desc(desc,addr,limit,type)           \
do {                                                     \
    (desc)[0].a =                                        \
        ((u32)(addr) << 16) | ((u32)(limit) & 0xFFFF);   \
    (desc)[0].b =                                        \
        ((u32)(addr) & 0xFF000000U) |                    \
        ((u32)(type) << 8) | 0x8000U |                   \
        (((u32)(addr) & 0x00FF0000U) >> 16);             \
    (desc)[1].a = (u32)(((unsigned long)(addr)) >> 32);  \
    (desc)[1].b = 0;                                     \
} while (0)

#elif defined(__i386__)

typedef struct desc_struct idt_entry_t;

#define _set_gate(gate_addr,type,dpl,addr) \
do { \
  int __d0, __d1; \
  __asm__ __volatile__ ("movw %%dx,%%ax\n\t" \
 "movw %4,%%dx\n\t" \
 "movl %%eax,%0\n\t" \
 "movl %%edx,%1" \
 :"=m" (*((long *) (gate_addr))), \
  "=m" (*(1+(long *) (gate_addr))), "=&a" (__d0), "=&d" (__d1) \
 :"i" ((short) (0x8000+(dpl<<13)+(type<<8))), \
  "3" ((char *) (addr)),"2" (__HYPERVISOR_CS << 16)); \
} while (0)

#define _set_tssldt_desc(n,addr,limit,type) \
__asm__ __volatile__ ("movw %w3,0(%2)\n\t" \
 "movw %%ax,2(%2)\n\t" \
 "rorl $16,%%eax\n\t" \
 "movb %%al,4(%2)\n\t" \
 "movb %4,5(%2)\n\t" \
 "movb $0,6(%2)\n\t" \
 "movb %%ah,7(%2)\n\t" \
 "rorl $16,%%eax" \
 : "=m"(*(n)) : "a" (addr), "r"(n), "ir"(limit), "i"(type|0x80))

#endif

extern struct desc_struct gdt_table[];
#ifdef CONFIG_COMPAT
extern struct desc_struct compat_gdt_table[];
#else
# define compat_gdt_table gdt_table
#endif

struct Xgt_desc_struct {
    unsigned short size;
    unsigned long address __attribute__((packed));
};

extern void set_intr_gate(unsigned int irq, void * addr);
extern void set_system_gate(unsigned int n, void *addr);
extern void set_task_gate(unsigned int n, unsigned int sel);
extern void set_tss_desc(unsigned int n, void *addr);

#endif /* !__ASSEMBLY__ */

#endif /* __ARCH_DESC_H */
