#ifndef __ARCH_DESC_H
#define __ARCH_DESC_H

#define LDT_ENTRY_SIZE 8

#define __DOUBLEFAULT_TSS_ENTRY FIRST_RESERVED_GDT_ENTRY

#define __FIRST_TSS_ENTRY (FIRST_RESERVED_GDT_ENTRY + 8)
#define __FIRST_LDT_ENTRY (__FIRST_TSS_ENTRY + 1)

#define __TSS(n) (((n)<<1) + __FIRST_TSS_ENTRY)
#define __LDT(n) (((n)<<1) + __FIRST_LDT_ENTRY)

#define load_TR(n)  __asm__ __volatile__ ("ltr  %%ax" : : "a" (__TSS(n)<<3) )

/*
 * Guest OS must provide its own code selectors, or use the one we provide. The
 * RPL must be 1, as we only create bounce frames to ring 1. Any LDT selector
 * value is okay. Note that checking only the RPL is insufficient: if the
 * selector is poked into an interrupt, trap or call gate then the RPL is
 * ignored when the gate is accessed.
 */
#define VALID_SEL(_s)                                                      \
    (((((_s)>>3) < FIRST_RESERVED_GDT_ENTRY) ||                            \
      (((_s)>>3) >  LAST_RESERVED_GDT_ENTRY) ||                            \
      ((_s)&4)) &&                                                         \
     (((_s)&3) == 1))
#define VALID_CODESEL(_s) ((_s) == FLAT_RING1_CS || VALID_SEL(_s))

/* These are bitmasks for the high 32 bits of a descriptor table entry. */
#define _SEGMENT_TYPE    (15<< 8)
#define _SEGMENT_EC      ( 1<<10) /* Expand-down or Conforming segment */
#define _SEGMENT_CODE    ( 1<<11) /* Code (vs data) segment for non-system
                                     segments */
#define _SEGMENT_S       ( 1<<12) /* System descriptor (yes iff S==0) */
#define _SEGMENT_DPL     ( 3<<13) /* Descriptor Privilege Level */
#define _SEGMENT_P       ( 1<<15) /* Segment Present */
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
#elif defined(__i386__)
typedef struct desc_struct idt_entry_t;
#endif

extern struct desc_struct gdt_table[];
extern struct desc_struct *gdt;
extern idt_entry_t        *idt;

struct Xgt_desc_struct {
    unsigned short size;
    unsigned long address __attribute__((packed));
};

#define idt_descr (*(struct Xgt_desc_struct *)((char *)&idt - 2))
#define gdt_descr (*(struct Xgt_desc_struct *)((char *)&gdt - 2))

extern void set_intr_gate(unsigned int irq, void * addr);
extern void set_tss_desc(unsigned int n, void *addr);

#endif /* !__ASSEMBLY__ */

#endif
