#ifndef __ARCH_DESC_H
#define __ARCH_DESC_H

#define LDT_ENTRY_SIZE 16

#define __DOUBLEFAULT_TSS_ENTRY FIRST_RESERVED_GDT_ENTRY

#define __FIRST_PER_CPU_ENTRY (FIRST_RESERVED_GDT_ENTRY + 8)

#define __CPU_DESC_INDEX(x,field) \
	((x) * sizeof(struct per_cpu_gdt) + offsetof(struct per_cpu_gdt, field) + (__FIRST_PER_CPU_ENTRY*8))
#define __LDT(n) (((n)<<1) + __FIRST_LDT_ENTRY)

#define load_TR(cpu) asm volatile("ltr %w0"::"r" (__CPU_DESC_INDEX(cpu, tss)));
#define __load_LDT(cpu) asm volatile("lldt %w0"::"r" (__CPU_DESC_INDEX(cpu, ldt)));
#define clear_LDT(n)  asm volatile("lldt %w0"::"r" (0))

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
     (((_s)&3) == 0))
#define VALID_CODESEL(_s) ((_s) == FLAT_RING3_CS || VALID_SEL(_s))

/* These are bitmasks for the first 32 bits of a descriptor table entry. */
#define _SEGMENT_TYPE    (15<< 8)
#define _SEGMENT_S       ( 1<<12) /* System descriptor (yes iff S==0) */
#define _SEGMENT_DPL     ( 3<<13) /* Descriptor Privilege Level */
#define _SEGMENT_P       ( 1<<15) /* Segment Present */
#define _SEGMENT_G       ( 1<<23) /* Granularity */

#ifndef __ASSEMBLY__

enum { 
	GATE_INTERRUPT = 0xE, 
	GATE_TRAP = 0xF, 	
	GATE_CALL = 0xC,
}; 	

// 16byte gate
struct gate_struct {          
	u16 offset_low;
	u16 segment; 
	unsigned ist : 3, zero0 : 5, type : 5, dpl : 2, p : 1;
	u16 offset_middle;
	u32 offset_high;
	u32 zero1; 
} __attribute__((packed));

// 8 byte segment descriptor
struct desc_struct { 
	u16 limit0;
	u16 base0;
	unsigned base1 : 8, type : 4, s : 1, dpl : 2, p : 1;
	unsigned limit : 4, avl : 1, l : 1, d : 1, g : 1, base2 : 8;
} __attribute__((packed)); 

// LDT or TSS descriptor in the GDT. 16 bytes.
struct ldttss_desc { 
	u16 limit0;
	u16 base0;
	unsigned base1 : 8, type : 5, dpl : 2, p : 1;
	unsigned limit1 : 4, zero0 : 3, g : 1, base2 : 8;
	u32 base3;
	u32 zero1; 
} __attribute__((packed)); 

// Union of above structures
union desc_union {
	struct desc_struct seg;
	struct ldttss_desc ldttss;
	struct gate_struct gate;
};

struct per_cpu_gdt {
	struct ldttss_desc tss;
	struct ldttss_desc ldt; 
} __cacheline_aligned; 


struct Xgt_desc_struct {
	unsigned short size;
	unsigned long address;
} __attribute__((packed));

extern __u8 gdt_table[];
extern __u8 gdt_end[];
extern union desc_union *gdt; 

extern struct per_cpu_gdt gdt_cpu_table[]; 

#define PTR_LOW(x) ((unsigned long)(x) & 0xFFFF) 
#define PTR_MIDDLE(x) (((unsigned long)(x) >> 16) & 0xFFFF)
#define PTR_HIGH(x) ((unsigned long)(x) >> 32)

enum { 
	DESC_TSS = 0x9,
	DESC_LDT = 0x2,
}; 

extern struct gate_struct *idt;

#define idt_descr (*(struct Xgt_desc_struct *)((char *)&idt - 2))
#define gdt_descr (*(struct Xgt_desc_struct *)((char *)&gdt - 2))

extern void set_intr_gate(unsigned int irq, void * addr);
extern void set_tss_desc(unsigned int n, void *addr);

#endif /* !__ASSEMBLY__ */

#endif
