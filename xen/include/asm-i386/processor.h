/*
 * include/asm-i386/processor.h
 *
 * Copyright (C) 1994 Linus Torvalds
 */

#ifndef __ASM_I386_PROCESSOR_H
#define __ASM_I386_PROCESSOR_H

#include <asm/page.h>
#include <asm/types.h>
#include <asm/cpufeature.h>
#include <asm/desc.h>
#include <asm/flushtlb.h>
#include <xen/config.h>
#include <xen/spinlock.h>
#include <hypervisor-ifs/hypervisor-if.h>

struct task_struct;

/*
 * Default implementation of macro that returns current
 * instruction pointer ("program counter").
 */
#define current_text_addr() \
  ({ void *pc; __asm__("movl $1f,%0\n1:":"=g" (pc)); pc; })

/*
 *  CPU type and hardware bug flags. Kept separately for each CPU.
 *  Members of this structure are referenced in head.S, so think twice
 *  before touching them. [mj]
 */

struct cpuinfo_x86 {
    __u8    x86;            /* CPU family */
    __u8    x86_vendor;     /* CPU vendor */
    __u8    x86_model;
    __u8    x86_mask;
    char    wp_works_ok;    /* It doesn't on 386's */
    char    hlt_works_ok;   /* Problems on some 486Dx4's and old 386's */
    char    hard_math;
    char    rfu;
    int     cpuid_level;    /* Maximum supported CPUID level, -1=no CPUID */
    __u32   x86_capability[NCAPINTS];
    char    x86_vendor_id[16];
    char    x86_model_id[64];
    int     x86_cache_size;  /* in KB - valid for CPUS which support this
                                call  */
    int     fdiv_bug;
    int     f00f_bug;
    int     coma_bug;
    unsigned long loops_per_jiffy;
    unsigned long *pgd_quick;
    unsigned long *pmd_quick;
    unsigned long *pte_quick;
    unsigned long pgtable_cache_sz;
} __attribute__((__aligned__(SMP_CACHE_BYTES)));

#define X86_VENDOR_INTEL 0
#define X86_VENDOR_CYRIX 1
#define X86_VENDOR_AMD 2
#define X86_VENDOR_UMC 3
#define X86_VENDOR_NEXGEN 4
#define X86_VENDOR_CENTAUR 5
#define X86_VENDOR_RISE 6
#define X86_VENDOR_TRANSMETA 7
#define X86_VENDOR_NSC 8
#define X86_VENDOR_SIS 9
#define X86_VENDOR_UNKNOWN 0xff

/*
 * capabilities of CPUs
 */

extern struct cpuinfo_x86 boot_cpu_data;
extern struct tss_struct init_tss[NR_CPUS];

#ifdef CONFIG_SMP
extern struct cpuinfo_x86 cpu_data[];
#define current_cpu_data cpu_data[smp_processor_id()]
#else
#define cpu_data (&boot_cpu_data)
#define current_cpu_data boot_cpu_data
#endif

extern char ignore_irq13;

extern void identify_cpu(struct cpuinfo_x86 *);
extern void print_cpu_info(struct cpuinfo_x86 *);
extern void dodgy_tsc(void);

/*
 * EFLAGS bits
 */
#define X86_EFLAGS_CF	0x00000001 /* Carry Flag */
#define X86_EFLAGS_PF	0x00000004 /* Parity Flag */
#define X86_EFLAGS_AF	0x00000010 /* Auxillary carry Flag */
#define X86_EFLAGS_ZF	0x00000040 /* Zero Flag */
#define X86_EFLAGS_SF	0x00000080 /* Sign Flag */
#define X86_EFLAGS_TF	0x00000100 /* Trap Flag */
#define X86_EFLAGS_IF	0x00000200 /* Interrupt Flag */
#define X86_EFLAGS_DF	0x00000400 /* Direction Flag */
#define X86_EFLAGS_OF	0x00000800 /* Overflow Flag */
#define X86_EFLAGS_IOPL	0x00003000 /* IOPL mask */
#define X86_EFLAGS_NT	0x00004000 /* Nested Task */
#define X86_EFLAGS_RF	0x00010000 /* Resume Flag */
#define X86_EFLAGS_VM	0x00020000 /* Virtual Mode */
#define X86_EFLAGS_AC	0x00040000 /* Alignment Check */
#define X86_EFLAGS_VIF	0x00080000 /* Virtual Interrupt Flag */
#define X86_EFLAGS_VIP	0x00100000 /* Virtual Interrupt Pending */
#define X86_EFLAGS_ID	0x00200000 /* CPUID detection flag */

/*
 * Generic CPUID function
 */
static inline void cpuid(int op, int *eax, int *ebx, int *ecx, int *edx)
{
    __asm__("cpuid"
            : "=a" (*eax),
            "=b" (*ebx),
            "=c" (*ecx),
            "=d" (*edx)
            : "0" (op));
}

/*
 * CPUID functions returning a single datum
 */
static inline unsigned int cpuid_eax(unsigned int op)
{
    unsigned int eax;

    __asm__("cpuid"
            : "=a" (eax)
            : "0" (op)
            : "bx", "cx", "dx");
    return eax;
}
static inline unsigned int cpuid_ebx(unsigned int op)
{
    unsigned int eax, ebx;

    __asm__("cpuid"
            : "=a" (eax), "=b" (ebx)
            : "0" (op)
            : "cx", "dx" );
    return ebx;
}
static inline unsigned int cpuid_ecx(unsigned int op)
{
    unsigned int eax, ecx;

    __asm__("cpuid"
            : "=a" (eax), "=c" (ecx)
            : "0" (op)
            : "bx", "dx" );
    return ecx;
}
static inline unsigned int cpuid_edx(unsigned int op)
{
    unsigned int eax, edx;

    __asm__("cpuid"
            : "=a" (eax), "=d" (edx)
            : "0" (op)
            : "bx", "cx");
    return edx;
}


/*
 * Intel CPU flags in CR0
 */
#define X86_CR0_PE              0x00000001 /* Enable Protected Mode    (RW) */
#define X86_CR0_MP              0x00000002 /* Monitor Coprocessor      (RW) */
#define X86_CR0_EM              0x00000004 /* Require FPU Emulation    (RO) */
#define X86_CR0_TS              0x00000008 /* Task Switched            (RW) */
#define X86_CR0_NE              0x00000020 /* Numeric Error Reporting  (RW) */
#define X86_CR0_WP              0x00010000 /* Supervisor Write Protect (RW) */
#define X86_CR0_AM              0x00040000 /* Alignment Checking       (RW) */
#define X86_CR0_NW              0x20000000 /* Not Write-Through        (RW) */
#define X86_CR0_CD              0x40000000 /* Cache Disable            (RW) */
#define X86_CR0_PG              0x80000000 /* Paging                   (RW) */

#define read_cr0() ({ \
	unsigned int __dummy; \
	__asm__( \
		"movl %%cr0,%0\n\t" \
		:"=r" (__dummy)); \
	__dummy; \
})

#define write_cr0(x) \
	__asm__("movl %0,%%cr0": :"r" (x));


/*
 * Intel CPU features in CR4
 */
#define X86_CR4_VME		0x0001	/* enable vm86 extensions */
#define X86_CR4_PVI		0x0002	/* virtual interrupts flag enable */
#define X86_CR4_TSD		0x0004	/* disable time stamp at ipl 3 */
#define X86_CR4_DE		0x0008	/* enable debugging extensions */
#define X86_CR4_PSE		0x0010	/* enable page size extensions */
#define X86_CR4_PAE		0x0020	/* enable physical address extensions */
#define X86_CR4_MCE		0x0040	/* Machine check enable */
#define X86_CR4_PGE		0x0080	/* enable global pages */
#define X86_CR4_PCE		0x0100	/* enable performance counters at ipl 3 */
#define X86_CR4_OSFXSR		0x0200	/* enable fast FPU save and restore */
#define X86_CR4_OSXMMEXCPT	0x0400	/* enable unmasked SSE exceptions */

/*
 * Save the cr4 feature set we're using (ie
 * Pentium 4MB enable and PPro Global page
 * enable), so that any CPU's that boot up
 * after us can get the correct flags.
 */
extern unsigned long mmu_cr4_features;

static inline void set_in_cr4 (unsigned long mask)
{
    mmu_cr4_features |= mask;
    __asm__("movl %%cr4,%%eax\n\t"
            "orl %0,%%eax\n\t"
            "movl %%eax,%%cr4\n"
            : : "irg" (mask)
            :"ax");
}

static inline void clear_in_cr4 (unsigned long mask)
{
    mmu_cr4_features &= ~mask;
    __asm__("movl %%cr4,%%eax\n\t"
            "andl %0,%%eax\n\t"
            "movl %%eax,%%cr4\n"
            : : "irg" (~mask)
            :"ax");
}



/*
 *      Cyrix CPU configuration register indexes
 */
#define CX86_CCR0 0xc0
#define CX86_CCR1 0xc1
#define CX86_CCR2 0xc2
#define CX86_CCR3 0xc3
#define CX86_CCR4 0xe8
#define CX86_CCR5 0xe9
#define CX86_CCR6 0xea
#define CX86_CCR7 0xeb
#define CX86_DIR0 0xfe
#define CX86_DIR1 0xff
#define CX86_ARR_BASE 0xc4
#define CX86_RCR_BASE 0xdc

/*
 *      Cyrix CPU indexed register access macros
 */

#define getCx86(reg) ({ outb((reg), 0x22); inb(0x23); })

#define setCx86(reg, data) do { \
	outb((reg), 0x22); \
	outb((data), 0x23); \
} while (0)

#define EISA_bus (0)
#define MCA_bus  (0)

/* from system description table in BIOS.  Mostly for MCA use, but
others may find it useful. */
extern unsigned int machine_id;
extern unsigned int machine_submodel_id;
extern unsigned int BIOS_revision;
extern unsigned int mca_pentium_flag;

/*
 * User space process size: 3GB (default).
 */
#define TASK_SIZE	(PAGE_OFFSET)

/* This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define TASK_UNMAPPED_BASE	(TASK_SIZE / 3)

/*
 * Size of io_bitmap in longwords:
 * For Xen we support the full 8kbyte IO bitmap but use the io_bitmap_sel field
 * of the task_struct to avoid a full 8kbyte copy when switching to / from
 * domains with bits cleared.
 */
#define IO_BITMAP_SIZE	2048
#define IO_BITMAP_BYTES (IO_BITMAP_SIZE * 4)
#define IO_BITMAP_OFFSET offsetof(struct tss_struct,io_bitmap)
#define INVALID_IO_BITMAP_OFFSET 0x8000

struct i387_fsave_struct {
    long	cwd;
    long	swd;
    long	twd;
    long	fip;
    long	fcs;
    long	foo;
    long	fos;
    long	st_space[20];	/* 8*10 bytes for each FP-reg = 80 bytes */
    long	status;		/* software status information */
};

struct i387_fxsave_struct {
    unsigned short	cwd;
    unsigned short	swd;
    unsigned short	twd;
    unsigned short	fop;
    long	fip;
    long	fcs;
    long	foo;
    long	fos;
    long	mxcsr;
    long	reserved;
    long	st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
    long	xmm_space[32];	/* 8*16 bytes for each XMM-reg = 128 bytes */
    long	padding[56];
} __attribute__ ((aligned (16)));

struct i387_soft_struct {
    long    cwd;
    long    swd;
    long    twd;
    long    fip;
    long    fcs;
    long    foo;
    long    fos;
    long    st_space[20];   /* 8*10 bytes for each FP-reg = 80 bytes */
    unsigned char   ftop, changed, lookahead, no_update, rm, alimit;
    struct info     *info;
    unsigned long   entry_eip;
};

union i387_union {
    struct i387_fsave_struct	fsave;
    struct i387_fxsave_struct	fxsave;
    struct i387_soft_struct soft;
};

typedef struct {
    unsigned long seg;
} mm_segment_t;

struct tss_struct {
    unsigned short	back_link,__blh;
    unsigned long	esp0;
    unsigned short	ss0,__ss0h;
    unsigned long	esp1;
    unsigned short	ss1,__ss1h;
    unsigned long	esp2;
    unsigned short	ss2,__ss2h;
    unsigned long	__cr3;
    unsigned long	eip;
    unsigned long	eflags;
    unsigned long	eax,ecx,edx,ebx;
    unsigned long	esp;
    unsigned long	ebp;
    unsigned long	esi;
    unsigned long	edi;
    unsigned short	es, __esh;
    unsigned short	cs, __csh;
    unsigned short	ss, __ssh;
    unsigned short	ds, __dsh;
    unsigned short	fs, __fsh;
    unsigned short	gs, __gsh;
    unsigned short	ldt, __ldth;
    unsigned short	trace, bitmap;
    unsigned long	io_bitmap[IO_BITMAP_SIZE+1];
    /*
     * pads the TSS to be cacheline-aligned (size is 0x100)
     */
    unsigned long __cacheline_filler[5];
};

struct thread_struct {
    unsigned long guestos_sp, guestos_ss;
/* Hardware debugging registers */
    unsigned long	debugreg[8];  /* %%db0-7 debug registers */
/* floating point info */
    union i387_union	i387;
/* Trap info. */
    int                 fast_trap_idx;
    struct desc_struct  fast_trap_desc;
    trap_info_t         traps[256];
};

#define IDT_ENTRIES 256
extern struct desc_struct idt_table[];
extern struct desc_struct *idt_tables[];

#define SET_DEFAULT_FAST_TRAP(_p) \
    (_p)->fast_trap_idx = 0x20;   \
    (_p)->fast_trap_desc.a = 0;   \
    (_p)->fast_trap_desc.b = 0;

#define CLEAR_FAST_TRAP(_p) \
    (memset(idt_tables[smp_processor_id()] + (_p)->fast_trap_idx, \
     0, 8))

#define SET_FAST_TRAP(_p)   \
    (memcpy(idt_tables[smp_processor_id()] + (_p)->fast_trap_idx, \
     &((_p)->fast_trap_desc), 8))

long set_fast_trap(struct task_struct *p, int idx);

#define INIT_THREAD  {						\
	0, 0,		      		       			\
	{ [0 ... 7] = 0 },	/* debugging registers */	\
	{ { 0, }, },		/* 387 state */			\
	0x20, { 0, 0 },		/* DEFAULT_FAST_TRAP */		\
	{ {0} }			/* io permissions */		\
}

#define INIT_TSS  {						\
	0,0, /* back_link, __blh */				\
	0, /* esp0 */						\
	0, 0, /* ss0 */						\
	0,0,0,0,0,0, /* stack1, stack2 */			\
	0, /* cr3 */						\
	0,0, /* eip,eflags */					\
	0,0,0,0, /* eax,ecx,edx,ebx */				\
	0,0,0,0, /* esp,ebp,esi,edi */				\
	0,0,0,0,0,0, /* es,cs,ss */				\
	0,0,0,0,0,0, /* ds,fs,gs */				\
	0,0, /* ldt */						\
	0, INVALID_IO_BITMAP_OFFSET, /* tace, bitmap */		\
	{ [0 ... IO_BITMAP_SIZE] = ~0UL }, /* ioperm */         \
}

struct mm_struct {
    /*
     * Every domain has a L1 pagetable of its own. Per-domain mappings
     * are put in this table (eg. the current GDT is mapped here).
     */
    l1_pgentry_t *perdomain_pt;
    pagetable_t  pagetable;

    unsigned int shadow_mode;  /* flags to control shadow table operation */
    pagetable_t  shadow_table;
    spinlock_t shadow_lock;
    struct shadow_status *shadow_ht;
    struct shadow_status *shadow_ht_free;
    struct shadow_status *shadow_ht_extras; /* extra allocation units */
    unsigned int *shadow_dirty_bitmap;
    unsigned int shadow_dirty_bitmap_size;  /* in pages, bit per page */
    unsigned int shadow_page_count;
    unsigned int shadow_max_page_count;
    unsigned int shadow_extras_count;

    /* Current LDT details. */
    unsigned long ldt_base, ldt_ents, shadow_ldt_mapcnt;
    /* Next entry is passed to LGDT on domain switch. */
    char gdt[6];
};

static inline void write_ptbase(struct mm_struct *mm)
{
    unsigned long pa;

    if ( unlikely(mm->shadow_mode) )
        pa = pagetable_val(mm->shadow_table);
    else
        pa = pagetable_val(mm->pagetable);

    __asm__ __volatile__ ( "movl %0, %%cr3" : : "r" (pa) : "memory" );
}

#define IDLE0_MM                                                    \
{                                                                   \
    perdomain_pt: 0,                                                \
    pagetable:   mk_pagetable(__pa(idle_pg_table))                  \
}

/* Convenient accessor for mm.gdt. */
#define SET_GDT_ENTRIES(_p, _e) ((*(u16 *)((_p)->mm.gdt + 0)) = (_e))
#define SET_GDT_ADDRESS(_p, _a) ((*(u32 *)((_p)->mm.gdt + 2)) = (_a))
#define GET_GDT_ENTRIES(_p)     ((*(u16 *)((_p)->mm.gdt + 0)))
#define GET_GDT_ADDRESS(_p)     ((*(u32 *)((_p)->mm.gdt + 2)))

long set_gdt(struct task_struct *p, 
             unsigned long *frames, 
             unsigned int entries);

long set_debugreg(struct task_struct *p, int reg, unsigned long value);

struct microcode {
    unsigned int hdrver;
    unsigned int rev;
    unsigned int date;
    unsigned int sig;
    unsigned int cksum;
    unsigned int ldrver;
    unsigned int pf;
    unsigned int reserved[5];
    unsigned int bits[500];
};

/* '6' because it used to be for P6 only (but now covers Pentium 4 as well) */
#define MICROCODE_IOCFREE	_IO('6',0)

/* REP NOP (PAUSE) is a good thing to insert into busy-wait loops. */
static inline void rep_nop(void)
{
    __asm__ __volatile__("rep;nop");
}

#define cpu_relax()	rep_nop()

/* Prefetch instructions for Pentium III and AMD Athlon */
#ifdef 	CONFIG_MPENTIUMIII

#define ARCH_HAS_PREFETCH
extern inline void prefetch(const void *x)
{
    __asm__ __volatile__ ("prefetchnta (%0)" : : "r"(x));
}

#elif CONFIG_X86_USE_3DNOW

#define ARCH_HAS_PREFETCH
#define ARCH_HAS_PREFETCHW
#define ARCH_HAS_SPINLOCK_PREFETCH

extern inline void prefetch(const void *x)
{
    __asm__ __volatile__ ("prefetch (%0)" : : "r"(x));
}

extern inline void prefetchw(const void *x)
{
    __asm__ __volatile__ ("prefetchw (%0)" : : "r"(x));
}
#define spin_lock_prefetch(x)	prefetchw(x)

#endif

#endif /* __ASM_I386_PROCESSOR_H */
