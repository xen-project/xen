
/* Portions are: Copyright (c) 1994 Linus Torvalds */

#ifndef __ASM_X86_PROCESSOR_H
#define __ASM_X86_PROCESSOR_H

#ifndef __ASSEMBLY__
#include <xen/config.h>
#include <xen/cache.h>
#include <xen/types.h>
#include <xen/smp.h>
#include <xen/percpu.h>
#include <public/xen.h>
#include <asm/types.h>
#include <asm/cpufeature.h>
#include <asm/desc.h>
#endif

/*
 * CPU vendor IDs
 */
#define X86_VENDOR_INTEL 0
#define X86_VENDOR_CYRIX 1
#define X86_VENDOR_AMD 2
#define X86_VENDOR_UMC 3
#define X86_VENDOR_NEXGEN 4
#define X86_VENDOR_CENTAUR 5
#define X86_VENDOR_RISE 6
#define X86_VENDOR_TRANSMETA 7
#define X86_VENDOR_NSC 8
#define X86_VENDOR_NUM 9
#define X86_VENDOR_UNKNOWN 0xff

/*
 * EFLAGS bits
 */
#define X86_EFLAGS_CF	0x00000001 /* Carry Flag */
#define X86_EFLAGS_MBS	0x00000002 /* Resvd bit */
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
 * Intel CPU flags in CR0
 */
#define X86_CR0_PE              0x00000001 /* Enable Protected Mode    (RW) */
#define X86_CR0_MP              0x00000002 /* Monitor Coprocessor      (RW) */
#define X86_CR0_EM              0x00000004 /* Require FPU Emulation    (RO) */
#define X86_CR0_TS              0x00000008 /* Task Switched            (RW) */
#define X86_CR0_ET              0x00000010 /* Extension type           (RO) */
#define X86_CR0_NE              0x00000020 /* Numeric Error Reporting  (RW) */
#define X86_CR0_WP              0x00010000 /* Supervisor Write Protect (RW) */
#define X86_CR0_AM              0x00040000 /* Alignment Checking       (RW) */
#define X86_CR0_NW              0x20000000 /* Not Write-Through        (RW) */
#define X86_CR0_CD              0x40000000 /* Cache Disable            (RW) */
#define X86_CR0_PG              0x80000000 /* Paging                   (RW) */

/*
 * Intel CPU features in CR4
 */
#define X86_CR4_VME        0x00000001 /* enable vm86 extensions */
#define X86_CR4_PVI        0x00000002 /* virtual interrupts flag enable */
#define X86_CR4_TSD        0x00000004 /* disable time stamp at ipl 3 */
#define X86_CR4_DE         0x00000008 /* enable debugging extensions */
#define X86_CR4_PSE        0x00000010 /* enable page size extensions */
#define X86_CR4_PAE        0x00000020 /* enable physical address extensions */
#define X86_CR4_MCE        0x00000040 /* Machine check enable */
#define X86_CR4_PGE        0x00000080 /* enable global pages */
#define X86_CR4_PCE        0x00000100 /* enable performance counters at ipl 3 */
#define X86_CR4_OSFXSR     0x00000200 /* enable fast FPU save and restore */
#define X86_CR4_OSXMMEXCPT 0x00000400 /* enable unmasked SSE exceptions */
#define X86_CR4_VMXE       0x00002000 /* enable VMX */
#define X86_CR4_SMXE       0x00004000 /* enable SMX */
#define X86_CR4_FSGSBASE   0x00010000 /* enable {rd,wr}{fs,gs}base */
#define X86_CR4_PCIDE      0x00020000 /* enable PCID */
#define X86_CR4_OSXSAVE    0x00040000 /* enable XSAVE/XRSTOR */
#define X86_CR4_SMEP       0x00100000 /* enable SMEP */
#define X86_CR4_SMAP       0x00200000 /* enable SMAP */
#define X86_CR4_PKE        0x00400000 /* enable PKE */

/*
 * Trap/fault mnemonics.
 */
#define TRAP_divide_error      0
#define TRAP_debug             1
#define TRAP_nmi               2
#define TRAP_int3              3
#define TRAP_overflow          4
#define TRAP_bounds            5
#define TRAP_invalid_op        6
#define TRAP_no_device         7
#define TRAP_double_fault      8
#define TRAP_copro_seg         9
#define TRAP_invalid_tss      10
#define TRAP_no_segment       11
#define TRAP_stack_error      12
#define TRAP_gp_fault         13
#define TRAP_page_fault       14
#define TRAP_spurious_int     15
#define TRAP_copro_error      16
#define TRAP_alignment_check  17
#define TRAP_machine_check    18
#define TRAP_simd_error       19
#define TRAP_virtualisation   20
#define TRAP_nr               32

#define TRAP_HAVE_EC                                                    \
    ((1u << TRAP_double_fault) | (1u << TRAP_invalid_tss) |             \
     (1u << TRAP_no_segment) | (1u << TRAP_stack_error) |               \
     (1u << TRAP_gp_fault) | (1u << TRAP_page_fault) |                  \
     (1u << TRAP_alignment_check))

/* Set for entry via SYSCALL. Informs return code to use SYSRETQ not IRETQ. */
/* NB. Same as VGCF_in_syscall. No bits in common with any other TRAP_ defn. */
#define TRAP_syscall         256

/* Boolean return code: the reason for a fault has been fixed. */
#define EXCRET_fault_fixed 1

/* 'trap_bounce' flags values */
#define TBF_EXCEPTION          1
#define TBF_EXCEPTION_ERRCODE  2
#define TBF_INTERRUPT          8

/* 'arch_vcpu' flags values */
#define _TF_kernel_mode        0
#define TF_kernel_mode         (1<<_TF_kernel_mode)

/* #PF error code values. */
#define PFEC_page_present   (_AC(1,U) << 0)
#define PFEC_write_access   (_AC(1,U) << 1)
#define PFEC_user_mode      (_AC(1,U) << 2)
#define PFEC_reserved_bit   (_AC(1,U) << 3)
#define PFEC_insn_fetch     (_AC(1,U) << 4)
#define PFEC_prot_key       (_AC(1,U) << 5)
/* Internally used only flags. */
#define PFEC_page_paged     (1U<<16)
#define PFEC_page_shared    (1U<<17)

/* Other exception error code values. */
#define X86_XEC_EXT         (_AC(1,U) << 0)
#define X86_XEC_IDT         (_AC(1,U) << 1)
#define X86_XEC_TI          (_AC(1,U) << 2)

#define XEN_MINIMAL_CR4 (X86_CR4_PGE | X86_CR4_PAE)

#define XEN_CR4_PV32_BITS (X86_CR4_SMEP|X86_CR4_SMAP)

#define XEN_SYSCALL_MASK (X86_EFLAGS_AC|X86_EFLAGS_VM|X86_EFLAGS_RF|    \
                          X86_EFLAGS_NT|X86_EFLAGS_DF|X86_EFLAGS_IF|    \
                          X86_EFLAGS_TF)

#ifndef __ASSEMBLY__

struct domain;
struct vcpu;

/*
 * Default implementation of macro that returns current
 * instruction pointer ("program counter").
 */
#define current_text_addr() ({                      \
    void *pc;                                       \
    asm ( "leaq 1f(%%rip),%0\n1:" : "=r" (pc) );    \
    pc;                                             \
})

struct x86_cpu_id {
    uint16_t vendor;
    uint16_t family;
    uint16_t model;
    uint16_t feature;   /* bit index */
    const void *driver_data;
};

struct cpuinfo_x86 {
    __u8 x86;            /* CPU family */
    __u8 x86_vendor;     /* CPU vendor */
    __u8 x86_model;
    __u8 x86_mask;
    int  cpuid_level;    /* Maximum supported CPUID level, -1=no CPUID */
    __u32 extended_cpuid_level; /* Maximum supported CPUID extended level */
    unsigned int x86_capability[NCAPINTS];
    char x86_vendor_id[16];
    char x86_model_id[64];
    int  x86_cache_size; /* in KB - valid for CPUS which support this call  */
    int  x86_cache_alignment;    /* In bytes */
    __u32 x86_max_cores; /* cpuid returned max cores value */
    __u32 booted_cores;  /* number of cores as seen by OS */
    __u32 x86_num_siblings; /* cpuid logical cpus per chip value */
    __u32 apicid;
    __u32 phys_proc_id;    /* package ID of each logical CPU */
    __u32 cpu_core_id;     /* core ID of each logical CPU*/
    __u32 compute_unit_id; /* AMD compute unit ID of each logical CPU */
    unsigned short x86_clflush_size;
} __cacheline_aligned;

/*
 * capabilities of CPUs
 */

extern struct cpuinfo_x86 boot_cpu_data;

extern struct cpuinfo_x86 cpu_data[];
#define current_cpu_data cpu_data[smp_processor_id()]

extern void (*ctxt_switch_levelling)(const struct vcpu *next);

extern u64 host_pat;
extern bool_t opt_cpu_info;
extern u32 cpuid_ext_features;
extern u64 trampoline_misc_enable_off;

/* Maximum width of physical addresses supported by the hardware. */
extern unsigned int paddr_bits;
/* Max physical address width supported within HAP guests. */
extern unsigned int hap_paddr_bits;
/* Maximum width of virtual addresses supported by the hardware. */
extern unsigned int vaddr_bits;

extern const struct x86_cpu_id *x86_match_cpu(const struct x86_cpu_id table[]);

extern void identify_cpu(struct cpuinfo_x86 *);
extern void setup_clear_cpu_cap(unsigned int);
extern void setup_force_cpu_cap(unsigned int);
extern void print_cpu_info(unsigned int cpu);
extern unsigned int init_intel_cacheinfo(struct cpuinfo_x86 *c);

extern void detect_extended_topology(struct cpuinfo_x86 *c);

extern void detect_ht(struct cpuinfo_x86 *c);

#define cpu_to_core(_cpu)   (cpu_data[_cpu].cpu_core_id)
#define cpu_to_socket(_cpu) (cpu_data[_cpu].phys_proc_id)

unsigned int apicid_to_socket(unsigned int);

/*
 * Generic CPUID function
 * clear %ecx since some cpus (Cyrix MII) do not set or clear %ecx
 * resulting in stale register contents being returned.
 */
#define cpuid(_op,_eax,_ebx,_ecx,_edx)          \
    asm volatile ( "cpuid"                      \
          : "=a" (*(int *)(_eax)),              \
            "=b" (*(int *)(_ebx)),              \
            "=c" (*(int *)(_ecx)),              \
            "=d" (*(int *)(_edx))               \
          : "0" (_op), "2" (0) )

/* Some CPUID calls want 'count' to be placed in ecx */
static inline void cpuid_count(
    unsigned int op,
    unsigned int count,
    unsigned int *eax,
    unsigned int *ebx,
    unsigned int *ecx,
    unsigned int *edx)
{
    asm volatile ( "cpuid"
          : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
          : "0" (op), "c" (count) );
}

/*
 * CPUID functions returning a single datum
 */
static always_inline unsigned int cpuid_eax(unsigned int op)
{
    unsigned int eax;

    asm volatile ( "cpuid"
          : "=a" (eax)
          : "0" (op)
          : "bx", "cx", "dx" );
    return eax;
}

static always_inline unsigned int cpuid_ebx(unsigned int op)
{
    unsigned int eax, ebx;

    asm volatile ( "cpuid"
          : "=a" (eax), "=b" (ebx)
          : "0" (op)
          : "cx", "dx" );
    return ebx;
}

static always_inline unsigned int cpuid_ecx(unsigned int op)
{
    unsigned int eax, ecx;

    asm volatile ( "cpuid"
          : "=a" (eax), "=c" (ecx)
          : "0" (op)
          : "bx", "dx" );
    return ecx;
}

static always_inline unsigned int cpuid_edx(unsigned int op)
{
    unsigned int eax, edx;

    asm volatile ( "cpuid"
          : "=a" (eax), "=d" (edx)
          : "0" (op)
          : "bx", "cx" );
    return edx;
}

static inline unsigned long read_cr0(void)
{
    unsigned long cr0;
    asm volatile ( "mov %%cr0,%0\n\t" : "=r" (cr0) );
    return cr0;
} 

static inline void write_cr0(unsigned long val)
{
    asm volatile ( "mov %0,%%cr0" : : "r" ((unsigned long)val) );
}

static inline unsigned long read_cr2(void)
{
    unsigned long cr2;
    asm volatile ( "mov %%cr2,%0\n\t" : "=r" (cr2) );
    return cr2;
}

static inline unsigned long read_cr4(void)
{
    return get_cpu_info()->cr4;
}

static inline void write_cr4(unsigned long val)
{
    get_cpu_info()->cr4 = val;
    asm volatile ( "mov %0,%%cr4" : : "r" (val) );
}

/* Clear and set 'TS' bit respectively */
static inline void clts(void) 
{
    asm volatile ( "clts" );
}

static inline void stts(void) 
{
    write_cr0(X86_CR0_TS|read_cr0());
}

/*
 * Save the cr4 feature set we're using (ie
 * Pentium 4MB enable and PPro Global page
 * enable), so that any CPU's that boot up
 * after us can get the correct flags.
 */
extern unsigned long mmu_cr4_features;

static always_inline void set_in_cr4 (unsigned long mask)
{
    mmu_cr4_features |= mask;
    write_cr4(read_cr4() | mask);
}

static always_inline void clear_in_cr4 (unsigned long mask)
{
    mmu_cr4_features &= ~mask;
    write_cr4(read_cr4() & ~mask);
}

static inline unsigned int read_pkru(void)
{
    unsigned int pkru;
    unsigned long cr4 = read_cr4();

    /*
     * _PAGE_PKEY_BITS have a conflict with _PAGE_GNTTAB used by PV guests,
     * so that X86_CR4_PKE  is disabled on hypervisor. To use RDPKRU, CR4.PKE
     * gets temporarily enabled.
     */
    write_cr4(cr4 | X86_CR4_PKE);
    asm volatile (".byte 0x0f,0x01,0xee"
        : "=a" (pkru) : "c" (0) : "dx");
    write_cr4(cr4);

    return pkru;
}

/* Macros for PKRU domain */
#define PKRU_READ  (0)
#define PKRU_WRITE (1)
#define PKRU_ATTRS (2)

/*
 * PKRU defines 32 bits, there are 16 domains and 2 attribute bits per
 * domain in pkru, pkeys is index to a defined domain, so the value of
 * pte_pkeys * PKRU_ATTRS + R/W is offset of a defined domain attribute.
 */
static inline bool_t read_pkru_ad(uint32_t pkru, unsigned int pkey)
{
    ASSERT(pkey < 16);
    return (pkru >> (pkey * PKRU_ATTRS + PKRU_READ)) & 1;
}

static inline bool_t read_pkru_wd(uint32_t pkru, unsigned int pkey)
{
    ASSERT(pkey < 16);
    return (pkru >> (pkey * PKRU_ATTRS + PKRU_WRITE)) & 1;
}

/*
 *      NSC/Cyrix CPU configuration register indexes
 */

#define CX86_PCR0 0x20
#define CX86_GCR  0xb8
#define CX86_CCR0 0xc0
#define CX86_CCR1 0xc1
#define CX86_CCR2 0xc2
#define CX86_CCR3 0xc3
#define CX86_CCR4 0xe8
#define CX86_CCR5 0xe9
#define CX86_CCR6 0xea
#define CX86_CCR7 0xeb
#define CX86_PCR1 0xf0
#define CX86_DIR0 0xfe
#define CX86_DIR1 0xff
#define CX86_ARR_BASE 0xc4
#define CX86_RCR_BASE 0xdc

/*
 *      NSC/Cyrix CPU indexed register access macros
 */

#define getCx86(reg) ({ outb((reg), 0x22); inb(0x23); })

#define setCx86(reg, data) do { \
    outb((reg), 0x22); \
    outb((data), 0x23); \
} while (0)

/* Stop speculative execution */
static inline void sync_core(void)
{
    int tmp;
    asm volatile (
        "cpuid"
        : "=a" (tmp)
        : "0" (1)
        : "ebx","ecx","edx","memory" );
}

static always_inline void __monitor(const void *eax, unsigned long ecx,
                                    unsigned long edx)
{
    /* "monitor %eax,%ecx,%edx;" */
    asm volatile (
        ".byte 0x0f,0x01,0xc8;"
        : : "a" (eax), "c" (ecx), "d"(edx) );
}

static always_inline void __mwait(unsigned long eax, unsigned long ecx)
{
    /* "mwait %eax,%ecx;" */
    asm volatile (
        ".byte 0x0f,0x01,0xc9;"
        : : "a" (eax), "c" (ecx) );
}

#define IOBMP_BYTES             8192
#define IOBMP_INVALID_OFFSET    0x8000

struct __packed __cacheline_aligned tss_struct {
    unsigned short	back_link,__blh;
    union { u64 rsp0, esp0; };
    union { u64 rsp1, esp1; };
    union { u64 rsp2, esp2; };
    u64 reserved1;
    u64 ist[7]; /* Interrupt Stack Table is 1-based so tss->ist[0]
                 * corresponds to an IST value of 1 in an Interrupt
                 * Descriptor */
    u64 reserved2;
    u16 reserved3;
    u16 bitmap;
    /* Pads the TSS to be cacheline-aligned (total size is 0x80). */
    u8 __cacheline_filler[24];
};

#define IST_NONE 0UL
#define IST_DF   1UL
#define IST_NMI  2UL
#define IST_MCE  3UL
#define IST_MAX  3UL

/* Set the interrupt stack table used by a particular interrupt
 * descriptor table entry. */
static always_inline void set_ist(idt_entry_t *idt, unsigned long ist)
{
    idt_entry_t new = *idt;

    /* IST is a 3 bit field, 32 bits into the IDT entry. */
    ASSERT(ist <= IST_MAX);
    new.a = (idt->a & ~(7UL << 32)) | (ist << 32);
    _write_gate_lower(idt, &new);
}

#define IDT_ENTRIES 256
extern idt_entry_t idt_table[];
extern idt_entry_t *idt_tables[];

DECLARE_PER_CPU(struct tss_struct, init_tss);
DECLARE_PER_CPU(root_pgentry_t *, root_pgt);

extern void init_int80_direct_trap(struct vcpu *v);

extern void write_ptbase(struct vcpu *v);

void destroy_gdt(struct vcpu *d);
long set_gdt(struct vcpu *d, 
             unsigned long *frames, 
             unsigned int entries);

/* REP NOP (PAUSE) is a good thing to insert into busy-wait loops. */
static always_inline void rep_nop(void)
{
    asm volatile ( "rep;nop" : : : "memory" );
}

#define cpu_relax() rep_nop()

void show_stack(const struct cpu_user_regs *regs);
void show_stack_overflow(unsigned int cpu, const struct cpu_user_regs *regs);
void show_registers(const struct cpu_user_regs *regs);
void show_execution_state(const struct cpu_user_regs *regs);
#define dump_execution_state() run_in_exception_handler(show_execution_state)
void show_page_walk(unsigned long addr);
void noreturn fatal_trap(const struct cpu_user_regs *regs, bool_t show_remote);

void compat_show_guest_stack(struct vcpu *v,
                             const struct cpu_user_regs *regs, int lines);

extern void mtrr_ap_init(void);
extern void mtrr_bp_init(void);

void mcheck_init(struct cpuinfo_x86 *c, bool_t bsp);

/* Dispatch table for exceptions */
extern void (* const exception_table[TRAP_nr])(struct cpu_user_regs *regs);

#define DECLARE_TRAP_HANDLER(_name)                    \
    void _name(void);                                  \
    void do_ ## _name(struct cpu_user_regs *regs)
#define DECLARE_TRAP_HANDLER_CONST(_name)              \
    void _name(void);                                  \
    void do_ ## _name(const struct cpu_user_regs *regs)

DECLARE_TRAP_HANDLER(divide_error);
DECLARE_TRAP_HANDLER(debug);
DECLARE_TRAP_HANDLER_CONST(nmi);
DECLARE_TRAP_HANDLER(int3);
DECLARE_TRAP_HANDLER(overflow);
DECLARE_TRAP_HANDLER(bounds);
DECLARE_TRAP_HANDLER(invalid_op);
DECLARE_TRAP_HANDLER(device_not_available);
DECLARE_TRAP_HANDLER(double_fault);
DECLARE_TRAP_HANDLER(invalid_TSS);
DECLARE_TRAP_HANDLER(segment_not_present);
DECLARE_TRAP_HANDLER(stack_segment);
DECLARE_TRAP_HANDLER(general_protection);
DECLARE_TRAP_HANDLER(page_fault);
DECLARE_TRAP_HANDLER(early_page_fault);
DECLARE_TRAP_HANDLER(coprocessor_error);
DECLARE_TRAP_HANDLER(simd_coprocessor_error);
DECLARE_TRAP_HANDLER_CONST(machine_check);
DECLARE_TRAP_HANDLER(alignment_check);

#undef DECLARE_TRAP_HANDLER_CONST
#undef DECLARE_TRAP_HANDLER

void trap_nop(void);
void enable_nmis(void);
void do_reserved_trap(struct cpu_user_regs *regs);

void sysenter_entry(void);
void sysenter_eflags_saved(void);
void compat_hypercall(void);
void int80_direct_trap(void);

#define STUBS_PER_PAGE (PAGE_SIZE / STUB_BUF_SIZE)

struct stubs {
    union {
        void(*func)(void);
        unsigned long addr;
    };
    unsigned long mfn;
};

DECLARE_PER_CPU(struct stubs, stubs);
unsigned long alloc_stub_page(unsigned int cpu, unsigned long *mfn);

int cpuid_hypervisor_leaves( uint32_t idx, uint32_t sub_idx,
          uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx);
int rdmsr_hypervisor_regs(uint32_t idx, uint64_t *val);
int wrmsr_hypervisor_regs(uint32_t idx, uint64_t val);

void microcode_set_module(unsigned int);
int microcode_update(XEN_GUEST_HANDLE_PARAM(const_void), unsigned long len);
int microcode_resume_cpu(unsigned int cpu);

enum get_cpu_vendor {
    gcv_host,
    gcv_guest,
};

int get_cpu_vendor(const char vendor_id[], enum get_cpu_vendor);
void pv_cpuid(struct cpu_user_regs *regs);

#endif /* !__ASSEMBLY__ */

#endif /* __ASM_X86_PROCESSOR_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
