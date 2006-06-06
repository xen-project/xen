/******************************************************************************
 * arch-x86_64.h
 * 
 * Guest OS interface to x86 64-bit Xen.
 * 
 * Copyright (c) 2004, K A Fraser
 */

#ifndef __XEN_PUBLIC_ARCH_X86_64_H__
#define __XEN_PUBLIC_ARCH_X86_64_H__

#define __DEFINE_XEN_GUEST_HANDLE(name, type) \
    typedef struct { type *p; } __guest_handle_ ## name

#define DEFINE_XEN_GUEST_HANDLE(name)   __DEFINE_XEN_GUEST_HANDLE(name, name)
#define XEN_GUEST_HANDLE(name)          __guest_handle_ ## name
#define set_xen_guest_handle(hnd, val)  do { (hnd).p = val; } while (0)
#ifdef __XEN_TOOLS__
#define get_xen_guest_handle(val, hnd)  do { val = (hnd).p; } while (0)
#endif

#ifndef __ASSEMBLY__
/* Guest handles for primitive C types. */
__DEFINE_XEN_GUEST_HANDLE(uchar, unsigned char);
__DEFINE_XEN_GUEST_HANDLE(uint,  unsigned int);
__DEFINE_XEN_GUEST_HANDLE(ulong, unsigned long);
DEFINE_XEN_GUEST_HANDLE(char);
DEFINE_XEN_GUEST_HANDLE(int);
DEFINE_XEN_GUEST_HANDLE(long);
DEFINE_XEN_GUEST_HANDLE(void);

typedef unsigned long xen_pfn_t;
DEFINE_XEN_GUEST_HANDLE(xen_pfn_t);
#endif

/*
 * SEGMENT DESCRIPTOR TABLES
 */
/*
 * A number of GDT entries are reserved by Xen. These are not situated at the
 * start of the GDT because some stupid OSes export hard-coded selector values
 * in their ABI. These hard-coded values are always near the start of the GDT,
 * so Xen places itself out of the way, at the far end of the GDT.
 */
#define FIRST_RESERVED_GDT_PAGE  14
#define FIRST_RESERVED_GDT_BYTE  (FIRST_RESERVED_GDT_PAGE * 4096)
#define FIRST_RESERVED_GDT_ENTRY (FIRST_RESERVED_GDT_BYTE / 8)

/*
 * 64-bit segment selectors
 * These flat segments are in the Xen-private section of every GDT. Since these
 * are also present in the initial GDT, many OSes will be able to avoid
 * installing their own GDT.
 */

#define FLAT_RING3_CS32 0xe023  /* GDT index 260 */
#define FLAT_RING3_CS64 0xe033  /* GDT index 261 */
#define FLAT_RING3_DS32 0xe02b  /* GDT index 262 */
#define FLAT_RING3_DS64 0x0000  /* NULL selector */
#define FLAT_RING3_SS32 0xe02b  /* GDT index 262 */
#define FLAT_RING3_SS64 0xe02b  /* GDT index 262 */

#define FLAT_KERNEL_DS64 FLAT_RING3_DS64
#define FLAT_KERNEL_DS32 FLAT_RING3_DS32
#define FLAT_KERNEL_DS   FLAT_KERNEL_DS64
#define FLAT_KERNEL_CS64 FLAT_RING3_CS64
#define FLAT_KERNEL_CS32 FLAT_RING3_CS32
#define FLAT_KERNEL_CS   FLAT_KERNEL_CS64
#define FLAT_KERNEL_SS64 FLAT_RING3_SS64
#define FLAT_KERNEL_SS32 FLAT_RING3_SS32
#define FLAT_KERNEL_SS   FLAT_KERNEL_SS64

#define FLAT_USER_DS64 FLAT_RING3_DS64
#define FLAT_USER_DS32 FLAT_RING3_DS32
#define FLAT_USER_DS   FLAT_USER_DS64
#define FLAT_USER_CS64 FLAT_RING3_CS64
#define FLAT_USER_CS32 FLAT_RING3_CS32
#define FLAT_USER_CS   FLAT_USER_CS64
#define FLAT_USER_SS64 FLAT_RING3_SS64
#define FLAT_USER_SS32 FLAT_RING3_SS32
#define FLAT_USER_SS   FLAT_USER_SS64

/* And the trap vector is... */
#define TRAP_INSTR "syscall"

#define __HYPERVISOR_VIRT_START 0xFFFF800000000000
#define __HYPERVISOR_VIRT_END   0xFFFF880000000000

#ifndef HYPERVISOR_VIRT_START
#define HYPERVISOR_VIRT_START mk_unsigned_long(__HYPERVISOR_VIRT_START)
#define HYPERVISOR_VIRT_END   mk_unsigned_long(__HYPERVISOR_VIRT_END)
#endif

/* Maximum number of virtual CPUs in multi-processor guests. */
#define MAX_VIRT_CPUS 32

#ifndef __ASSEMBLY__

/* The machine->physical mapping table starts at this address, read-only. */
#ifndef machine_to_phys_mapping
#define machine_to_phys_mapping ((unsigned long *)HYPERVISOR_VIRT_START)
#endif

/*
 * int HYPERVISOR_set_segment_base(unsigned int which, unsigned long base)
 *  @which == SEGBASE_*  ;  @base == 64-bit base address
 * Returns 0 on success.
 */
#define SEGBASE_FS          0
#define SEGBASE_GS_USER     1
#define SEGBASE_GS_KERNEL   2
#define SEGBASE_GS_USER_SEL 3 /* Set user %gs specified in base[15:0] */

/*
 * int HYPERVISOR_iret(void)
 * All arguments are on the kernel stack, in the following format.
 * Never returns if successful. Current kernel context is lost.
 * The saved CS is mapped as follows:
 *   RING0 -> RING3 kernel mode.
 *   RING1 -> RING3 kernel mode.
 *   RING2 -> RING3 kernel mode.
 *   RING3 -> RING3 user mode.
 * However RING0 indicates that the guest kernel should return to iteself
 * directly with
 *      orb   $3,1*8(%rsp)
 *      iretq
 * If flags contains VGCF_IN_SYSCALL:
 *   Restore RAX, RIP, RFLAGS, RSP.
 *   Discard R11, RCX, CS, SS.
 * Otherwise:
 *   Restore RAX, R11, RCX, CS:RIP, RFLAGS, SS:RSP.
 * All other registers are saved on hypercall entry and restored to user.
 */
/* Guest exited in SYSCALL context? Return to guest with SYSRET? */
#define VGCF_IN_SYSCALL (1<<8)
struct iret_context {
    /* Top of stack (%rsp at point of hypercall). */
    uint64_t rax, r11, rcx, flags, rip, cs, rflags, rsp, ss;
    /* Bottom of iret stack frame. */
};

/*
 * Send an array of these to HYPERVISOR_set_trap_table().
 * N.B. As in x86/32 mode, the privilege level specifies which modes may enter
 * a trap via a software interrupt. Since rings 1 and 2 are unavailable, we
 * allocate privilege levels as follows:
 *  Level == 0: Noone may enter
 *  Level == 1: Kernel may enter
 *  Level == 2: Kernel may enter
 *  Level == 3: Everyone may enter
 */
#define TI_GET_DPL(_ti)      ((_ti)->flags & 3)
#define TI_GET_IF(_ti)       ((_ti)->flags & 4)
#define TI_SET_DPL(_ti,_dpl) ((_ti)->flags |= (_dpl))
#define TI_SET_IF(_ti,_if)   ((_ti)->flags |= ((!!(_if))<<2))
struct trap_info {
    uint8_t       vector;  /* exception vector                              */
    uint8_t       flags;   /* 0-3: privilege level; 4: clear event enable?  */
    uint16_t      cs;      /* code selector                                 */
    unsigned long address; /* code offset                                   */
};
typedef struct trap_info trap_info_t;
DEFINE_XEN_GUEST_HANDLE(trap_info_t);

#ifdef __GNUC__
/* Anonymous union includes both 32- and 64-bit names (e.g., eax/rax). */
#define __DECL_REG(name) union { uint64_t r ## name, e ## name; }
#else
/* Non-gcc sources must always use the proper 64-bit name (e.g., rax). */
#define __DECL_REG(name) uint64_t r ## name
#endif

struct cpu_user_regs {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    __DECL_REG(bp);
    __DECL_REG(bx);
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    __DECL_REG(ax);
    __DECL_REG(cx);
    __DECL_REG(dx);
    __DECL_REG(si);
    __DECL_REG(di);
    uint32_t error_code;    /* private */
    uint32_t entry_vector;  /* private */
    __DECL_REG(ip);
    uint16_t cs, _pad0[1];
    uint8_t  saved_upcall_mask;
    uint8_t  _pad1[3];
    __DECL_REG(flags);      /* rflags.IF == !saved_upcall_mask */
    __DECL_REG(sp);
    uint16_t ss, _pad2[3];
    uint16_t es, _pad3[3];
    uint16_t ds, _pad4[3];
    uint16_t fs, _pad5[3]; /* Non-zero => takes precedence over fs_base.     */
    uint16_t gs, _pad6[3]; /* Non-zero => takes precedence over gs_base_usr. */
};
typedef struct cpu_user_regs cpu_user_regs_t;
DEFINE_XEN_GUEST_HANDLE(cpu_user_regs_t);

#undef __DECL_REG

typedef uint64_t tsc_timestamp_t; /* RDTSC timestamp */

/*
 * The following is all CPU context. Note that the fpu_ctxt block is filled 
 * in by FXSAVE if the CPU has feature FXSR; otherwise FSAVE is used.
 */
struct vcpu_guest_context {
    /* FPU registers come first so they can be aligned for FXSAVE/FXRSTOR. */
    struct { char x[512]; } fpu_ctxt;       /* User-level FPU registers     */
#define VGCF_I387_VALID                (1<<0)
#define VGCF_HVM_GUEST                 (1<<1)
#define VGCF_IN_KERNEL                 (1<<2)
#define _VGCF_i387_valid               0
#define VGCF_i387_valid                (1<<_VGCF_i387_valid)
#define _VGCF_hvm_guest                1
#define VGCF_hvm_guest                 (1<<_VGCF_hvm_guest)
#define _VGCF_in_kernel                2
#define VGCF_in_kernel                 (1<<_VGCF_in_kernel)
#define _VGCF_failsafe_disables_events 3
#define VGCF_failsafe_disables_events  (1<<_VGCF_failsafe_disables_events)
#define _VGCF_syscall_disables_events  4
#define VGCF_syscall_disables_events   (1<<_VGCF_syscall_disables_events)
    unsigned long flags;                    /* VGCF_* flags                 */
    struct cpu_user_regs user_regs;         /* User-level CPU registers     */
    struct trap_info trap_ctxt[256];        /* Virtual IDT                  */
    unsigned long ldt_base, ldt_ents;       /* LDT (linear address, # ents) */
    unsigned long gdt_frames[16], gdt_ents; /* GDT (machine frames, # ents) */
    unsigned long kernel_ss, kernel_sp;     /* Virtual TSS (only SS1/SP1)   */
    unsigned long ctrlreg[8];               /* CR0-CR7 (control registers)  */
    unsigned long debugreg[8];              /* DB0-DB7 (debug registers)    */
    unsigned long event_callback_eip;
    unsigned long failsafe_callback_eip;
    unsigned long syscall_callback_eip;
    unsigned long vm_assist;                /* VMASST_TYPE_* bitmap */
    /* Segment base addresses. */
    uint64_t      fs_base;
    uint64_t      gs_base_kernel;
    uint64_t      gs_base_user;
};
typedef struct vcpu_guest_context vcpu_guest_context_t;
DEFINE_XEN_GUEST_HANDLE(vcpu_guest_context_t);

#define xen_pfn_to_cr3(pfn) ((unsigned long)(pfn) << 12)
#define xen_cr3_to_pfn(cr3) ((unsigned long)(cr3) >> 12)

struct arch_shared_info {
    unsigned long max_pfn;                  /* max pfn that appears in table */
    /* Frame containing list of mfns containing list of mfns containing p2m. */
    xen_pfn_t     pfn_to_mfn_frame_list_list;
    unsigned long nmi_reason;
};
typedef struct arch_shared_info arch_shared_info_t;

struct arch_vcpu_info {
    unsigned long cr2;
    unsigned long pad; /* sizeof(vcpu_info_t) == 64 */
};
typedef struct arch_vcpu_info  arch_vcpu_info_t;

typedef unsigned long xen_callback_t;

#endif /* !__ASSEMBLY__ */

/*
 * Prefix forces emulation of some non-trapping instructions.
 * Currently only CPUID.
 */
#ifdef __ASSEMBLY__
#define XEN_EMULATE_PREFIX .byte 0x0f,0x0b,0x78,0x65,0x6e ;
#define XEN_CPUID          XEN_EMULATE_PREFIX cpuid
#else
#define XEN_EMULATE_PREFIX ".byte 0x0f,0x0b,0x78,0x65,0x6e ; "
#define XEN_CPUID          XEN_EMULATE_PREFIX "cpuid"
#endif

#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
