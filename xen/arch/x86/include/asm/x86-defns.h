#ifndef __XEN_X86_DEFNS_H__
#define __XEN_X86_DEFNS_H__

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

#define X86_EFLAGS_ARITH_MASK                          \
    (X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |   \
     X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF)

/*
 * Intel CPU flags in CR0
 */
#define X86_CR0_PE              _AC(0x00000001, UL) /* Enable Protected Mode    (RW) */
#define X86_CR0_MP              _AC(0x00000002, UL) /* Monitor Coprocessor      (RW) */
#define X86_CR0_EM              _AC(0x00000004, UL) /* Require FPU Emulation    (RO) */
#define X86_CR0_TS              _AC(0x00000008, UL) /* Task Switched            (RW) */
#define X86_CR0_ET              _AC(0x00000010, UL) /* Extension type           (RO) */
#define X86_CR0_NE              _AC(0x00000020, UL) /* Numeric Error Reporting  (RW) */
#define X86_CR0_WP              _AC(0x00010000, UL) /* Supervisor Write Protect (RW) */
#define X86_CR0_AM              _AC(0x00040000, UL) /* Alignment Checking       (RW) */
#define X86_CR0_NW              _AC(0x20000000, UL) /* Not Write-Through        (RW) */
#define X86_CR0_CD              _AC(0x40000000, UL) /* Cache Disable            (RW) */
#define X86_CR0_PG              _AC(0x80000000, UL) /* Paging                   (RW) */

/*
 * Intel CPU flags in CR3
 */
#define X86_CR3_NOFLUSH    (_AC(1, ULL) << 63)
#define X86_CR3_ADDR_MASK  (PAGE_MASK & PADDR_MASK)
#define X86_CR3_PCID_MASK  _AC(0x0fff, ULL) /* Mask for PCID */

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
#define X86_CR4_UMIP       0x00000800 /* enable UMIP */
#define X86_CR4_LA57       0x00001000 /* enable 5-level paging */
#define X86_CR4_VMXE       0x00002000 /* enable VMX */
#define X86_CR4_SMXE       0x00004000 /* enable SMX */
#define X86_CR4_FSGSBASE   0x00010000 /* enable {rd,wr}{fs,gs}base */
#define X86_CR4_PCIDE      0x00020000 /* enable PCID */
#define X86_CR4_OSXSAVE    0x00040000 /* enable XSAVE/XRSTOR */
#define X86_CR4_SMEP       0x00100000 /* enable SMEP */
#define X86_CR4_SMAP       0x00200000 /* enable SMAP */
#define X86_CR4_PKE        0x00400000 /* enable PKE */
#define X86_CR4_CET        0x00800000 /* Control-flow Enforcement Technology */
#define X86_CR4_PKS        0x01000000 /* Protection Key Supervisor */

/*
 * XSTATE component flags in XCR0 | MSR_XSS
 */
#define X86_XCR0_X87              (_AC(1, ULL) <<  0)
#define X86_XCR0_SSE              (_AC(1, ULL) <<  1)
#define X86_XCR0_YMM              (_AC(1, ULL) <<  2)
#define X86_XCR0_BNDREGS          (_AC(1, ULL) <<  3)
#define X86_XCR0_BNDCSR           (_AC(1, ULL) <<  4)
#define X86_XCR0_OPMASK           (_AC(1, ULL) <<  5)
#define X86_XCR0_ZMM              (_AC(1, ULL) <<  6)
#define X86_XCR0_HI_ZMM           (_AC(1, ULL) <<  7)
#define X86_XSS_PROC_TRACE        (_AC(1, ULL) <<  8)
#define X86_XCR0_PKRU             (_AC(1, ULL) <<  9)
#define X86_XSS_PASID             (_AC(1, ULL) << 10)
#define X86_XSS_CET_U             (_AC(1, ULL) << 11)
#define X86_XSS_CET_S             (_AC(1, ULL) << 12)
#define X86_XSS_HDC               (_AC(1, ULL) << 13)
#define X86_XSS_UINTR             (_AC(1, ULL) << 14)
#define X86_XSS_LBR               (_AC(1, ULL) << 15)
#define X86_XSS_HWP               (_AC(1, ULL) << 16)
#define X86_XCR0_TILE_CFG         (_AC(1, ULL) << 17)
#define X86_XCR0_TILE_DATA        (_AC(1, ULL) << 18)
#define X86_XCR0_LWP              (_AC(1, ULL) << 62)

#define X86_XCR0_STATES                                                 \
    (X86_XCR0_X87 | X86_XCR0_SSE | X86_XCR0_YMM | X86_XCR0_BNDREGS |    \
     X86_XCR0_BNDCSR | X86_XCR0_OPMASK | X86_XCR0_ZMM |                 \
     X86_XCR0_HI_ZMM | X86_XCR0_PKRU | X86_XCR0_TILE_CFG |              \
     X86_XCR0_TILE_DATA |                                               \
     X86_XCR0_LWP)

#define X86_XSS_STATES                                                  \
    (X86_XSS_PROC_TRACE | X86_XSS_PASID | X86_XSS_CET_U |               \
     X86_XSS_CET_S | X86_XSS_HDC | X86_XSS_UINTR | X86_XSS_LBR |        \
     X86_XSS_HWP |                                                      \
     0)

/*
 * Debug status flags in DR6.
 *
 * For backwards compatibility, status flags which overlap with
 * X86_DR6_DEFAULT have inverted polarity.
 */
#define X86_DR6_B0              (_AC(1, UL) <<  0)   /* Breakpoint 0                */
#define X86_DR6_B1              (_AC(1, UL) <<  1)   /* Breakpoint 1                */
#define X86_DR6_B2              (_AC(1, UL) <<  2)   /* Breakpoint 2                */
#define X86_DR6_B3              (_AC(1, UL) <<  3)   /* Breakpoint 3                */
#define X86_DR6_BLD             (_AC(1, UL) << 11)   /* BusLock detect (INV)        */
#define X86_DR6_BD              (_AC(1, UL) << 13)   /* %dr access                  */
#define X86_DR6_BS              (_AC(1, UL) << 14)   /* Single step                 */
#define X86_DR6_BT              (_AC(1, UL) << 15)   /* Task switch                 */
#define X86_DR6_RTM             (_AC(1, UL) << 16)   /* #DB/#BP in RTM region (INV) */

#define X86_DR6_ZEROS           _AC(0x00001000, UL)  /* %dr6 bits forced to 0       */
#define X86_DR6_DEFAULT         _AC(0xffff0ff0, UL)  /* Default %dr6 value          */

#define X86_DR6_BP_MASK                                 \
    (X86_DR6_B0 | X86_DR6_B1 | X86_DR6_B2 | X86_DR6_B3)

#define X86_DR6_KNOWN_MASK                                              \
    (X86_DR6_BP_MASK | X86_DR6_BLD | X86_DR6_BD | X86_DR6_BS |          \
     X86_DR6_BT | X86_DR6_RTM)

/*
 * Debug control flags in DR7.
 */
#define X86_DR7_RTM             (_AC(1, UL) << 11)   /* RTM debugging enable        */

#define X86_DR7_ZEROS           _AC(0x0000d000, UL)  /* %dr7 bits forced to 0       */
#define X86_DR7_DEFAULT         _AC(0x00000400, UL)  /* Default %dr7 value          */

/*
 * Invalidation types for the INVPCID instruction.
 */
#define X86_INVPCID_INDIV_ADDR      0
#define X86_INVPCID_SINGLE_CTXT     1
#define X86_INVPCID_ALL_INCL_GLOBAL 2
#define X86_INVPCID_ALL_NON_GLOBAL  3

#define X86_NR_VECTORS 256

/* Exception Vectors */
#define X86_EXC_DE             0 /* Divide Error */
#define X86_EXC_DB             1 /* Debug Exception */
#define X86_EXC_NMI            2 /* NMI */
#define X86_EXC_BP             3 /* Breakpoint */
#define X86_EXC_OF             4 /* Overflow */
#define X86_EXC_BR             5 /* BOUND Range */
#define X86_EXC_UD             6 /* Invalid Opcode */
#define X86_EXC_NM             7 /* Device Not Available */
#define X86_EXC_DF             8 /* Double Fault */
#define X86_EXC_CSO            9 /* Coprocessor Segment Overrun */
#define X86_EXC_TS            10 /* Invalid TSS */
#define X86_EXC_NP            11 /* Segment Not Present */
#define X86_EXC_SS            12 /* Stack-Segment Fault */
#define X86_EXC_GP            13 /* General Protection Fault */
#define X86_EXC_PF            14 /* Page Fault */
#define X86_EXC_SPV           15 /* PIC Spurious Interrupt Vector */
#define X86_EXC_MF            16 /* Maths fault (x87 FPU) */
#define X86_EXC_AC            17 /* Alignment Check */
#define X86_EXC_MC            18 /* Machine Check */
#define X86_EXC_XM            19 /* SIMD Exception */
#define X86_EXC_VE            20 /* Virtualisation Exception */
#define X86_EXC_CP            21 /* Control-flow Protection */
#define X86_EXC_HV            28 /* Hypervisor Injection */
#define X86_EXC_VC            29 /* VMM Communication */
#define X86_EXC_SX            30 /* Security Exception */

#define X86_EXC_NUM           32 /* 32 reserved vectors */

/* Bitmap of exceptions which have error codes. */
#define X86_EXC_HAVE_EC                                             \
    ((1u << X86_EXC_DF) | (1u << X86_EXC_TS) | (1u << X86_EXC_NP) | \
     (1u << X86_EXC_SS) | (1u << X86_EXC_GP) | (1u << X86_EXC_PF) | \
     (1u << X86_EXC_AC) | (1u << X86_EXC_CP) |                      \
     (1u << X86_EXC_VC) | (1u << X86_EXC_SX))

/* Memory types */
#define X86_MT_UC     0x00 /* uncachable */
#define X86_MT_WC     0x01 /* write-combined */
#define X86_MT_RSVD_2 0x02 /* reserved */
#define X86_MT_RSVD_3 0x03 /* reserved */
#define X86_MT_WT     0x04 /* write-through */
#define X86_MT_WP     0x05 /* write-protect */
#define X86_MT_WB     0x06 /* write-back */
#define X86_MT_UCM    0x07 /* UC- */
#define X86_NUM_MT    0x08

/*
 * Event Types.
 *
 * These encodings were first used in VMCB/VMCS fields, but have become
 * architectural in the FRED spec.
 */
#define X86_ET_EXT_INTR    0 /* External Interrupt */
#define X86_ET_NMI         2 /* NMI */
#define X86_ET_HW_EXC      3 /* Hardware Exception (#PF/#GP/etc) */
#define X86_ET_SW_INT      4 /* Software Interrupt (INT $n) */
#define X86_ET_PRIV_SW_EXC 5 /* Privileged Software Exception (ICEBP/INT1) */
#define X86_ET_SW_EXC      6 /* Software Exception (INT3, INTO) */
#define X86_ET_OTHER       7 /* Misc event: MTF=0, SYSCALL=1, SYSENTER=2 */

#endif	/* __XEN_X86_DEFNS_H__ */
