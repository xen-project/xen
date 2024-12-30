/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef X86_CPU_USER_REGS_H
#define X86_CPU_USER_REGS_H

#include <xen/stdint.h>

/*
 * cpu_user_regs represents the interrupted GPR state at the point of an
 * interrupt, exception or syscall.  The layout is dictated by the hardware
 * format for the event frame, with software filling in the rest.
 */
struct cpu_user_regs
{
    union { uint64_t r15;    uint32_t r15d;   uint16_t r15w;  uint8_t r15b; };
    union { uint64_t r14;    uint32_t r14d;   uint16_t r14w;  uint8_t r14b; };
    union { uint64_t r13;    uint32_t r13d;   uint16_t r13w;  uint8_t r13b; };
    union { uint64_t r12;    uint32_t r12d;   uint16_t r12w;  uint8_t r12b; };
    union { uint64_t rbp;    uint32_t ebp;    uint16_t bp;    uint8_t bpl;  };
    union { uint64_t rbx;    uint32_t ebx;    uint16_t bx;    struct { uint8_t bl, bh; }; };
    union { uint64_t r11;    uint32_t r11d;   uint16_t r11w;  uint8_t r11b; };
    union { uint64_t r10;    uint32_t r10d;   uint16_t r10w;  uint8_t r10b; };
    union { uint64_t r9;     uint32_t r9d;    uint16_t r9w;   uint8_t r9b;  };
    union { uint64_t r8;     uint32_t r8d;    uint16_t r8w;   uint8_t r8b;  };
    union { uint64_t rax;    uint32_t eax;    uint16_t ax;    struct { uint8_t al, ah; }; };
    union { uint64_t rcx;    uint32_t ecx;    uint16_t cx;    struct { uint8_t cl, ch; }; };
    union { uint64_t rdx;    uint32_t edx;    uint16_t dx;    struct { uint8_t dl, dh; }; };
    union { uint64_t rsi;    uint32_t esi;    uint16_t si;    uint8_t sil;  };
    union { uint64_t rdi;    uint32_t edi;    uint16_t di;    uint8_t dil;  };

    /*
     * During IDT delivery for exceptions with an error code, hardware pushes
     * to this point.  Entry_vector is filled in by software.
     *
     * During FRED delivery, hardware always pushes to this point.  Software
     * copies fred_ss.vector into entry_vector so most interrupt/exception
     * handling can be FRED-agnostic.
     */

    uint32_t error_code;
    uint32_t entry_vector;

    /*
     * During IDT delivery for interrupts or exceptions without an error code,
     * hardware pushes to this point.  Both error_code and entry_vector are
     * filled in by software.
     */

    union { uint64_t rip;    uint32_t eip;    uint16_t ip; };
    union {
        struct {
            uint16_t      cs;
            unsigned long :16;
            uint8_t       saved_upcall_mask; /* PV (v)rflags.IF == !saved_upcall_mask */
        };
        unsigned long     csx;
        struct {
            /*
             * Bits 0 to 31 control ERET{U,S} behaviour, and are state of the
             * interrupted context.
             */
            uint16_t      cs;
            unsigned int  sl:2;      /* Stack Level */
            bool          wfe:1;     /* Wait-for-ENDBRANCH state */
        } fred_cs;
    };
    union { uint64_t rflags; uint32_t eflags; uint16_t flags; };
    union { uint64_t rsp;    uint32_t esp;    uint16_t sp;    uint8_t spl; };
    union {
        uint16_t          ss;
        unsigned long     ssx;
        struct {
            /*
             * Bits 0 to 31 control ERET{U,S} behaviour, and are state about
             * the event which occured.
             */
            uint16_t      ss;
            bool          sti:1;     /* Was blocked-by-STI, and not cancelled */
            bool          swint:1;   /* Was a SYSCALL/SYSENTER/INT $N.  On ERETx, pend_DB iff TF */
            bool          nmi:1;     /* Was an NMI. */
            unsigned long :13;

            /*
             * Bits 32 to 63 are ignored by ERET{U,S} and are informative
             * only.
             */
            uint8_t       vector;
            unsigned long :8;
            unsigned int  type:4;    /* X86_ET_* */
            unsigned long :4;
            bool          enclave:1; /* Event taken in SGX mode */
            bool          l:1;       /* Event taken in 64bit mode (old %cs.l) */
            bool          nested:1;  /* Exception during event delivery (clear for #DF) */
            unsigned long :1;
            unsigned int  insnlen:4; /* .type >= SW_INT */
        } fred_ss;
    };

    /*
     * For IDT delivery, tss->rsp0 points to this boundary as embedded within
     * struct cpu_info.  It must be 16-byte aligned.
     */
};
struct fred_info
{
    /*
     * Event Data.  For:
     *   #DB: PENDING_DBG (%dr6 with positive polarity)
     *   NMI: NMI-Source Bitmap (on capable hardware)
     *   #PF: %cr2
     *   #NM: MSR_XFD_ERR (only XFD-induced #NMs)
     */
    uint64_t edata;
    uint64_t _rsvd;

    /*
     * For FRED delivery, MSR_FRED_RSP_SL0 points to this boundary as embedded
     * within struct cpu_info.  It must be 64-byte aligned.
     */
};

static inline uint64_t msr_fold(const struct cpu_user_regs *regs)
{
    return (regs->rdx << 32) | regs->eax;
}

static inline void msr_split(struct cpu_user_regs *regs, uint64_t val)
{
    regs->rdx = val >> 32;
    regs->rax = (uint32_t)val;
}

#endif /* X86_CPU_USER_REGS_H */
