#ifndef _X86_DEBUGREG_H
#define _X86_DEBUGREG_H

#include <asm/x86-defns.h>

/* Indicate the register numbers for a number of the specific
   debug registers.  Registers 0-3 contain the addresses we wish to trap on */

#define DR_FIRSTADDR 0
#define DR_LASTADDR  3
#define DR_STATUS    6
#define DR_CONTROL   7

/* Define a few things for the status register.  We can use this to determine
   which debugging register was responsible for the trap.  The other bits
   are either reserved or not of interest to us. */

#define DR_TRAP0        (0x1)           /* db0 */
#define DR_TRAP1        (0x2)           /* db1 */
#define DR_TRAP2        (0x4)           /* db2 */
#define DR_TRAP3        (0x8)           /* db3 */
#define DR_STEP         (0x4000)        /* single-step */
#define DR_SWITCH       (0x8000)        /* task switch */
#define DR_NOT_RTM      (0x10000)       /* clear: #BP inside RTM region */
#define DR_STATUS_RESERVED_ONE  0xffff0ff0UL /* Reserved, read as one */

/* Now define a bunch of things for manipulating the control register.
   The top two bytes of the control register consist of 4 fields of 4
   bits - each field corresponds to one of the four debug registers,
   and indicates what types of access we trap on, and how large the data
   field is that we are looking at */

#define DR_CONTROL_SHIFT 16 /* Skip this many bits in ctl register */
#define DR_CONTROL_SIZE   4 /* 4 control bits per register */

#define DR_RW_EXECUTE (0x0) /* Settings for the access types to trap on */
#define DR_RW_WRITE   (0x1)
#define DR_IO         (0x2)
#define DR_RW_READ    (0x3)

#define DR_LEN_1      (0x0) /* Settings for data length to trap on */
#define DR_LEN_2      (0x4)
#define DR_LEN_4      (0xC)
#define DR_LEN_8      (0x8)

/* The low byte to the control register determine which registers are
   enabled.  There are 4 fields of two bits.  One bit is "local", meaning
   that the processor will reset the bit after a task switch and the other
   is global meaning that we have to explicitly reset the bit. */

#define DR_LOCAL_ENABLE_SHIFT  0   /* Extra shift to the local enable bit */
#define DR_GLOBAL_ENABLE_SHIFT 1   /* Extra shift to the global enable bit */
#define DR_ENABLE_SIZE         2   /* 2 enable bits per register */

#define DR_LOCAL_ENABLE_MASK (0x55)  /* Set  local bits for all 4 regs */
#define DR_GLOBAL_ENABLE_MASK (0xAA) /* Set global bits for all 4 regs */

#define DR7_ACTIVE_MASK (DR_LOCAL_ENABLE_MASK|DR_GLOBAL_ENABLE_MASK)

/* The second byte to the control register has a few special things.
   We can slow the instruction pipeline for instructions coming via the
   gdt or the ldt if we want to.  I am not sure why this is an advantage */

#define DR_LOCAL_EXACT_ENABLE    (0x00000100UL) /* Local exact enable */
#define DR_GLOBAL_EXACT_ENABLE   (0x00000200UL) /* Global exact enable */
#define DR_RTM_ENABLE            (0x00000800UL) /* RTM debugging enable */
#define DR_GENERAL_DETECT        (0x00002000UL) /* General detect enable */

#define write_debugreg(reg, val) do {                       \
    unsigned long __val = (val);                            \
    asm volatile ( "mov %0,%%db" #reg : : "r" (__val) );    \
} while (0)
#define read_debugreg(reg) ({                               \
    unsigned long __val;                                    \
    asm volatile ( "mov %%db" #reg ",%0" : "=r" (__val) );  \
    __val;                                                  \
})

/*
 * Architecturally, %dr{0..3} can have any arbitrary value.  However, Xen
 * can't allow the guest to breakpoint the Xen address range, so we limit the
 * guest to the lower canonical half, or above the Xen range in the higher
 * canonical half.
 *
 * Breakpoint lengths are specified to mask the low order address bits,
 * meaning all breakpoints are naturally aligned.  With %dr7, the widest
 * breakpoint is 8 bytes.  With DBEXT, the widest breakpoint is 4G.  Both of
 * the Xen boundaries have >4G alignment.
 *
 * In principle we should account for HYPERVISOR_COMPAT_VIRT_START(d), but
 * 64bit Xen has never enforced this for compat guests, and there's no problem
 * (to Xen) if the guest breakpoints it's alias of the M2P.  Skipping this
 * aspect simplifies the logic, and causes us not to reject a migrating guest
 * which operated fine on prior versions of Xen.
 */
#define breakpoint_addr_ok(a) __addr_ok(a)

struct vcpu;
long set_debugreg(struct vcpu *v, unsigned int reg, unsigned long value);
void activate_debugregs(const struct vcpu *curr);

struct cpu_policy;

/*
 * Architecturally dr6/7 are full GPR-width, but only the bottom 32 bits may
 * legally be non-zero.  We avoid storing the upper bits when possible.
 */
unsigned int x86_adj_dr6_rsvd(const struct cpu_policy *p, unsigned int dr6);
unsigned int x86_adj_dr7_rsvd(const struct cpu_policy *p, unsigned int dr7);

/*
 * Merge new bits into dr6.  'new' is always given in positive polarity,
 * matching the Intel VMCS PENDING_DBG semantics.
 */
unsigned int x86_merge_dr6(const struct cpu_policy *p, unsigned int dr6,
                           unsigned int new);

/*
 * Calculate the width of a breakpoint from its dr7 encoding.
 *
 * The LEN encoding in dr7 is 2 bits wide per breakpoint and encoded as a X-1
 * (0, 1 and 3) for widths of 1, 2 and 4 respectively in the 32bit days.
 *
 * In 64bit, the unused value (2) was given a meaning of width 8, which is
 * great for efficiency but less great for nicely calculating the width.
 */
static inline unsigned int x86_bp_width(unsigned int dr7, unsigned int bp)
{
    unsigned int raw = (dr7 >> (DR_CONTROL_SHIFT +
                                DR_CONTROL_SIZE * bp + 2)) & 3;

    /*
     * If the top bit is set (i.e. we've got an 4 or 8 byte wide breakpoint),
     * flip the bottom to reverse their order, making them sorted properly.
     * Then it's a simple shift to calculate the width.
     */
    if ( raw & 2 )
        raw ^= 1;

    return 1U << raw;
}

#endif /* _X86_DEBUGREG_H */
