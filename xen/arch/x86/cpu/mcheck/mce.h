#ifndef _MCE_H

#define _MCE_H

#include <xen/init.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <asm/types.h>
#include <asm/traps.h>
#include <asm/atomic.h>
#include <asm/percpu.h>

#include "x86_mca.h"
#include "mctelem.h"

#define MCE_QUIET       0
#define MCE_VERBOSE     1
/* !only for developer debug as printk is unsafe in MCE context */
#define MCE_CRITICAL    2

extern int mce_verbosity;
/*
 * Define the default level of machine check related print.
 * When set mce_verbosity=verbose, all mce debug information
 * will be printed, otherwise, those information will not be
 * printed.
 */
#define mce_printk(v, s, a...) do {       \
        if ((v) <= mce_verbosity) \
            printk(s, ##a);       \
        } while (0)

enum mcheck_type {
    mcheck_unset = -1,
    mcheck_none,
    mcheck_amd_famXX,
    mcheck_amd_k8,
    mcheck_intel
};

extern uint8_t cmci_apic_vector;
extern bool lmce_support;

/* Init functions */
enum mcheck_type amd_mcheck_init(struct cpuinfo_x86 *c);
enum mcheck_type intel_mcheck_init(struct cpuinfo_x86 *c, bool bsp);

void amd_nonfatal_mcheck_init(struct cpuinfo_x86 *c);

extern unsigned int firstbank;

struct mcinfo_extended *intel_get_extended_msrs(
    struct mcinfo_global *mig, struct mc_info *mi);

bool mce_available(const struct cpuinfo_x86 *c);
unsigned int mce_firstbank(struct cpuinfo_x86 *c);
/* Helper functions used for collecting error telemetry */
void noreturn mc_panic(char *s);
void x86_mc_get_cpu_info(unsigned, uint32_t *, uint16_t *, uint16_t *,
                         uint32_t *, uint32_t *, uint32_t *, uint32_t *);

/* Register a handler for machine check exceptions. */
typedef void (*x86_mce_vector_t)(const struct cpu_user_regs *regs);
extern void x86_mce_vector_register(x86_mce_vector_t);

/*
 * Common generic MCE handler that implementations may nominate
 * via x86_mce_vector_register.
 */
extern void mcheck_cmn_handler(const struct cpu_user_regs *regs);

/* Register a handler for judging whether mce is recoverable. */
typedef bool (*mce_recoverable_t)(uint64_t status);
extern void mce_recoverable_register(mce_recoverable_t);

/* Read an MSR, checking for an interposed value first */
extern struct intpose_ent *intpose_lookup(unsigned int, uint64_t,
    uint64_t *);
extern bool intpose_inval(unsigned int, uint64_t);

static inline uint64_t mca_rdmsr(unsigned int msr)
{
    uint64_t val;
    if (intpose_lookup(smp_processor_id(), msr, &val) == NULL)
        rdmsrl(msr, val);
    return val;
}

/* Write an MSR, invalidating any interposed value */
#define mca_wrmsr(msr, val) do { \
    if ( !intpose_inval(smp_processor_id(), msr) ) \
        wrmsrl(msr, val); \
} while ( 0 )


/*
 * Utility function to "logout" all architectural MCA telemetry from the MCA
 * banks of the current processor.  A cookie is returned which may be
 * uses to reference the data so logged (the cookie can be NULL if
 * no logout structures were available).  The caller can also pass a pointer
 * to a structure which will be completed with some summary information
 * of the MCA data observed in the logout operation.
 */

enum mca_source {
    MCA_POLLER,
    MCA_CMCI_HANDLER,
    MCA_RESET,
    MCA_MCE_SCAN
};

struct mca_summary {
    uint32_t    errcnt; /* number of banks with valid errors */
    int         ripv;   /* meaningful on #MC */
    int         eipv;   /* meaningful on #MC */
    bool        uc;     /* UC flag */
    bool        pcc;    /* PCC flag */
    bool        lmce;   /* LMCE flag (Intel only) */
    bool        recoverable; /* software error recoverable flag */
};

DECLARE_PER_CPU(struct mca_banks *, poll_bankmask);
DECLARE_PER_CPU(struct mca_banks *, no_cmci_banks);
DECLARE_PER_CPU(struct mca_banks *, mce_clear_banks);

extern bool cmci_support;
extern bool is_mc_panic;
extern bool mce_broadcast;
extern void mcheck_mca_clearbanks(struct mca_banks *);

extern mctelem_cookie_t mcheck_mca_logout(enum mca_source, struct mca_banks *,
    struct mca_summary *, struct mca_banks *);

/*
 * Register callbacks to be made during bank telemetry logout.
 * Those callbacks are only available to those machine check handlers
 * that call to the common mcheck_cmn_handler or who use the common
 * telemetry logout function mcheck_mca_logout in error polling.
 */

/* Register a handler for judging whether the bank need to be cleared */
typedef bool (*mce_need_clearbank_t)(enum mca_source who, u64 status);
extern void mce_need_clearbank_register(mce_need_clearbank_t);

/*
 * Register a callback to collect additional information (typically non-
 * architectural) provided by newer CPU families/models without the need
 * to duplicate the whole handler resulting in various handlers each with
 * its own tweaks and bugs. The callback receives an struct mc_info pointer
 * which it can use with x86_mcinfo_reserve to add additional telemetry,
 * the current MCA bank number we are reading telemetry from, and the
 * MCi_STATUS value for that bank.
 */
typedef struct mcinfo_extended *(*x86_mce_callback_t)
    (struct mc_info *, uint16_t, uint64_t);
extern void x86_mce_callback_register(x86_mce_callback_t);

void *x86_mcinfo_reserve(struct mc_info *mi,
                         unsigned int size, unsigned int type);
void x86_mcinfo_dump(struct mc_info *mi);

static inline int mce_vendor_bank_msr(const struct vcpu *v, uint32_t msr)
{
    switch (boot_cpu_data.x86_vendor) {
    case X86_VENDOR_INTEL:
        if (msr >= MSR_IA32_MC0_CTL2 &&
            msr < MSR_IA32_MCx_CTL2(v->arch.vmce.mcg_cap & MCG_CAP_COUNT) )
            return 1;
        break;

    case X86_VENDOR_AMD:
        switch (msr) {
        case MSR_F10_MC4_MISC1:
        case MSR_F10_MC4_MISC2:
        case MSR_F10_MC4_MISC3:
            return 1;
        }
        break;
    }
    return 0;
}

static inline int mce_bank_msr(const struct vcpu *v, uint32_t msr)
{
    if ( (msr >= MSR_IA32_MC0_CTL &&
         msr < MSR_IA32_MCx_CTL(v->arch.vmce.mcg_cap & MCG_CAP_COUNT)) ||
         mce_vendor_bank_msr(v, msr) )
        return 1;
    return 0;
}

/* MC softirq */
void mce_handler_init(void);

extern const struct mca_error_handler *mce_dhandlers;
extern const struct mca_error_handler *mce_uhandlers;
extern unsigned int mce_dhandler_num;
extern unsigned int mce_uhandler_num;

/* Fields are zero when not available */
struct mce {
    uint64_t status;
    uint64_t misc;
    uint64_t addr;
    uint64_t mcgstatus;
    uint64_t ip;
    uint64_t tsc;      /* cpu time stamp counter */
    uint64_t time;     /* wall time_t when error was detected */
    uint8_t  cpuvendor;        /* cpu vendor as encoded in system.h */
    uint8_t  inject_flags;     /* software inject flags */
    uint16_t pad;
    uint32_t cpuid;    /* CPUID 1 EAX */
    uint8_t  cs;       /* code segment */
    uint8_t  bank;     /* machine check bank */
    uint8_t  cpu;      /* cpu number; obsolete; use extcpu now */
    uint8_t  finished; /* entry is valid */
    uint32_t extcpu;   /* linux cpu number that detected the error */
    uint32_t socketid; /* CPU socket ID */
    uint32_t apicid;   /* CPU initial apic ID */
    uint64_t mcgcap;   /* MCGCAP MSR: machine check capabilities of CPU */
};

extern int apei_write_mce(struct mce *m);

#endif /* _MCE_H */
