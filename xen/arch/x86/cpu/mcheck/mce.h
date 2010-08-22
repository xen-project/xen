#ifndef _MCE_H

#define _MCE_H

#include <xen/init.h>
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
/* Define the default level of machine check related print.
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
	mcheck_amd_k7,
	mcheck_amd_k8,
	mcheck_intel
};

/* Init functions */
enum mcheck_type amd_k7_mcheck_init(struct cpuinfo_x86 *c);
enum mcheck_type amd_k8_mcheck_init(struct cpuinfo_x86 *c);
enum mcheck_type amd_f10_mcheck_init(struct cpuinfo_x86 *c);

enum mcheck_type intel_mcheck_init(struct cpuinfo_x86 *c);

void intel_mcheck_timer(struct cpuinfo_x86 *c);
void mce_intel_feature_init(struct cpuinfo_x86 *c);
void amd_nonfatal_mcheck_init(struct cpuinfo_x86 *c);

int is_vmce_ready(struct mcinfo_bank *bank, struct domain *d);

u64 mce_cap_init(void);
extern int firstbank;

int intel_mce_rdmsr(uint32_t msr, uint64_t *val);
int intel_mce_wrmsr(uint32_t msr, uint64_t val);

int mce_available(struct cpuinfo_x86 *c);
int mce_firstbank(struct cpuinfo_x86 *c);
/* Helper functions used for collecting error telemetry */
struct mc_info *x86_mcinfo_getptr(void);
void mc_panic(char *s);
void x86_mc_get_cpu_info(unsigned, uint32_t *, uint16_t *, uint16_t *,
			 uint32_t *, uint32_t *, uint32_t *, uint32_t *);

#define dom0_vmce_enabled() (dom0 && dom0->max_vcpus && dom0->vcpu[0] \
	&& guest_enabled_event(dom0->vcpu[0], VIRQ_MCA))

/* Register a handler for machine check exceptions. */
typedef void (*x86_mce_vector_t)(struct cpu_user_regs *, long);
extern void x86_mce_vector_register(x86_mce_vector_t);

/* Common generic MCE handler that implementations may nominate
 * via x86_mce_vector_register. */
extern void mcheck_cmn_handler(struct cpu_user_regs *, long, struct mca_banks *);

/* Register a handler for judging whether mce is recoverable. */
typedef int (*mce_recoverable_t)(u64 status);
extern void mce_recoverable_register(mce_recoverable_t);

/* Read an MSR, checking for an interposed value first */
extern struct intpose_ent *intpose_lookup(unsigned int, uint64_t,
    uint64_t *);
extern void intpose_inval(unsigned int, uint64_t);

static inline uint64_t mca_rdmsr(unsigned int msr)
{
	uint64_t val;
	if (intpose_lookup(smp_processor_id(), msr, &val) == NULL)
		rdmsrl(msr, val);
	return val;
}

/* Write an MSR, invalidating any interposed value */
#define mca_wrmsr(msr, val) do { \
       intpose_inval(smp_processor_id(), msr); \
       wrmsrl(msr, val); \
} while (0)


/* Utility function to "logout" all architectural MCA telemetry from the MCA
 * banks of the current processor.  A cookie is returned which may be
 * uses to reference the data so logged (the cookie can be NULL if
 * no logout structures were available).  The caller can also pass a pointer
 * to a structure which will be completed with some summary information
 * of the MCA data observed in the logout operation. */

enum mca_source {
	MCA_MCE_HANDLER,
	MCA_POLLER,
	MCA_CMCI_HANDLER,
	MCA_RESET,
	MCA_MCE_SCAN
};

struct mca_summary {
	uint32_t	errcnt;	/* number of banks with valid errors */
	int		ripv;	/* meaningful on #MC */
	int		eipv;	/* meaningful on #MC */
	uint32_t	uc;	/* bitmask of banks with UC */
	uint32_t	pcc;	/* bitmask of banks with PCC */
	/* bitmask of banks with software error recovery ability*/
	uint32_t	recoverable; 
};

DECLARE_PER_CPU(struct mca_banks *, poll_bankmask);
DECLARE_PER_CPU(struct mca_banks *, no_cmci_banks);

extern int cmci_support;
extern int ser_support;
extern int is_mc_panic;
extern int mce_broadcast;
extern void mcheck_mca_clearbanks(struct mca_banks *);

extern mctelem_cookie_t mcheck_mca_logout(enum mca_source, struct mca_banks *,
    struct mca_summary *, struct mca_banks *);

/* Register a callback to be made during bank telemetry logout.
 * This callback is only available to those machine check handlers
 * that call to the common mcheck_cmn_handler or who use the common
 * telemetry logout function mcheck_mca_logout in error polling.
 *
 * This can be used to collect additional information (typically non-
 * architectural) provided by newer CPU families/models without the need
 * to duplicate the whole handler resulting in various handlers each with
 * its own tweaks and bugs.  The callback receives an struct mc_info pointer
 * which it can use with x86_mcinfo_add to add additional telemetry,
 * the current MCA bank number we are reading telemetry from, and the
 * MCi_STATUS value for that bank.
 */

/* Register a handler for judging whether the bank need to be cleared */
typedef int (*mce_need_clearbank_t)(enum mca_source who, u64 status);
extern void mce_need_clearbank_register(mce_need_clearbank_t);

typedef struct mcinfo_extended *(*x86_mce_callback_t)
    (struct mc_info *, uint16_t, uint64_t);
extern void x86_mce_callback_register(x86_mce_callback_t);

void *x86_mcinfo_add(struct mc_info *mi, void *mcinfo);
void *x86_mcinfo_reserve(struct mc_info *mi, int size);
void x86_mcinfo_dump(struct mc_info *mi);

int fill_vmsr_data(struct mcinfo_bank *mc_bank, struct domain *d,
        uint64_t gstatus);
int inject_vmce(struct domain *d);
int vmce_domain_inject(struct mcinfo_bank *bank, struct domain *d, struct mcinfo_global *global);

extern int vmce_init(struct cpuinfo_x86 *c);

extern unsigned int nr_mce_banks;

static inline int mce_vendor_bank_msr(uint32_t msr)
{
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL &&
         msr >= MSR_IA32_MC0_CTL2 && msr < (MSR_IA32_MC0_CTL2 + nr_mce_banks) )
          return 1;
    return 0;
}

static inline int mce_bank_msr(uint32_t msr)
{
    if ( (msr >= MSR_IA32_MC0_CTL && msr < MSR_IA32_MCx_CTL(nr_mce_banks)) ||
        mce_vendor_bank_msr(msr) )
        return 1;
    return 0;
}

/* Fields are zero when not available */
struct mce {
    __u64 status;
    __u64 misc;
    __u64 addr;
    __u64 mcgstatus;
    __u64 ip;
    __u64 tsc;      /* cpu time stamp counter */
    __u64 time;     /* wall time_t when error was detected */
    __u8  cpuvendor;        /* cpu vendor as encoded in system.h */
    __u8  inject_flags;     /* software inject flags */
    __u16  pad;
    __u32 cpuid;    /* CPUID 1 EAX */
    __u8  cs;               /* code segment */
    __u8  bank;     /* machine check bank */
    __u8  cpu;      /* cpu number; obsolete; use extcpu now */
    __u8  finished;   /* entry is valid */
    __u32 extcpu;   /* linux cpu number that detected the error */
    __u32 socketid; /* CPU socket ID */
    __u32 apicid;   /* CPU initial apic ID */
    __u64 mcgcap;   /* MCGCAP MSR: machine check capabilities of CPU */
};

#endif /* _MCE_H */
