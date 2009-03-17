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

/* Init functions */
int amd_k7_mcheck_init(struct cpuinfo_x86 *c);
int amd_k8_mcheck_init(struct cpuinfo_x86 *c);
int amd_f10_mcheck_init(struct cpuinfo_x86 *c);

int intel_p5_mcheck_init(struct cpuinfo_x86 *c);
int winchip_mcheck_init(struct cpuinfo_x86 *c);
int intel_mcheck_init(struct cpuinfo_x86 *c);

void intel_mcheck_timer(struct cpuinfo_x86 *c);
void mce_intel_feature_init(struct cpuinfo_x86 *c);
void amd_nonfatal_mcheck_init(struct cpuinfo_x86 *c);

int mce_available(struct cpuinfo_x86 *c);
int mce_firstbank(struct cpuinfo_x86 *c);
/* Helper functions used for collecting error telemetry */
struct mc_info *x86_mcinfo_getptr(void);
void mc_panic(char *s);
void x86_mc_get_cpu_info(unsigned, uint32_t *, uint16_t *, uint16_t *,
			 uint32_t *, uint32_t *, uint32_t *, uint32_t *);


/* Register a handler for machine check exceptions. */
typedef void (*x86_mce_vector_t)(struct cpu_user_regs *, long);
extern void x86_mce_vector_register(x86_mce_vector_t);

/* Common generic MCE handler that implementations may nominate
 * via x86_mce_vector_register. */
extern void mcheck_cmn_handler(struct cpu_user_regs *, long, cpu_banks_t);

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
	MCA_RESET
};

enum mca_extinfo {
	MCA_EXTINFO_LOCAL,
	MCA_EXTINFO_GLOBAL,
	MCA_EXTINFO_IGNORED
};

struct mca_summary {
	uint32_t	errcnt;	/* number of banks with valid errors */
	int		ripv;	/* meaningful on #MC */
	int		eipv;	/* meaningful on #MC */
	uint32_t	uc;	/* bitmask of banks with UC */
	uint32_t	pcc;	/* bitmask of banks with PCC */
};

extern cpu_banks_t mca_allbanks;

extern mctelem_cookie_t mcheck_mca_logout(enum mca_source, cpu_banks_t,
    struct mca_summary *);

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
typedef enum mca_extinfo (*x86_mce_callback_t)
    (struct mc_info *, uint16_t, uint64_t);
extern void x86_mce_callback_register(x86_mce_callback_t);

int x86_mcinfo_add(struct mc_info *mi, void *mcinfo);
void x86_mcinfo_dump(struct mc_info *mi);

#endif /* _MCE_H */
