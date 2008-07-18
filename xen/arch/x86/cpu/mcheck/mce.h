#include <xen/init.h>
#include <asm/traps.h>

/* Init functions */
void amd_nonfatal_mcheck_init(struct cpuinfo_x86 *c);
void amd_k7_mcheck_init(struct cpuinfo_x86 *c);
void amd_k8_mcheck_init(struct cpuinfo_x86 *c);
void amd_f10_mcheck_init(struct cpuinfo_x86 *c);
void intel_p4_mcheck_init(struct cpuinfo_x86 *c);
void intel_p5_mcheck_init(struct cpuinfo_x86 *c);
void intel_p6_mcheck_init(struct cpuinfo_x86 *c);
void winchip_mcheck_init(struct cpuinfo_x86 *c);

/* Function pointer used in the handlers to collect additional information
 * provided by newer CPU families/models without the need to duplicate
 * the whole handler resulting in various handlers each with its own
 * tweaks and bugs */
extern int (*mc_callback_bank_extended)(struct mc_info *mi,
		uint16_t bank, uint64_t status);


/* Helper functions used for collecting error telemetry */
struct mc_info *x86_mcinfo_getptr(void);
void x86_mcinfo_clear(struct mc_info *mi);
int x86_mcinfo_add(struct mc_info *mi, void *mcinfo);
void x86_mcinfo_dump(struct mc_info *mi);

/* Global variables */
extern int mce_disabled __initdata;
extern unsigned int nr_mce_banks;
