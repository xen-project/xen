#ifndef __X86_SETUP_H_
#define __X86_SETUP_H_

#include <xen/multiboot.h>
#include <asm/numa.h>

extern const char __2M_text_start[], __2M_text_end[];
extern const char __ro_after_init_start[], __ro_after_init_end[];
extern const char __2M_rodata_start[], __2M_rodata_end[];
extern char __2M_init_start[], __2M_init_end[];
extern char __2M_rwdata_start[], __2M_rwdata_end[];

extern unsigned long xenheap_initial_phys_start;
extern uint64_t boot_tsc_stamp;

extern void *stack_start;

void early_cpu_init(bool verbose);
void early_time_init(void);

void set_nr_cpu_ids(unsigned int max_cpus);

void arch_init_memory(void);
void subarch_init_memory(void);

void init_IRQ(void);

int construct_dom0(
    struct domain *d,
    const module_t *image, unsigned long image_headroom,
    module_t *initrd,
    const char *cmdline);
void setup_io_bitmap(struct domain *d);

unsigned long initial_images_nrpages(nodeid_t node);
void discard_initial_images(void);
void *bootstrap_map(const module_t *mod);

int remove_xen_ranges(struct rangeset *r);

int cf_check stub_selftest(void);

extern uint8_t kbd_shift_flags;

#ifdef NDEBUG
# define highmem_start 0
#else
extern unsigned long highmem_start;
#endif

extern unsigned int i8259A_alias_mask;
extern unsigned int pit_alias_mask;

extern int8_t opt_smt;
extern int8_t opt_probe_port_aliases;

#ifdef CONFIG_SHADOW_PAGING
extern bool opt_dom0_shadow;
#else
#define opt_dom0_shadow false
#endif
extern bool opt_dom0_pvh;
extern bool opt_dom0_verbose;
extern bool opt_dom0_cpuid_faulting;
extern bool opt_dom0_msr_relaxed;

extern unsigned long cr4_pv32_mask;

#define max_init_domid (0)

#endif
