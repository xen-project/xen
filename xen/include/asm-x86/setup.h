#ifndef __X86_SETUP_H_
#define __X86_SETUP_H_

#include <xen/multiboot.h>
#include <asm/numa.h>

extern unsigned long xenheap_initial_phys_start;

void early_cpu_init(void);
void early_time_init(void);

int intel_cpu_init(void);
int amd_init_cpu(void);
int cyrix_init_cpu(void);
int nsc_init_cpu(void);
int centaur_init_cpu(void);
int transmeta_init_cpu(void);

void set_nr_cpu_ids(unsigned int max_cpus);

void numa_initmem_init(unsigned long start_pfn, unsigned long end_pfn);
void arch_init_memory(void);
void subarch_init_memory(void);

void init_IRQ(void);
void vesa_init(void);
void vesa_mtrr_init(void);

int construct_dom0(
    struct domain *d,
    const module_t *kernel, unsigned long kernel_headroom,
    module_t *initrd,
    void *(*bootstrap_map)(const module_t *),
    char *cmdline);
void setup_io_bitmap(struct domain *d);

unsigned long initial_images_nrpages(nodeid_t node);
void discard_initial_images(void);

unsigned int dom0_max_vcpus(void);

int xen_in_range(unsigned long mfn);

void microcode_grab_module(
    unsigned long *, const multiboot_info_t *, void *(*)(const module_t *));

extern uint8_t kbd_shift_flags;

#ifdef NDEBUG
# define highmem_start 0
#else
extern unsigned long highmem_start;
#endif

#endif
