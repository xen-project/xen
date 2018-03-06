#ifndef _DOM0_BUILD_H_
#define _DOM0_BUILD_H_

#include <xen/libelf.h>
#include <xen/sched.h>

#include <asm/setup.h>

extern unsigned int dom0_memflags;

unsigned long dom0_compute_nr_pages(struct domain *d,
                                    struct elf_dom_parms *parms,
                                    unsigned long initrd_len);
struct vcpu *dom0_setup_vcpu(struct domain *d, unsigned int vcpu_id,
                             unsigned int cpu);
int dom0_setup_permissions(struct domain *d);

int dom0_construct_pv(struct domain *d, const module_t *image,
                      unsigned long image_headroom,
                      module_t *initrd,
                      void *(*bootstrap_map)(const module_t *),
                      char *cmdline);

int dom0_construct_pvh(struct domain *d, const module_t *image,
                       unsigned long image_headroom,
                       module_t *initrd,
                       void *(*bootstrap_map)(const module_t *),
                       char *cmdline);

unsigned long dom0_paging_pages(const struct domain *d,
                                unsigned long nr_pages);

void dom0_update_physmap(struct domain *d, unsigned long pfn,
                         unsigned long mfn, unsigned long vphysmap_s);

#endif	/* _DOM0_BUILD_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
