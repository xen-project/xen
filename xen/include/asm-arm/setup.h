#ifndef __ARM_SETUP_H_
#define __ARM_SETUP_H_

#include <public/version.h>

#define NR_MEM_BANKS 8

#define MOD_XEN    0
#define MOD_FDT    1
#define MOD_KERNEL 2
#define MOD_INITRD 3
#define MOD_XSM    4
#define NR_MODULES 5

#define MOD_DISCARD_FIRST MOD_FDT

struct membank {
    paddr_t start;
    paddr_t size;
};

struct meminfo {
    int nr_banks;
    struct membank bank[NR_MEM_BANKS];
};

struct bootmodule {
    paddr_t start;
    paddr_t size;
    char cmdline[1024];
};

struct bootmodules {
    int nr_mods;
    /* Module 0 is Xen itself, followed by the provided modules-proper */
    struct bootmodule module[NR_MODULES];
};

struct bootinfo {
    struct meminfo mem;
    struct bootmodules modules;
};

extern struct bootinfo bootinfo;

void arch_init_memory(void);

void copy_from_paddr(void *dst, paddr_t paddr, unsigned long len);

void arch_get_xen_caps(xen_capabilities_info_t *info);

int construct_dom0(struct domain *d);

void discard_initial_modules(void);

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
