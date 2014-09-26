#ifndef __ARM_SETUP_H_
#define __ARM_SETUP_H_

#include <public/version.h>

#define NR_MEM_BANKS 64

#define MAX_MODULES 5 /* Current maximum useful modules */

typedef enum {
    BOOTMOD_XEN,
    BOOTMOD_FDT,
    BOOTMOD_KERNEL,
    BOOTMOD_RAMDISK,
    BOOTMOD_XSM,
    BOOTMOD_UNKNOWN
}  bootmodule_kind;


struct membank {
    paddr_t start;
    paddr_t size;
};

struct meminfo {
    int nr_banks;
    struct membank bank[NR_MEM_BANKS];
};

#define BOOTMOD_MAX_CMDLINE 1024
struct bootmodule {
    bootmodule_kind kind;
    paddr_t start;
    paddr_t size;
    char cmdline[BOOTMOD_MAX_CMDLINE];
};

struct bootmodules {
    int nr_mods;
    struct bootmodule module[MAX_MODULES];
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

size_t __init boot_fdt_info(const void *fdt, paddr_t paddr);
const char __init *boot_fdt_cmdline(const void *fdt);

struct bootmodule *add_boot_module(bootmodule_kind kind,
                                   paddr_t start, paddr_t size,
                                   const char *cmdline);
struct bootmodule *boot_module_find_by_kind(bootmodule_kind kind);
const char * __init boot_module_kind_as_string(bootmodule_kind kind);

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
