#ifndef __ARM_SETUP_H_
#define __ARM_SETUP_H_

#include <public/version.h>

#define MIN_FDT_ALIGN 8
#define MAX_FDT_SIZE SZ_2M

#define NR_MEM_BANKS 128

#define MAX_MODULES 32 /* Current maximum useful modules */

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

/*
 * The domU flag is set for kernels and ramdisks of "xen,domain" nodes.
 * The purpose of the domU flag is to avoid getting confused in
 * kernel_probe, where we try to guess which is the dom0 kernel and
 * initrd to be compatible with all versions of the multiboot spec. 
 */
#define BOOTMOD_MAX_CMDLINE 1024
struct bootmodule {
    bootmodule_kind kind;
    bool domU;
    paddr_t start;
    paddr_t size;
};

/* DT_MAX_NAME is the node name max length according the DT spec */
#define DT_MAX_NAME 41
struct bootcmdline {
    bootmodule_kind kind;
    bool domU;
    paddr_t start;
    char dt_name[DT_MAX_NAME];
    char cmdline[BOOTMOD_MAX_CMDLINE];
};

struct bootmodules {
    int nr_mods;
    struct bootmodule module[MAX_MODULES];
};

struct bootcmdlines {
    unsigned int nr_mods;
    struct bootcmdline cmdline[MAX_MODULES];
};

struct bootinfo {
    struct meminfo mem;
    struct meminfo reserved_mem;
    struct bootmodules modules;
    struct bootcmdlines cmdlines;
#ifdef CONFIG_ACPI
    struct meminfo acpi;
#endif
};

extern struct bootinfo bootinfo;

extern domid_t max_init_domid;

void copy_from_paddr(void *dst, paddr_t paddr, unsigned long len);

size_t estimate_efi_size(int mem_nr_banks);

void acpi_create_efi_system_table(struct domain *d,
                                  struct membank tbl_add[]);

void acpi_create_efi_mmap_table(struct domain *d,
                                const struct meminfo *mem,
                                struct membank tbl_add[]);

int acpi_make_efi_nodes(void *fdt, struct membank tbl_add[]);

int construct_dom0(struct domain *d);
void create_domUs(void);

void discard_initial_modules(void);
void dt_unreserved_regions(paddr_t s, paddr_t e,
                           void (*cb)(paddr_t, paddr_t), int first);

size_t boot_fdt_info(const void *fdt, paddr_t paddr);
const char *boot_fdt_cmdline(const void *fdt);

struct bootmodule *add_boot_module(bootmodule_kind kind,
                                   paddr_t start, paddr_t size, bool domU);
struct bootmodule *boot_module_find_by_kind(bootmodule_kind kind);
struct bootmodule * boot_module_find_by_addr_and_kind(bootmodule_kind kind,
                                                             paddr_t start);
void add_boot_cmdline(const char *name, const char *cmdline,
                      bootmodule_kind kind, paddr_t start, bool domU);
struct bootcmdline *boot_cmdline_find_by_kind(bootmodule_kind kind);
struct bootcmdline * boot_cmdline_find_by_name(const char *name);
const char *boot_module_kind_as_string(bootmodule_kind kind);

extern uint32_t hyp_traps_vector[];
void init_traps(void);

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
