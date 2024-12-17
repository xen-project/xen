#ifndef __ARM_SETUP_H_
#define __ARM_SETUP_H_

#include <public/version.h>
#include <asm/p2m.h>
#include <xen/bootfdt.h>
#include <xen/device_tree.h>

#if defined(CONFIG_MMU)
# include <asm/mmu/setup.h>
#elif !defined(CONFIG_MPU)
# error "Unknown memory management layout"
#endif

#define MAX_FDT_SIZE SZ_2M

struct map_range_data
{
    struct domain *d;
    p2m_type_t p2mt;
    /* Set if mapping of the memory ranges must be skipped. */
    bool skip_mapping;
    /* Rangeset to store IRQs and IOMEM for overlay nodes. */
    struct rangeset *iomem_ranges;
    struct rangeset *irq_ranges;
};

extern domid_t max_init_domid;

void copy_from_paddr(void *dst, paddr_t paddr, unsigned long len);

size_t estimate_efi_size(unsigned int mem_nr_banks);

void acpi_create_efi_system_table(struct domain *d,
                                  struct membank tbl_add[]);

void acpi_create_efi_mmap_table(struct domain *d,
                                const struct membanks *mem,
                                struct membank tbl_add[]);

int acpi_make_efi_nodes(void *fdt, struct membank tbl_add[]);

void create_dom0(void);

void discard_initial_modules(void);
void fw_unreserved_regions(paddr_t s, paddr_t e,
                           void (*cb)(paddr_t ps, paddr_t pe),
                           unsigned int first);

void init_pdx(void);
void setup_mm(void);

extern uint32_t hyp_traps_vector[];
void init_traps(void);

void device_tree_get_reg(const __be32 **cell, uint32_t address_cells,
                         uint32_t size_cells, paddr_t *start, paddr_t *size);

u32 device_tree_get_u32(const void *fdt, int node,
                        const char *prop_name, u32 dflt);

int handle_device(struct domain *d, struct dt_device_node *dev, p2m_type_t p2mt,
                  struct rangeset *iomem_ranges, struct rangeset *irq_ranges);

int map_device_irqs_to_domain(struct domain *d, struct dt_device_node *dev,
                              bool need_mapping, struct rangeset *irq_ranges);

int map_irq_to_domain(struct domain *d, unsigned int irq,
                      bool need_mapping, const char *devname);

int map_range_to_domain(const struct dt_device_node *dev,
                        uint64_t addr, uint64_t len, void *data);

extern const char __ro_after_init_start[], __ro_after_init_end[];

struct init_info
{
    /* Pointer to the stack, used by head.S when entering in C */
    unsigned char *stack;
    /* Logical CPU ID, used by start_secondary */
    unsigned int cpuid;
};

paddr_t consider_modules(paddr_t s, paddr_t e, uint32_t size, paddr_t align,
                         int first_mod);

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
