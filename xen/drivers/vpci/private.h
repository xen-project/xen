#ifndef VPCI_PRIVATE_H
#define VPCI_PRIVATE_H

#include <xen/vpci.h>

typedef uint32_t vpci_read_t(const struct pci_dev *pdev, unsigned int reg,
                             void *data);

typedef void vpci_write_t(const struct pci_dev *pdev, unsigned int reg,
                          uint32_t val, void *data);

/* Internal struct to store the emulated PCI registers. */
struct vpci_register {
    vpci_read_t *read;
    vpci_write_t *write;
    unsigned int size;
    unsigned int offset;
    void *private;
    struct list_head node;
    uint32_t ro_mask;
    uint32_t rw1c_mask;
    uint32_t rsvdp_mask;
    uint32_t rsvdz_mask;
};

typedef struct {
    unsigned int id;
    bool is_ext;
    int (* init)(struct pci_dev *pdev);
    int (* cleanup)(const struct pci_dev *pdev, bool hide);
} vpci_capability_t;

#define REGISTER_VPCI_CAPABILITY(cap, name, finit, fclean, ext) \
    static const vpci_capability_t name##_entry \
        __used_section(".data.rel.ro.vpci") = { \
        .id = (cap), \
        .init = (finit), \
        .cleanup = (fclean), \
        .is_ext = (ext), \
    }

#define REGISTER_VPCI_CAP(name, finit, fclean) \
    REGISTER_VPCI_CAPABILITY(PCI_CAP_ID_##name, name, finit, fclean, false)
#define REGISTER_VPCI_EXTCAP(name, finit, fclean) \
    REGISTER_VPCI_CAPABILITY(PCI_EXT_CAP_ID_##name, name, finit, fclean, true)

int __must_check vpci_init_header(struct pci_dev *pdev);

int vpci_init_capabilities(struct pci_dev *pdev);
void vpci_cleanup_capabilities(struct pci_dev *pdev);

/* Add/remove a register handler. */
int __must_check vpci_add_register_mask(struct vpci *vpci,
                                        vpci_read_t *read_handler,
                                        vpci_write_t *write_handler,
                                        unsigned int offset, unsigned int size,
                                        void *data, uint32_t ro_mask,
                                        uint32_t rw1c_mask, uint32_t rsvdp_mask,
                                        uint32_t rsvdz_mask);
int __must_check vpci_add_register(struct vpci *vpci,
                                   vpci_read_t *read_handler,
                                   vpci_write_t *write_handler,
                                   unsigned int offset, unsigned int size,
                                   void *data);

int vpci_remove_registers(struct vpci *vpci, unsigned int start,
                          unsigned int size);

struct vpci_register *vpci_get_register(const struct vpci *vpci,
                                        unsigned int offset,
                                        unsigned int size);

/* Helper to return the value passed in data. */
uint32_t cf_check vpci_read_val(
    const struct pci_dev *pdev, unsigned int reg, void *data);

/* Passthrough handlers. */
uint32_t cf_check vpci_hw_read8(
    const struct pci_dev *pdev, unsigned int reg, void *data);
uint32_t cf_check vpci_hw_read16(
    const struct pci_dev *pdev, unsigned int reg, void *data);
uint32_t cf_check vpci_hw_read32(
    const struct pci_dev *pdev, unsigned int reg, void *data);
void cf_check vpci_hw_write8(
    const struct pci_dev *pdev, unsigned int reg, uint32_t val, void *data);
void cf_check vpci_hw_write16(
    const struct pci_dev *pdev, unsigned int reg, uint32_t val, void *data);

#ifdef __XEN__
/* Make sure there's a hole in the p2m for the MSIX mmio areas. */
int vpci_make_msix_hole(const struct pci_dev *pdev);

/*
 * Helper functions to fetch MSIX related data. They are used by both the
 * emulated MSIX code and the BAR handlers.
 */
static inline paddr_t vmsix_table_host_base(const struct vpci *vpci,
                                            unsigned int nr)
{
    return vpci->header.bars[vpci->msix->tables[nr] & PCI_MSIX_BIRMASK].addr;
}

static inline paddr_t vmsix_table_host_addr(const struct vpci *vpci,
                                            unsigned int nr)
{
    return vmsix_table_host_base(vpci, nr) +
           (vpci->msix->tables[nr] & ~PCI_MSIX_BIRMASK);
}

static inline paddr_t vmsix_table_base(const struct vpci *vpci, unsigned int nr)
{
    return vpci->header.bars[vpci->msix->tables[nr] &
                             PCI_MSIX_BIRMASK].guest_addr;
}

static inline paddr_t vmsix_table_addr(const struct vpci *vpci, unsigned int nr)
{
    return vmsix_table_base(vpci, nr) +
           (vpci->msix->tables[nr] & ~PCI_MSIX_BIRMASK);
}

/*
 * Note regarding the size calculation of the PBA: the spec mentions "The last
 * QWORD will not necessarily be fully populated", so it implies that the PBA
 * size is 64-bit aligned.
 */
static inline size_t vmsix_table_size(const struct vpci *vpci, unsigned int nr)
{
    return
        (nr == VPCI_MSIX_TABLE) ? vpci->msix->max_entries * PCI_MSIX_ENTRY_SIZE
                                : ROUNDUP(DIV_ROUND_UP(vpci->msix->max_entries,
                                                       8), 8);
}

#endif /* __XEN__ */

#endif /* VPCI_PRIVATE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
