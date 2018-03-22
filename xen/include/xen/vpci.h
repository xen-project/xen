#ifndef _XEN_VPCI_H_
#define _XEN_VPCI_H_

#ifdef CONFIG_HAS_VPCI

#include <xen/pci.h>
#include <xen/types.h>
#include <xen/list.h>

typedef uint32_t vpci_read_t(const struct pci_dev *pdev, unsigned int reg,
                             void *data);

typedef void vpci_write_t(const struct pci_dev *pdev, unsigned int reg,
                          uint32_t val, void *data);

typedef int vpci_register_init_t(struct pci_dev *dev);

#define VPCI_PRIORITY_HIGH      "1"
#define VPCI_PRIORITY_MIDDLE    "5"
#define VPCI_PRIORITY_LOW       "9"

#define REGISTER_VPCI_INIT(x, p)                \
  static vpci_register_init_t *const x##_entry  \
               __used_section(".data.vpci." p) = x

/* Add vPCI handlers to device. */
int __must_check vpci_add_handlers(struct pci_dev *dev);

/* Remove all handlers and free vpci related structures. */
void vpci_remove_device(struct pci_dev *pdev);

/* Add/remove a register handler. */
int __must_check vpci_add_register(struct vpci *vpci,
                                   vpci_read_t *read_handler,
                                   vpci_write_t *write_handler,
                                   unsigned int offset, unsigned int size,
                                   void *data);
int __must_check vpci_remove_register(struct vpci *vpci, unsigned int offset,
                                      unsigned int size);

/* Generic read/write handlers for the PCI config space. */
uint32_t vpci_read(pci_sbdf_t sbdf, unsigned int reg, unsigned int size);
void vpci_write(pci_sbdf_t sbdf, unsigned int reg, unsigned int size,
                uint32_t data);

/* Passthrough handlers. */
uint32_t vpci_hw_read16(const struct pci_dev *pdev, unsigned int reg,
                        void *data);
uint32_t vpci_hw_read32(const struct pci_dev *pdev, unsigned int reg,
                        void *data);

/*
 * Check for pending vPCI operations on this vcpu. Returns true if the vcpu
 * should not run.
 */
bool __must_check vpci_process_pending(struct vcpu *v);

struct vpci {
    /* List of vPCI handlers for a device. */
    struct list_head handlers;
    spinlock_t lock;

#ifdef __XEN__
    /* Hide the rest of the vpci struct from the user-space test harness. */
    struct vpci_header {
        /* Information about the PCI BARs of this device. */
        struct vpci_bar {
            uint64_t addr;
            uint64_t size;
            enum {
                VPCI_BAR_EMPTY,
                VPCI_BAR_IO,
                VPCI_BAR_MEM32,
                VPCI_BAR_MEM64_LO,
                VPCI_BAR_MEM64_HI,
                VPCI_BAR_ROM,
            } type;
            bool prefetchable : 1;
            /* Store whether the BAR is mapped into guest p2m. */
            bool enabled      : 1;
#define PCI_HEADER_NORMAL_NR_BARS        6
#define PCI_HEADER_BRIDGE_NR_BARS        2
        } bars[PCI_HEADER_NORMAL_NR_BARS + 1];
        /* At most 6 BARS + 1 expansion ROM BAR. */

        /*
         * Store whether the ROM enable bit is set (doesn't imply ROM BAR
         * is mapped into guest p2m) if there's a ROM BAR on the device.
         */
        bool rom_enabled      : 1;
        /* FIXME: currently there's no support for SR-IOV. */
    } header;
#endif

    /* MSI data. */
    struct vpci_msi {
#ifdef __XEN__
      /* Address. */
        uint64_t address;
        /* Mask bitfield. */
        uint32_t mask;
        /* Data. */
        uint16_t data;
        /* Maximum number of vectors supported by the device. */
        uint8_t max_vectors : 5;
        /* Enabled? */
        bool enabled        : 1;
        /* Supports per-vector masking? */
        bool masking        : 1;
        /* 64-bit address capable? */
        bool address64      : 1;
        /* Number of vectors configured. */
        uint8_t vectors     : 5;
        /* Arch-specific data. */
        struct vpci_arch_msi arch;
#endif
    } *msi;
};

struct vpci_vcpu {
    /* Per-vcpu structure to store state while {un}mapping of PCI BARs. */
    struct rangeset *mem;
    struct pci_dev *pdev;
    bool map      : 1;
    bool rom_only : 1;
};

#ifdef __XEN__
void vpci_dump_msi(void);

/* Arch-specific vPCI MSI helpers. */
void vpci_msi_arch_mask(struct vpci_msi *msi, const struct pci_dev *pdev,
                        unsigned int entry, bool mask);
int __must_check vpci_msi_arch_enable(struct vpci_msi *msi,
                                      const struct pci_dev *pdev,
                                      unsigned int vectors);
void vpci_msi_arch_disable(struct vpci_msi *msi, const struct pci_dev *pdev);
void vpci_msi_arch_init(struct vpci_msi *msi);
void vpci_msi_arch_print(const struct vpci_msi *msi);
#endif /* __XEN__ */

#else /* !CONFIG_HAS_VPCI */
struct vpci_vcpu {};
#endif

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
