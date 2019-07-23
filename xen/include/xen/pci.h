/******************************************************************************
 * pci.h
 * 
 * PCI access functions.
 */

#ifndef __XEN_PCI_H__
#define __XEN_PCI_H__

#include <xen/types.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <xen/irq.h>
#include <xen/pci_regs.h>
#include <xen/pfn.h>
#include <asm/device.h>
#include <asm/numa.h>
#include <asm/pci.h>

/*
 * The PCI interface treats multi-function devices as independent
 * devices.  The slot/function address of each device is encoded
 * in a single byte as follows:
 *
 * 15:8 = bus
 *  7:3 = slot
 *  2:0 = function
 */
#define PCI_SEG(sbdf) (((sbdf) >> 16) & 0xffff)
#define PCI_BUS(bdf)    (((bdf) >> 8) & 0xff)
#define PCI_SLOT(bdf)   (((bdf) >> 3) & 0x1f)
#define PCI_FUNC(bdf)   ((bdf) & 0x07)
#define PCI_DEVFN(d,f)  ((((d) & 0x1f) << 3) | ((f) & 0x07))
#define PCI_DEVFN2(bdf) ((bdf) & 0xff)
#define PCI_BDF(b,d,f)  ((((b) & 0xff) << 8) | PCI_DEVFN(d,f))
#define PCI_BDF2(b,df)  ((((b) & 0xff) << 8) | ((df) & 0xff))
#define PCI_SBDF(s,b,d,f) \
    ((pci_sbdf_t){ .sbdf = (((s) & 0xffff) << 16) | PCI_BDF(b, d, f) })
#define PCI_SBDF2(s,bdf) \
    ((pci_sbdf_t){ .sbdf = (((s) & 0xffff) << 16) | ((bdf) & 0xffff) })
#define PCI_SBDF3(s,b,df) \
    ((pci_sbdf_t){ .sbdf = (((s) & 0xffff) << 16) | PCI_BDF2(b, df) })

typedef union {
    uint32_t sbdf;
    struct {
        union {
            uint16_t bdf;
            struct {
                union {
                    struct {
                        uint8_t fn   : 3,
                                dev  : 5;
                    };
                    uint8_t     devfn,
                                extfunc;
                };
                uint8_t         bus;
            };
        };
        uint16_t                seg;
    };
} pci_sbdf_t;

struct pci_dev_info {
    /*
     * VF's 'is_extfn' field is used to indicate whether its PF is an extended
     * function.
     */
    bool_t is_extfn;
    bool_t is_virtfn;
    struct {
        u8 bus;
        u8 devfn;
    } physfn;
};

struct pci_dev {
    struct list_head alldevs_list;
    struct list_head domain_list;

    struct list_head msi_list;

    struct arch_msix *msix;

    struct domain *domain;

    const union {
        struct {
            uint8_t devfn;
            uint8_t bus;
            uint16_t seg;
        };
        pci_sbdf_t sbdf;
    };

    u8 phantom_stride;

    nodeid_t node; /* NUMA node */

    /* Device with errata, ignore the BARs. */
    bool ignore_bars;

    enum pdev_type {
        DEV_TYPE_PCI_UNKNOWN,
        DEV_TYPE_PCIe_ENDPOINT,
        DEV_TYPE_PCIe_BRIDGE,       // PCIe root port, switch
        DEV_TYPE_PCIe2PCI_BRIDGE,   // PCIe-to-PCI/PCIx bridge
        DEV_TYPE_PCI2PCIe_BRIDGE,   // PCI/PCIx-to-PCIe bridge
        DEV_TYPE_LEGACY_PCI_BRIDGE, // Legacy PCI bridge
        DEV_TYPE_PCI_HOST_BRIDGE,   // PCI Host bridge
        DEV_TYPE_PCI,
    } type;

    struct pci_dev_info info;
    struct arch_pci_dev arch;
    struct {
        struct list_head list;
        unsigned int cap_pos;
        unsigned int queue_depth;
    } ats;
    struct {
        s_time_t time;
        unsigned int count;
#define PT_FAULT_THRESHOLD 10
    } fault;
    u64 vf_rlen[6];

    /* Data for vPCI. */
    struct vpci *vpci;
};

#define for_each_pdev(domain, pdev) \
    list_for_each_entry(pdev, &(domain)->pdev_list, domain_list)

#define has_arch_pdevs(d) (!list_empty(&(d)->pdev_list))

/*
 * The pcidevs_lock protect alldevs_list, and the assignment for the 
 * devices, it also sync the access to the msi capability that is not
 * interrupt handling related (the mask bit register).
 */

void pcidevs_lock(void);
void pcidevs_unlock(void);
bool_t __must_check pcidevs_locked(void);
bool_t __must_check pcidevs_trylock(void);

bool_t pci_known_segment(u16 seg);
bool_t pci_device_detect(u16 seg, u8 bus, u8 dev, u8 func);
int scan_pci_devices(void);
enum pdev_type pdev_type(u16 seg, u8 bus, u8 devfn);
int find_upstream_bridge(u16 seg, u8 *bus, u8 *devfn, u8 *secbus);
struct pci_dev *pci_lock_pdev(int seg, int bus, int devfn);
struct pci_dev *pci_lock_domain_pdev(
    struct domain *, int seg, int bus, int devfn);

void setup_hwdom_pci_devices(struct domain *,
                            int (*)(u8 devfn, struct pci_dev *));
int pci_release_devices(struct domain *d);
void pci_segments_init(void);
int pci_add_segment(u16 seg);
const unsigned long *pci_get_ro_map(u16 seg);
int pci_add_device(u16 seg, u8 bus, u8 devfn,
                   const struct pci_dev_info *, nodeid_t node);
int pci_remove_device(u16 seg, u8 bus, u8 devfn);
int pci_ro_device(int seg, int bus, int devfn);
int pci_hide_device(unsigned int seg, unsigned int bus, unsigned int devfn);
struct pci_dev *pci_get_pdev(int seg, int bus, int devfn);
struct pci_dev *pci_get_real_pdev(int seg, int bus, int devfn);
struct pci_dev *pci_get_pdev_by_domain(const struct domain *, int seg,
                                       int bus, int devfn);
void pci_check_disable_device(u16 seg, u8 bus, u8 devfn);

uint8_t pci_conf_read8(pci_sbdf_t sbdf, unsigned int reg);
uint16_t pci_conf_read16(pci_sbdf_t sbdf, unsigned int reg);
uint32_t pci_conf_read32(pci_sbdf_t sbdf, unsigned int reg);
void pci_conf_write8(pci_sbdf_t sbdf, unsigned int reg, uint8_t data);
void pci_conf_write16(pci_sbdf_t sbdf, unsigned int reg, uint16_t data);
void pci_conf_write32(
    unsigned int seg, unsigned int bus, unsigned int dev, unsigned int func,
    unsigned int reg, uint32_t data);
uint32_t pci_conf_read(uint32_t cf8, uint8_t offset, uint8_t bytes);
void pci_conf_write(uint32_t cf8, uint8_t offset, uint8_t bytes, uint32_t data);
int pci_mmcfg_read(unsigned int seg, unsigned int bus,
                   unsigned int devfn, int reg, int len, u32 *value);
int pci_mmcfg_write(unsigned int seg, unsigned int bus,
                    unsigned int devfn, int reg, int len, u32 value);
int pci_find_cap_offset(u16 seg, u8 bus, u8 dev, u8 func, u8 cap);
int pci_find_next_cap(u16 seg, u8 bus, unsigned int devfn, u8 pos, int cap);
int pci_find_ext_capability(int seg, int bus, int devfn, int cap);
int pci_find_next_ext_capability(int seg, int bus, int devfn, int pos, int cap);
const char *parse_pci(const char *, unsigned int *seg, unsigned int *bus,
                      unsigned int *dev, unsigned int *func);
const char *parse_pci_seg(const char *, unsigned int *seg, unsigned int *bus,
                          unsigned int *dev, unsigned int *func, bool *def_seg);

#define PCI_BAR_VF      (1u << 0)
#define PCI_BAR_LAST    (1u << 1)
#define PCI_BAR_ROM     (1u << 2)
unsigned int pci_size_mem_bar(pci_sbdf_t sbdf, unsigned int pos,
                              uint64_t *paddr, uint64_t *psize,
                              unsigned int flags);

void pci_intx(const struct pci_dev *, bool enable);
bool_t pcie_aer_get_firmware_first(const struct pci_dev *);

struct pirq;
int msixtbl_pt_register(struct domain *, struct pirq *, uint64_t gtable);
void msixtbl_pt_unregister(struct domain *, struct pirq *);
void msixtbl_pt_cleanup(struct domain *d);

#endif /* __XEN_PCI_H__ */
