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
#include <xen/numa.h>
#include <xen/pci_regs.h>
#include <xen/pfn.h>
#include <asm/device.h>

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

#define PCI_DEVFN1_(df)   ((df) & 0xff)
#define PCI_DEVFN2_(d, f) ((((d) & 0x1f) << 3) | ((f) & 7))
#define PCI_SBDF4_(s, b, d, f...) \
    ((pci_sbdf_t){ .sbdf = (((s) & 0xffff) << 16) | PCI_BDF(b, d, ##f) })
#define PCI_SBDF3_ PCI_SBDF4_
#define PCI_SBDF2_(s, bdf) \
    ((pci_sbdf_t){ .sbdf = (((s) & 0xffff) << 16) | ((bdf) & 0xffff) })

#define PCI__(what, nr) PCI_##what##nr##_
#define PCI_(what, nr)  PCI__(what, nr)

#define PCI_DEVFN(d, f...)   PCI_(DEVFN, count_args(d, ##f))(d, ##f)
#define PCI_BDF(b, d, f...)  ((((b) & 0xff) << 8) | PCI_DEVFN(d, ##f))
#define PCI_SBDF(s, b, d...) PCI_(SBDF, count_args(s, b, ##d))(s, b, ##d)

#define ECAM_REG_OFFSET(addr)  ((addr) & 0x00000fff)

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

#ifdef CONFIG_HAS_PCI
#include <asm/pci.h>
#else

struct arch_pci_dev { };

static inline bool is_pci_passthrough_enabled(void)
{
    return false;
}

static inline bool arch_pci_device_physdevop(void)
{
    return false;
}

#endif

struct pci_dev_info {
    /*
     * VF's 'is_extfn' field is used to indicate whether its PF is an extended
     * function.
     */
    bool is_extfn;
    bool is_virtfn;
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

    uint8_t msi_pos;
    uint8_t msix_pos;

    uint8_t msi_maxvec;
    uint8_t phantom_stride;

    nodeid_t node; /* NUMA node */

    /* Device to be quarantined, don't automatically re-assign to dom0 */
    bool quarantine;

    /* Device with errata, ignore the BARs. */
    bool ignore_bars;

    /* Device misbehaving, prevent assigning it to guests. */
    bool broken;

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

    /*
     * List head if PF.
     * List entry if VF.
     */
    struct list_head vf_list;
    union {
        struct pf_info {
            /* Only populated for PFs. */
            uint64_t vf_rlen[PCI_SRIOV_NUM_BARS];
        } physfn;
        /* Link from VF to PF. Only populated for VFs. */
        const struct pci_dev *pf_pdev;
    };

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
void pcidevs_lock_unsafe(void);
static always_inline void pcidevs_lock(void)
{
    pcidevs_lock_unsafe();
    block_lock_speculation();
}
void pcidevs_unlock(void);
bool __must_check pcidevs_locked(void);
bool pcidevs_trylock_unsafe(void);
static always_inline bool pcidevs_trylock(void)
{
    return lock_evaluate_nospec(pcidevs_trylock_unsafe());
}

#ifndef NDEBUG
/*
 * Check to ensure there will be no changes to the entries in d->pdev_list (but
 * not the contents of each entry).
 * This check is not suitable for protecting other state or critical regions.
 */
#define ASSERT_PDEV_LIST_IS_READ_LOCKED(d)                               \
        /* NB: d may be evaluated multiple times, or not at all */       \
        ASSERT(pcidevs_locked() || ((d) && rw_is_locked(&(d)->pci_lock)))
#else
#define ASSERT_PDEV_LIST_IS_READ_LOCKED(d) ((void)(d))
#endif

bool pci_known_segment(u16 seg);
bool pci_device_detect(u16 seg, u8 bus, u8 dev, u8 func);
int scan_pci_devices(void);
enum pdev_type pdev_type(u16 seg, u8 bus, u8 devfn);
int find_upstream_bridge(u16 seg, u8 *bus, u8 *devfn, u8 *secbus);

void setup_hwdom_pci_devices(struct domain *d,
                             int (*handler)(uint8_t devfn,
                                            struct pci_dev *pdev));
int pci_release_devices(struct domain *d);
int pci_add_segment(u16 seg);
const unsigned long *pci_get_ro_map(u16 seg);
int pci_add_device(u16 seg, u8 bus, u8 devfn,
                   const struct pci_dev_info *info, nodeid_t node);
int pci_remove_device(u16 seg, u8 bus, u8 devfn);
int pci_ro_device(int seg, int bus, int devfn);
int pci_hide_device(unsigned int seg, unsigned int bus, unsigned int devfn);
struct pci_dev *pci_get_pdev(const struct domain *d, pci_sbdf_t sbdf);
struct pci_dev *pci_get_real_pdev(pci_sbdf_t sbdf);
void pci_check_disable_device(u16 seg, u8 bus, u8 devfn);

/*
 * Iterate without locking or preemption over all PCI devices known by Xen.
 * Can be called with interrupts disabled.
 */
int pci_iterate_devices(int (*handler)(struct pci_dev *pdev, void *arg),
                        void *arg);

uint8_t pci_conf_read8(pci_sbdf_t sbdf, unsigned int reg);
uint16_t pci_conf_read16(pci_sbdf_t sbdf, unsigned int reg);
uint32_t pci_conf_read32(pci_sbdf_t sbdf, unsigned int reg);
void pci_conf_write8(pci_sbdf_t sbdf, unsigned int reg, uint8_t data);
void pci_conf_write16(pci_sbdf_t sbdf, unsigned int reg, uint16_t data);
void pci_conf_write32(pci_sbdf_t sbdf, unsigned int reg, uint32_t data);
uint32_t pci_conf_read(uint32_t cf8, uint8_t offset, uint8_t bytes);
void pci_conf_write(uint32_t cf8, uint8_t offset, uint8_t bytes, uint32_t data);
int pci_mmcfg_read(unsigned int seg, unsigned int bus,
                   unsigned int devfn, int reg, int len, u32 *value);
int pci_mmcfg_write(unsigned int seg, unsigned int bus,
                    unsigned int devfn, int reg, int len, u32 value);
unsigned int pci_find_cap_offset(pci_sbdf_t sbdf, unsigned int cap);
unsigned int pci_find_next_cap_ttl(pci_sbdf_t sbdf, unsigned int pos,
                                   const unsigned int caps[], unsigned int n,
                                   unsigned int *ttl);
unsigned int pci_find_next_cap(pci_sbdf_t sbdf, unsigned int pos,
                               unsigned int cap);
unsigned int pci_find_ext_capability(pci_sbdf_t sbdf, unsigned int cap);
unsigned int pci_find_next_ext_capability(pci_sbdf_t sbdf, unsigned int start,
                                          unsigned int cap);
const char *parse_pci(const char *s, unsigned int *seg_p, unsigned int *bus_p,
                      unsigned int *dev_p, unsigned int *func_p);
const char *parse_pci_seg(const char *s, unsigned int *seg_p,
                          unsigned int *bus_p, unsigned int *dev_p,
                          unsigned int *func_p, bool *def_seg);

#define PCI_BAR_VF      (1u << 0)
#define PCI_BAR_LAST    (1u << 1)
#define PCI_BAR_ROM     (1u << 2)
unsigned int pci_size_mem_bar(pci_sbdf_t sbdf, unsigned int pos,
                              uint64_t *paddr, uint64_t *psize,
                              unsigned int flags);

void pci_intx(const struct pci_dev *pdev, bool enable);
bool pcie_aer_get_firmware_first(const struct pci_dev *pdev);

struct pirq;
int msixtbl_pt_register(struct domain *d, struct pirq *pirq, uint64_t gtable);
void msixtbl_pt_unregister(struct domain *d, struct pirq *pirq);
void msixtbl_pt_cleanup(struct domain *d);

#ifdef CONFIG_HVM
int arch_pci_clean_pirqs(struct domain *d);
#else
static inline int arch_pci_clean_pirqs(struct domain *d)
{
    return 0;
}
#endif /* CONFIG_HVM */

#endif /* __XEN_PCI_H__ */
