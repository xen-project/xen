/*
 * ARM GICv3 ITS support
 *
 * Andre Przywara <andre.przywara@arm.com>
 * Copyright (c) 2016,2017 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_ARM_ITS_H__
#define __ASM_ARM_ITS_H__

#define GITS_CTLR                       0x000
#define GITS_IIDR                       0x004
#define GITS_TYPER                      0x008
#define GITS_CBASER                     0x080
#define GITS_CWRITER                    0x088
#define GITS_CREADR                     0x090
#define GITS_BASER_NR_REGS              8
#define GITS_BASER0                     0x100
#define GITS_BASER1                     0x108
#define GITS_BASER2                     0x110
#define GITS_BASER3                     0x118
#define GITS_BASER4                     0x120
#define GITS_BASER5                     0x128
#define GITS_BASER6                     0x130
#define GITS_BASER7                     0x138
#define GITS_PIDR2                      GICR_PIDR2

/* Register bits */
#define GITS_VALID_BIT                  BIT(63)

#define GITS_CTLR_QUIESCENT             BIT(31)
#define GITS_CTLR_ENABLE                BIT(0)

#define GITS_TYPER_PTA                  BIT(19)
#define GITS_TYPER_DEVIDS_SHIFT         13
#define GITS_TYPER_DEVIDS_MASK          (0x1fUL << GITS_TYPER_DEVIDS_SHIFT)
#define GITS_TYPER_DEVICE_ID_BITS(r)    (((r & GITS_TYPER_DEVIDS_MASK) >> \
                                               GITS_TYPER_DEVIDS_SHIFT) + 1)

#define GITS_TYPER_IDBITS_SHIFT         8
#define GITS_TYPER_IDBITS_MASK          (0x1fUL << GITS_TYPER_IDBITS_SHIFT)
#define GITS_TYPER_EVENT_ID_BITS(r)     (((r & GITS_TYPER_IDBITS_MASK) >> \
                                               GITS_TYPER_IDBITS_SHIFT) + 1)

#define GITS_TYPER_ITT_SIZE_SHIFT       4
#define GITS_TYPER_ITT_SIZE_MASK        (0xfUL << GITS_TYPER_ITT_SIZE_SHIFT)
#define GITS_TYPER_ITT_SIZE(r)          ((((r) & GITS_TYPER_ITT_SIZE_MASK) >> \
                                                 GITS_TYPER_ITT_SIZE_SHIFT) + 1)
#define GITS_TYPER_PHYSICAL             (1U << 0)

#define GITS_BASER_INDIRECT             BIT(62)
#define GITS_BASER_INNER_CACHEABILITY_SHIFT        59
#define GITS_BASER_TYPE_SHIFT           56
#define GITS_BASER_TYPE_MASK            (7ULL << GITS_BASER_TYPE_SHIFT)
#define GITS_BASER_OUTER_CACHEABILITY_SHIFT        53
#define GITS_BASER_TYPE_NONE            0UL
#define GITS_BASER_TYPE_DEVICE          1UL
#define GITS_BASER_TYPE_VCPU            2UL
#define GITS_BASER_TYPE_CPU             3UL
#define GITS_BASER_TYPE_COLLECTION      4UL
#define GITS_BASER_TYPE_RESERVED5       5UL
#define GITS_BASER_TYPE_RESERVED6       6UL
#define GITS_BASER_TYPE_RESERVED7       7UL
#define GITS_BASER_ENTRY_SIZE_SHIFT     48
#define GITS_BASER_ENTRY_SIZE(reg)                                       \
                        (((reg >> GITS_BASER_ENTRY_SIZE_SHIFT) & 0x1f) + 1)
#define GITS_BASER_SHAREABILITY_SHIFT   10
#define GITS_BASER_PAGE_SIZE_SHIFT      8
#define GITS_BASER_SIZE_MASK            0xff
#define GITS_BASER_SHAREABILITY_MASK   (0x3ULL << GITS_BASER_SHAREABILITY_SHIFT)
#define GITS_BASER_OUTER_CACHEABILITY_MASK   (0x7ULL << GITS_BASER_OUTER_CACHEABILITY_SHIFT)
#define GITS_BASER_INNER_CACHEABILITY_MASK   (0x7ULL << GITS_BASER_INNER_CACHEABILITY_SHIFT)

#define GITS_CBASER_SIZE_MASK           0xff

/* ITS command definitions */
#define ITS_CMD_SIZE                    32

#define GITS_CMD_MOVI                   0x01
#define GITS_CMD_INT                    0x03
#define GITS_CMD_CLEAR                  0x04
#define GITS_CMD_SYNC                   0x05
#define GITS_CMD_MAPD                   0x08
#define GITS_CMD_MAPC                   0x09
#define GITS_CMD_MAPTI                  0x0a
#define GITS_CMD_MAPI                   0x0b
#define GITS_CMD_INV                    0x0c
#define GITS_CMD_INVALL                 0x0d
#define GITS_CMD_MOVALL                 0x0e
#define GITS_CMD_DISCARD                0x0f

#define ITS_DOORBELL_OFFSET             0x10040
#define GICV3_ITS_SIZE                  SZ_128K

#include <xen/device_tree.h>
#include <xen/rbtree.h>

#define HOST_ITS_FLUSH_CMD_QUEUE        (1U << 0)
#define HOST_ITS_USES_PTA               (1U << 1)

/* We allocate LPIs on the hosts in chunks of 32 to reduce handling overhead. */
#define LPI_BLOCK                       32U

/* data structure for each hardware ITS */
struct host_its {
    struct list_head entry;
    const struct dt_device_node *dt_node;
    paddr_t addr;
    paddr_t size;
    void __iomem *its_base;
    unsigned int devid_bits;
    unsigned int evid_bits;
    unsigned int itte_size;
    spinlock_t cmd_lock;
    void *cmd_buf;
    unsigned int flags;
};


#ifdef CONFIG_HAS_ITS

extern struct list_head host_its_list;

#ifdef CONFIG_ACPI
unsigned long gicv3_its_make_hwdom_madt(const struct domain *d,
                                        void *base_ptr);
#endif

/* Deny iomem access for its */
int gicv3_its_deny_access(const struct domain *d);

bool gicv3_its_host_has_its(void);

unsigned int vgic_v3_its_count(const struct domain *d);

void gicv3_do_LPI(unsigned int lpi);

int gicv3_lpi_init_rdist(void __iomem * rdist_base);

/* Initialize the host structures for LPIs and the host ITSes. */
int gicv3_lpi_init_host_lpis(unsigned int host_lpi_bits);
int gicv3_its_init(void);

/* Store the physical address and ID for each redistributor as read from DT. */
void gicv3_set_redist_address(paddr_t address, unsigned int redist_id);
uint64_t gicv3_get_redist_address(unsigned int cpu, bool use_pta);

/* Map a collection for this host CPU to each host ITS. */
int gicv3_its_setup_collection(unsigned int cpu);

/* Initialize and destroy the per-domain parts of the virtual ITS support. */
int vgic_v3_its_init_domain(struct domain *d);
void vgic_v3_its_free_domain(struct domain *d);

/* Create the appropriate DT nodes for a hardware domain. */
int gicv3_its_make_hwdom_dt_nodes(const struct domain *d,
                                  const struct dt_device_node *gic,
                                  void *fdt);

/*
 * Map a device on the host by allocating an ITT on the host (ITS).
 * "nr_event" specifies how many events (interrupts) this device will need.
 * Setting "valid" to false deallocates the device.
 */
int gicv3_its_map_guest_device(struct domain *d,
                               paddr_t host_doorbell, uint32_t host_devid,
                               paddr_t guest_doorbell, uint32_t guest_devid,
                               uint64_t nr_events, bool valid);

int gicv3_allocate_host_lpi_block(struct domain *d, uint32_t *first_lpi);
void gicv3_free_host_lpi_block(uint32_t first_lpi);

void vgic_vcpu_inject_lpi(struct domain *d, unsigned int virq);

struct pending_irq *gicv3_its_get_event_pending_irq(struct domain *d,
                                                    paddr_t vdoorbell_address,
                                                    uint32_t vdevid,
                                                    uint32_t eventid);
int gicv3_remove_guest_event(struct domain *d, paddr_t vdoorbell_address,
                                     uint32_t vdevid, uint32_t eventid);
struct pending_irq *gicv3_assign_guest_event(struct domain *d, paddr_t doorbell,
                                             uint32_t devid, uint32_t eventid,
                                             uint32_t virt_lpi);
void gicv3_lpi_update_host_entry(uint32_t host_lpi, int domain_id,
                                 uint32_t virt_lpi);

#else

#ifdef CONFIG_ACPI
static inline unsigned long gicv3_its_make_hwdom_madt(const struct domain *d,
                                                      void *base_ptr)
{
    return 0;
}
#endif

static inline int gicv3_its_deny_access(const struct domain *d)
{
    return 0;
}

static inline bool gicv3_its_host_has_its(void)
{
    return false;
}

static inline unsigned int vgic_v3_its_count(const struct domain *d)
{
    return 0;
}

static inline void gicv3_do_LPI(unsigned int lpi)
{
    /* We don't enable LPIs without an ITS. */
    BUG();
}

static inline int gicv3_lpi_init_rdist(void __iomem * rdist_base)
{
    return -ENODEV;
}

static inline int gicv3_lpi_init_host_lpis(unsigned int host_lpi_bits)
{
    return 0;
}

static inline int gicv3_its_init(void)
{
    return 0;
}

static inline void gicv3_set_redist_address(paddr_t address,
                                            unsigned int redist_id)
{
}

static inline int gicv3_its_setup_collection(unsigned int cpu)
{
    /* We should never get here without an ITS. */
    BUG();
}

static inline int vgic_v3_its_init_domain(struct domain *d)
{
    return 0;
}

static inline void vgic_v3_its_free_domain(struct domain *d)
{
}

static inline int gicv3_its_make_hwdom_dt_nodes(const struct domain *d,
                                                const struct dt_device_node *gic,
                                                void *fdt)
{
    return 0;
}

#endif /* CONFIG_HAS_ITS */

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
