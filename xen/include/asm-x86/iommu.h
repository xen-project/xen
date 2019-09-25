/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef __ARCH_X86_IOMMU_H__
#define __ARCH_X86_IOMMU_H__

#include <xen/errno.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <asm/apicdef.h>
#include <asm/processor.h>
#include <asm/hvm/vmx/vmcs.h>

#define DEFAULT_DOMAIN_ADDRESS_WIDTH 48
#define MAX_IOMMUS 32

struct g2m_ioport {
    struct list_head list;
    unsigned int gport;
    unsigned int mport;
    unsigned int np;
};

#define IOMMU_PAGE_SHIFT 12
#define IOMMU_PAGE_SIZE  (1 << IOMMU_PAGE_SHIFT)
#define IOMMU_PAGE_MASK  (~(IOMMU_PAGE_SIZE - 1))

typedef uint64_t daddr_t;

#define __dfn_to_daddr(dfn) ((daddr_t)(dfn) << IOMMU_PAGE_SHIFT)
#define __daddr_to_dfn(daddr) ((daddr) >> IOMMU_PAGE_SHIFT)

#define dfn_to_daddr(dfn) __dfn_to_daddr(dfn_x(dfn))
#define daddr_to_dfn(daddr) _dfn(__daddr_to_dfn(daddr))

struct arch_iommu
{
    u64 pgd_maddr;                 /* io page directory machine address */
    spinlock_t mapping_lock;            /* io page table lock */
    int agaw;     /* adjusted guest address width, 0 is level 2 30-bit */
    u64 iommu_bitmap;              /* bitmap of iommu(s) that the domain uses */
    struct list_head mapped_rmrrs;

    /* amd iommu support */
    int paging_mode;
    struct page_info *root_table;
    struct guest_iommu *g_iommu;
};

extern struct iommu_ops iommu_ops;

#ifdef NDEBUG
# include <asm/alternative.h>
# define iommu_call(ops, fn, args...) ({      \
    (void)(ops);                              \
    alternative_call(iommu_ops.fn, ## args);  \
})

# define iommu_vcall(ops, fn, args...) ({     \
    (void)(ops);                              \
    alternative_vcall(iommu_ops.fn, ## args); \
})
#endif

static inline const struct iommu_ops *iommu_get_ops(void)
{
    BUG_ON(!iommu_ops.init);
    return &iommu_ops;
}

struct iommu_init_ops {
    const struct iommu_ops *ops;
    int (*setup)(void);
    bool (*supports_x2apic)(void);
};

extern const struct iommu_init_ops *iommu_init_ops;

void iommu_update_ire_from_apic(unsigned int apic, unsigned int reg, unsigned int value);
unsigned int iommu_read_apic_from_ire(unsigned int apic, unsigned int reg);
int iommu_setup_hpet_msi(struct msi_desc *);

static inline int iommu_adjust_irq_affinities(void)
{
    return iommu_ops.adjust_irq_affinities
           ? iommu_ops.adjust_irq_affinities()
           : 0;
}

/* While VT-d specific, this must get declared in a generic header. */
int __must_check iommu_pte_flush(struct domain *d, u64 gfn, u64 *pte,
                                 int order, int present);

static inline bool iommu_supports_x2apic(void)
{
    return iommu_init_ops && iommu_init_ops->supports_x2apic
           ? iommu_init_ops->supports_x2apic()
           : false;
}

int iommu_enable_x2apic(void);

static inline void iommu_disable_x2apic(void)
{
    if ( x2apic_enabled && iommu_ops.disable_x2apic )
        iommu_ops.disable_x2apic();
}

extern bool untrusted_msi;

int pi_update_irte(const struct pi_desc *pi_desc, const struct pirq *pirq,
                   const uint8_t gvec);

#endif /* !__ARCH_X86_IOMMU_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
