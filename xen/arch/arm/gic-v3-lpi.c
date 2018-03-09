/*
 * xen/arch/arm/gic-v3-lpi.c
 *
 * ARM GICv3 Locality-specific Peripheral Interrupts (LPI) support
 *
 * Copyright (C) 2016,2017 - ARM Ltd
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

#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/sizes.h>
#include <xen/warning.h>
#include <asm/atomic.h>
#include <asm/domain.h>
#include <asm/gic.h>
#include <asm/gic_v3_defs.h>
#include <asm/gic_v3_its.h>
#include <asm/io.h>
#include <asm/page.h>

/*
 * There could be a lot of LPIs on the host side, and they always go to
 * a guest. So having a struct irq_desc for each of them would be wasteful
 * and useless.
 * Instead just store enough information to find the right VCPU to inject
 * those LPIs into, which just requires the virtual LPI number.
 * To avoid a global lock on this data structure, this is using a lockless
 * approach relying on the architectural atomicity of native data types:
 * We read or write the "data" view of this union atomically, then can
 * access the broken-down fields in our local copy.
 */
union host_lpi {
    uint64_t data;
    struct {
        uint32_t virt_lpi;
        uint16_t dom_id;
        uint16_t pad;
    };
};

#define LPI_PROPTABLE_NEEDS_FLUSHING    (1U << 0)

/* Global state */
static struct {
    /* The global LPI property table, shared by all redistributors. */
    uint8_t *lpi_property;
    /*
     * A two-level table to lookup LPIs firing on the host and look up the
     * VCPU and virtual LPI number to inject into.
     */
    union host_lpi **host_lpis;
    /*
     * Number of physical LPIs the host supports. This is a property of
     * the GIC hardware. We depart from the habit of naming these things
     * "physical" in Xen, as the GICv3/4 spec uses the term "physical LPI"
     * in a different context to differentiate them from "virtual LPIs".
     */
    unsigned long int max_host_lpi_ids;
    /*
     * Protects allocation and deallocation of host LPIs and next_free_lpi,
     * but not the actual data stored in the host_lpi entry.
     */
    spinlock_t host_lpis_lock;
    uint32_t next_free_lpi;
    unsigned int flags;
} lpi_data;

struct lpi_redist_data {
    paddr_t             redist_addr;
    unsigned int        redist_id;
    void                *pending_table;
};

static DEFINE_PER_CPU(struct lpi_redist_data, lpi_redist);

#define MAX_NR_HOST_LPIS   (lpi_data.max_host_lpi_ids - LPI_OFFSET)
#define HOST_LPIS_PER_PAGE      (PAGE_SIZE / sizeof(union host_lpi))

static union host_lpi *gic_get_host_lpi(uint32_t plpi)
{
    union host_lpi *block;

    if ( !is_lpi(plpi) || plpi >= MAX_NR_HOST_LPIS + LPI_OFFSET )
        return NULL;

    ASSERT(plpi >= LPI_OFFSET);

    plpi -= LPI_OFFSET;

    block = lpi_data.host_lpis[plpi / HOST_LPIS_PER_PAGE];
    if ( !block )
        return NULL;

    /* Matches the write barrier in allocation code. */
    smp_rmb();

    return &block[plpi % HOST_LPIS_PER_PAGE];
}

/*
 * An ITS can refer to redistributors in two ways: either by an ID (possibly
 * the CPU number) or by its MMIO address. This is a hardware implementation
 * choice, so we have to cope with both approaches. The GICv3 code calculates
 * both values and calls this function to let the ITS store them when it's
 * later required to provide them. This is done in a per-CPU variable.
 */
void gicv3_set_redist_address(paddr_t address, unsigned int redist_id)
{
    this_cpu(lpi_redist).redist_addr = address;
    this_cpu(lpi_redist).redist_id = redist_id;
}

/*
 * Returns a redistributor's ID (either as an address or as an ID).
 * This must be (and is) called only after it has been setup by the above
 * function.
 */
uint64_t gicv3_get_redist_address(unsigned int cpu, bool use_pta)
{
    if ( use_pta )
        return per_cpu(lpi_redist, cpu).redist_addr & GENMASK(51, 16);
    else
        return per_cpu(lpi_redist, cpu).redist_id << 16;
}

void vgic_vcpu_inject_lpi(struct domain *d, unsigned int virq)
{
    /*
     * TODO: this assumes that the struct pending_irq stays valid all of
     * the time. We cannot properly protect this with the current locking
     * scheme, but the future per-IRQ lock will solve this problem.
     */
    struct pending_irq *p = irq_to_pending(d->vcpu[0], virq);
    unsigned int vcpu_id;

    if ( !p )
        return;

    vcpu_id = ACCESS_ONCE(p->lpi_vcpu_id);
    if ( vcpu_id >= d->max_vcpus )
          return;

    vgic_inject_irq(d, d->vcpu[vcpu_id], virq, true);
}

/*
 * Handle incoming LPIs, which are a bit special, because they are potentially
 * numerous and also only get injected into guests. Treat them specially here,
 * by just looking up their target vCPU and virtual LPI number and hand it
 * over to the injection function.
 * Please note that LPIs are edge-triggered only, also have no active state,
 * so spurious interrupts on the host side are no issue (we can just ignore
 * them).
 * Also a guest cannot expect that firing interrupts that haven't been
 * fully configured yet will reach the CPU, so we don't need to care about
 * this special case.
 */
void gicv3_do_LPI(unsigned int lpi)
{
    struct domain *d;
    union host_lpi *hlpip, hlpi;

    irq_enter();

    /* EOI the LPI already. */
    WRITE_SYSREG32(lpi, ICC_EOIR1_EL1);

    /* Find out if a guest mapped something to this physical LPI. */
    hlpip = gic_get_host_lpi(lpi);
    if ( !hlpip )
        goto out;

    hlpi.data = read_u64_atomic(&hlpip->data);

    /*
     * Unmapped events are marked with an invalid LPI ID. We can safely
     * ignore them, as they have no further state and no-one can expect
     * to see them if they have not been mapped.
     */
    if ( hlpi.virt_lpi == INVALID_LPI )
        goto out;

    d = rcu_lock_domain_by_id(hlpi.dom_id);
    if ( !d )
        goto out;

    /*
     * TODO: Investigate what to do here for potential interrupt storms.
     * As we keep all host LPIs enabled, for disabling LPIs we would need
     * to queue a ITS host command, which we avoid so far during a guest's
     * runtime. Also re-enabling would trigger a host command upon the
     * guest sending a command, which could be an attack vector for
     * hogging the host command queue.
     * See the thread around here for some background:
     * https://lists.xen.org/archives/html/xen-devel/2016-12/msg00003.html
     */
    vgic_vcpu_inject_lpi(d, hlpi.virt_lpi);

    rcu_unlock_domain(d);

out:
    irq_exit();
}

void gicv3_lpi_update_host_entry(uint32_t host_lpi, int domain_id,
                                 uint32_t virt_lpi)
{
    union host_lpi *hlpip, hlpi;

    ASSERT(host_lpi >= LPI_OFFSET);

    host_lpi -= LPI_OFFSET;

    hlpip = &lpi_data.host_lpis[host_lpi / HOST_LPIS_PER_PAGE][host_lpi % HOST_LPIS_PER_PAGE];

    hlpi.virt_lpi = virt_lpi;
    hlpi.dom_id = domain_id;

    write_u64_atomic(&hlpip->data, hlpi.data);
}

static int gicv3_lpi_allocate_pendtable(uint64_t *reg)
{
    uint64_t val;
    void *pendtable;

    if ( this_cpu(lpi_redist).pending_table )
        return -EBUSY;

    val  = GIC_BASER_CACHE_RaWaWb << GICR_PENDBASER_INNER_CACHEABILITY_SHIFT;
    val |= GIC_BASER_CACHE_SameAsInner << GICR_PENDBASER_OUTER_CACHEABILITY_SHIFT;
    val |= GIC_BASER_InnerShareable << GICR_PENDBASER_SHAREABILITY_SHIFT;

    /*
     * The pending table holds one bit per LPI and even covers bits for
     * interrupt IDs below 8192, so we allocate the full range.
     * The GICv3 imposes a 64KB alignment requirement, also requires
     * physically contiguous memory.
     */
    pendtable = _xzalloc(lpi_data.max_host_lpi_ids / 8, SZ_64K);
    if ( !pendtable )
        return -ENOMEM;

    /* Make sure the physical address can be encoded in the register. */
    if ( virt_to_maddr(pendtable) & ~GENMASK(51, 16) )
    {
        xfree(pendtable);
        return -ERANGE;
    }
    clean_and_invalidate_dcache_va_range(pendtable,
                                         lpi_data.max_host_lpi_ids / 8);

    this_cpu(lpi_redist).pending_table = pendtable;

    val |= GICR_PENDBASER_PTZ;

    val |= virt_to_maddr(pendtable);

    *reg = val;

    return 0;
}

/*
 * Tell a redistributor about the (shared) property table, allocating one
 * if not already done.
 */
static int gicv3_lpi_set_proptable(void __iomem * rdist_base)
{
    uint64_t reg;

    reg  = GIC_BASER_CACHE_RaWaWb << GICR_PROPBASER_INNER_CACHEABILITY_SHIFT;
    reg |= GIC_BASER_CACHE_SameAsInner << GICR_PROPBASER_OUTER_CACHEABILITY_SHIFT;
    reg |= GIC_BASER_InnerShareable << GICR_PROPBASER_SHAREABILITY_SHIFT;

    /*
     * The property table is shared across all redistributors, so allocate
     * this only once, but return the same value on subsequent calls.
     */
    if ( !lpi_data.lpi_property )
    {
        /* The property table holds one byte per LPI. */
        void *table = _xmalloc(lpi_data.max_host_lpi_ids, SZ_4K);

        if ( !table )
            return -ENOMEM;

        /* Make sure the physical address can be encoded in the register. */
        if ( (virt_to_maddr(table) & ~GENMASK(51, 12)) )
        {
            xfree(table);
            return -ERANGE;
        }
        memset(table, GIC_PRI_IRQ | LPI_PROP_RES1, MAX_NR_HOST_LPIS);
        clean_and_invalidate_dcache_va_range(table, MAX_NR_HOST_LPIS);
        lpi_data.lpi_property = table;
    }

    /* Encode the number of bits needed, minus one */
    reg |= fls(lpi_data.max_host_lpi_ids - 1) - 1;

    reg |= virt_to_maddr(lpi_data.lpi_property);

    writeq_relaxed(reg, rdist_base + GICR_PROPBASER);
    reg = readq_relaxed(rdist_base + GICR_PROPBASER);

    /* If we can't do shareable, we have to drop cacheability as well. */
    if ( !(reg & GICR_PROPBASER_SHAREABILITY_MASK) )
    {
        reg &= ~GICR_PROPBASER_INNER_CACHEABILITY_MASK;
        reg |= GIC_BASER_CACHE_nC << GICR_PROPBASER_INNER_CACHEABILITY_SHIFT;
    }

    /* Remember that we have to flush the property table if non-cacheable. */
    if ( (reg & GICR_PROPBASER_INNER_CACHEABILITY_MASK) <= GIC_BASER_CACHE_nC )
    {
        lpi_data.flags |= LPI_PROPTABLE_NEEDS_FLUSHING;
        /* Update the redistributors knowledge about the attributes. */
        writeq_relaxed(reg, rdist_base + GICR_PROPBASER);
    }

    return 0;
}

int gicv3_lpi_init_rdist(void __iomem * rdist_base)
{
    uint32_t reg;
    uint64_t table_reg;
    int ret;

    /* We don't support LPIs without an ITS. */
    if ( !gicv3_its_host_has_its() )
        return -ENODEV;

    /* Make sure LPIs are disabled before setting up the tables. */
    reg = readl_relaxed(rdist_base + GICR_CTLR);
    if ( reg & GICR_CTLR_ENABLE_LPIS )
        return -EBUSY;

    ret = gicv3_lpi_allocate_pendtable(&table_reg);
    if ( ret )
        return ret;
    writeq_relaxed(table_reg, rdist_base + GICR_PENDBASER);
    table_reg = readq_relaxed(rdist_base + GICR_PENDBASER);

    /* If the hardware reports non-shareable, drop cacheability as well. */
    if ( !(table_reg & GICR_PENDBASER_SHAREABILITY_MASK) )
    {
        table_reg &= ~GICR_PENDBASER_INNER_CACHEABILITY_MASK;
        table_reg |= GIC_BASER_CACHE_nC << GICR_PENDBASER_INNER_CACHEABILITY_SHIFT;

        writeq_relaxed(table_reg, rdist_base + GICR_PENDBASER);
    }

    return gicv3_lpi_set_proptable(rdist_base);
}

static unsigned int max_lpi_bits = 20;
integer_param("max_lpi_bits", max_lpi_bits);

/*
 * Allocate the 2nd level array for host LPIs. This one holds pointers
 * to the page with the actual "union host_lpi" entries. Our LPI limit
 * avoids excessive memory usage.
 */
int gicv3_lpi_init_host_lpis(unsigned int host_lpi_bits)
{
    unsigned int nr_lpi_ptrs;

    /* We rely on the data structure being atomically accessible. */
    BUILD_BUG_ON(sizeof(union host_lpi) > sizeof(unsigned long));

    /*
     * An implementation needs to support at least 14 bits of LPI IDs.
     * Tell the user about it, the actual number is reported below.
     */
    if ( max_lpi_bits < 14 || max_lpi_bits > 32 )
        printk(XENLOG_WARNING "WARNING: max_lpi_bits must be between 14 and 32, adjusting.\n");

    max_lpi_bits = max(max_lpi_bits, 14U);
    lpi_data.max_host_lpi_ids = BIT(min(host_lpi_bits, max_lpi_bits));

    /*
     * Warn if the number of LPIs are quite high, as the user might not want
     * to waste megabytes of memory for a mostly empty table.
     * It's very unlikely that we need more than 24 bits worth of LPIs.
     */
    if ( lpi_data.max_host_lpi_ids > BIT(24) )
        warning_add("Using high number of LPIs, limit memory usage with max_lpi_bits\n");

    spin_lock_init(&lpi_data.host_lpis_lock);
    lpi_data.next_free_lpi = 0;

    nr_lpi_ptrs = MAX_NR_HOST_LPIS / (PAGE_SIZE / sizeof(union host_lpi));
    lpi_data.host_lpis = xzalloc_array(union host_lpi *, nr_lpi_ptrs);
    if ( !lpi_data.host_lpis )
        return -ENOMEM;

    printk("GICv3: using at most %lu LPIs on the host.\n", MAX_NR_HOST_LPIS);

    return 0;
}

static int find_unused_host_lpi(uint32_t start, uint32_t *index)
{
    unsigned int chunk;
    uint32_t i = *index;

    ASSERT(spin_is_locked(&lpi_data.host_lpis_lock));

    for ( chunk = start;
          chunk < MAX_NR_HOST_LPIS / HOST_LPIS_PER_PAGE;
          chunk++ )
    {
        /* If we hit an unallocated chunk, use entry 0 in that one. */
        if ( !lpi_data.host_lpis[chunk] )
        {
            *index = 0;
            return chunk;
        }

        /* Find an unallocated entry in this chunk. */
        for ( ; i < HOST_LPIS_PER_PAGE; i += LPI_BLOCK )
        {
            if ( lpi_data.host_lpis[chunk][i].dom_id == DOMID_INVALID )
            {
                *index = i;
                return chunk;
            }
        }
        i = 0;
    }

    return -1;
}

/*
 * Allocate a block of 32 LPIs on the given host ITS for device "devid",
 * starting with "eventid". Put them into the respective ITT by issuing a
 * MAPTI command for each of them.
 */
int gicv3_allocate_host_lpi_block(struct domain *d, uint32_t *first_lpi)
{
    uint32_t lpi, lpi_idx;
    int chunk;
    int i;

    spin_lock(&lpi_data.host_lpis_lock);
    lpi_idx = lpi_data.next_free_lpi % HOST_LPIS_PER_PAGE;
    chunk = find_unused_host_lpi(lpi_data.next_free_lpi / HOST_LPIS_PER_PAGE,
                                 &lpi_idx);

    if ( chunk == - 1 )          /* rescan for a hole from the beginning */
    {
        lpi_idx = 0;
        chunk = find_unused_host_lpi(0, &lpi_idx);
        if ( chunk == -1 )
        {
            spin_unlock(&lpi_data.host_lpis_lock);
            return -ENOSPC;
        }
    }

    /* If we hit an unallocated chunk, we initialize it and use entry 0. */
    if ( !lpi_data.host_lpis[chunk] )
    {
        union host_lpi *new_chunk;

        /* TODO: NUMA locality for quicker IRQ path? */
        new_chunk = alloc_xenheap_page();
        if ( !new_chunk )
        {
            spin_unlock(&lpi_data.host_lpis_lock);
            return -ENOMEM;
        }

        for ( i = 0; i < HOST_LPIS_PER_PAGE; i += LPI_BLOCK )
            new_chunk[i].dom_id = DOMID_INVALID;

        /*
         * Make sure all slots are really marked empty before publishing the
         * new chunk.
         */
        smp_wmb();

        lpi_data.host_lpis[chunk] = new_chunk;
        lpi_idx = 0;
    }

    lpi = chunk * HOST_LPIS_PER_PAGE + lpi_idx;

    for ( i = 0; i < LPI_BLOCK; i++ )
    {
        union host_lpi hlpi;

        /*
         * Mark this host LPI as belonging to the domain, but don't assign
         * any virtual LPI or a VCPU yet.
         */
        hlpi.virt_lpi = INVALID_LPI;
        hlpi.dom_id = d->domain_id;
        write_u64_atomic(&lpi_data.host_lpis[chunk][lpi_idx + i].data,
                         hlpi.data);

        /*
         * Enable this host LPI, so we don't have to do this during the
         * guest's runtime.
         */
        lpi_data.lpi_property[lpi + i] |= LPI_PROP_ENABLED;
    }

    lpi_data.next_free_lpi = lpi + LPI_BLOCK;

    /*
     * We have allocated and initialized the host LPI entries, so it's safe
     * to drop the lock now. Access to the structures can be done concurrently
     * as it involves only an atomic uint64_t access.
     */
    spin_unlock(&lpi_data.host_lpis_lock);

    if ( lpi_data.flags & LPI_PROPTABLE_NEEDS_FLUSHING )
        clean_and_invalidate_dcache_va_range(&lpi_data.lpi_property[lpi],
                                             LPI_BLOCK);

    *first_lpi = lpi + LPI_OFFSET;

    return 0;
}

void gicv3_free_host_lpi_block(uint32_t first_lpi)
{
    union host_lpi *hlpi, empty_lpi = { .dom_id = DOMID_INVALID };
    int i;

    /* This should only be called with the beginning of a block. */
    ASSERT((first_lpi % LPI_BLOCK) == 0);

    hlpi = gic_get_host_lpi(first_lpi);
    if ( !hlpi )
        return;         /* Nothing to free here. */

    spin_lock(&lpi_data.host_lpis_lock);

    for ( i = 0; i < LPI_BLOCK; i++ )
        write_u64_atomic(&hlpi[i].data, empty_lpi.data);

    /*
     * Make sure the next allocation can reuse this block, as we do only
     * forward scanning when finding an unused block.
     */
    if ( lpi_data.next_free_lpi > first_lpi )
        lpi_data.next_free_lpi = first_lpi;

    spin_unlock(&lpi_data.host_lpis_lock);

    return;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
