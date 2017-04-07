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
#include <xen/sizes.h>
#include <xen/warning.h>
#include <asm/gic.h>
#include <asm/gic_v3_defs.h>
#include <asm/gic_v3_its.h>
#include <asm/io.h>
#include <asm/page.h>

#define LPI_PROPTABLE_NEEDS_FLUSHING    (1U << 0)

/* Global state */
static struct {
    /* The global LPI property table, shared by all redistributors. */
    uint8_t *lpi_property;
    /*
     * Number of physical LPIs the host supports. This is a property of
     * the GIC hardware. We depart from the habit of naming these things
     * "physical" in Xen, as the GICv3/4 spec uses the term "physical LPI"
     * in a different context to differentiate them from "virtual LPIs".
     */
    unsigned long int max_host_lpi_ids;
    unsigned int flags;
} lpi_data;

struct lpi_redist_data {
    paddr_t             redist_addr;
    unsigned int        redist_id;
    void                *pending_table;
};

static DEFINE_PER_CPU(struct lpi_redist_data, lpi_redist);

#define MAX_NR_HOST_LPIS   (lpi_data.max_host_lpi_ids - LPI_OFFSET)

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
        table_reg &= GICR_PENDBASER_SHAREABILITY_MASK;
        table_reg &= GICR_PENDBASER_INNER_CACHEABILITY_MASK;
        table_reg |= GIC_BASER_CACHE_nC << GICR_PENDBASER_INNER_CACHEABILITY_SHIFT;

        writeq_relaxed(table_reg, rdist_base + GICR_PENDBASER);
    }

    return gicv3_lpi_set_proptable(rdist_base);
}

static unsigned int max_lpi_bits = 20;
integer_param("max_lpi_bits", max_lpi_bits);

int gicv3_lpi_init_host_lpis(unsigned int host_lpi_bits)
{
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

    printk("GICv3: using at most %lu LPIs on the host.\n", MAX_NR_HOST_LPIS);

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
