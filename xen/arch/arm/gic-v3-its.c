/*
 * xen/arch/arm/gic-v3-its.c
 *
 * ARM GICv3 Interrupt Translation Service (ITS) support
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
#include <xen/delay.h>
#include <xen/mm.h>
#include <xen/sizes.h>
#include <asm/gic.h>
#include <asm/gic_v3_defs.h>
#include <asm/gic_v3_its.h>
#include <asm/io.h>
#include <asm/page.h>

#define ITS_CMD_QUEUE_SZ                SZ_1M

/*
 * No lock here, as this list gets only populated upon boot while scanning
 * firmware tables for all host ITSes, and only gets iterated afterwards.
 */
LIST_HEAD(host_its_list);

bool gicv3_its_host_has_its(void)
{
    return !list_empty(&host_its_list);
}

#define BUFPTR_MASK                     GENMASK(19, 5)
static int its_send_command(struct host_its *hw_its, const void *its_cmd)
{
    /*
     * The command queue should actually never become full, if it does anyway
     * and this situation is not resolved quickly, this points to a much
     * bigger problem, probably an hardware error.
     * So to cover the one-off case where we actually hit a full command
     * queue, we introduce a small grace period to not give up too quickly.
     * Given the usual multi-hundred MHz frequency the ITS usually runs with,
     * one millisecond (for a single command) seem to be more than enough.
     * But this value is rather arbitrarily chosen based on theoretical
     * considerations.
     */
    s_time_t deadline = NOW() + MILLISECS(1);
    uint64_t readp, writep;
    int ret = -EBUSY;

    /* No ITS commands from an interrupt handler (at the moment). */
    ASSERT(!in_irq());

    spin_lock(&hw_its->cmd_lock);

    do {
        readp = readq_relaxed(hw_its->its_base + GITS_CREADR) & BUFPTR_MASK;
        writep = readq_relaxed(hw_its->its_base + GITS_CWRITER) & BUFPTR_MASK;

        if ( ((writep + ITS_CMD_SIZE) % ITS_CMD_QUEUE_SZ) != readp )
        {
            ret = 0;
            break;
        }

        /*
         * If the command queue is full, wait for a bit in the hope it drains
         * before giving up.
         */
        spin_unlock(&hw_its->cmd_lock);
        cpu_relax();
        udelay(1);
        spin_lock(&hw_its->cmd_lock);
    } while ( NOW() <= deadline );

    if ( ret )
    {
        spin_unlock(&hw_its->cmd_lock);
        if ( printk_ratelimit() )
            printk(XENLOG_WARNING "host ITS: command queue full.\n");
        return ret;
    }

    memcpy(hw_its->cmd_buf + writep, its_cmd, ITS_CMD_SIZE);
    if ( hw_its->flags & HOST_ITS_FLUSH_CMD_QUEUE )
        clean_and_invalidate_dcache_va_range(hw_its->cmd_buf + writep,
                                             ITS_CMD_SIZE);
    else
        dsb(ishst);

    writep = (writep + ITS_CMD_SIZE) % ITS_CMD_QUEUE_SZ;
    writeq_relaxed(writep & BUFPTR_MASK, hw_its->its_base + GITS_CWRITER);

    spin_unlock(&hw_its->cmd_lock);

    return 0;
}

/* Wait for an ITS to finish processing all commands. */
static int gicv3_its_wait_commands(struct host_its *hw_its)
{
    /*
     * As there could be quite a number of commands in a queue, we will
     * wait a bit longer than the one millisecond for a single command above.
     * Again this value is based on theoretical considerations, actually the
     * command queue should drain much faster.
     */
    s_time_t deadline = NOW() + MILLISECS(100);
    uint64_t readp, writep;

    do {
        spin_lock(&hw_its->cmd_lock);
        readp = readq_relaxed(hw_its->its_base + GITS_CREADR) & BUFPTR_MASK;
        writep = readq_relaxed(hw_its->its_base + GITS_CWRITER) & BUFPTR_MASK;
        spin_unlock(&hw_its->cmd_lock);

        if ( readp == writep )
            return 0;

        cpu_relax();
        udelay(1);
    } while ( NOW() <= deadline );

    return -ETIMEDOUT;
}

static uint64_t encode_rdbase(struct host_its *hw_its, unsigned int cpu,
                              uint64_t reg)
{
    reg &= ~GENMASK(51, 16);

    reg |= gicv3_get_redist_address(cpu, hw_its->flags & HOST_ITS_USES_PTA);

    return reg;
}

static int its_send_cmd_sync(struct host_its *its, unsigned int cpu)
{
    uint64_t cmd[4];

    cmd[0] = GITS_CMD_SYNC;
    cmd[1] = 0x00;
    cmd[2] = encode_rdbase(its, cpu, 0x0);
    cmd[3] = 0x00;

    return its_send_command(its, cmd);
}

static int its_send_cmd_mapc(struct host_its *its, uint32_t collection_id,
                             unsigned int cpu)
{
    uint64_t cmd[4];

    cmd[0] = GITS_CMD_MAPC;
    cmd[1] = 0x00;
    cmd[2] = encode_rdbase(its, cpu, collection_id);
    cmd[2] |= GITS_VALID_BIT;
    cmd[3] = 0x00;

    return its_send_command(its, cmd);
}

/* Set up the (1:1) collection mapping for the given host CPU. */
int gicv3_its_setup_collection(unsigned int cpu)
{
    struct host_its *its;
    int ret;

    list_for_each_entry(its, &host_its_list, entry)
    {
        ret = its_send_cmd_mapc(its, cpu, cpu);
        if ( ret )
            return ret;

        ret = its_send_cmd_sync(its, cpu);
        if ( ret )
            return ret;

        ret = gicv3_its_wait_commands(its);
        if ( ret )
            return ret;
    }

    return 0;
}

#define BASER_ATTR_MASK                                           \
        ((0x3UL << GITS_BASER_SHAREABILITY_SHIFT)               | \
         (0x7UL << GITS_BASER_OUTER_CACHEABILITY_SHIFT)         | \
         (0x7UL << GITS_BASER_INNER_CACHEABILITY_SHIFT))
#define BASER_RO_MASK   (GENMASK(58, 56) | GENMASK(52, 48))

/* Check that the physical address can be encoded in the PROPBASER register. */
static bool check_baser_phys_addr(void *vaddr, unsigned int page_bits)
{
    paddr_t paddr = virt_to_maddr(vaddr);

    return (!(paddr & ~GENMASK(page_bits < 16 ? 47 : 51, page_bits)));
}

static uint64_t encode_baser_phys_addr(paddr_t addr, unsigned int page_bits)
{
    uint64_t ret = addr & GENMASK(47, page_bits);

    if ( page_bits < 16 )
        return ret;

    /* For 64K pages address bits 51-48 are encoded in bits 15-12. */
    return ret | ((addr & GENMASK(51, 48)) >> (48 - 12));
}

static void *its_map_cbaser(struct host_its *its)
{
    void __iomem *cbasereg = its->its_base + GITS_CBASER;
    uint64_t reg;
    void *buffer;

    reg  = GIC_BASER_InnerShareable << GITS_BASER_SHAREABILITY_SHIFT;
    reg |= GIC_BASER_CACHE_SameAsInner << GITS_BASER_OUTER_CACHEABILITY_SHIFT;
    reg |= GIC_BASER_CACHE_RaWaWb << GITS_BASER_INNER_CACHEABILITY_SHIFT;

    buffer = _xzalloc(ITS_CMD_QUEUE_SZ, SZ_64K);
    if ( !buffer )
        return NULL;

    if ( virt_to_maddr(buffer) & ~GENMASK(51, 12) )
    {
        xfree(buffer);
        return NULL;
    }

    reg |= GITS_VALID_BIT | virt_to_maddr(buffer);
    reg |= ((ITS_CMD_QUEUE_SZ / SZ_4K) - 1) & GITS_CBASER_SIZE_MASK;
    writeq_relaxed(reg, cbasereg);
    reg = readq_relaxed(cbasereg);

    /* If the ITS dropped shareability, drop cacheability as well. */
    if ( (reg & GITS_BASER_SHAREABILITY_MASK) == 0 )
    {
        reg &= ~GITS_BASER_INNER_CACHEABILITY_MASK;
        writeq_relaxed(reg, cbasereg);
    }

    /*
     * If the command queue memory is mapped as uncached, we need to flush
     * it on every access.
     */
    if ( !(reg & GITS_BASER_INNER_CACHEABILITY_MASK) )
    {
        its->flags |= HOST_ITS_FLUSH_CMD_QUEUE;
        printk(XENLOG_WARNING "using non-cacheable ITS command queue\n");
    }

    return buffer;
}

/* The ITS BASE registers work with page sizes of 4K, 16K or 64K. */
#define BASER_PAGE_BITS(sz) ((sz) * 2 + 12)

static int its_map_baser(void __iomem *basereg, uint64_t regc,
                         unsigned int nr_items)
{
    uint64_t attr, reg;
    unsigned int entry_size = GITS_BASER_ENTRY_SIZE(regc);
    unsigned int pagesz = 2;    /* try 64K pages first, then go down. */
    unsigned int table_size;
    void *buffer;

    attr  = GIC_BASER_InnerShareable << GITS_BASER_SHAREABILITY_SHIFT;
    attr |= GIC_BASER_CACHE_SameAsInner << GITS_BASER_OUTER_CACHEABILITY_SHIFT;
    attr |= GIC_BASER_CACHE_RaWaWb << GITS_BASER_INNER_CACHEABILITY_SHIFT;

    /*
     * Setup the BASE register with the attributes that we like. Then read
     * it back and see what sticks (page size, cacheability and shareability
     * attributes), retrying if necessary.
     */
retry:
    table_size = ROUNDUP(nr_items * entry_size, BIT(BASER_PAGE_BITS(pagesz)));
    /* The BASE registers support at most 256 pages. */
    table_size = min(table_size, 256U << BASER_PAGE_BITS(pagesz));

    buffer = _xzalloc(table_size, BIT(BASER_PAGE_BITS(pagesz)));
    if ( !buffer )
        return -ENOMEM;

    if ( !check_baser_phys_addr(buffer, BASER_PAGE_BITS(pagesz)) )
    {
        xfree(buffer);
        return -ERANGE;
    }

    reg  = attr;
    reg |= (pagesz << GITS_BASER_PAGE_SIZE_SHIFT);
    reg |= (table_size >> BASER_PAGE_BITS(pagesz)) - 1;
    reg |= regc & BASER_RO_MASK;
    reg |= GITS_VALID_BIT;
    reg |= encode_baser_phys_addr(virt_to_maddr(buffer),
                                  BASER_PAGE_BITS(pagesz));

    writeq_relaxed(reg, basereg);
    regc = readq_relaxed(basereg);

    /* The host didn't like our attributes, just use what it returned. */
    if ( (regc & BASER_ATTR_MASK) != attr )
    {
        /* If we can't map it shareable, drop cacheability as well. */
        if ( (regc & GITS_BASER_SHAREABILITY_MASK) == GIC_BASER_NonShareable )
        {
            regc &= ~GITS_BASER_INNER_CACHEABILITY_MASK;
            writeq_relaxed(regc, basereg);
        }
        attr = regc & BASER_ATTR_MASK;
    }
    if ( (regc & GITS_BASER_INNER_CACHEABILITY_MASK) <= GIC_BASER_CACHE_nC )
        clean_and_invalidate_dcache_va_range(buffer, table_size);

    /* If the host accepted our page size, we are done. */
    if ( ((regc >> GITS_BASER_PAGE_SIZE_SHIFT) & 0x3UL) == pagesz )
        return 0;

    xfree(buffer);

    if ( pagesz-- > 0 )
        goto retry;

    /* None of the page sizes was accepted, give up */
    return -EINVAL;
}

/*
 * Before an ITS gets initialized, it should be in a quiescent state, where
 * all outstanding commands and transactions have finished.
 * So if the ITS is already enabled, turn it off and wait for all outstanding
 * operations to get processed by polling the QUIESCENT bit.
 */
static int gicv3_disable_its(struct host_its *hw_its)
{
    uint32_t reg;
    /*
     * As we also need to wait for the command queue to drain, we use the same
     * (arbitrary) timeout value as above for gicv3_its_wait_commands().
     */
    s_time_t deadline = NOW() + MILLISECS(100);

    reg = readl_relaxed(hw_its->its_base + GITS_CTLR);
    if ( !(reg & GITS_CTLR_ENABLE) && (reg & GITS_CTLR_QUIESCENT) )
        return 0;

    writel_relaxed(reg & ~GITS_CTLR_ENABLE, hw_its->its_base + GITS_CTLR);

    do {
        reg = readl_relaxed(hw_its->its_base + GITS_CTLR);
        if ( reg & GITS_CTLR_QUIESCENT )
            return 0;

        cpu_relax();
        udelay(1);
    } while ( NOW() <= deadline );

    printk(XENLOG_ERR "ITS@%lx not quiescent.\n", hw_its->addr);

    return -ETIMEDOUT;
}

static int gicv3_its_init_single_its(struct host_its *hw_its)
{
    uint64_t reg;
    int i, ret;

    hw_its->its_base = ioremap_nocache(hw_its->addr, hw_its->size);
    if ( !hw_its->its_base )
        return -ENOMEM;

    ret = gicv3_disable_its(hw_its);
    if ( ret )
        return ret;

    reg = readq_relaxed(hw_its->its_base + GITS_TYPER);
    hw_its->devid_bits = GITS_TYPER_DEVICE_ID_BITS(reg);
    hw_its->evid_bits = GITS_TYPER_EVENT_ID_BITS(reg);
    hw_its->itte_size = GITS_TYPER_ITT_SIZE(reg);
    if ( reg & GITS_TYPER_PTA )
        hw_its->flags |= HOST_ITS_USES_PTA;
    spin_lock_init(&hw_its->cmd_lock);

    for ( i = 0; i < GITS_BASER_NR_REGS; i++ )
    {
        void __iomem *basereg = hw_its->its_base + GITS_BASER0 + i * 8;
        unsigned int type;

        reg = readq_relaxed(basereg);
        type = (reg & GITS_BASER_TYPE_MASK) >> GITS_BASER_TYPE_SHIFT;
        switch ( type )
        {
        case GITS_BASER_TYPE_NONE:
            continue;
        case GITS_BASER_TYPE_DEVICE:
            ret = its_map_baser(basereg, reg, BIT(hw_its->devid_bits));
            if ( ret )
                return ret;
            break;
        case GITS_BASER_TYPE_COLLECTION:
            ret = its_map_baser(basereg, reg, num_possible_cpus());
            if ( ret )
                return ret;
            break;
        /* In case this is a GICv4, provide a (dummy) vPE table as well. */
        case GITS_BASER_TYPE_VCPU:
            ret = its_map_baser(basereg, reg, 1);
            if ( ret )
                return ret;
            break;
        default:
            continue;
        }
    }

    hw_its->cmd_buf = its_map_cbaser(hw_its);
    if ( !hw_its->cmd_buf )
        return -ENOMEM;
    writeq_relaxed(0, hw_its->its_base + GITS_CWRITER);

    return 0;
}

int gicv3_its_init(void)
{
    struct host_its *hw_its;
    int ret;

    list_for_each_entry(hw_its, &host_its_list, entry)
    {
        ret = gicv3_its_init_single_its(hw_its);
        if ( ret )
            return ret;
    }

    return 0;
}

/* Scan the DT for any ITS nodes and create a list of host ITSes out of it. */
void gicv3_its_dt_init(const struct dt_device_node *node)
{
    const struct dt_device_node *its = NULL;
    struct host_its *its_data;

    /*
     * Check for ITS MSI subnodes. If any, add the ITS register
     * frames to the ITS list.
     */
    dt_for_each_child_node(node, its)
    {
        uint64_t addr, size;

        if ( !dt_device_is_compatible(its, "arm,gic-v3-its") )
            continue;

        if ( dt_device_get_address(its, 0, &addr, &size) )
            panic("GICv3: Cannot find a valid ITS frame address");

        its_data = xzalloc(struct host_its);
        if ( !its_data )
            panic("GICv3: Cannot allocate memory for ITS frame");

        its_data->addr = addr;
        its_data->size = size;
        its_data->dt_node = its;

        printk("GICv3: Found ITS @0x%lx\n", addr);

        list_add_tail(&its_data->entry, &host_its_list);
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
