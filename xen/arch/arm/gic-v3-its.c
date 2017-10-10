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

#include <xen/acpi.h>
#include <xen/lib.h>
#include <xen/delay.h>
#include <xen/iocap.h>
#include <xen/libfdt/libfdt.h>
#include <xen/mm.h>
#include <xen/rbtree.h>
#include <xen/sched.h>
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

/*
 * Describes a device which is using the ITS and is used by a guest.
 * Since device IDs are per ITS (in contrast to vLPIs, which are per
 * guest), we have to differentiate between different virtual ITSes.
 * We use the doorbell address here, since this is a nice architectural
 * property of MSIs in general and we can easily get to the base address
 * of the ITS and look that up.
 */
struct its_device {
    struct rb_node rbnode;
    struct host_its *hw_its;
    void *itt_addr;
    paddr_t guest_doorbell;             /* Identifies the virtual ITS */
    uint32_t host_devid;
    uint32_t guest_devid;
    uint32_t eventids;                  /* Number of event IDs (MSIs) */
    uint32_t *host_lpi_blocks;          /* Which LPIs are used on the host */
    struct pending_irq *pend_irqs;      /* One struct per event */
};

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

static int its_send_cmd_mapti(struct host_its *its,
                              uint32_t deviceid, uint32_t eventid,
                              uint32_t pintid, uint16_t icid)
{
    uint64_t cmd[4];

    cmd[0] = GITS_CMD_MAPTI | ((uint64_t)deviceid << 32);
    cmd[1] = eventid | ((uint64_t)pintid << 32);
    cmd[2] = icid;
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

static int its_send_cmd_mapd(struct host_its *its, uint32_t deviceid,
                             uint8_t size_bits, paddr_t itt_addr, bool valid)
{
    uint64_t cmd[4];

    if ( valid )
    {
        ASSERT(size_bits <= its->evid_bits);
        ASSERT(size_bits > 0);
        ASSERT(!(itt_addr & ~GENMASK(51, 8)));

        /* The number of events is encoded as "number of bits minus one". */
        size_bits--;
    }
    cmd[0] = GITS_CMD_MAPD | ((uint64_t)deviceid << 32);
    cmd[1] = size_bits;
    cmd[2] = itt_addr;
    if ( valid )
        cmd[2] |= GITS_VALID_BIT;
    cmd[3] = 0x00;

    return its_send_command(its, cmd);
}

static int its_send_cmd_inv(struct host_its *its,
                            uint32_t deviceid, uint32_t eventid)
{
    uint64_t cmd[4];

    cmd[0] = GITS_CMD_INV | ((uint64_t)deviceid << 32);
    cmd[1] = eventid;
    cmd[2] = 0x00;
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

    /* Now enable interrupt translation and command processing on that ITS. */
    reg = readl_relaxed(hw_its->its_base + GITS_CTLR);
    writel_relaxed(reg | GITS_CTLR_ENABLE, hw_its->its_base + GITS_CTLR);

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

/*
 * TODO: Investigate the interaction when a guest removes a device while
 * some LPIs are still in flight.
 */
static int remove_mapped_guest_device(struct its_device *dev)
{
    int ret = 0;
    unsigned int i;

    if ( dev->hw_its )
        /* MAPD also discards all events with this device ID. */
        ret = its_send_cmd_mapd(dev->hw_its, dev->host_devid, 0, 0, false);

    for ( i = 0; i < dev->eventids / LPI_BLOCK; i++ )
        gicv3_free_host_lpi_block(dev->host_lpi_blocks[i]);

    /* Make sure the MAPD command above is really executed. */
    if ( !ret )
        ret = gicv3_its_wait_commands(dev->hw_its);

    /* This should never happen, but just in case ... */
    if ( ret && printk_ratelimit() )
        printk(XENLOG_WARNING "Can't unmap host ITS device 0x%x\n",
               dev->host_devid);

    xfree(dev->itt_addr);
    xfree(dev->pend_irqs);
    xfree(dev->host_lpi_blocks);
    xfree(dev);

    return 0;
}

static struct host_its *gicv3_its_find_by_doorbell(paddr_t doorbell_address)
{
    struct host_its *hw_its;

    list_for_each_entry(hw_its, &host_its_list, entry)
    {
        if ( hw_its->addr + ITS_DOORBELL_OFFSET == doorbell_address )
            return hw_its;
    }

    return NULL;
}

static int compare_its_guest_devices(struct its_device *dev,
                                     paddr_t vdoorbell, uint32_t vdevid)
{
    if ( dev->guest_doorbell < vdoorbell )
        return -1;

    if ( dev->guest_doorbell > vdoorbell )
        return 1;

    if ( dev->guest_devid < vdevid )
        return -1;

    if ( dev->guest_devid > vdevid )
        return 1;

    return 0;
}

/*
 * On the host ITS @its, map @nr_events consecutive LPIs.
 * The mapping connects a device @devid and event @eventid pair to LPI @lpi,
 * increasing both @eventid and @lpi to cover the number of requested LPIs.
 */
static int gicv3_its_map_host_events(struct host_its *its,
                                     uint32_t devid, uint32_t eventid,
                                     uint32_t lpi, uint32_t nr_events)
{
    uint32_t i;
    int ret;

    for ( i = 0; i < nr_events; i++ )
    {
        /* For now we map every host LPI to host CPU 0 */
        ret = its_send_cmd_mapti(its, devid, eventid + i, lpi + i, 0);
        if ( ret )
            return ret;

        ret = its_send_cmd_inv(its, devid, eventid + i);
        if ( ret )
            return ret;
    }

    /* TODO: Consider using INVALL here. Didn't work on the model, though. */

    ret = its_send_cmd_sync(its, 0);
    if ( ret )
        return ret;

    return gicv3_its_wait_commands(its);
}

/*
 * Map a hardware device, identified by a certain host ITS and its device ID
 * to domain d, a guest ITS (identified by its doorbell address) and device ID.
 * Also provide the number of events (MSIs) needed for that device.
 * This does not check if this particular hardware device is already mapped
 * at another domain, it is expected that this would be done by the caller.
 */
int gicv3_its_map_guest_device(struct domain *d,
                               paddr_t host_doorbell, uint32_t host_devid,
                               paddr_t guest_doorbell, uint32_t guest_devid,
                               uint64_t nr_events, bool valid)
{
    void *itt_addr = NULL;
    struct host_its *hw_its;
    struct its_device *dev = NULL;
    struct rb_node **new = &d->arch.vgic.its_devices.rb_node, *parent = NULL;
    int i, ret = -ENOENT;      /* "i" must be signed to check for >= 0 below. */

    hw_its = gicv3_its_find_by_doorbell(host_doorbell);
    if ( !hw_its )
        return ret;

    /* Sanitise the provided hardware values against the host ITS. */
    if ( host_devid >= BIT(hw_its->devid_bits) )
        return -EINVAL;

    /*
     * The ITS requires the number of events to be a power of 2. We allocate
     * events and LPIs in chunks of LPI_BLOCK (=32), so make sure we
     * allocate at least that many.
     * TODO: Investigate if the number of events can be limited to smaller
     * values if the guest does not require that many.
     */
    nr_events = BIT(fls(nr_events - 1));
    if ( nr_events < LPI_BLOCK )
        nr_events = LPI_BLOCK;
    if ( nr_events >= BIT(hw_its->evid_bits) )
        return -EINVAL;

    /* check for already existing mappings */
    spin_lock(&d->arch.vgic.its_devices_lock);
    while ( *new )
    {
        struct its_device *temp;
        int cmp;

        temp = rb_entry(*new, struct its_device, rbnode);

        parent = *new;
        cmp = compare_its_guest_devices(temp, guest_doorbell, guest_devid);
        if ( !cmp )
        {
            if ( !valid )
                rb_erase(&temp->rbnode, &d->arch.vgic.its_devices);

            spin_unlock(&d->arch.vgic.its_devices_lock);

            if ( valid )
            {
                printk(XENLOG_G_WARNING "d%d tried to remap guest ITS device 0x%x to host device 0x%x\n",
                        d->domain_id, guest_devid, host_devid);
                return -EBUSY;
            }

            return remove_mapped_guest_device(temp);
        }

        if ( cmp > 0 )
            new = &((*new)->rb_left);
        else
            new = &((*new)->rb_right);
    }

    if ( !valid )
        goto out_unlock;

    ret = -ENOMEM;

    /* An Interrupt Translation Table needs to be 256-byte aligned. */
    itt_addr = _xzalloc(nr_events * hw_its->itte_size, 256);
    if ( !itt_addr )
        goto out_unlock;

    dev = xzalloc(struct its_device);
    if ( !dev )
        goto out_unlock;

    /*
     * Allocate the pending_irqs for each virtual LPI. They will be put
     * into the domain's radix tree upon the guest's MAPTI command.
     * Pre-allocating memory for each *possible* LPI would be using way
     * too much memory (they can be sparsely used by the guest), also
     * allocating them on demand requires memory allocation in the interrupt
     * injection code path, which is not really desired.
     * So we compromise here by pre-allocating memory for each possible event
     * up to the max specified by MAPD.
     * See the mailing list discussion for some background:
     * https://lists.xen.org/archives/html/xen-devel/2017-03/msg03645.html
     */
    dev->pend_irqs = xzalloc_array(struct pending_irq, nr_events);
    if ( !dev->pend_irqs )
        goto out_unlock;

    dev->host_lpi_blocks = xzalloc_array(uint32_t, nr_events);
    if ( !dev->host_lpi_blocks )
        goto out_unlock;

    ret = its_send_cmd_mapd(hw_its, host_devid, fls(nr_events - 1),
                            virt_to_maddr(itt_addr), true);
    if ( ret )
        goto out_unlock;

    dev->itt_addr = itt_addr;
    dev->hw_its = hw_its;
    dev->guest_doorbell = guest_doorbell;
    dev->guest_devid = guest_devid;
    dev->host_devid = host_devid;
    dev->eventids = nr_events;

    rb_link_node(&dev->rbnode, parent, new);
    rb_insert_color(&dev->rbnode, &d->arch.vgic.its_devices);

    spin_unlock(&d->arch.vgic.its_devices_lock);

    /*
     * Map all host LPIs within this device already. We can't afford to queue
     * any host ITS commands later on during the guest's runtime.
     */
    for ( i = 0; i < nr_events / LPI_BLOCK; i++ )
    {
        ret = gicv3_allocate_host_lpi_block(d, &dev->host_lpi_blocks[i]);
        if ( ret < 0 )
            break;

        ret = gicv3_its_map_host_events(hw_its, host_devid, i * LPI_BLOCK,
                                        dev->host_lpi_blocks[i], LPI_BLOCK);
        if ( ret < 0 )
            break;
    }

    if ( ret )
    {
        /* Clean up all allocated host LPI blocks. */
        for ( ; i >= 0; i-- )
        {
            if ( dev->host_lpi_blocks[i] )
                gicv3_free_host_lpi_block(dev->host_lpi_blocks[i]);
        }

        /*
         * Unmapping the device will discard all LPIs mapped so far.
         * We are already on the failing path, so no error checking to
         * not mask the original error value. This should never fail anyway.
         */
        its_send_cmd_mapd(hw_its, host_devid, 0, 0, false);

        goto out;
    }

    return 0;

out_unlock:
    spin_unlock(&d->arch.vgic.its_devices_lock);

out:
    if ( dev )
    {
        xfree(dev->pend_irqs);
        xfree(dev->host_lpi_blocks);
    }
    xfree(itt_addr);
    xfree(dev);

    return ret;
}

/* Must be called with the its_device_lock held. */
static struct its_device *get_its_device(struct domain *d, paddr_t vdoorbell,
                                         uint32_t vdevid)
{
    struct rb_node *node = d->arch.vgic.its_devices.rb_node;
    struct its_device *dev;

    ASSERT(spin_is_locked(&d->arch.vgic.its_devices_lock));

    while (node)
    {
        int cmp;

        dev = rb_entry(node, struct its_device, rbnode);
        cmp = compare_its_guest_devices(dev, vdoorbell, vdevid);

        if ( !cmp )
            return dev;

        if ( cmp > 0 )
            node = node->rb_left;
        else
            node = node->rb_right;
    }

    return NULL;
}

static struct pending_irq *get_event_pending_irq(struct domain *d,
                                                 paddr_t vdoorbell_address,
                                                 uint32_t vdevid,
                                                 uint32_t eventid,
                                                 uint32_t *host_lpi)
{
    struct its_device *dev;
    struct pending_irq *pirq = NULL;

    spin_lock(&d->arch.vgic.its_devices_lock);
    dev = get_its_device(d, vdoorbell_address, vdevid);
    if ( dev && eventid < dev->eventids )
    {
        pirq = &dev->pend_irqs[eventid];
        if ( host_lpi )
            *host_lpi = dev->host_lpi_blocks[eventid / LPI_BLOCK] +
                        (eventid % LPI_BLOCK);
    }
    spin_unlock(&d->arch.vgic.its_devices_lock);

    return pirq;
}

struct pending_irq *gicv3_its_get_event_pending_irq(struct domain *d,
                                                    paddr_t vdoorbell_address,
                                                    uint32_t vdevid,
                                                    uint32_t eventid)
{
    return get_event_pending_irq(d, vdoorbell_address, vdevid, eventid, NULL);
}

int gicv3_remove_guest_event(struct domain *d, paddr_t vdoorbell_address,
                             uint32_t vdevid, uint32_t eventid)
{
    uint32_t host_lpi = INVALID_LPI;

    if ( !get_event_pending_irq(d, vdoorbell_address, vdevid, eventid,
                                &host_lpi) )
        return -EINVAL;

    if ( host_lpi == INVALID_LPI )
        return -EINVAL;

    gicv3_lpi_update_host_entry(host_lpi, d->domain_id, INVALID_LPI);

    return 0;
}

/*
 * Connects the event ID for an already assigned device to the given VCPU/vLPI
 * pair. The corresponding physical LPI is already mapped on the host side
 * (when assigning the physical device to the guest), so we just connect the
 * target VCPU/vLPI pair to that interrupt to inject it properly if it fires.
 * Returns a pointer to the already allocated struct pending_irq that is
 * meant to be used by that event.
 */
struct pending_irq *gicv3_assign_guest_event(struct domain *d,
                                             paddr_t vdoorbell_address,
                                             uint32_t vdevid, uint32_t eventid,
                                             uint32_t virt_lpi)
{
    struct pending_irq *pirq;
    uint32_t host_lpi = INVALID_LPI;

    pirq = get_event_pending_irq(d, vdoorbell_address, vdevid, eventid,
                                 &host_lpi);

    if ( !pirq )
        return NULL;

    gicv3_lpi_update_host_entry(host_lpi, d->domain_id, virt_lpi);

    return pirq;
}

int gicv3_its_deny_access(const struct domain *d)
{
    int rc = 0;
    unsigned long mfn, nr;
    const struct host_its *its_data;

    list_for_each_entry( its_data, &host_its_list, entry )
    {
        mfn = paddr_to_pfn(its_data->addr);
        nr = PFN_UP(its_data->size);
        rc = iomem_deny_access(d, mfn, mfn + nr);
        if ( rc )
        {
            printk("iomem_deny_access failed for %lx:%lx \r\n", mfn, nr);
            break;
        }
    }

    return rc;
}

/*
 * Create the respective guest DT nodes from a list of host ITSes.
 * This copies the reg property, so the guest sees the ITS at the same address
 * as the host.
 */
int gicv3_its_make_hwdom_dt_nodes(const struct domain *d,
                                  const struct dt_device_node *gic,
                                  void *fdt)
{
    uint32_t len;
    int res;
    const void *prop = NULL;
    const struct dt_device_node *its = NULL;
    const struct host_its *its_data;

    if ( list_empty(&host_its_list) )
        return 0;

    /* The sub-nodes require the ranges property */
    prop = dt_get_property(gic, "ranges", &len);
    if ( !prop )
    {
        printk(XENLOG_ERR "Can't find ranges property for the gic node\n");
        return -FDT_ERR_XEN(ENOENT);
    }

    res = fdt_property(fdt, "ranges", prop, len);
    if ( res )
        return res;

    list_for_each_entry(its_data, &host_its_list, entry)
    {
        its = its_data->dt_node;

        res = fdt_begin_node(fdt, its->name);
        if ( res )
            return res;

        res = fdt_property_string(fdt, "compatible", "arm,gic-v3-its");
        if ( res )
            return res;

        res = fdt_property(fdt, "msi-controller", NULL, 0);
        if ( res )
            return res;

        if ( its->phandle )
        {
            res = fdt_property_cell(fdt, "phandle", its->phandle);
            if ( res )
                return res;
        }

        /* Use the same reg regions as the ITS node in host DTB. */
        prop = dt_get_property(its, "reg", &len);
        if ( !prop )
        {
            printk(XENLOG_ERR "GICv3: Can't find ITS reg property.\n");
            res = -FDT_ERR_XEN(ENOENT);
            return res;
        }

        res = fdt_property(fdt, "reg", prop, len);
        if ( res )
            return res;

        fdt_end_node(fdt);
    }

    return res;
}

/* Common function for adding to host_its_list */
static void add_to_host_its_list(paddr_t addr, paddr_t size,
                                 const struct dt_device_node *node)
{
    struct host_its *its_data;

    its_data = xzalloc(struct host_its);
    if ( !its_data )
        panic("GICv3: Cannot allocate memory for ITS frame");

    its_data->addr = addr;
    its_data->size = size;
    its_data->dt_node = node;

    printk("GICv3: Found ITS @0x%lx\n", addr);

    list_add_tail(&its_data->entry, &host_its_list);
}

/* Scan the DT for any ITS nodes and create a list of host ITSes out of it. */
void gicv3_its_dt_init(const struct dt_device_node *node)
{
    const struct dt_device_node *its = NULL;

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

        add_to_host_its_list(addr, size, its);
    }
}

#ifdef CONFIG_ACPI
static int gicv3_its_acpi_probe(struct acpi_subtable_header *header,
                                const unsigned long end)
{
    struct acpi_madt_generic_translator *its;

    its = (struct acpi_madt_generic_translator *)header;
    if ( BAD_MADT_ENTRY(its, end) )
        return -EINVAL;

    add_to_host_its_list(its->base_address, GICV3_ITS_SIZE, NULL);

    return 0;
}

void gicv3_its_acpi_init(void)
{
    /* Parse ITS information */
    acpi_table_parse_madt(ACPI_MADT_TYPE_GENERIC_TRANSLATOR,
                          gicv3_its_acpi_probe, 0);
}

unsigned long gicv3_its_make_hwdom_madt(const struct domain *d, void *base_ptr)
{
    unsigned int i;
    void *fw_its;
    struct acpi_madt_generic_translator *hwdom_its;

    hwdom_its = base_ptr;

    for ( i = 0; i < vgic_v3_its_count(d); i++ )
    {
        fw_its = acpi_table_get_entry_madt(ACPI_MADT_TYPE_GENERIC_TRANSLATOR,
                                           i);
        memcpy(hwdom_its, fw_its, sizeof(struct acpi_madt_generic_translator));
        hwdom_its++;
    }

    return sizeof(struct acpi_madt_generic_translator) * vgic_v3_its_count(d);
}
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
