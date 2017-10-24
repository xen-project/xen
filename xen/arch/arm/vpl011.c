/*
 * arch/arm/vpl011.c
 *
 * Virtual PL011 UART
 *
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

#define XEN_WANT_FLEX_CONSOLE_RING 1

/* We assume the PL011 default of "1/2 way" for the FIFO trigger level. */
#define SBSA_UART_FIFO_LEVEL (SBSA_UART_FIFO_SIZE / 2)

#include <xen/errno.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <public/domctl.h>
#include <public/io/console.h>
#include <asm/pl011-uart.h>
#include <asm/vgic-emul.h>
#include <asm/vpl011.h>

/*
 * Since pl011 registers are 32-bit registers, all registers
 * are handled similarly allowing 8-bit, 16-bit and 32-bit
 * accesses except 64-bit access.
 */
static bool vpl011_reg32_check_access(struct hsr_dabt dabt)
{
    return (dabt.size != DABT_DOUBLE_WORD);
}

static void vpl011_update_interrupt_status(struct domain *d)
{
    struct vpl011 *vpl011 = &d->arch.vpl011;
    uint32_t uartmis = vpl011->uartris & vpl011->uartimsc;

    /*
     * This function is expected to be called with the lock taken.
     */
    ASSERT(spin_is_locked(&vpl011->lock));

    /*
     * TODO: PL011 interrupts are level triggered which means
     * that interrupt needs to be set/clear instead of being
     * injected. However, currently vGIC does not handle level
     * triggered interrupts properly. This function needs to be
     * revisited once vGIC starts handling level triggered
     * interrupts.
     */

    /*
     * Raise an interrupt only if any additional interrupt
     * status bit has been set since the last time.
     */
    if ( uartmis & ~vpl011->shadow_uartmis )
        vgic_vcpu_inject_spi(d, GUEST_VPL011_SPI);

    vpl011->shadow_uartmis = uartmis;
}

static uint8_t vpl011_read_data(struct domain *d)
{
    unsigned long flags;
    uint8_t data = 0;
    struct vpl011 *vpl011 = &d->arch.vpl011;
    struct xencons_interface *intf = vpl011->ring_buf;
    XENCONS_RING_IDX in_cons, in_prod;

    VPL011_LOCK(d, flags);

    in_cons = intf->in_cons;
    in_prod = intf->in_prod;

    smp_rmb();

    /*
     * It is expected that there will be data in the ring buffer when this
     * function is called since the guest is expected to read the data register
     * only if the TXFE flag is not set.
     * If the guest still does read when TXFE bit is set then 0 will be returned.
     */
    if ( xencons_queued(in_prod, in_cons, sizeof(intf->in)) > 0 )
    {
        unsigned int fifo_level;

        data = intf->in[xencons_mask(in_cons, sizeof(intf->in))];
        in_cons += 1;
        smp_mb();
        intf->in_cons = in_cons;

        fifo_level = xencons_queued(in_prod, in_cons, sizeof(intf->in));

        /* If the FIFO is now empty, we clear the receive timeout interrupt. */
        if ( fifo_level == 0 )
        {
            vpl011->uartfr |= RXFE;
            vpl011->uartris &= ~RTI;
        }

        /* If the FIFO is more than half empty, we clear the RX interrupt. */
        if ( fifo_level < sizeof(intf->in) - SBSA_UART_FIFO_LEVEL )
            vpl011->uartris &= ~RXI;

        vpl011_update_interrupt_status(d);
    }
    else
        gprintk(XENLOG_ERR, "vpl011: Unexpected IN ring buffer empty\n");

    /*
     * We have consumed a character or the FIFO was empty, so clear the
     * "FIFO full" bit.
     */
    vpl011->uartfr &= ~RXFF;

    VPL011_UNLOCK(d, flags);

    /*
     * Send an event to console backend to indicate that data has been
     * read from the IN ring buffer.
     */
    notify_via_xen_event_channel(d, vpl011->evtchn);

    return data;
}

static void vpl011_update_tx_fifo_status(struct vpl011 *vpl011,
                                         unsigned int fifo_level)
{
    struct xencons_interface *intf = vpl011->ring_buf;
    unsigned int fifo_threshold = sizeof(intf->out) - SBSA_UART_FIFO_LEVEL;

    BUILD_BUG_ON(sizeof(intf->out) < SBSA_UART_FIFO_SIZE);

    /*
     * Set the TXI bit only when there is space for fifo_size/2 bytes which
     * is the trigger level for asserting/de-assterting the TX interrupt.
     */
    if ( fifo_level <= fifo_threshold )
        vpl011->uartris |= TXI;
    else
        vpl011->uartris &= ~TXI;
}

static void vpl011_write_data(struct domain *d, uint8_t data)
{
    unsigned long flags;
    struct vpl011 *vpl011 = &d->arch.vpl011;
    struct xencons_interface *intf = vpl011->ring_buf;
    XENCONS_RING_IDX out_cons, out_prod;

    VPL011_LOCK(d, flags);

    out_cons = intf->out_cons;
    out_prod = intf->out_prod;

    smp_mb();

    /*
     * It is expected that the ring is not full when this function is called
     * as the guest is expected to write to the data register only when the
     * TXFF flag is not set.
     * In case the guest does write even when the TXFF flag is set then the
     * data will be silently dropped.
     */
    if ( xencons_queued(out_prod, out_cons, sizeof(intf->out)) !=
         sizeof (intf->out) )
    {
        unsigned int fifo_level;

        intf->out[xencons_mask(out_prod, sizeof(intf->out))] = data;
        out_prod += 1;
        smp_wmb();
        intf->out_prod = out_prod;

        fifo_level = xencons_queued(out_prod, out_cons, sizeof(intf->out));

        if ( fifo_level == sizeof(intf->out) )
        {
            vpl011->uartfr |= TXFF;

            /*
             * This bit is set only when FIFO becomes full. This ensures that
             * the SBSA UART driver can write the early console data as fast as
             * possible, without waiting for the BUSY bit to get cleared before
             * writing each byte.
             */
            vpl011->uartfr |= BUSY;
        }

        vpl011_update_tx_fifo_status(vpl011, fifo_level);

        vpl011_update_interrupt_status(d);
    }
    else
        gprintk(XENLOG_ERR, "vpl011: Unexpected OUT ring buffer full\n");

    vpl011->uartfr &= ~TXFE;

    VPL011_UNLOCK(d, flags);

    /*
     * Send an event to console backend to indicate that there is
     * data in the OUT ring buffer.
     */
    notify_via_xen_event_channel(d, vpl011->evtchn);
}

static int vpl011_mmio_read(struct vcpu *v,
                            mmio_info_t *info,
                            register_t *r,
                            void *priv)
{
    struct hsr_dabt dabt = info->dabt;
    uint32_t vpl011_reg = (uint32_t)(info->gpa - GUEST_PL011_BASE);
    struct vpl011 *vpl011 = &v->domain->arch.vpl011;
    struct domain *d = v->domain;
    unsigned long flags;

    switch ( vpl011_reg )
    {
    case DR:
        if ( !vpl011_reg32_check_access(dabt) ) goto bad_width;

        *r = vreg_reg32_extract(vpl011_read_data(d), info);
        return 1;

    case RSR:
        if ( !vpl011_reg32_check_access(dabt) ) goto bad_width;

        /* It always returns 0 as there are no physical errors. */
        *r = 0;
        return 1;

    case FR:
        if ( !vpl011_reg32_check_access(dabt) ) goto bad_width;

        VPL011_LOCK(d, flags);
        *r = vreg_reg32_extract(vpl011->uartfr, info);
        VPL011_UNLOCK(d, flags);
        return 1;

    case RIS:
        if ( !vpl011_reg32_check_access(dabt) ) goto bad_width;

        VPL011_LOCK(d, flags);
        *r = vreg_reg32_extract(vpl011->uartris, info);
        VPL011_UNLOCK(d, flags);
        return 1;

    case MIS:
        if ( !vpl011_reg32_check_access(dabt) ) goto bad_width;

        VPL011_LOCK(d, flags);
        *r = vreg_reg32_extract(vpl011->uartris & vpl011->uartimsc,
                                info);
        VPL011_UNLOCK(d, flags);
        return 1;

    case IMSC:
        if ( !vpl011_reg32_check_access(dabt) ) goto bad_width;

        VPL011_LOCK(d, flags);
        *r = vreg_reg32_extract(vpl011->uartimsc, info);
        VPL011_UNLOCK(d, flags);
        return 1;

    case ICR:
        if ( !vpl011_reg32_check_access(dabt) ) goto bad_width;

        /* Only write is valid. */
        return 0;

    default:
        gprintk(XENLOG_ERR, "vpl011: unhandled read r%d offset %#08x\n",
                dabt.reg, vpl011_reg);
        return 0;
    }

    return 1;

bad_width:
    gprintk(XENLOG_ERR, "vpl011: bad read width %d r%d offset %#08x\n",
            dabt.size, dabt.reg, vpl011_reg);
    domain_crash_synchronous();
    return 0;

}

static int vpl011_mmio_write(struct vcpu *v,
                             mmio_info_t *info,
                             register_t r,
                             void *priv)
{
    struct hsr_dabt dabt = info->dabt;
    uint32_t vpl011_reg = (uint32_t)(info->gpa - GUEST_PL011_BASE);
    struct vpl011 *vpl011 = &v->domain->arch.vpl011;
    struct domain *d = v->domain;
    unsigned long flags;

    switch ( vpl011_reg )
    {
    case DR:
    {
        uint32_t data = 0;

        if ( !vpl011_reg32_check_access(dabt) ) goto bad_width;

        vreg_reg32_update(&data, r, info);
        data &= 0xFF;
        vpl011_write_data(v->domain, data);
        return 1;
    }

    case RSR: /* Nothing to clear. */
        if ( !vpl011_reg32_check_access(dabt) ) goto bad_width;

        return 1;

    case FR:
    case RIS:
    case MIS:
        goto write_ignore;

    case IMSC:
        if ( !vpl011_reg32_check_access(dabt) ) goto bad_width;

        VPL011_LOCK(d, flags);
        vreg_reg32_update(&vpl011->uartimsc, r, info);
        vpl011_update_interrupt_status(v->domain);
        VPL011_UNLOCK(d, flags);
        return 1;

    case ICR:
        if ( !vpl011_reg32_check_access(dabt) ) goto bad_width;

        VPL011_LOCK(d, flags);
        vreg_reg32_clearbits(&vpl011->uartris, r, info);
        vpl011_update_interrupt_status(d);
        VPL011_UNLOCK(d, flags);
        return 1;

    default:
        gprintk(XENLOG_ERR, "vpl011: unhandled write r%d offset %#08x\n",
                dabt.reg, vpl011_reg);
        return 0;
    }

write_ignore:
    return 1;

bad_width:
    gprintk(XENLOG_ERR, "vpl011: bad write width %d r%d offset %#08x\n",
            dabt.size, dabt.reg, vpl011_reg);
    domain_crash_synchronous();
    return 0;

}

static const struct mmio_handler_ops vpl011_mmio_handler = {
    .read = vpl011_mmio_read,
    .write = vpl011_mmio_write,
};

static void vpl011_data_avail(struct domain *d)
{
    unsigned long flags;
    struct vpl011 *vpl011 = &d->arch.vpl011;
    struct xencons_interface *intf = vpl011->ring_buf;
    XENCONS_RING_IDX in_cons, in_prod, out_cons, out_prod;
    XENCONS_RING_IDX in_fifo_level, out_fifo_level;

    VPL011_LOCK(d, flags);

    in_cons = intf->in_cons;
    in_prod = intf->in_prod;
    out_cons = intf->out_cons;
    out_prod = intf->out_prod;

    smp_rmb();

    in_fifo_level = xencons_queued(in_prod,
                                   in_cons,
                                   sizeof(intf->in));

    out_fifo_level = xencons_queued(out_prod,
                                    out_cons,
                                    sizeof(intf->out));

    /**** Update the UART RX state ****/

    /* Clear the FIFO_EMPTY bit if the FIFO holds at least one character. */
    if ( in_fifo_level > 0 )
        vpl011->uartfr &= ~RXFE;

    /* Set the FIFO_FULL bit if the Xen buffer is full. */
    if ( in_fifo_level == sizeof(intf->in) )
        vpl011->uartfr |= RXFF;

    /* Assert the RX interrupt if the FIFO is more than half way filled. */
    if ( in_fifo_level >= sizeof(intf->in) - SBSA_UART_FIFO_LEVEL )
        vpl011->uartris |= RXI;

    /*
     * If the input queue is not empty, we assert the receive timeout interrupt.
     * As we don't emulate any timing here, so we ignore the actual timeout
     * of 32 baud cycles.
     */
    if ( in_fifo_level > 0 )
        vpl011->uartris |= RTI;

    /**** Update the UART TX state ****/

    if ( out_fifo_level != sizeof(intf->out) )
    {
        vpl011->uartfr &= ~TXFF;

        /*
         * Clear the BUSY bit as soon as space becomes available
         * so that the SBSA UART driver can start writing more data
         * without any further delay.
         */
        vpl011->uartfr &= ~BUSY;

        vpl011_update_tx_fifo_status(vpl011, out_fifo_level);
    }

    vpl011_update_interrupt_status(d);

    if ( out_fifo_level == 0 )
        vpl011->uartfr |= TXFE;

    VPL011_UNLOCK(d, flags);
}

static void vpl011_notification(struct vcpu *v, unsigned int port)
{
    vpl011_data_avail(v->domain);
}

int domain_vpl011_init(struct domain *d, struct vpl011_init_info *info)
{
    int rc;
    struct vpl011 *vpl011 = &d->arch.vpl011;

    if ( vpl011->ring_buf )
        return -EINVAL;

    /* Map the guest PFN to Xen address space. */
    rc =  prepare_ring_for_helper(d,
                                  gfn_x(info->gfn),
                                  &vpl011->ring_page,
                                  &vpl011->ring_buf);
    if ( rc < 0 )
        goto out;

    rc = vgic_reserve_virq(d, GUEST_VPL011_SPI);
    if ( !rc )
    {
        rc = -EINVAL;
        goto out1;
    }

    rc = alloc_unbound_xen_event_channel(d, 0, info->console_domid,
                                         vpl011_notification);
    if ( rc < 0 )
        goto out2;

    vpl011->evtchn = info->evtchn = rc;

    spin_lock_init(&vpl011->lock);

    register_mmio_handler(d, &vpl011_mmio_handler,
                          GUEST_PL011_BASE, GUEST_PL011_SIZE, NULL);

    return 0;

out2:
    vgic_free_virq(d, GUEST_VPL011_SPI);

out1:
    destroy_ring_for_helper(&vpl011->ring_buf, vpl011->ring_page);

out:
    return rc;
}

void domain_vpl011_deinit(struct domain *d)
{
    struct vpl011 *vpl011 = &d->arch.vpl011;

    if ( !vpl011->ring_buf )
        return;

    free_xen_event_channel(d, vpl011->evtchn);
    destroy_ring_for_helper(&vpl011->ring_buf, vpl011->ring_page);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
