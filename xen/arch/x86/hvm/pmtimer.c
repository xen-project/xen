/*
 * hvm/pmtimer.c: emulation of the ACPI PM timer 
 *
 * Copyright (c) 2007, XenSource inc.
 * Copyright (c) 2006, Intel Corporation.
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

#include <asm/hvm/vpt.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/acpi.h> /* for hvm_acpi_power_button prototype */
#include <public/hvm/params.h>

/* Slightly more readable port I/O addresses for the registers we intercept */
#define PM1a_STS_ADDR_V0 (ACPI_PM1A_EVT_BLK_ADDRESS_V0)
#define PM1a_EN_ADDR_V0  (ACPI_PM1A_EVT_BLK_ADDRESS_V0 + 2)
#define TMR_VAL_ADDR_V0  (ACPI_PM_TMR_BLK_ADDRESS_V0)
#define PM1a_STS_ADDR_V1 (ACPI_PM1A_EVT_BLK_ADDRESS_V1)
#define PM1a_EN_ADDR_V1  (ACPI_PM1A_EVT_BLK_ADDRESS_V1 + 2)
#define TMR_VAL_ADDR_V1  (ACPI_PM_TMR_BLK_ADDRESS_V1)

/* The interesting bits of the PM1a_STS register */
#define TMR_STS    (1 << 0)
#define GBL_STS    (1 << 5)
#define PWRBTN_STS (1 << 8)
#define SLPBTN_STS (1 << 9)

/* The same in PM1a_EN */
#define TMR_EN     (1 << 0)
#define GBL_EN     (1 << 5)
#define PWRBTN_EN  (1 << 8)
#define SLPBTN_EN  (1 << 9)

/* Mask of bits in PM1a_STS that can generate an SCI. */
#define SCI_MASK (TMR_STS|PWRBTN_STS|SLPBTN_STS|GBL_STS) 

/* SCI IRQ number (must match SCI_INT number in ACPI FADT in hvmloader) */
#define SCI_IRQ 9

/* We provide a 32-bit counter (must match the TMR_VAL_EXT bit in the FADT) */
#define TMR_VAL_MASK  (0xffffffff)
#define TMR_VAL_MSB   (0x80000000)

/* Dispatch SCIs based on the PM1a_STS and PM1a_EN registers */
static void pmt_update_sci(PMTState *s)
{
    struct hvm_hw_acpi *acpi = &s->vcpu->domain->arch.hvm_domain.acpi;

    ASSERT(spin_is_locked(&s->lock));

    if ( acpi->pm1a_en & acpi->pm1a_sts & SCI_MASK )
        hvm_isa_irq_assert(s->vcpu->domain, SCI_IRQ);
    else
        hvm_isa_irq_deassert(s->vcpu->domain, SCI_IRQ);
}

void hvm_acpi_power_button(struct domain *d)
{
    PMTState *s = &d->arch.hvm_domain.pl_time->vpmt;

    if ( !has_vpm(d) )
        return;

    spin_lock(&s->lock);
    d->arch.hvm_domain.acpi.pm1a_sts |= PWRBTN_STS;
    pmt_update_sci(s);
    spin_unlock(&s->lock);
}

void hvm_acpi_sleep_button(struct domain *d)
{
    PMTState *s = &d->arch.hvm_domain.pl_time->vpmt;

    if ( !has_vpm(d) )
        return;

    spin_lock(&s->lock);
    d->arch.hvm_domain.acpi.pm1a_sts |= PWRBTN_STS;
    pmt_update_sci(s);
    spin_unlock(&s->lock);
}

/* Set the correct value in the timer, accounting for time elapsed
 * since the last time we did that. */
static void pmt_update_time(PMTState *s)
{
    uint64_t curr_gtime, tmp;
    struct hvm_hw_acpi *acpi = &s->vcpu->domain->arch.hvm_domain.acpi;
    uint32_t tmr_val = acpi->tmr_val, msb = tmr_val & TMR_VAL_MSB;
    
    ASSERT(spin_is_locked(&s->lock));

    /* Update the timer */
    curr_gtime = hvm_get_guest_time(s->vcpu);
    tmp = ((curr_gtime - s->last_gtime) * s->scale) + s->not_accounted;
    s->not_accounted = (uint32_t)tmp;
    tmr_val += tmp >> 32;
    tmr_val &= TMR_VAL_MASK;
    s->last_gtime = curr_gtime;

    /* Update timer value atomically wrt lock-free reads in handle_pmt_io(). */
    write_atomic(&acpi->tmr_val, tmr_val);

    /* If the counter's MSB has changed, set the status bit */
    if ( (tmr_val & TMR_VAL_MSB) != msb )
    {
        acpi->pm1a_sts |= TMR_STS;
        pmt_update_sci(s);
    }
}

/* This function should be called soon after each time the MSB of the
 * pmtimer register rolls over, to make sure we update the status
 * registers and SCI at least once per rollover */
static void pmt_timer_callback(void *opaque)
{
    PMTState *s = opaque;
    uint32_t pmt_cycles_until_flip;
    uint64_t time_until_flip;

    spin_lock(&s->lock);

    /* Recalculate the timer and make sure we get an SCI if we need one */
    pmt_update_time(s);

    /* How close are we to the next MSB flip? */
    pmt_cycles_until_flip = TMR_VAL_MSB -
        (s->vcpu->domain->arch.hvm_domain.acpi.tmr_val & (TMR_VAL_MSB - 1));

    /* Overall time between MSB flips */
    time_until_flip = (1000000000ULL << 23) / FREQUENCE_PMTIMER;

    /* Reduced appropriately */
    time_until_flip = (time_until_flip * pmt_cycles_until_flip) >> 23;

    /* Wake up again near the next bit-flip */
    set_timer(&s->timer, NOW() + time_until_flip + MILLISECS(1));

    spin_unlock(&s->lock);
}

/* Handle port I/O to the PM1a_STS and PM1a_EN registers */
static int handle_evt_io(
    int dir, unsigned int port, unsigned int bytes, uint32_t *val)
{
    struct vcpu *v = current;
    struct hvm_hw_acpi *acpi = &v->domain->arch.hvm_domain.acpi;
    PMTState *s = &v->domain->arch.hvm_domain.pl_time->vpmt;
    uint32_t addr, data, byte;
    int i;

    addr = port -
        ((v->domain->arch.hvm_domain.params[
            HVM_PARAM_ACPI_IOPORTS_LOCATION] == 0) ?
         PM1a_STS_ADDR_V0 : PM1a_STS_ADDR_V1);

    spin_lock(&s->lock);

    if ( dir == IOREQ_WRITE )
    {
        /* Handle this I/O one byte at a time */
        for ( i = bytes, data = *val;
              i > 0;
              i--, addr++, data >>= 8 )
        {
            byte = data & 0xff;
            switch ( addr )
            {
                /* PM1a_STS register bits are write-to-clear */
            case 0 /* PM1a_STS_ADDR */:
                acpi->pm1a_sts &= ~byte;
                break;
            case 1 /* PM1a_STS_ADDR + 1 */:
                acpi->pm1a_sts &= ~(byte << 8);
                break;
            case 2 /* PM1a_EN_ADDR */:
                acpi->pm1a_en = (acpi->pm1a_en & 0xff00) | byte;
                break;
            case 3 /* PM1a_EN_ADDR + 1 */:
                acpi->pm1a_en = (acpi->pm1a_en & 0xff) | (byte << 8);
                break;
            default:
                gdprintk(XENLOG_WARNING, 
                         "Bad ACPI PM register write: %x bytes (%x) at %x\n", 
                         bytes, *val, port);
            }
        }
        /* Fix up the SCI state to match the new register state */
        pmt_update_sci(s);
    }
    else /* p->dir == IOREQ_READ */
    {
        data = acpi->pm1a_sts | ((uint32_t)acpi->pm1a_en << 16);
        data >>= 8 * addr;
        if ( bytes == 1 ) data &= 0xff;
        else if ( bytes == 2 ) data &= 0xffff;
        *val = data;
    }

    spin_unlock(&s->lock);

    return X86EMUL_OKAY;
}


/* Handle port I/O to the TMR_VAL register */
static int handle_pmt_io(
    int dir, unsigned int port, unsigned int bytes, uint32_t *val)
{
    struct vcpu *v = current;
    struct hvm_hw_acpi *acpi = &v->domain->arch.hvm_domain.acpi;
    PMTState *s = &v->domain->arch.hvm_domain.pl_time->vpmt;

    if ( bytes != 4 || dir != IOREQ_READ )
    {
        gdprintk(XENLOG_WARNING, "HVM_PMT bad access\n");
        *val = ~0;
    }
    else if ( spin_trylock(&s->lock) )
    {
        /* We hold the lock: update timer value and return it. */
        pmt_update_time(s);
        *val = acpi->tmr_val;
        spin_unlock(&s->lock);
    }
    else
    {
        /*
         * Someone else is updating the timer: rather than do the work
         * again ourselves, wait for them to finish and then steal their
         * updated value with a lock-free atomic read.
         */
        spin_barrier(&s->lock);
        *val = read_atomic(&acpi->tmr_val);
    }

    return X86EMUL_OKAY;
}

static int acpi_save(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_hw_acpi *acpi = &d->arch.hvm_domain.acpi;
    PMTState *s = &d->arch.hvm_domain.pl_time->vpmt;
    uint32_t x, msb = acpi->tmr_val & TMR_VAL_MSB;
    int rc;

    if ( !has_vpm(d) )
        return 0;

    spin_lock(&s->lock);

    /*
     * Update the counter to the guest's current time.  Make sure it only
     * goes forwards.
     */
    x = (((s->vcpu->arch.hvm_vcpu.guest_time ?: hvm_get_guest_time(s->vcpu)) -
          s->last_gtime) * s->scale) >> 32;
    if ( x < 1UL<<31 )
        acpi->tmr_val += x;
    if ( (acpi->tmr_val & TMR_VAL_MSB) != msb )
        acpi->pm1a_sts |= TMR_STS;
    /* No point in setting the SCI here because we'll already have saved the 
     * IRQ and *PIC state; we'll fix it up when we restore the domain */
    rc = hvm_save_entry(PMTIMER, 0, h, acpi);

    spin_unlock(&s->lock);

    return rc;
}

static int acpi_load(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_hw_acpi *acpi = &d->arch.hvm_domain.acpi;
    PMTState *s = &d->arch.hvm_domain.pl_time->vpmt;

    if ( !has_vpm(d) )
        return -ENODEV;

    spin_lock(&s->lock);

    /* Reload the registers */
    if ( hvm_load_entry(PMTIMER, h, acpi) )
    {
        spin_unlock(&s->lock);
        return -EINVAL;
    }

    /* Calculate future counter values from now. */
    s->last_gtime = hvm_get_guest_time(s->vcpu);
    s->not_accounted = 0;

    /* Set the SCI state from the registers */ 
    pmt_update_sci(s);

    spin_unlock(&s->lock);
    
    return 0;
}

HVM_REGISTER_SAVE_RESTORE(PMTIMER, acpi_save, acpi_load,
                          1, HVMSR_PER_DOM);

int pmtimer_change_ioport(struct domain *d, unsigned int version)
{
    unsigned int old_version;

    if ( !has_vpm(d) )
        return -ENODEV;

    /* Check that version is changing. */
    old_version = d->arch.hvm_domain.params[HVM_PARAM_ACPI_IOPORTS_LOCATION];
    if ( version == old_version )
        return 0;

    /* Only allow changes between versions 0 and 1. */
    if ( (version ^ old_version) != 1 )
        return -EINVAL;

    if ( version == 1 )
    {
        /* Moving from version 0 to version 1. */
        relocate_portio_handler(d, TMR_VAL_ADDR_V0, TMR_VAL_ADDR_V1, 4);
        relocate_portio_handler(d, PM1a_STS_ADDR_V0, PM1a_STS_ADDR_V1, 4);
    }
    else
    {
        /* Moving from version 1 to version 0. */
        relocate_portio_handler(d, TMR_VAL_ADDR_V1, TMR_VAL_ADDR_V0, 4);
        relocate_portio_handler(d, PM1a_STS_ADDR_V1, PM1a_STS_ADDR_V0, 4);
    }

    return 0;
}

void pmtimer_init(struct vcpu *v)
{
    PMTState *s = &v->domain->arch.hvm_domain.pl_time->vpmt;

    if ( !has_vpm(v->domain) )
        return;

    spin_lock_init(&s->lock);

    s->scale = ((uint64_t)FREQUENCE_PMTIMER << 32) / SYSTEM_TIME_HZ;
    s->not_accounted = 0;
    s->vcpu = v;

    /* Intercept port I/O (need two handlers because PM1a_CNT is between
     * PM1a_EN and TMR_VAL and is handled by qemu) */
    register_portio_handler(v->domain, TMR_VAL_ADDR_V0, 4, handle_pmt_io);
    register_portio_handler(v->domain, PM1a_STS_ADDR_V0, 4, handle_evt_io);

    /* Set up callback to fire SCIs when the MSB of TMR_VAL changes */
    init_timer(&s->timer, pmt_timer_callback, s, v->processor);
    pmt_timer_callback(s);
}


void pmtimer_deinit(struct domain *d)
{
    PMTState *s = &d->arch.hvm_domain.pl_time->vpmt;

    if ( !has_vpm(d) )
        return;

    kill_timer(&s->timer);
}

void pmtimer_reset(struct domain *d)
{
    if ( !has_vpm(d) )
        return;

    /* Reset the counter. */
    d->arch.hvm_domain.acpi.tmr_val = 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
