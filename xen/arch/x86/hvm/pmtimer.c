#include <asm/hvm/vpt.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>

static int handle_pmt_io(ioreq_t *p)
{
    struct vcpu *v = current;
    PMTState *s = &v->domain->arch.hvm_domain.pl_time.vpmt;
    uint64_t curr_gtime;

    if (p->size != 4 ||
        p->data_is_ptr ||
        p->type != IOREQ_TYPE_PIO){
        printk("HVM_PMT: wrong PM timer IO\n");
        return 1;
    }
    
    if (p->dir == 0) { /* write */
        /* PM_TMR_BLK is read-only */
        return 1;
    } else if (p->dir == 1) { /* read */
        /* Set the correct value in the timer, accounting for time
         * elapsed since the last time we did that. */
        curr_gtime = hvm_get_guest_time(s->vcpu);
        s->pm.timer += ((curr_gtime - s->last_gtime) * s->scale) >> 32;
        p->data = s->pm.timer;
        s->last_gtime = curr_gtime;
        return 1;
    }
    return 0;
}

static int pmtimer_save(struct domain *d, hvm_domain_context_t *h)
{
    PMTState *s = &d->arch.hvm_domain.pl_time.vpmt;
    uint32_t x;

    /* Update the counter to the guest's current time.  We always save
     * with the domain paused, so the saved time should be after the
     * last_gtime, but just in case, make sure we only go forwards */
    x = ((s->vcpu->arch.hvm_vcpu.guest_time - s->last_gtime) * s->scale) >> 32;
    if ( x < 1UL<<31 )
        s->pm.timer += x;
    return hvm_save_entry(PMTIMER, 0, h, &s->pm);
}

static int pmtimer_load(struct domain *d, hvm_domain_context_t *h)
{
    PMTState *s = &d->arch.hvm_domain.pl_time.vpmt;

    /* Reload the counter */
    if ( hvm_load_entry(PMTIMER, h, &s->pm) )
        return -EINVAL;

    /* Calculate future counter values from now. */
    s->last_gtime = hvm_get_guest_time(s->vcpu);
    
    return 0;
}

HVM_REGISTER_SAVE_RESTORE(PMTIMER, pmtimer_save, pmtimer_load, 
                          1, HVMSR_PER_DOM);


void pmtimer_init(struct vcpu *v, int base)
{
    PMTState *s = &v->domain->arch.hvm_domain.pl_time.vpmt;

    s->pm.timer = 0;
    s->scale = ((uint64_t)FREQUENCE_PMTIMER << 32) / ticks_per_sec(v);
    s->vcpu = v;

    /* Not implemented: we should set TMR_STS (bit 0 of PM1a_STS) every
     * time the timer's top bit flips, and generate an SCI if TMR_EN
     * (bit 0 of PM1a_EN) is set.  For now, those registers are in
     * qemu-dm, and we just calculate the timer's value on demand. */  

    register_portio_handler(v->domain, base, 4, handle_pmt_io);
}

