#include <asm/hvm/vpt.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>

#define TMR_STS (1 << 0)
static void pmt_update_status(void *opaque)
{
   PMTState *s = opaque;
   s->pm1_status |= TMR_STS;

   /* TODO: When TMR_EN == 1, generate a SCI event */

   set_timer(&s->timer, NOW() + (1000000000ULL << 31) / FREQUENCE_PMTIMER);
}

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
        curr_gtime = hvm_get_guest_time(s->vcpu);
        s->pm1_timer += ((curr_gtime - s->last_gtime) * s->scale) >> 32;
        p->data = s->pm1_timer;
        s->last_gtime = curr_gtime;
        return 1;
    }
    return 0;
}

void pmtimer_init(struct vcpu *v, int base)
{
    PMTState *s = &v->domain->arch.hvm_domain.pl_time.vpmt;

    s->pm1_timer = 0;
    s->pm1_status = 0;
    s->scale = ((uint64_t)FREQUENCE_PMTIMER << 32) / ticks_per_sec(v);
    s->vcpu = v;

    init_timer(&s->timer, pmt_update_status, s, v->processor);
    /* ACPI supports a 32-bit power management timer */
    set_timer(&s->timer, NOW() + (1000000000ULL << 31) / FREQUENCE_PMTIMER);
    
    register_portio_handler(base, 4, handle_pmt_io);
}

void pmtimer_deinit(struct domain *d)
{
    PMTState *s = &d->arch.hvm_domain.pl_time.vpmt;

    kill_timer(&s->timer);
}
