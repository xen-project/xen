/******************************************************************************
 * arch/x86/hpet.c
 * 
 * HPET management.
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/time.h>
#include <xen/timer.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include <xen/irq.h>
#include <asm/fixmap.h>
#include <asm/div64.h>
#include <asm/hpet.h>
#include <asm/msi.h>
#include <mach_apic.h>
#include <xen/cpuidle.h>

#define MAX_DELTA_NS MILLISECS(10*1000)
#define MIN_DELTA_NS MICROSECS(20)

#define MAX_HPET_NUM 32

#define HPET_EVT_USED_BIT    0
#define HPET_EVT_USED       (1 << HPET_EVT_USED_BIT)
#define HPET_EVT_DISABLE_BIT 1
#define HPET_EVT_DISABLE    (1 << HPET_EVT_DISABLE_BIT)

struct hpet_event_channel
{
    unsigned long mult;
    int           shift;
    s_time_t      next_event;
    cpumask_t     cpumask;
    spinlock_t    lock;
    void          (*event_handler)(struct hpet_event_channel *);

    unsigned int idx;   /* physical channel idx */
    int cpu;            /* msi target */
    int irq;            /* msi irq */
    unsigned int flags; /* HPET_EVT_x */
} __cacheline_aligned;
static struct hpet_event_channel legacy_hpet_event;
static struct hpet_event_channel hpet_events[MAX_HPET_NUM] = 
    { [0 ... MAX_HPET_NUM-1].irq = -1 };
static unsigned int num_hpets_used; /* msi hpet channels used for broadcast */

DEFINE_PER_CPU(struct hpet_event_channel *, cpu_bc_channel);

static int *irq_channel;

#define irq_to_channel(irq)   irq_channel[irq]

unsigned long hpet_address;

/*
 * force_hpet_broadcast: by default legacy hpet broadcast will be stopped
 * if RTC interrupts are enabled. Enable this option if want to always enable
 * legacy hpet broadcast for deep C state
 */
int force_hpet_broadcast;
boolean_param("hpetbroadcast", force_hpet_broadcast);

/*
 * Calculate a multiplication factor for scaled math, which is used to convert
 * nanoseconds based values to clock ticks:
 *
 * clock_ticks = (nanoseconds * factor) >> shift.
 *
 * div_sc is the rearranged equation to calculate a factor from a given clock
 * ticks / nanoseconds ratio:
 *
 * factor = (clock_ticks << shift) / nanoseconds
 */
static inline unsigned long div_sc(unsigned long ticks, unsigned long nsec,
                                   int shift)
{
    uint64_t tmp = ((uint64_t)ticks) << shift;

    do_div(tmp, nsec);
    return (unsigned long) tmp;
}

/*
 * Convert nanoseconds based values to clock ticks:
 *
 * clock_ticks = (nanoseconds * factor) >> shift.
 */
static inline unsigned long ns2ticks(unsigned long nsec, int shift,
                                     unsigned long factor)
{
    uint64_t tmp = ((uint64_t)nsec * factor) >> shift;

    return (unsigned long) tmp;
}

static int hpet_next_event(unsigned long delta, int timer)
{
    uint32_t cnt, cmp;
    unsigned long flags;

    local_irq_save(flags);
    cnt = hpet_read32(HPET_COUNTER);
    cmp = cnt + delta;
    hpet_write32(cmp, HPET_Tn_CMP(timer));
    cmp = hpet_read32(HPET_COUNTER);
    local_irq_restore(flags);

    /* Are we within two ticks of the deadline passing? Then we may miss. */
    return ((cmp + 2 - cnt) > delta) ? -ETIME : 0;
}

static int reprogram_hpet_evt_channel(
    struct hpet_event_channel *ch,
    s_time_t expire, s_time_t now, int force)
{
    int64_t delta;
    int ret;

    if ( (ch->flags & HPET_EVT_DISABLE) || (expire == 0) )
        return 0;

    if ( unlikely(expire < 0) )
    {
        printk(KERN_DEBUG "reprogram: expire <= 0\n");
        return -ETIME;
    }

    delta = expire - now;
    if ( (delta <= 0) && !force )
        return -ETIME;

    ch->next_event = expire;

    if ( expire == STIME_MAX )
    {
        /* We assume it will take a long time for the timer to wrap. */
        hpet_write32(0, HPET_Tn_CMP(ch->idx));
        return 0;
    }

    delta = min_t(int64_t, delta, MAX_DELTA_NS);
    delta = max_t(int64_t, delta, MIN_DELTA_NS);
    delta = ns2ticks(delta, ch->shift, ch->mult);

    ret = hpet_next_event(delta, ch->idx);
    while ( ret && force )
    {
        delta += delta;
        ret = hpet_next_event(delta, ch->idx);
    }

    return ret;
}

static int evt_do_broadcast(cpumask_t mask)
{
    int ret = 0, cpu = smp_processor_id();

    if ( cpu_isset(cpu, mask) )
    {
        cpu_clear(cpu, mask);
        raise_softirq(TIMER_SOFTIRQ);
        ret = 1;
    }

    cpuidle_wakeup_mwait(&mask);

    if ( !cpus_empty(mask) )
    {
       cpumask_raise_softirq(mask, TIMER_SOFTIRQ);
       ret = 1;
    }
    return ret;
}

static void handle_hpet_broadcast(struct hpet_event_channel *ch)
{
    cpumask_t mask;
    s_time_t now, next_event;
    int cpu;

    spin_lock_irq(&ch->lock);

again:
    ch->next_event = STIME_MAX;

    spin_unlock_irq(&ch->lock);

    next_event = STIME_MAX;
    mask = (cpumask_t)CPU_MASK_NONE;
    now = NOW();

    /* find all expired events */
    for_each_cpu_mask(cpu, ch->cpumask)
    {
        spin_lock_irq(&ch->lock);

        if ( cpumask_test_cpu(cpu, ch->cpumask) )
        {
            if ( per_cpu(timer_deadline_start, cpu) <= now )
                cpu_set(cpu, mask);
            else if ( per_cpu(timer_deadline_end, cpu) < next_event )
                next_event = per_cpu(timer_deadline_end, cpu);
        }

        spin_unlock_irq(&ch->lock);
    }

    /* wakeup the cpus which have an expired event. */
    evt_do_broadcast(mask);

    if ( next_event != STIME_MAX )
    {
        spin_lock_irq(&ch->lock);

        if ( next_event < ch->next_event &&
             reprogram_hpet_evt_channel(ch, next_event, now, 0) )
            goto again;

        spin_unlock_irq(&ch->lock);
    }
}

static void hpet_interrupt_handler(int irq, void *data,
        struct cpu_user_regs *regs)
{
    struct hpet_event_channel *ch = (struct hpet_event_channel *)data;

    this_cpu(irq_count)--;

    if ( !ch->event_handler )
    {
        printk(XENLOG_WARNING "Spurious HPET timer interrupt on HPET timer %d\n", ch->idx);
        return;
    }

    ch->event_handler(ch);
}

static void hpet_msi_unmask(unsigned int irq)
{
    unsigned long cfg;
    int ch_idx = irq_to_channel(irq);
    struct hpet_event_channel *ch;

    BUG_ON(ch_idx < 0);
    ch = &hpet_events[ch_idx];

    cfg = hpet_read32(HPET_Tn_CFG(ch->idx));
    cfg |= HPET_TN_FSB;
    hpet_write32(cfg, HPET_Tn_CFG(ch->idx));
}

static void hpet_msi_mask(unsigned int irq)
{
    unsigned long cfg;
    int ch_idx = irq_to_channel(irq);
    struct hpet_event_channel *ch;

    BUG_ON(ch_idx < 0);
    ch = &hpet_events[ch_idx];

    cfg = hpet_read32(HPET_Tn_CFG(ch->idx));
    cfg &= ~HPET_TN_FSB;
    hpet_write32(cfg, HPET_Tn_CFG(ch->idx));
}

static void hpet_msi_write(unsigned int irq, struct msi_msg *msg)
{
    int ch_idx = irq_to_channel(irq);
    struct hpet_event_channel *ch;

    BUG_ON(ch_idx < 0);
    ch = &hpet_events[ch_idx];

    hpet_write32(msg->data, HPET_Tn_ROUTE(ch->idx));
    hpet_write32(msg->address_lo, HPET_Tn_ROUTE(ch->idx) + 4);
}

static void hpet_msi_read(unsigned int irq, struct msi_msg *msg)
{
    int ch_idx = irq_to_channel(irq);
    struct hpet_event_channel *ch;

    BUG_ON(ch_idx < 0);
    ch = &hpet_events[ch_idx];

    msg->data = hpet_read32(HPET_Tn_ROUTE(ch->idx));
    msg->address_lo = hpet_read32(HPET_Tn_ROUTE(ch->idx) + 4);
    msg->address_hi = 0;
}

static unsigned int hpet_msi_startup(unsigned int irq)
{
    hpet_msi_unmask(irq);
    return 0;
}

static void hpet_msi_shutdown(unsigned int irq)
{
    hpet_msi_mask(irq);
}

static void hpet_msi_ack(unsigned int irq)
{
    struct irq_desc *desc = irq_to_desc(irq);

    irq_complete_move(&desc);
    move_native_irq(irq);
    ack_APIC_irq();
}

static void hpet_msi_end(unsigned int irq)
{
}

static void hpet_msi_set_affinity(unsigned int irq, cpumask_t mask)
{
    struct msi_msg msg;
    unsigned int dest;
    struct irq_desc * desc = irq_to_desc(irq);
    struct irq_cfg *cfg= desc->chip_data;

    dest = set_desc_affinity(desc, mask);
    if (dest == BAD_APICID)
        return;

    hpet_msi_read(irq, &msg);
    msg.data &= ~MSI_DATA_VECTOR_MASK;
    msg.data |= MSI_DATA_VECTOR(cfg->vector);
    msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
    msg.address_lo |= MSI_ADDR_DEST_ID(dest);
    hpet_msi_write(irq, &msg);
}

/*
 * IRQ Chip for MSI HPET Devices,
 */
static hw_irq_controller hpet_msi_type = {
    .typename   = "HPET-MSI",
    .startup    = hpet_msi_startup,
    .shutdown   = hpet_msi_shutdown,
    .enable	    = hpet_msi_unmask,
    .disable    = hpet_msi_mask,
    .ack        = hpet_msi_ack,
    .end        = hpet_msi_end,
    .set_affinity   = hpet_msi_set_affinity,
};

static int hpet_setup_msi_irq(unsigned int irq)
{
    int ret;
    struct msi_msg msg;
    struct hpet_event_channel *ch = &hpet_events[irq_to_channel(irq)];

    irq_desc[irq].handler = &hpet_msi_type;
    ret = request_irq(irq, hpet_interrupt_handler,
                      0, "HPET", ch);
    if ( ret < 0 )
        return ret;

    msi_compose_msg(NULL, irq, &msg);
    hpet_msi_write(irq, &msg);

    return 0;
}

static int hpet_assign_irq(struct hpet_event_channel *ch)
{
    int irq = ch->irq;

    if ( irq < 0 )
    {
        if ( (irq = create_irq()) < 0 )
            return irq;

        irq_channel[irq] = ch - &hpet_events[0];
        ch->irq = irq;
    }

    /* hpet_setup_msi_irq should also be called for S3 resuming */
    if ( hpet_setup_msi_irq(irq) )
    {
        destroy_irq(irq);
        irq_channel[irq] = -1;
        ch->irq = -1;
        return -EINVAL;
    }

    return 0;
}

static int hpet_fsb_cap_lookup(void)
{
    unsigned int id;
    unsigned int num_chs, num_chs_used;
    int i;

    /* TODO. */
    if ( iommu_intremap )
    {
        printk(XENLOG_INFO "HPET's MSI mode hasn't been supported when "
            "Interrupt Remapping is enabled.\n");
        return 0;
    }

    id = hpet_read32(HPET_ID);

    num_chs = ((id & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT);
    num_chs++; /* Value read out starts from 0 */

    num_chs_used = 0;
    for ( i = 0; i < num_chs; i++ )
    {
        struct hpet_event_channel *ch = &hpet_events[num_chs_used];
        unsigned long cfg = hpet_read32(HPET_Tn_CFG(i));

        /* Only consider HPET timer with MSI support */
        if ( !(cfg & HPET_TN_FSB_CAP) )
            continue;

        ch->flags = 0;
        ch->idx = i;

        if ( hpet_assign_irq(ch) )
            continue;

        num_chs_used++;
    }

    printk(XENLOG_INFO
           "HPET: %d timers in total, %d timers will be used for broadcast\n",
           num_chs, num_chs_used);

    return num_chs_used;
}

static int next_channel;
static spinlock_t next_lock = SPIN_LOCK_UNLOCKED;

static struct hpet_event_channel *hpet_get_channel(int cpu)
{
    int i;
    int next;
    struct hpet_event_channel *ch;

    if ( num_hpets_used == 0 )
        return &legacy_hpet_event;

    spin_lock(&next_lock);
    next = next_channel = (next_channel + 1) % num_hpets_used;
    spin_unlock(&next_lock);

    /* try unused channel first */
    for ( i = next; i < next + num_hpets_used; i++ )
    {
        ch = &hpet_events[i % num_hpets_used];
        if ( !test_and_set_bit(HPET_EVT_USED_BIT, &ch->flags) )
        {
            ch->cpu = cpu;
            return ch;
        }
    }

    /* share a in-use channel */
    ch = &hpet_events[next];
    if ( !test_and_set_bit(HPET_EVT_USED_BIT, &ch->flags) )
        ch->cpu = cpu;

    return ch;
}

static void hpet_attach_channel(int cpu, struct hpet_event_channel *ch)
{
    ASSERT(spin_is_locked(&ch->lock));

    per_cpu(cpu_bc_channel, cpu) = ch;

    /* try to be the channel owner again while holding the lock */
    if ( !test_and_set_bit(HPET_EVT_USED_BIT, &ch->flags) )
        ch->cpu = cpu;

    if ( ch->cpu != cpu )
        return;

    /* set irq affinity */
    irq_desc[ch->irq].handler->
        set_affinity(ch->irq, cpumask_of_cpu(ch->cpu));
}

static void hpet_detach_channel(int cpu, struct hpet_event_channel *ch)
{
    ASSERT(spin_is_locked(&ch->lock));
    ASSERT(ch == per_cpu(cpu_bc_channel, cpu));

    per_cpu(cpu_bc_channel, cpu) = NULL;

    if ( cpu != ch->cpu )
        return;

    if ( cpus_empty(ch->cpumask) )
    {
        ch->cpu = -1;
        clear_bit(HPET_EVT_USED_BIT, &ch->flags);
        return;
    }

    ch->cpu = first_cpu(ch->cpumask);
    /* set irq affinity */
    irq_desc[ch->irq].handler->
        set_affinity(ch->irq, cpumask_of_cpu(ch->cpu));
}

#include <asm/mc146818rtc.h>

void (*pv_rtc_handler)(unsigned int port, uint8_t value);

static void handle_rtc_once(unsigned int port, uint8_t value)
{
    static int index;

    if ( port == 0x70 )
    {
        index = value;
        return;
    }

    if ( index != RTC_REG_B )
        return;
    
    /* RTC Reg B, contain PIE/AIE/UIE */
    if ( value & (RTC_PIE | RTC_AIE | RTC_UIE ) )
    {
        cpuidle_disable_deep_cstate();
        pv_rtc_handler = NULL;
    }
}

void hpet_broadcast_init(void)
{
    u64 hpet_rate;
    u32 hpet_id, cfg;
    int i;

    if ( irq_channel == NULL )
    {
        irq_channel = xmalloc_array(int, nr_irqs);
        BUG_ON(irq_channel == NULL);
        for ( i = 0; i < nr_irqs; i++ )
            irq_channel[i] = -1;
    }

    hpet_rate = hpet_setup();
    if ( hpet_rate == 0 )
        return;

    num_hpets_used = hpet_fsb_cap_lookup();
    if ( num_hpets_used > 0 )
    {
        /* Stop HPET legacy interrupts */
        cfg = hpet_read32(HPET_CFG);
        cfg &= ~HPET_CFG_LEGACY;
        hpet_write32(cfg, HPET_CFG);

        for ( i = 0; i < num_hpets_used; i++ )
        {
            /* set HPET Tn as oneshot */
            cfg = hpet_read32(HPET_Tn_CFG(hpet_events[i].idx));
            cfg &= ~HPET_TN_PERIODIC;
            cfg |= HPET_TN_ENABLE | HPET_TN_32BIT;
            hpet_write32(cfg, HPET_Tn_CFG(hpet_events[i].idx));
  
            hpet_events[i].mult = div_sc((unsigned long)hpet_rate,
                                         1000000000ul, 32);
            hpet_events[i].shift = 32;
            hpet_events[i].next_event = STIME_MAX;
            hpet_events[i].event_handler = handle_hpet_broadcast;
            spin_lock_init(&hpet_events[i].lock);
        }

        return;
    }

    if ( legacy_hpet_event.flags & HPET_EVT_DISABLE )
        return;

    hpet_id = hpet_read32(HPET_ID);
    if ( !(hpet_id & HPET_ID_LEGSUP) )
        return;

    /* Start HPET legacy interrupts */
    cfg = hpet_read32(HPET_CFG);
    cfg |= HPET_CFG_LEGACY;
    hpet_write32(cfg, HPET_CFG);

    /* set HPET T0 as oneshot */
    cfg = hpet_read32(HPET_T0_CFG);
    cfg &= ~HPET_TN_PERIODIC;
    cfg |= HPET_TN_ENABLE | HPET_TN_32BIT;
    hpet_write32(cfg, HPET_T0_CFG);

    /*
     * The period is a femto seconds value. We need to calculate the scaled
     * math multiplication factor for nanosecond to hpet tick conversion.
     */
    legacy_hpet_event.mult = div_sc((unsigned long)hpet_rate, 1000000000ul, 32);
    legacy_hpet_event.shift = 32;
    legacy_hpet_event.next_event = STIME_MAX;
    legacy_hpet_event.event_handler = handle_hpet_broadcast;
    legacy_hpet_event.idx = 0;
    legacy_hpet_event.flags = 0;
    spin_lock_init(&legacy_hpet_event.lock);

    if ( !force_hpet_broadcast )
        pv_rtc_handler = handle_rtc_once;
}

void hpet_disable_legacy_broadcast(void)
{
    u32 cfg;
    unsigned long flags;

    spin_lock_irqsave(&legacy_hpet_event.lock, flags);

    legacy_hpet_event.flags |= HPET_EVT_DISABLE;

    /* disable HPET T0 */
    cfg = hpet_read32(HPET_T0_CFG);
    cfg &= ~HPET_TN_ENABLE;
    hpet_write32(cfg, HPET_T0_CFG);

    /* Stop HPET legacy interrupts */
    cfg = hpet_read32(HPET_CFG);
    cfg &= ~HPET_CFG_LEGACY;
    hpet_write32(cfg, HPET_CFG);

    spin_unlock_irqrestore(&legacy_hpet_event.lock, flags);

    smp_send_event_check_mask(&cpu_online_map);
}

void hpet_broadcast_enter(void)
{
    int cpu = smp_processor_id();
    struct hpet_event_channel *ch = per_cpu(cpu_bc_channel, cpu);

    if ( this_cpu(timer_deadline_start) == 0 )
        return;

    if ( !ch )
        ch = hpet_get_channel(cpu);

    ASSERT(!local_irq_is_enabled());

    if ( ch != &legacy_hpet_event )
    {
        spin_lock(&ch->lock);
        hpet_attach_channel(cpu, ch);
        spin_unlock(&ch->lock);
    }

    /* Cancel any outstanding LAPIC timer event and disable interrupts. */
    reprogram_timer(0);
    disable_APIC_timer();

    spin_lock(&ch->lock);

    cpu_set(cpu, ch->cpumask);
    /* reprogram if current cpu expire time is nearer */
    if ( this_cpu(timer_deadline_end) < ch->next_event )
        reprogram_hpet_evt_channel(ch, this_cpu(timer_deadline_end), NOW(), 1);

    spin_unlock(&ch->lock);
}

void hpet_broadcast_exit(void)
{
    int cpu = smp_processor_id();
    struct hpet_event_channel *ch = per_cpu(cpu_bc_channel, cpu);

    if ( this_cpu(timer_deadline_start) == 0 )
        return;

    if ( !ch )
        ch = hpet_get_channel(cpu);

    /* Reprogram the deadline; trigger timer work now if it has passed. */
    enable_APIC_timer();
    if ( !reprogram_timer(this_cpu(timer_deadline_start)) )
        raise_softirq(TIMER_SOFTIRQ);

    spin_lock_irq(&ch->lock);

    cpu_clear(cpu, ch->cpumask);
    if ( cpus_empty(ch->cpumask) && ch->next_event != STIME_MAX )
        reprogram_hpet_evt_channel(ch, STIME_MAX, 0, 0);

    spin_unlock_irq(&ch->lock);

    if ( ch != &legacy_hpet_event )
    {
        spin_lock_irq(&ch->lock);
        hpet_detach_channel(cpu, ch);
        spin_unlock_irq(&ch->lock);
    }
}

int hpet_broadcast_is_available(void)
{
    return (legacy_hpet_event.event_handler == handle_hpet_broadcast
            || num_hpets_used > 0);
}

int hpet_legacy_irq_tick(void)
{
    this_cpu(irq_count)--;

    if ( !legacy_hpet_event.event_handler )
        return 0;
    legacy_hpet_event.event_handler(&legacy_hpet_event);
    return 1;
}

u64 hpet_setup(void)
{
    static u64 hpet_rate;
    static u32 system_reset_latch;
    u32 hpet_id, hpet_period, cfg;
    int i;

    if ( system_reset_latch == system_reset_counter )
        return hpet_rate;
    system_reset_latch = system_reset_counter;

    if ( hpet_address == 0 )
        return 0;

    set_fixmap_nocache(FIX_HPET_BASE, hpet_address);

    hpet_id = hpet_read32(HPET_ID);
    if ( (hpet_id & HPET_ID_REV) == 0 )
    {
        printk("BAD HPET revision id.\n");
        return 0;
    }

    /* Check for sane period (100ps <= period <= 100ns). */
    hpet_period = hpet_read32(HPET_PERIOD);
    if ( (hpet_period > 100000000) || (hpet_period < 100000) )
    {
        printk("BAD HPET period %u.\n", hpet_period);
        return 0;
    }

    cfg = hpet_read32(HPET_CFG);
    cfg &= ~(HPET_CFG_ENABLE | HPET_CFG_LEGACY);
    hpet_write32(cfg, HPET_CFG);

    for ( i = 0; i <= ((hpet_id >> 8) & 31); i++ )
    {
        cfg = hpet_read32(HPET_Tn_CFG(i));
        cfg &= ~HPET_TN_ENABLE;
        hpet_write32(cfg, HPET_Tn_CFG(i));
    }

    cfg = hpet_read32(HPET_CFG);
    cfg |= HPET_CFG_ENABLE;
    hpet_write32(cfg, HPET_CFG);

    hpet_rate = 1000000000000000ULL; /* 10^15 */
    (void)do_div(hpet_rate, hpet_period);

    return hpet_rate;
}
