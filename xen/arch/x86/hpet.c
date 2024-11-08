/******************************************************************************
 * arch/x86/hpet.c
 *
 * HPET management.
 */

#include <xen/errno.h>
#include <xen/time.h>
#include <xen/timer.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include <xen/irq.h>
#include <xen/numa.h>
#include <xen/param.h>
#include <xen/sched.h>

#include <asm/apic.h>
#include <asm/fixmap.h>
#include <asm/div64.h>
#include <asm/hpet.h>
#include <asm/msi.h>
#include <xen/cpuidle.h>

#define MAX_DELTA_NS MILLISECS(10*1000)
#define MIN_DELTA_NS MICROSECS(20)

#define HPET_EVT_USED_BIT    0
#define HPET_EVT_USED       (1 << HPET_EVT_USED_BIT)
#define HPET_EVT_DISABLE_BIT 1
#define HPET_EVT_DISABLE    (1 << HPET_EVT_DISABLE_BIT)
#define HPET_EVT_LEGACY_BIT  2
#define HPET_EVT_LEGACY     (1 << HPET_EVT_LEGACY_BIT)

struct hpet_event_channel
{
    unsigned long mult;
    int           shift;
    s_time_t      next_event;
    cpumask_var_t cpumask;
    spinlock_t    lock;
    void          (*event_handler)(struct hpet_event_channel *ch);

    unsigned int idx;   /* physical channel idx */
    unsigned int cpu;   /* msi target */
    struct msi_desc msi;/* msi state */
    unsigned int flags; /* HPET_EVT_x */
} __cacheline_aligned;
static struct hpet_event_channel *__read_mostly hpet_events;

/* msi hpet channels used for broadcast */
static unsigned int __read_mostly num_hpets_used;

static DEFINE_PER_CPU(struct hpet_event_channel *, cpu_bc_channel);

unsigned long __initdata hpet_address;
int8_t __initdata opt_hpet_legacy_replacement = -1;
static bool __initdata opt_hpet = true;
u8 __initdata hpet_blockid;
u8 __initdata hpet_flags;

/*
 * force_hpet_broadcast: by default legacy hpet broadcast will be stopped
 * if RTC interrupts are enabled. Enable this option if want to always enable
 * legacy hpet broadcast for deep C state
 */
static bool __initdata force_hpet_broadcast;
boolean_param("hpetbroadcast", force_hpet_broadcast);

static int __init cf_check parse_hpet_param(const char *s)
{
    const char *ss;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_bool(s, ss)) >= 0 )
            opt_hpet = val;
        else if ( (val = parse_boolean("broadcast", s, ss)) >= 0 )
            force_hpet_broadcast = val;
        else if ( (val = parse_boolean("legacy-replacement", s, ss)) >= 0 )
            opt_hpet_legacy_replacement = val;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("hpet", parse_hpet_param);

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
    return ((uint64_t)ticks << shift) / nsec;
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

static void evt_do_broadcast(cpumask_t *mask)
{
    unsigned int cpu = smp_processor_id();

    if ( __cpumask_test_and_clear_cpu(cpu, mask) )
        raise_softirq(TIMER_SOFTIRQ);

    cpuidle_wakeup_mwait(mask);

    if ( !cpumask_empty(mask) )
       cpumask_raise_softirq(mask, TIMER_SOFTIRQ);
}

static void cf_check handle_hpet_broadcast(struct hpet_event_channel *ch)
{
    cpumask_t mask;
    s_time_t now, next_event;
    unsigned int cpu;
    unsigned long flags;

    spin_lock_irqsave(&ch->lock, flags);

again:
    ch->next_event = STIME_MAX;

    spin_unlock_irqrestore(&ch->lock, flags);

    next_event = STIME_MAX;
    cpumask_clear(&mask);
    now = NOW();

    /* find all expired events */
    for_each_cpu(cpu, ch->cpumask)
    {
        s_time_t deadline = ACCESS_ONCE(per_cpu(timer_deadline, cpu));

        if ( deadline <= now )
            __cpumask_set_cpu(cpu, &mask);
        else if ( deadline < next_event )
            next_event = deadline;
    }

    /* wakeup the cpus which have an expired event. */
    evt_do_broadcast(&mask);

    if ( next_event != STIME_MAX )
    {
        spin_lock_irqsave(&ch->lock, flags);

        if ( next_event < ch->next_event &&
             reprogram_hpet_evt_channel(ch, next_event, now, 0) )
            goto again;

        spin_unlock_irqrestore(&ch->lock, flags);
    }
}

static void cf_check hpet_interrupt_handler(int irq, void *data)
{
    struct hpet_event_channel *ch = data;

    this_cpu(irq_count)--;

    if ( !ch->event_handler )
    {
        printk(XENLOG_WARNING "Spurious HPET timer interrupt on HPET timer %d\n", ch->idx);
        return;
    }

    ch->event_handler(ch);
}

static void cf_check hpet_msi_unmask(struct irq_desc *desc)
{
    u32 cfg;
    struct hpet_event_channel *ch = desc->action->dev_id;

    cfg = hpet_read32(HPET_Tn_CFG(ch->idx));
    cfg |= HPET_TN_ENABLE;
    hpet_write32(cfg, HPET_Tn_CFG(ch->idx));
    ch->msi.msi_attrib.host_masked = 0;
}

static void cf_check hpet_msi_mask(struct irq_desc *desc)
{
    u32 cfg;
    struct hpet_event_channel *ch = desc->action->dev_id;

    cfg = hpet_read32(HPET_Tn_CFG(ch->idx));
    cfg &= ~HPET_TN_ENABLE;
    hpet_write32(cfg, HPET_Tn_CFG(ch->idx));
    ch->msi.msi_attrib.host_masked = 1;
}

static int hpet_msi_write(struct hpet_event_channel *ch, struct msi_msg *msg)
{
    ch->msi.msg = *msg;

    if ( iommu_intremap != iommu_intremap_off )
    {
        int rc = iommu_update_ire_from_msi(&ch->msi, msg);

        if ( rc )
            return rc;
    }

    hpet_write32(msg->data, HPET_Tn_ROUTE(ch->idx));
    hpet_write32(msg->address_lo, HPET_Tn_ROUTE(ch->idx) + 4);

    return 0;
}

static unsigned int cf_check hpet_msi_startup(struct irq_desc *desc)
{
    hpet_msi_unmask(desc);
    return 0;
}

#define hpet_msi_shutdown hpet_msi_mask

static void cf_check hpet_msi_ack(struct irq_desc *desc)
{
    irq_complete_move(desc);
    move_native_irq(desc);
    ack_APIC_irq();
}

static void cf_check hpet_msi_set_affinity(
    struct irq_desc *desc, const cpumask_t *mask)
{
    struct hpet_event_channel *ch = desc->action->dev_id;
    struct msi_msg msg = ch->msi.msg;

    msg.dest32 = set_desc_affinity(desc, mask);
    if ( msg.dest32 == BAD_APICID )
        return;

    msg.data &= ~MSI_DATA_VECTOR_MASK;
    msg.data |= MSI_DATA_VECTOR(desc->arch.vector);
    msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
    msg.address_lo |= MSI_ADDR_DEST_ID(msg.dest32);
    if ( msg.data != ch->msi.msg.data || msg.dest32 != ch->msi.msg.dest32 )
        hpet_msi_write(ch, &msg);
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
    .set_affinity   = hpet_msi_set_affinity,
};

static int __hpet_setup_msi_irq(struct irq_desc *desc)
{
    struct msi_msg msg;

    msi_compose_msg(desc->arch.vector, desc->arch.cpu_mask, &msg);
    return hpet_msi_write(desc->action->dev_id, &msg);
}

static int __init hpet_setup_msi_irq(struct hpet_event_channel *ch)
{
    int ret;
    u32 cfg = hpet_read32(HPET_Tn_CFG(ch->idx));
    irq_desc_t *desc = irq_to_desc(ch->msi.irq);

    if ( iommu_intremap != iommu_intremap_off )
    {
        ch->msi.hpet_id = hpet_blockid;
        ret = iommu_setup_hpet_msi(&ch->msi);
        if ( ret )
            return ret;
    }

    /* set HPET Tn as oneshot */
    cfg &= ~(HPET_TN_LEVEL | HPET_TN_PERIODIC);
    cfg |= HPET_TN_FSB | HPET_TN_32BIT;
    hpet_write32(cfg, HPET_Tn_CFG(ch->idx));

    desc->handler = &hpet_msi_type;
    ret = request_irq(ch->msi.irq, 0, hpet_interrupt_handler, "HPET", ch);
    if ( ret >= 0 )
        ret = __hpet_setup_msi_irq(desc);
    if ( ret < 0 )
    {
        if ( iommu_intremap != iommu_intremap_off )
            iommu_update_ire_from_msi(&ch->msi, NULL);
        return ret;
    }

    desc->msi_desc = &ch->msi;

    return 0;
}

static int __init hpet_assign_irq(struct hpet_event_channel *ch)
{
    int irq;

    if ( (irq = create_irq(NUMA_NO_NODE, false)) < 0 )
        return irq;

    ch->msi.irq = irq;
    if ( hpet_setup_msi_irq(ch) )
    {
        destroy_irq(irq);
        return -EINVAL;
    }

    return 0;
}

static void __init hpet_fsb_cap_lookup(void)
{
    u32 id;
    unsigned int i, num_chs;

    if ( unlikely(acpi_gbl_FADT.boot_flags & ACPI_FADT_NO_MSI) )
        return;

    id = hpet_read32(HPET_ID);

    num_chs = ((id & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT);
    num_chs++; /* Value read out starts from 0 */

    hpet_events = xzalloc_array(struct hpet_event_channel, num_chs);
    if ( !hpet_events )
        return;

    for ( i = 0; i < num_chs && num_hpets_used < nr_cpu_ids; i++ )
    {
        struct hpet_event_channel *ch = &hpet_events[num_hpets_used];
        u32 cfg = hpet_read32(HPET_Tn_CFG(i));

        /* Only consider HPET timer with MSI support */
        if ( !(cfg & HPET_TN_FSB_CAP) )
            continue;

        if ( !zalloc_cpumask_var(&ch->cpumask) )
        {
            if ( !num_hpets_used )
            {
                xfree(hpet_events);
                hpet_events = NULL;
            }
            break;
        }

        ch->flags = 0;
        ch->idx = i;

        if ( hpet_assign_irq(ch) == 0 )
            num_hpets_used++;
    }

    printk(XENLOG_INFO "HPET: %u timers usable for broadcast (%u total)\n",
           num_hpets_used, num_chs);
}

static struct hpet_event_channel *hpet_get_channel(unsigned int cpu)
{
    static unsigned int next_channel;
    unsigned int i, next;
    struct hpet_event_channel *ch;

    if ( num_hpets_used == 0 )
        return hpet_events;

    if ( num_hpets_used >= nr_cpu_ids )
        return &hpet_events[cpu];

    next = arch_fetch_and_add(&next_channel, 1) % num_hpets_used;

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

static void set_channel_irq_affinity(struct hpet_event_channel *ch)
{
    struct irq_desc *desc = irq_to_desc(ch->msi.irq);

    ASSERT(!local_irq_is_enabled());
    spin_lock(&desc->lock);
    hpet_msi_mask(desc);
    hpet_msi_set_affinity(desc, cpumask_of(ch->cpu));
    hpet_msi_unmask(desc);
    spin_unlock(&desc->lock);

    spin_unlock(&ch->lock);

    /* We may have missed an interrupt due to the temporary masking. */
    if ( ch->event_handler && ch->next_event < NOW() )
        ch->event_handler(ch);
}

static void hpet_attach_channel(unsigned int cpu,
                                struct hpet_event_channel *ch)
{
    ASSERT(!local_irq_is_enabled());
    spin_lock(&ch->lock);

    per_cpu(cpu_bc_channel, cpu) = ch;

    /* try to be the channel owner again while holding the lock */
    if ( !test_and_set_bit(HPET_EVT_USED_BIT, &ch->flags) )
        ch->cpu = cpu;

    if ( ch->cpu != cpu )
        spin_unlock(&ch->lock);
    else
        set_channel_irq_affinity(ch);
}

static void hpet_detach_channel(unsigned int cpu,
                                struct hpet_event_channel *ch)
{
    unsigned int next;

    spin_lock_irq(&ch->lock);

    ASSERT(ch == per_cpu(cpu_bc_channel, cpu));

    per_cpu(cpu_bc_channel, cpu) = NULL;

    if ( cpu != ch->cpu )
        spin_unlock_irq(&ch->lock);
    else if ( (next = cpumask_first(ch->cpumask)) >= nr_cpu_ids )
    {
        ch->cpu = -1;
        clear_bit(HPET_EVT_USED_BIT, &ch->flags);
        spin_unlock_irq(&ch->lock);
    }
    else
    {
        ch->cpu = next;
        set_channel_irq_affinity(ch);
        local_irq_enable();
    }
}

#include <asm/mc146818rtc.h>

void (*__read_mostly pv_rtc_handler)(uint8_t index, uint8_t value);

static void cf_check handle_rtc_once(uint8_t index, uint8_t value)
{
    if ( index != RTC_REG_B )
        return;

    /* RTC Reg B, contain PIE/AIE/UIE */
    if ( value & (RTC_PIE | RTC_AIE | RTC_UIE ) )
    {
        cpuidle_disable_deep_cstate();
        ACCESS_ONCE(pv_rtc_handler) = NULL;
    }
}

void __init hpet_broadcast_init(void)
{
    u64 hpet_rate = hpet_setup();
    u32 hpet_id, cfg;
    unsigned int i, n;

    if ( hpet_rate == 0 || hpet_broadcast_is_available() )
        return;

    cfg = hpet_read32(HPET_CFG);

    hpet_fsb_cap_lookup();
    if ( num_hpets_used > 0 )
    {
        /* Stop HPET legacy interrupts */
        cfg &= ~HPET_CFG_LEGACY;
        n = num_hpets_used;
    }
    else
    {
        hpet_id = hpet_read32(HPET_ID);
        if ( !(hpet_id & HPET_ID_LEGSUP) )
            return;

        if ( !hpet_events )
            hpet_events = xzalloc(struct hpet_event_channel);
        if ( !hpet_events || !zalloc_cpumask_var(&hpet_events->cpumask) )
            return;
        hpet_events->msi.irq = -1;

        /* Start HPET legacy interrupts */
        cfg |= HPET_CFG_LEGACY;
        n = 1;

        if ( !force_hpet_broadcast )
            pv_rtc_handler = handle_rtc_once;
    }

    hpet_write32(cfg, HPET_CFG);

    for ( i = 0; i < n; i++ )
    {
        if ( i == 0 && (cfg & HPET_CFG_LEGACY) )
        {
            /* set HPET T0 as oneshot */
            cfg = hpet_read32(HPET_Tn_CFG(0));
            cfg &= ~(HPET_TN_LEVEL | HPET_TN_PERIODIC);
            cfg |= HPET_TN_ENABLE | HPET_TN_32BIT;
            hpet_write32(cfg, HPET_Tn_CFG(0));
        }

        /*
         * The period is a femto seconds value. We need to calculate the scaled
         * math multiplication factor for nanosecond to hpet tick conversion.
         */
        hpet_events[i].mult = div_sc((unsigned long)hpet_rate,
                                     1000000000UL, 32);
        hpet_events[i].shift = 32;
        hpet_events[i].next_event = STIME_MAX;
        spin_lock_init(&hpet_events[i].lock);
        smp_wmb();
        hpet_events[i].event_handler = handle_hpet_broadcast;

        hpet_events[i].msi.msi_attrib.maskbit = 1;
        hpet_events[i].msi.msi_attrib.pos = MSI_TYPE_HPET;
    }

    if ( !num_hpets_used )
        hpet_events->flags = HPET_EVT_LEGACY;
}

void hpet_broadcast_resume(void)
{
    u32 cfg;
    unsigned int i, n;

    if ( !hpet_events )
        return;

    hpet_resume(NULL);

    cfg = hpet_read32(HPET_CFG);

    if ( num_hpets_used > 0 )
    {
        /* Stop HPET legacy interrupts */
        cfg &= ~HPET_CFG_LEGACY;
        n = num_hpets_used;
    }
    else if ( hpet_events->flags & HPET_EVT_DISABLE )
        return;
    else
    {
        /* Start HPET legacy interrupts */
        cfg |= HPET_CFG_LEGACY;
        n = 1;
    }

    hpet_write32(cfg, HPET_CFG);

    for ( i = 0; i < n; i++ )
    {
        if ( hpet_events[i].msi.irq >= 0 )
            __hpet_setup_msi_irq(irq_to_desc(hpet_events[i].msi.irq));

        /* set HPET Tn as oneshot */
        cfg = hpet_read32(HPET_Tn_CFG(hpet_events[i].idx));
        cfg &= ~(HPET_TN_LEVEL | HPET_TN_PERIODIC);
        cfg |= HPET_TN_ENABLE | HPET_TN_32BIT;
        if ( !(hpet_events[i].flags & HPET_EVT_LEGACY) )
            cfg |= HPET_TN_FSB;
        hpet_write32(cfg, HPET_Tn_CFG(hpet_events[i].idx));

        hpet_events[i].next_event = STIME_MAX;
    }
}

void hpet_disable_legacy_broadcast(void)
{
    u32 cfg;
    unsigned long flags;

    if ( !hpet_events || !(hpet_events->flags & HPET_EVT_LEGACY) )
        return;

    spin_lock_irqsave(&hpet_events->lock, flags);

    hpet_events->flags |= HPET_EVT_DISABLE;

    /* disable HPET T0 */
    cfg = hpet_read32(HPET_Tn_CFG(0));
    cfg &= ~HPET_TN_ENABLE;
    hpet_write32(cfg, HPET_Tn_CFG(0));

    /* Stop HPET legacy interrupts */
    cfg = hpet_read32(HPET_CFG);
    cfg &= ~HPET_CFG_LEGACY;
    hpet_write32(cfg, HPET_CFG);

    spin_unlock_irqrestore(&hpet_events->lock, flags);

    smp_send_event_check_mask(&cpu_online_map);
}

void cf_check hpet_broadcast_enter(void)
{
    unsigned int cpu = smp_processor_id();
    struct hpet_event_channel *ch = per_cpu(cpu_bc_channel, cpu);
    s_time_t deadline = per_cpu(timer_deadline, cpu);

    if ( deadline == 0 )
        return;

    if ( !ch )
        ch = hpet_get_channel(cpu);

    ASSERT(!local_irq_is_enabled());

    if ( !(ch->flags & HPET_EVT_LEGACY) )
        hpet_attach_channel(cpu, ch);

    /* Disable LAPIC timer interrupts. */
    disable_APIC_timer();
    cpumask_set_cpu(cpu, ch->cpumask);

    spin_lock(&ch->lock);
    /*
     * Reprogram if current cpu expire time is nearer.  deadline is never
     * written by a remote cpu, so the value read earlier is still valid.
     */
    if ( deadline < ch->next_event )
        reprogram_hpet_evt_channel(ch, deadline, NOW(), 1);
    spin_unlock(&ch->lock);
}

void cf_check hpet_broadcast_exit(void)
{
    unsigned int cpu = smp_processor_id();
    struct hpet_event_channel *ch = per_cpu(cpu_bc_channel, cpu);
    s_time_t deadline = per_cpu(timer_deadline, cpu);

    if ( deadline == 0 )
        return;

    if ( !ch )
        ch = hpet_get_channel(cpu);

    /* Reprogram the deadline; trigger timer work now if it has passed. */
    enable_APIC_timer();
    if ( !reprogram_timer(deadline) )
        raise_softirq(TIMER_SOFTIRQ);

    cpumask_clear_cpu(cpu, ch->cpumask);

    if ( !(ch->flags & HPET_EVT_LEGACY) )
        hpet_detach_channel(cpu, ch);
}

int hpet_broadcast_is_available(void)
{
    return ((hpet_events && (hpet_events->flags & HPET_EVT_LEGACY))
            || num_hpets_used > 0);
}

int hpet_legacy_irq_tick(void)
{
    this_cpu(irq_count)--;

    if ( !hpet_events ||
         (hpet_events->flags & (HPET_EVT_DISABLE|HPET_EVT_LEGACY)) !=
         HPET_EVT_LEGACY )
        return 0;
    hpet_events->event_handler(hpet_events);
    return 1;
}

static u32 *hpet_boot_cfg;
static uint64_t __initdata hpet_rate;
static __initdata struct {
    uint32_t cmp, cfg;
} pre_legacy_c0;

bool __init hpet_enable_legacy_replacement_mode(void)
{
    unsigned int cfg, c0_cfg, ticks, count;

    if ( !hpet_rate ||
         !(hpet_read32(HPET_ID) & HPET_ID_LEGSUP) ||
         ((cfg = hpet_read32(HPET_CFG)) & HPET_CFG_LEGACY) )
        return false;

    /* Stop the main counter. */
    hpet_write32(cfg & ~HPET_CFG_ENABLE, HPET_CFG);

    /* Stash channel 0's old CFG/CMP incase we need to undo. */
    pre_legacy_c0.cfg = c0_cfg = hpet_read32(HPET_Tn_CFG(0));
    pre_legacy_c0.cmp = hpet_read32(HPET_Tn_CMP(0));

    /* Reconfigure channel 0 to be 32bit periodic. */
    c0_cfg |= (HPET_TN_ENABLE | HPET_TN_PERIODIC | HPET_TN_SETVAL |
               HPET_TN_32BIT);
    hpet_write32(c0_cfg, HPET_Tn_CFG(0));

    /*
     * The exact period doesn't have to match a legacy PIT.  All we need
     * is an interrupt queued up via the IO-APIC to check routing.
     *
     * Use HZ as the frequency.
     */
    ticks = ((SECONDS(1) / HZ) * div_sc(hpet_rate, SECONDS(1), 32)) >> 32;

    count = hpet_read32(HPET_COUNTER);

    /*
     * HPET_TN_SETVAL above is atrociously documented in the spec.
     *
     * Periodic HPET channels have a main comparator register, and
     * separate "accumulator" register.  Despite being named accumulator
     * in the spec, this is not an accurate description of its behaviour
     * or purpose.
     *
     * Each time an interrupt is generated, the "accumulator" register is
     * re-added to the comparator set up the new period.
     *
     * Normally, writes to the CMP register update both registers.
     * However, under these semantics, it is impossible to set up a
     * periodic timer correctly without the main HPET counter being at 0.
     *
     * Instead, HPET_TN_SETVAL is a self-clearing control bit which we can
     * use for periodic timers to mean that the second write to CMP
     * updates the accumulator only, and not the absolute comparator
     * value.
     *
     * This lets us set a period when the main counter isn't at 0.
     */
    hpet_write32(count + ticks, HPET_Tn_CMP(0));
    hpet_write32(ticks,         HPET_Tn_CMP(0));

    /* Restart the main counter, and legacy mode. */
    hpet_write32(cfg | HPET_CFG_ENABLE | HPET_CFG_LEGACY, HPET_CFG);

    return true;
}

void __init hpet_disable_legacy_replacement_mode(void)
{
    unsigned int cfg = hpet_read32(HPET_CFG);

    ASSERT(hpet_rate);

    cfg &= ~(HPET_CFG_LEGACY | HPET_CFG_ENABLE);

    /* Stop the main counter and disable legacy mode. */
    hpet_write32(cfg, HPET_CFG);

    /* Restore pre-Legacy Replacement Mode settings. */
    hpet_write32(pre_legacy_c0.cfg, HPET_Tn_CFG(0));
    hpet_write32(pre_legacy_c0.cmp, HPET_Tn_CMP(0));

    /* Restart the main counter. */
    hpet_write32(cfg | HPET_CFG_ENABLE, HPET_CFG);
}

u64 __init hpet_setup(void)
{
    unsigned int hpet_id, hpet_period;
    unsigned int last, rem;

    if ( hpet_rate || !hpet_address || !opt_hpet )
        return hpet_rate;

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

    last = (hpet_id & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT;
    hpet_boot_cfg = xmalloc_array(u32, 2 + last);
    hpet_resume(hpet_boot_cfg);

    hpet_rate = 1000000000000000ULL; /* 10^15 */
    rem = do_div(hpet_rate, hpet_period);
    if ( (rem * 2) > hpet_period )
        hpet_rate++;

    if ( opt_hpet_legacy_replacement > 0 )
        hpet_enable_legacy_replacement_mode();

    return hpet_rate;
}

void hpet_resume(uint32_t *boot_cfg)
{
    static u32 system_reset_latch;
    u32 hpet_id, cfg;
    unsigned int i, last;

    if ( system_reset_latch == system_reset_counter )
        return;
    system_reset_latch = system_reset_counter;

    cfg = hpet_read32(HPET_CFG);
    if ( boot_cfg )
        *boot_cfg = cfg;
    cfg &= ~(HPET_CFG_ENABLE | HPET_CFG_LEGACY);
    if ( cfg )
    {
        printk(XENLOG_WARNING
               "HPET: reserved bits %#x set in global config register\n",
               cfg);
        cfg = 0;
    }
    hpet_write32(cfg, HPET_CFG);

    hpet_id = hpet_read32(HPET_ID);
    last = (hpet_id & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT;
    for ( i = 0; i <= last; ++i )
    {
        cfg = hpet_read32(HPET_Tn_CFG(i));
        if ( boot_cfg )
            boot_cfg[i + 1] = cfg;
        cfg &= ~HPET_TN_ENABLE;
        if ( cfg & HPET_TN_RESERVED )
        {
            printk(XENLOG_WARNING
                   "HPET: reserved bits %#x set in channel %u config register\n",
                   cfg & HPET_TN_RESERVED, i);
            cfg &= ~HPET_TN_RESERVED;
        }
        hpet_write32(cfg, HPET_Tn_CFG(i));
    }

    cfg = hpet_read32(HPET_CFG);
    cfg |= HPET_CFG_ENABLE;
    hpet_write32(cfg, HPET_CFG);
}

void hpet_disable(void)
{
    unsigned int i;
    u32 id;

    if ( !hpet_boot_cfg )
    {
        if ( hpet_broadcast_is_available() )
            hpet_disable_legacy_broadcast();
        return;
    }

    hpet_write32(*hpet_boot_cfg & ~HPET_CFG_ENABLE, HPET_CFG);

    id = hpet_read32(HPET_ID);
    for ( i = 0; i <= ((id & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT); ++i )
        hpet_write32(hpet_boot_cfg[i + 1], HPET_Tn_CFG(i));

    if ( *hpet_boot_cfg & HPET_CFG_ENABLE )
        hpet_write32(*hpet_boot_cfg, HPET_CFG);
}
