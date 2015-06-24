/*
 * Xen emulation for hpet
 *
 * Copyright (C) 2014 Verizon Corporation
 *
 * This file is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License Version 2 (GPLv2)
 * as published by the Free Software Foundation.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details. <http://www.gnu.org/licenses/>.
 */

/*
 * http://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/software-developers-hpet-spec-1-0a.pdf
 *
 * xen_source is a directory that has all xen source below it.
 *
 * Usage:
 *


  xen_source=../../..
  sed -e "/#include/d" -e "1i#include \"emul.h\"\n" <$xen_source/xen/arch/x86/hvm/hpet.c >hpet.c
  cp $xen_source/xen/include/asm-x86/hpet.h .

  gcc -g -o test_vhpet hpet.c main.c
  ./test_vhpet >test_vhpet.out

 *
 *
 * This is almost the same as
 *

  make run

 *
 * Or
 *
 * make -C tools/tests/vhpet run
 *
 * From a xen source tree.  The differance
 * is that you need to be in a xen source tree
 * and normal make rules apply.
 *
 */

#define FORCE_THOUSANDS_SEP

#include <locale.h>
#include <langinfo.h>
#include <stdarg.h>
#include "emul.h"
#include "hpet.h"

#define S_TO_NS    1000000000ULL           /* 1s  = 10^9  ns */

#define START_MC64 0x108a8

static int hpet_mult = 1;
static int hpet_add;
static int hvm_clock_cost = 1234567;
static int tick_count = 1;
static int debug = 3;

static int skip_load;
static int skip_error_on_load;

static char *global_thousep;

extern const struct hvm_mmio_ops hpet_mmio_ops;

struct domain dom1;
struct vcpu vcpu0;
struct hvm_hw_hpet hpet_save;


uint64_t hvm_guest_time;

static struct
{
    hvm_save_handler save;
    hvm_load_handler load;
    const char *name;
    size_t size;
    int kind;
} hvm_sr_handlers[3] = {{NULL, NULL, "<?>"},};

static uint64_t new_guest_time[] = {
    0x20,
    0x2a840,
    0xf4200,
    0x10000000000ULL,
    0x0fffffffffefff00ULL,
    0x20,
    0xffffffff00000000ULL,
    0x20,
};

static int print_error(const char *fmt, ...)
{
    va_list args;
    int i = 0;

    if ( (debug & 0x0100) && skip_error_on_load )
        return i;

    va_start(args, fmt);
    if ( debug & 0x0001 )
        i = vfprintf(stdout, fmt, args);
    va_end(args);
    va_start(args, fmt);
    if ( debug & 0x0002 )
        i = vfprintf(stderr, fmt, args);
    va_end(args);
    return i;
}


int current_domain_id(void)
{
    return current->domain->domain_id;
}

struct vcpu *get_current()
{
    return &vcpu0;
}

void __domain_crash(struct domain *d)
{
    exit(42);
}

uint64_t hvm_get_guest_time(struct vcpu *v)
{
    uint64_t ret = hvm_guest_time;

    hvm_guest_time += hvm_clock_cost;
    return ret;
}

int _hvm_init_entry(struct hvm_domain_context *h,
                    uint16_t tc, uint16_t inst, uint32_t len)
{
    h->cur = 0;
    h->size = sizeof(hpet_save);
    h->data = (void *)&hpet_save;

    return 0;
}

int _hvm_check_entry(struct hvm_domain_context *h,
                     uint16_t type, uint32_t len, bool_t strict_length)
{
    h->cur = 0;
    h->size = sizeof(hpet_save);
    h->data = (void *)&hpet_save;

    return 0;
}

void __init hvm_register_savevm(uint16_t typecode,
                                const char *name,
                                hvm_save_handler save_state,
                                hvm_load_handler load_state,
                                size_t size, int kind)
{
    hvm_sr_handlers[typecode].save = save_state;
    hvm_sr_handlers[typecode].load = load_state;
    hvm_sr_handlers[typecode].name = name;
    hvm_sr_handlers[typecode].size = size;
    hvm_sr_handlers[typecode].kind = kind;
}

int do_save(uint16_t typecode, struct domain *d, hvm_domain_context_t *h)
{
    return hvm_sr_handlers[typecode].save(d, h);
}

int do_load(uint16_t typecode, struct domain *d, hvm_domain_context_t *h)
{
    if (skip_load & 0x1)
    {
        printf("skip_load=%#x\n", skip_load);
    }
    else
    {
        int ret;

        printf("do_load\n");
        skip_error_on_load = 1;
        ret = hvm_sr_handlers[typecode].load(d, h);
        skip_error_on_load = 0;
    }
}

static void dump_hpet(void)
{
    int i;
    unsigned long long conf;
    struct hvm_hw_hpet h = hpet_save;
    conf = (unsigned long long) h.config;
    printf("    HPET: capability %#llx config %#llx(%s%s)\n",
           (unsigned long long) h.capability,
           conf,
           conf & HPET_CFG_ENABLE ? "E" : "",
           conf & HPET_CFG_LEGACY ? "L" : "");
    printf("          isr %#llx counter %#llx(%'lld)\n",
           (unsigned long long) h.isr,
           (unsigned long long) h.mc64,
           (unsigned long long) h.mc64);
    for (i = 0; i < HPET_TIMER_NUM; i++)
    {
        conf = (unsigned long long) h.timers[i].config;
        printf("          timer%i config %#llx(%s%s%s) cmp %#llx(%'lld)\n", i,
               conf,
               conf & HPET_TN_ENABLE ? "E" : "",
               conf & HPET_TN_PERIODIC ? "P" : "",
               conf & HPET_TN_32BIT ? "32" : "",
               (unsigned long long) h.timers[i].cmp,
               (unsigned long long) h.timers[i].cmp);
        printf("          timer%i period %#llx(%'lld) fsb %#llx\n", i,
               (unsigned long long) h.period[i],
               (unsigned long long) h.period[i],
               (unsigned long long) h.timers[i].fsb);
    }
}

void pit_stop_channel0_irq(PITState *pit)
{
    printf("pit_stop_channel0_irq: pit=%p\n", pit);

    TRACE_1D(TRC_HVM_VCHIP_PIT_STOP_TIMER, get_cycles());
    spin_lock(&pit->lock);
    destroy_periodic_time(&pit->pt0);
    spin_unlock(&pit->lock);
}

void destroy_periodic_time(struct periodic_time *pt)
{
    int idx = ((long)pt) & 0x7;

    printf("destroy_periodic_time: pt=%d\n", idx);
}

void create_periodic_time(struct vcpu *v, struct periodic_time *pt,
                          uint64_t delta, uint64_t period, uint8_t irq,
                          time_cb *cb, void *data)
{
    int idx = ((long)pt) & 0x7;

    if ( debug & 0x0010 )
    {
        int i;

        printf("create_periodic_time: "
               "mc64=%#lx(%'ld) mc_offset=%#lx(%'ld)\n",
               dom1.arch.hvm_domain.pl_time.vhpet.hpet.mc64,
               dom1.arch.hvm_domain.pl_time.vhpet.hpet.mc64,
               dom1.arch.hvm_domain.pl_time.vhpet.mc_offset,
               dom1.arch.hvm_domain.pl_time.vhpet.mc_offset);
        for (i = 0; i < 3; i++)
        {
            printf("                 "
                   "[%d] cmp64=%#lx(%'ld) cmp=%#lx(%'ld)\n", i,
                   dom1.arch.hvm_domain.pl_time.vhpet.hpet.comparator64[i],
                   dom1.arch.hvm_domain.pl_time.vhpet.hpet.comparator64[i],
                   dom1.arch.hvm_domain.pl_time.vhpet.hpet.timers[i].cmp,
                   dom1.arch.hvm_domain.pl_time.vhpet.hpet.timers[i].cmp);
        }
    }
    if ( period )
    {
        printf("create_periodic_time: pt=%d delta=%'"PRId64" period=%'"PRIu64
               " - %'"PRIu64".%02d Hz irq=%d\n",
               idx, delta, period, (uint64_t)(S_TO_NS / period),
               (int)((S_TO_NS / (period / 100ULL)) % 100), irq);
        /* +160 is for hpet_tick_to_ns() not simple. */
        if ( delta > (period * (hpet_mult + hpet_add + 160)) )
            print_error("%s(%ld): Possible ..MP-BIOS bug: 8254 timer...: delta=%'"PRId64
                        " period=%'"PRIu64"\n", __func__, __LINE__,
                        delta, period);
    }
    else
        printf("create_periodic_time: pt=%d delta=%'"PRId64
               " period=%'"PRIu64" irq=%d\n",
               idx, delta, period, irq);
}

void udelay(int w)
{
}

unsigned int hpet_readl(unsigned long a)
{
    unsigned long ret = 0;
    hpet_mmio_ops.read(current, a, 4, &ret);
    return ret;
}

void hpet_writel(unsigned long d, unsigned long a)
{
    hpet_mmio_ops.write(current, a, 4, d);
    return;
}

static void _hpet_print_config(const char *function, int line)
{
    u32 i, timers, l, h;
    printk(KERN_INFO "hpet: %s(%d):\n", function, line);
    l = hpet_readl(HPET_ID);
    h = hpet_readl(HPET_PERIOD);
    timers = ((l & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT) + 1;
    printk(KERN_INFO "hpet: ID: 0x%x, PERIOD: 0x%x\n", l, h);
    l = hpet_readl(HPET_CFG);
    h = hpet_readl(HPET_STATUS);
    printk(KERN_INFO "hpet: CFG: 0x%x, STATUS: 0x%x\n", l, h);
    l = hpet_readl(HPET_COUNTER);
    h = hpet_readl(HPET_COUNTER + 4);
    printk(KERN_INFO "hpet: COUNTER_l: 0x%x, COUNTER_h: 0x%x\n", l, h);

    for (i = 0; i < timers; i++)
    {
        l = hpet_readl(HPET_Tn_CFG(i));
        h = hpet_readl(HPET_Tn_CFG(i) + 4);
        printk(KERN_INFO "hpet: T%d: CFG_l: 0x%x, CFG_h: 0x%x\n",
               i, l, h);
        l = hpet_readl(HPET_Tn_CMP(i));
        h = hpet_readl(HPET_Tn_CMP(i) + 4);
        printk(KERN_INFO "hpet: T%d: CMP_l: 0x%x, CMP_h: 0x%x\n",
               i, l, h);
        l = hpet_readl(HPET_Tn_ROUTE(i));
        h = hpet_readl(HPET_Tn_ROUTE(i) + 4);
        printk(KERN_INFO "hpet: T%d ROUTE_l: 0x%x, ROUTE_h: 0x%x\n",
               i, l, h);
    }
}

#define hpet_print_config()                     \
    do {                                        \
        _hpet_print_config(__func__, __LINE__); \
    } while ( 0 )

static void hpet_stop_counter(void)
{
    unsigned long cfg = hpet_readl(HPET_CFG);
    cfg &= ~HPET_CFG_ENABLE;
    hpet_writel(cfg, HPET_CFG);
}

static void hpet_reset_counter(unsigned long low, unsigned long high)
{
    hpet_writel(low, HPET_COUNTER);
    hpet_writel(high, HPET_COUNTER + 4);
}

static void hpet_start_counter(void)
{
    unsigned long cfg = hpet_readl(HPET_CFG);
    cfg |= HPET_CFG_ENABLE;
    hpet_writel(cfg, HPET_CFG);
}

static void hpet_restart_counter(void)
{
    hpet_stop_counter();
    hpet_reset_counter(0, 0);
    hpet_start_counter();
}

static void hpet_set_mode(uint64_t delta, int timer)
{
    unsigned long cfg, cmp, cmp2, now;

    hpet_stop_counter();
    now = hpet_readl(HPET_COUNTER);
    cmp = now + (unsigned long)(hpet_mult * delta) + hpet_add;
    cfg = hpet_readl(HPET_Tn_CFG(timer));
    /* Make sure we use edge triggered interrupts */
    cfg &= ~HPET_TN_LEVEL;
    cfg |= HPET_TN_ENABLE | HPET_TN_PERIODIC |
           HPET_TN_SETVAL | HPET_TN_32BIT;
    /* Mask to 32 bits just like the hardware */
    cmp = (uint32_t)cmp;
    delta = (uint32_t)delta;
    /* Do the config */
    hpet_writel(cfg, HPET_Tn_CFG(timer));
    hpet_writel(cmp, HPET_Tn_CMP(timer));
    printf("%s(%ld): HPET_TN_SETVAL cmp=%#lx(%'ld) timer=%d\n",
           __func__, __LINE__, cmp, cmp, timer);
    udelay(1);
    /*
     * HPET on AMD 81xx needs a second write (with HPET_TN_SETVAL
     * cleared) to T0_CMP to set the period. The HPET_TN_SETVAL
     * bit is automatically cleared after the first write.
     * (See AMD-8111 HyperTransport I/O Hub Data Sheet,
     * Publication # 24674)
     */
    hpet_writel((unsigned long) delta, HPET_Tn_CMP(timer));
    printf("%s(%ld): period=%#lx(%'ld) timer=%d\n", __func__, __LINE__,
           (unsigned long) delta, (unsigned long) delta, timer);
    cmp2 = hpet_readl(HPET_Tn_CMP(timer));
    if ( cmp2 != cmp )
        print_error("%s(%ld): T%d Error: Set %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, cmp, cmp, cmp2, cmp2);

    hpet_start_counter();
    hpet_print_config();
}


hpet_check_stopped(uint64_t old_delta, int timer)
{
    unsigned long mc_low, mc_high, old_cmp, now;
    unsigned long cfg, cmp, delta, cmp2, cmp3;

    if (skip_load & 0x2)
    {
        printf("Skip hpet_check_stopped. skip_load=%#x\n", skip_load);
        return;
    }
    hpet_stop_counter();
    mc_low = hpet_readl(HPET_COUNTER);
    mc_high = hpet_readl(HPET_COUNTER + 4);
    old_cmp = hpet_readl(HPET_Tn_CMP(timer));

    hpet_reset_counter(67752, 0);
    cmp = 255252;
    delta = 62500;

    now = hpet_readl(HPET_COUNTER);
    if ( now != 67752 )
        print_error("%s(%ld): T%d Error: Set mc %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, 67752, 67752, now, now);
    cfg = hpet_readl(HPET_Tn_CFG(timer));
    cfg |= HPET_TN_SETVAL;
    hpet_writel(cfg, HPET_Tn_CFG(timer));
    hpet_writel(cmp, HPET_Tn_CMP(timer));
    printf("%s(%ld): HPET_TN_SETVAL cmp=%#lx(%'ld) timer=%d\n",
           __func__, __LINE__, cmp, cmp, timer);
    cmp2 = hpet_readl(HPET_Tn_CMP(timer));
    if ( cmp2 != cmp )
        print_error("%s(%ld): T%d Error: Set cmp %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, cmp, cmp, cmp2, cmp2);

    hpet_writel((unsigned long) delta, HPET_Tn_CMP(timer));
    printf("%s(%ld): period=%#lx(%'ld) timer=%d\n", __func__, __LINE__,
           (unsigned long) delta, (unsigned long) delta, timer);
    cmp3 = hpet_readl(HPET_Tn_CMP(timer));
    if ( cmp3 != cmp )
        print_error("%s(%ld): T%d Error: Set period, cmp %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, cmp, cmp, cmp3, cmp3);

    if ( dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer] != delta )
        printf("%s(%ld): T%d Warning: Set period %#lx(%'ld) != %#lx(%'ld)\n",
               __func__, __LINE__, timer, delta, delta,
               dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer],
               dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer]);

    hpet_reset_counter(67752, 0);
    cmp = 255252;
    delta = 62500;

    now = hpet_readl(HPET_COUNTER);
    if ( now != 67752 )
        print_error("%s(%ld): T%d Error: Set mc %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, 67752, 67752, now, now);
    cfg = hpet_readl(HPET_Tn_CFG(timer));
    cfg |= HPET_TN_SETVAL;
    hpet_writel(cfg, HPET_Tn_CFG(timer));
    hpet_writel(cmp, HPET_Tn_CMP(timer));
    printf("%s(%ld): HPET_TN_SETVAL cmp=%#lx(%'ld) timer=%d\n",
           __func__, __LINE__, cmp, cmp, timer);
    cmp2 = hpet_readl(HPET_Tn_CMP(timer));
    if ( cmp2 != cmp )
        print_error("%s(%ld): T%d Error: Set cmp %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, cmp, cmp, cmp2, cmp2);

    hpet_writel((unsigned long) delta, HPET_Tn_CMP(timer));
    printf("%s(%ld): period=%#lx(%'ld) timer=%d\n", __func__, __LINE__,
           (unsigned long) delta, (unsigned long) delta, timer);
    cmp3 = hpet_readl(HPET_Tn_CMP(timer));
    if ( cmp3 != cmp )
        print_error("%s(%ld): T%d Error: Set period, cmp %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, cmp, cmp, cmp3, cmp3);

    if ( dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer] != delta )
        printf("%s(%ld): T%d Warning: Set period %#lx(%'ld) != %#lx(%'ld)\n",
               __func__, __LINE__, timer, delta, delta,
               dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer],
               dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer]);

    hpet_reset_counter(67700, 0);

    now = hpet_readl(HPET_COUNTER);
    if ( now != 67700 )
        print_error("%s(%ld): T%d Error: Set mc %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, 67752, 67752, now, now);
    cmp2 = hpet_readl(HPET_Tn_CMP(timer));
    if ( cmp2 != cmp )
        print_error("%s(%ld): T%d Error: Set mc, cmp %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, cmp, cmp, cmp2, cmp2);

    cmp3 = hpet_readl(HPET_Tn_CMP(timer));
    if ( cmp3 != cmp )
        print_error("%s(%ld): T%d Error: Set mc, cmp %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, cmp, cmp, cmp3, cmp3);

    if ( dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer] != delta )
        printf("%s(%ld): T%d Warning: Set mc, period %#lx(%'ld) != %#lx(%'ld)\n",
               __func__, __LINE__, timer, delta, delta,
               dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer],
               dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer]);

    cmp = 67701;

    now = hpet_readl(HPET_COUNTER);
    if ( now != 67700 )
        print_error("%s(%ld): T%d Error: Set cmp, mc %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, 67752, 67752, now, now);
    cfg = hpet_readl(HPET_Tn_CFG(timer));
    cfg |= HPET_TN_SETVAL;
    hpet_writel(cfg, HPET_Tn_CFG(timer));
    hpet_writel(cmp, HPET_Tn_CMP(timer));
    printf("%s(%ld): HPET_TN_SETVAL cmp=%#lx(%'ld) timer=%d\n",
           __func__, __LINE__, cmp, cmp, timer);
    cmp2 = hpet_readl(HPET_Tn_CMP(timer));
    if ( cmp2 != cmp )
        print_error("%s(%ld): T%d Error: Set cmp, cmp %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, cmp, cmp, cmp2, cmp2);

    cmp3 = hpet_readl(HPET_Tn_CMP(timer));
    if ( cmp3 != cmp )
        print_error("%s(%ld): T%d Error: Set cmp, cmp %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, cmp, cmp, cmp3, cmp3);

    if ( dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer] != delta )
        printf("%s(%ld): T%d Warning: Set cmp, period %#lx(%'ld) != %#lx(%'ld)\n",
               __func__, __LINE__, timer, delta, delta,
               dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer],
               dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer]);

    delta = 500;

    now = hpet_readl(HPET_COUNTER);
    if ( now != 67700 )
        print_error("%s(%ld): T%d Error: Set period, mc %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, 67752, 67752, now, now);
    cmp2 = hpet_readl(HPET_Tn_CMP(timer));
    if ( cmp2 != cmp )
        print_error("%s(%ld): T%d Error: Set period, cmp %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, cmp, cmp, cmp2, cmp2);

    hpet_writel((unsigned long) delta, HPET_Tn_CMP(timer));
    printf("%s(%ld): period=%#lx(%'ld) timer=%d\n", __func__, __LINE__,
           (unsigned long) delta, (unsigned long) delta, timer);
    cmp3 = hpet_readl(HPET_Tn_CMP(timer));
    if ( cmp3 != cmp )
        print_error("%s(%ld): T%d Error: Set period, cmp %#lx(%'ld) != %#lx(%'ld)\n",
                    __func__, __LINE__, timer, cmp, cmp, cmp3, cmp3);

    if ( dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer] != delta )
        printf("%s(%ld): T%d Warning: Set period, period %#lx(%'ld) != %#lx(%'ld)\n",
               __func__, __LINE__, timer, delta, delta,
               dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer],
               dom1.arch.hvm_domain.pl_time.vhpet.hpet.period[timer]);

    hpet_reset_counter(mc_low, mc_high);
    cfg = hpet_readl(HPET_Tn_CFG(timer));
    cfg |= HPET_TN_SETVAL;
    hpet_writel(cfg, HPET_Tn_CFG(timer));
    hpet_writel(old_cmp, HPET_Tn_CMP(timer));
    hpet_writel(old_delta, HPET_Tn_CMP(timer));
    hpet_start_counter();
}


int
main(int argc, char **argv)
{
    hvm_domain_context_t hdc;
    struct hvm_hw_hpet hpet0;
    struct hvm_hw_hpet hpet1;
    struct hvm_hw_hpet hpet2;
    int i, k;

    setlocale(LC_ALL, "");

#ifdef FORCE_THOUSANDS_SEP
    setlocale(LC_NUMERIC, "en_US.utf8");
#endif
    global_thousep = nl_langinfo(THOUSEP);

    printf("test_vhpet 1.0\n");

    if ( argc > 1 )
        hvm_clock_cost = atoi(argv[1]);
    if ( argc > 2 )
        hpet_mult = atoi(argv[2]);
    if ( argc > 3 )
        hpet_add = atoi(argv[3]);
    if ( argc > 4 )
        tick_count = atoi(argv[4]);
    if ( argc > 5 )
        debug = strtol(argv[5], NULL, 0);

    printf("hvm_clock_cost=%'d hpet_mult=%'d hpet_add=%'d tick_count=%d debug=%#x\n",
           hvm_clock_cost, hpet_mult, hpet_add, tick_count, debug);

    dom1.domain_id = 1;
    dom1.vcpu[0] = &vcpu0;
    vcpu0.vcpu_id = 0;
    vcpu0.domain = &dom1;

    __hvm_register_HPET_save_and_restore();

    for (skip_load = 3; skip_load >= 0; skip_load--)
    {

        printf("\nskip_load=%d\n", skip_load);

        hvm_guest_time = 16;

        hpet_init(&vcpu0);

        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet0 = hpet_save;
        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet1 = hpet_save;
        if (hpet0.mc64 != hpet1.mc64)
            print_error("%s(%ld): With clock stopped mc64 changed: %'ld to %'ld\n",
                        __func__, __LINE__, hpet0.mc64, hpet1.mc64);

        do_load(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet2 = hpet_save;
        if (hpet1.mc64 != hpet2.mc64)
            print_error("%s(%ld): With clock stopped mc64 changed: %'ld to %'ld\n",
                        __func__, __LINE__, hpet1.mc64, hpet2.mc64);

        dom1.arch.hvm_domain.pl_time.vhpet.hpet.mc64 = START_MC64;
        dom1.arch.hvm_domain.pl_time.vhpet.mc_offset = START_MC64
            - hvm_guest_time - hvm_clock_cost;
        printf("\n"
               "mc64=%#lx(%'ld) mc_offset=%#lx(%'ld)\n",
               dom1.arch.hvm_domain.pl_time.vhpet.hpet.mc64,
               dom1.arch.hvm_domain.pl_time.vhpet.hpet.mc64,
               dom1.arch.hvm_domain.pl_time.vhpet.mc_offset,
               dom1.arch.hvm_domain.pl_time.vhpet.mc_offset);

        printf("\nhvm_guest_time=%#lx(%'ld)\n",
               hvm_guest_time, hvm_guest_time);

        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet0 = hpet_save;
        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet1 = hpet_save;
        if (hpet0.mc64 != hpet1.mc64)
            print_error("%s(%ld): With clock stopped mc64 changed: %'ld to %'ld\n",
                        __func__, __LINE__, hpet0.mc64, hpet1.mc64);

        do_load(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet2 = hpet_save;
        if (hpet1.mc64 != hpet2.mc64)
            print_error("%s(%ld): With clock stopped mc64 changed: %'ld to %'ld\n",
                        __func__, __LINE__, hpet1.mc64, hpet2.mc64);

        hpet_set_mode(0xf424, 0);
        hpet_check_stopped(0xf424, 0);

        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet0 = hpet_save;
        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet1 = hpet_save;
        do_load(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet2 = hpet_save;

        hpet_set_mode(0, 1);
        hpet_check_stopped(0, 1);

        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet0 = hpet_save;
        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet1 = hpet_save;

        do_load(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet2 = hpet_save;

        hpet_set_mode(~0ULL, 2);
        hpet_check_stopped(~0ULL, 2);

        hpet_set_mode(0x80000000, 2);
        hpet_check_stopped(0x80000000, 2);

        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet0 = hpet_save;
        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet1 = hpet_save;

        do_load(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
        dump_hpet();
        hpet2 = hpet_save;


        for (k = 0; k < ARRAY_SIZE(new_guest_time); k++)
        {
            hvm_guest_time = new_guest_time[k];
            printf("\nhvm_guest_time=%#lx(%'ld)\n",
                   hvm_guest_time, hvm_guest_time);

            do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
            dump_hpet();
            hpet0 = hpet_save;
            do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
            dump_hpet();
            hpet1 = hpet_save;

            do_load(HVM_SAVE_CODE(HPET), &dom1, &hdc);
            do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
            dump_hpet();
            hpet2 = hpet_save;

            for (i = 0; i < tick_count; i++)
            {
                hvm_guest_time += 0x10;
                printf("\nhvm_guest_time=%#lx(%'ld)\n",
                       hvm_guest_time, hvm_guest_time);

                do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
                dump_hpet();
                hpet0 = hpet_save;
                do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
                dump_hpet();
                hpet1 = hpet_save;

                do_load(HVM_SAVE_CODE(HPET), &dom1, &hdc);
                do_save(HVM_SAVE_CODE(HPET), &dom1, &hdc);
                dump_hpet();
                hpet2 = hpet_save;

            }
        }
    }

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
