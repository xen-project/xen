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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#define PCI_HAVE_64BIT_ADDRESS
#include <pci/types.h>

#include "hpet.h"

#define NR_CPUS 8

typedef int64_t s_time_t;
typedef int spinlock_t;
typedef int bool_t;

#define BITS_PER_LONG __WORDSIZE
#define BITS_TO_LONGS(bits) \
    (((bits) + BITS_PER_LONG - 1) / BITS_PER_LONG)
#define DECLARE_BITMAP(name, bits) \
    unsigned long name[BITS_TO_LONGS(bits)]
typedef struct cpumask
{
    DECLARE_BITMAP(bits, NR_CPUS);
} cpumask_t;
typedef cpumask_t *cpumask_var_t;
struct msi_desc
{
    struct msi_attrib
    {
        u8    type    : 5;    /* {0: unused, 5h:MSI, 11h:MSI-X} */
        u8    maskbit : 1;    /* mask-pending bit supported ?   */
        u8    masked  : 1;
        u8    is_64   : 1;    /* Address size: 0=32bit 1=64bit  */
        u8    pos;            /* Location of the msi capability */
        u16   entry_nr;       /* specific enabled entry         */
    } msi_attrib;
};

struct msi_msg
{
    u32     address_lo;     /* low 32 bits of msi message address */
    u32     address_hi;     /* high 32 bits of msi message address */
    u32     data;           /* 16 bits of msi message data */
    u32     dest32;         /* used when Interrupt Remapping with EIM is enabled */
};

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define X86EMUL_OKAY 100
#define EINVAL 101

#define DBG_LEVEL_PIT 200

#define TRC_HW_VCHIP_HPET_START_TIMER 300
#define TRC_HW_VCHIP_HPET_STOP_TIMER 301
#define TRC_HW_VCHIP_PIT_STOP_TIMER 302

#define TRC_HVM_VCHIP_HPET_START_TIMER 400
#define TRC_HVM_VCHIP_HPET_STOP_TIMER 401
#define TRC_HVM_VCHIP_PIT_STOP_TIMER 402

#define TRC_HVM_EMUL_HPET_START_TIMER 400
#define TRC_HVM_EMUL_HPET_STOP_TIMER 401
#define TRC_HVM_EMUL_PIT_STOP_TIMER 402

#define __read_mostly
#define __initdata
#define __init
#define __maybe_unused
#define __cacheline_aligned
#define boolean_param(a, b)
#define fix_to_virt(a) a
#define xmalloc_array(_type, _num) (void *)(_type)(_num)
#define DEFINE_PER_CPU(_type, _name) _type _name

#define KERN_DEBUG
#define KERN_INFO

#define XENLOG_WARNING
#define XENLOG_INFO
#define XENLOG_ERR
#define XENLOG_GUEST

#define MSI_TYPE_UNKNOWN 0
#define MSI_TYPE_HPET    1
#define MSI_TYPE_IOMMU   2

#define STIME_MAX ((s_time_t)((uint64_t)~0ull>>1))

/* Low-latency softirqs come first in the following list. */
enum
{
    TIMER_SOFTIRQ = 0,
    SCHEDULE_SOFTIRQ,
    NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ,
    RCU_SOFTIRQ,
    TASKLET_SOFTIRQ,
    NR_COMMON_SOFTIRQS
};
/*
 * ..and if you can't take the strict
 * types, you can specify one yourself.
 *
 * Or not use min/max at all, of course.
 */
#define min_t(type, x, y) \
    ({ type __x = (x); type __y = (y); __x < __y ? __x : __y; })
#define max_t(type, x, y) \
    ({ type __x = (x); type __y = (y); __x > __y ? __x : __y; })
#define offsetof(t, m) ((unsigned long )&((t *)0)->m)
#define container_of(ptr, type, member) ({              \
        typeof( ((type *)0)->member ) *__mptr = (ptr);  \
        (type *)( (char *)__mptr - offsetof(type,member) ); })

struct domain;

struct vcpu
{
    int vcpu_id;
    struct domain *domain;
};

typedef void time_cb(struct vcpu *v, void *opaque);

struct periodic_time
{
#define PTSRC_isa    1 /* ISA time source */
#define PTSRC_lapic  2 /* LAPIC time source */
    u8 source;                  /* PTSRC_ */
};

void destroy_periodic_time(struct periodic_time *pt);
void create_periodic_time(
    struct vcpu *v, struct periodic_time *pt, uint64_t delta,
    uint64_t period, uint8_t irq, time_cb *cb, void *data);

#define HPET_TIMER_NUM 3

struct hpet_registers
{
    /* Memory-mapped, software visible registers */
    uint64_t capability;        /* capabilities */
    uint64_t config;            /* configuration */
    uint64_t isr;               /* interrupt status reg */
    uint64_t mc64;              /* main counter */
    struct                      /* timers */
    {
        uint64_t config;        /* configuration/cap */
        uint64_t cmp;           /* comparator */
        uint64_t fsb;           /* FSB route, not supported now */
    } timers[HPET_TIMER_NUM];

    /* Hidden register state */
    uint64_t period[HPET_TIMER_NUM]; /* Last value written to comparator */
    uint64_t comparator64[HPET_TIMER_NUM]; /* 64 bit running comparator */
    uint64_t offset64[HPET_TIMER_NUM]; /* offset so comparator calc "works" */
    uint64_t first_mc64[HPET_TIMER_NUM]; /* 1st interval main counter */
    bool_t first_enabled[HPET_TIMER_NUM]; /* In 1st interval */
};

typedef struct HPETState
{
    struct hpet_registers hpet;
    uint64_t stime_freq;
    uint64_t hpet_to_ns_scale; /* hpet ticks to ns (multiplied by 2^10) */
    uint64_t hpet_to_ns_limit; /* max hpet ticks convertable to ns      */
    uint64_t mc_offset;
    struct periodic_time pt[HPET_TIMER_NUM];
    spinlock_t lock;
} HPETState;

typedef struct PITState
{
    struct periodic_time pt0;
    spinlock_t lock;
} PITState;


struct pl_time      /* platform time */
{
    struct HPETState vhpet;
    /* guest_time = Xen sys time + stime_offset */
    int64_t stime_offset;
    /* Ensures monotonicity in appropriate timer modes. */
    uint64_t last_guest_time;
    spinlock_t pl_time_lock;
};

#define HVM_PARAM_HPET_ENABLED 11

struct hvm_domain
{
    struct pl_time         pl_time;
    long params[20];
};

struct arch_domain
{
    struct hvm_domain hvm_domain;
    struct PITState vpit;
};

struct domain
{
    int domain_id;
    struct arch_domain arch;
    struct vcpu *vcpu[NR_CPUS];
};

typedef int (*hvm_mmio_read_t)(struct vcpu *v,
                               unsigned long addr,
                               unsigned long length,
                               unsigned long *val);
typedef int (*hvm_mmio_write_t)(struct vcpu *v,
                                unsigned long addr,
                                unsigned long length,
                                unsigned long val);
typedef int (*hvm_mmio_check_t)(struct vcpu *v, unsigned long addr);


struct hvm_mmio_handler
{
    hvm_mmio_check_t check_handler;
    hvm_mmio_read_t read_handler;
    hvm_mmio_write_t write_handler;
};

/* Marshalling and unmarshalling uses a buffer with size and cursor. */
typedef struct hvm_domain_context
{
    uint32_t cur;
    uint32_t size;
    uint8_t *data;
} hvm_domain_context_t;

int current_domain_id(void);
#define dprintk(_l, _f, _a...)                  \
    printk(_l "%s:%d: " _f, __FILE__ , __LINE__ , ## _a )
#define gdprintk(_l, _f, _a...)                         \
    printk(XENLOG_GUEST _l "%s:%d:d%d " _f, __FILE__,   \
           __LINE__, current_domain_id() , ## _a )
struct vcpu *get_current();
#define current get_current()

#define HVM_SAVE_CODE(_x) HVM_SAVE_CODE_##_x
#define HVM_SAVE_LENGTH(_x) HVM_SAVE_LENGTH_##_x

/*
 * HPET
 */

uint64_t hvm_get_guest_time(struct vcpu *v);

#define HPET_TIMER_NUM     3    /* 3 timers supported now */
struct hvm_hw_hpet
{
    /* Memory-mapped, software visible registers */
    uint64_t capability;        /* capabilities */
    uint64_t res0;              /* reserved */
    uint64_t config;            /* configuration */
    uint64_t res1;              /* reserved */
    uint64_t isr;               /* interrupt status reg */
    uint64_t res2[25];          /* reserved */
    uint64_t mc64;              /* main counter */
    uint64_t res3;              /* reserved */
    struct                      /* timers */
    {
        uint64_t config;        /* configuration/cap */
        uint64_t cmp;           /* comparator */
        uint64_t fsb;           /* FSB route, not supported now */
        uint64_t res4;          /* reserved */
    } timers[HPET_TIMER_NUM];
    uint64_t res5[4 * (24 - HPET_TIMER_NUM)]; /* reserved, up to 0x3ff */

    /* Hidden register state */
    uint64_t period[HPET_TIMER_NUM]; /* Last value written to comparator */
};

typedef int (*hvm_save_handler)(struct domain *d,
                                hvm_domain_context_t *h);
typedef int (*hvm_load_handler)(struct domain *d,
                                hvm_domain_context_t *h);

struct hvm_save_descriptor
{
    uint16_t typecode;          /* Used to demux the various types below */
    uint16_t instance;          /* Further demux within a type */
    uint32_t length;            /* In bytes, *not* including this descriptor */
};

void hvm_register_savevm(uint16_t typecode,
                         const char *name,
                         hvm_save_handler save_state,
                         hvm_load_handler load_state,
                         size_t size, int kind);

#define HVMSR_PER_DOM 1

#define HVM_REGISTER_SAVE_RESTORE(_x, _save, _load, _num, _k)       \
    int __init __hvm_register_##_x##_save_and_restore(void)     \
    {                                                                   \
        hvm_register_savevm(HVM_SAVE_CODE(_x),                          \
                            #_x,                                        \
                            &_save,                                     \
                            &_load,                                     \
                            (_num) * (HVM_SAVE_LENGTH(_x)               \
                                 + sizeof(struct hvm_save_descriptor)), \
                            _k);                                        \
        return 0;                                                       \
    }                                                                   \

#define HVM_SAVE_CODE_HPET 0
#define HVM_SAVE_LENGTH_HPET sizeof(struct hvm_hw_hpet)

#define printk printf

#define spin_lock(a)
#define spin_unlock(a)
#define spin_lock_init(a)
#define spin_is_locked(a) 1
#define ASSERT(a)

#define ADDR (*(volatile long *) addr)

static inline void __set_bit(int nr, volatile void *addr)
{
    asm volatile(
        "btsl %1,%0"
        : "=m"(ADDR)
        : "Ir"(nr), "m"(ADDR) : "memory");
}

static inline void __clear_bit(int nr, volatile void *addr)
{
    asm volatile(
        "btrl %1,%0"
        : "=m"(ADDR)
        : "Ir"(nr), "m"(ADDR) : "memory");
}

static inline unsigned int find_first_set_bit(unsigned long word)
{
    asm("bsf %1,%0" : "=r"(word) : "r"(word));
    return (unsigned int)word;
}

#define HVM_DBG_LOG(level, _f, _a...)                   \
    do {                                \
        printf("[HVM:%d.%d] <%s> " _f "\n",                             \
               current->domain->domain_id, current->vcpu_id, __func__,  \
               ## _a);                                                  \
    } while ( 0 )

void __domain_crash(struct domain *d);
#define domain_crash(d) do {                        \
        printf("domain_crash called from %s:%d\n", __FILE__, __LINE__); \
        __domain_crash(d);                                              \
    } while ( 0 )

#define MICROSECS(_us) ((s_time_t)((_us) * 1000ULL))

#define pt_global_vcpu_target(d)        \
    ((d)->vcpu ? (d)->vcpu[0] : NULL)

#define TRACE_0D(a)
#define TRACE_1D(a, b)
#define TRACE_2D(a, b, c)
#define TRACE_3D(a, b, c, d)
#define TRACE_4D(a, b, c, d, e)
#define TRACE_5D(a, b, c, d, e, f)
#define TRACE_6D(a, b, c, d, e, f, g)

#define TRC_PAR_LONG(par) ((par)&0xFFFFFFFF),((par)>>32)

#define TRACE_2_LONG_2D(_e, d1, d2, ...) \
    TRACE_4D(_e, d1, d2)
#define TRACE_2_LONG_3D(_e, d1, d2, d3, ...) \
    TRACE_5D(_e, d1, d2, d3)
#define TRACE_2_LONG_4D(_e, d1, d2, d3, d4, ...) \
    TRACE_6D(_e, d1, d2, d3, d4)

/* debug */

extern int __read_mostly hpet_debug;
extern uint64_t __read_mostly hpet_force_diff;
extern uint64_t __read_mostly hpet_force_mc64;
extern uint64_t __read_mostly hpet_force_cmp;
extern uint64_t __read_mostly hpet_force_period;

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
