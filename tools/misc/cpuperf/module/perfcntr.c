/*
 * Linux loadable kernel module to use P4 performance counters.
 *
 * James Bulpin, Feb 2003.
 *
 * $Id$
 *
 * $Log$
 */

#define DRV_NAME        "perfcntr"
#define DRV_VERSION     "0.2"
#define DRV_RELDATE     "02 Jun 2004"


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/processor.h>

#define NOHT

#include "../p4perf.h"

#ifdef NOHT
# define CPUMASK 0x00000003
#else
# define CPUMASK 0x00000005
#endif

/*****************************************************************************
 * Module admin                                                              *
 *****************************************************************************/

MODULE_AUTHOR("James Bulpin <James.Bulpin@cl.cam.ac.uk>");
MODULE_DESCRIPTION("P4 Performance Counters access "
                   DRV_VERSION " " DRV_RELDATE);
MODULE_LICENSE("GPL");

static char version[] __devinitdata =
DRV_NAME ": James Bulpin.\n";

static unsigned char foobar[4];

/* rpcc: get full 64-bit Pentium TSC value
 */
static __inline__ unsigned long long int rpcc(void) 
{
    unsigned int __h, __l;
    __asm__ __volatile__ ("rdtsc" :"=a" (__l), "=d" (__h));
    return (((unsigned long long)__h) << 32) + __l;
}

/*****************************************************************************
 * Display the counters                                                      *
 *****************************************************************************/

//#define processor cpu // post 2.4.16

typedef union {
    struct {
        unsigned long lo;
        unsigned long hi;
    };
    unsigned long long cnt;
} cpu_perfcntr_t;

typedef struct counters_t_struct {
    int                processor;
    unsigned long long tsc;
    cpu_perfcntr_t     counters[18];
} counters_t;

typedef struct perfcntr_t_struct {
    unsigned long cpu_mask;
    counters_t    cpus[4]; // Actually for each cpu in system
} perfcntr_t;

#ifdef HUMAN_READABLE
# define SHOW_COUNTER(c) rdmsr (c, l, h);\
    seq_printf(m, "0x%03x: 0x%08x%08x\n", c, h, l)
#else
# define SHOW_COUNTER(c) rdmsr (c, l, h);\
    seq_printf(m, " %llu", \
               (unsigned long long)h << 32 | (unsigned long long)l)
#endif

#if 0
static unsigned long last_l = 0, last_h = 0, last_msr = 0;
static int last_cpu = 0;
#endif

#define READ_COUNTER(_i, _msr) rdmsr((_msr), l, h); c->counters[_i].lo = l; \
    c->counters[_i].hi = h;

static perfcntr_t perfcntrs;

static void show_perfcntr_for(void *v)
{
    unsigned int l, h;

    perfcntr_t *p = &perfcntrs;
    counters_t *c;

    if (!((1 << smp_processor_id()) & p->cpu_mask))
        return;

    c = &p->cpus[smp_processor_id()];

    c->processor = smp_processor_id();
    c->tsc = rpcc();

    READ_COUNTER(0,  MSR_P4_BPU_COUNTER0);
    READ_COUNTER(1,  MSR_P4_BPU_COUNTER1);
    READ_COUNTER(2,  MSR_P4_BPU_COUNTER2);
    READ_COUNTER(3,  MSR_P4_BPU_COUNTER3);

    READ_COUNTER(4,  MSR_P4_MS_COUNTER0);
    READ_COUNTER(5,  MSR_P4_MS_COUNTER1);
    READ_COUNTER(6,  MSR_P4_MS_COUNTER2);
    READ_COUNTER(7,  MSR_P4_MS_COUNTER3);

    READ_COUNTER(8,  MSR_P4_FLAME_COUNTER0);
    READ_COUNTER(9,  MSR_P4_FLAME_COUNTER1);
    READ_COUNTER(10, MSR_P4_FLAME_COUNTER2);
    READ_COUNTER(11, MSR_P4_FLAME_COUNTER3);

    READ_COUNTER(12, MSR_P4_IQ_COUNTER0);
    READ_COUNTER(13, MSR_P4_IQ_COUNTER1);
    READ_COUNTER(14, MSR_P4_IQ_COUNTER2);
    READ_COUNTER(15, MSR_P4_IQ_COUNTER3);
    READ_COUNTER(16, MSR_P4_IQ_COUNTER4);
    READ_COUNTER(17, MSR_P4_IQ_COUNTER5);

    return;    
}

static int show_perfcntr(struct seq_file *m, void *v)
{
    int i, j;

    // Get each physical cpu to read counters
    perfcntrs.cpu_mask = CPUMASK;

    smp_call_function(show_perfcntr_for, NULL, 1, 1);
    show_perfcntr_for(NULL);

    for (i = 0; i < 32; i++) {
        if (((1 << i) & (perfcntrs.cpu_mask = CPUMASK))) {
            counters_t *c = &perfcntrs.cpus[i];
            seq_printf(m, "%u %llu", c->processor, c->tsc);
            for (j = 0; j < 18; j++) {
                seq_printf(m, " %llu", c->counters[j].cnt);
            }
            seq_printf(m, "\n");
        }
    }

#if 0
    unsigned long long t;
    unsigned int l, h;

    t = rpcc();



#ifdef HUMAN_READABLE
    seq_printf(m,
               "show_perfcntr\nprocessor: %u\ntime: %llu\n"
               "last write: 0x%08lx%08lx -> 0x%lx (CPU%u)\n",
               smp_processor_id(),
               t,
               last_h,
               last_l,
               last_msr,
               last_cpu);
#else
    seq_printf(m, "%u %llu", smp_processor_id(), t);
#endif

    SHOW_COUNTER(MSR_P4_BPU_COUNTER0);
    SHOW_COUNTER(MSR_P4_BPU_COUNTER1);
    SHOW_COUNTER(MSR_P4_BPU_COUNTER2);
    SHOW_COUNTER(MSR_P4_BPU_COUNTER3);

    SHOW_COUNTER(MSR_P4_MS_COUNTER0);
    SHOW_COUNTER(MSR_P4_MS_COUNTER1);
    SHOW_COUNTER(MSR_P4_MS_COUNTER2);
    SHOW_COUNTER(MSR_P4_MS_COUNTER3);

    SHOW_COUNTER(MSR_P4_FLAME_COUNTER0);
    SHOW_COUNTER(MSR_P4_FLAME_COUNTER1);
    SHOW_COUNTER(MSR_P4_FLAME_COUNTER2);
    SHOW_COUNTER(MSR_P4_FLAME_COUNTER3);

    SHOW_COUNTER(MSR_P4_IQ_COUNTER0);
    SHOW_COUNTER(MSR_P4_IQ_COUNTER1);
    SHOW_COUNTER(MSR_P4_IQ_COUNTER2);
    SHOW_COUNTER(MSR_P4_IQ_COUNTER3);
    SHOW_COUNTER(MSR_P4_IQ_COUNTER4);
    SHOW_COUNTER(MSR_P4_IQ_COUNTER5);

#ifndef HUMAN_READBLE
    seq_printf(m, "\n");
#endif

#endif

    return 0;
}

/*****************************************************************************
 * Show counter configuration                                                *
 *****************************************************************************/

typedef union {
    struct {
        unsigned long lo;
        unsigned long hi;
    };
    unsigned long long cnt;
} cpu_perfcfg_t;

typedef struct configs_t_struct {
    int                processor;
    unsigned long long tsc;
    cpu_perfcfg_t      cccr[18];
    cpu_perfcfg_t      escr[0x42];
} configs_t;

typedef struct perfcfg_t_struct {
    unsigned long cpu_mask;
    configs_t     cpus[4]; // Actually for each cpu in system
} perfcfg_t;

static perfcfg_t perfcfgs;

#define READ_CCCR(_i, _msr) rdmsr((_msr), l, h); c->cccr[_i].lo = l; \
    c->cccr[_i].hi = h;
#define READ_ESCR(_i, _msr) rdmsr((_msr), l, h); c->escr[_i].lo = l; \
    c->escr[_i].hi = h;

static void show_perfcfg_for(void *v)
{
    unsigned int l, h;

    perfcfg_t *p = &perfcfgs;
    configs_t *c;

    if (!((1 << smp_processor_id()) & p->cpu_mask))
        return;

    c = &p->cpus[smp_processor_id()];

    c->processor = smp_processor_id();
    c->tsc = rpcc();

    READ_CCCR(0,  MSR_P4_BPU_CCCR0);
    READ_CCCR(1,  MSR_P4_BPU_CCCR1);
    READ_CCCR(2,  MSR_P4_BPU_CCCR2);
    READ_CCCR(3,  MSR_P4_BPU_CCCR3);

    READ_CCCR(4,  MSR_P4_MS_CCCR0);
    READ_CCCR(5,  MSR_P4_MS_CCCR1);
    READ_CCCR(6,  MSR_P4_MS_CCCR2);
    READ_CCCR(7,  MSR_P4_MS_CCCR3);

    READ_CCCR(8,  MSR_P4_FLAME_CCCR0);
    READ_CCCR(9,  MSR_P4_FLAME_CCCR1);
    READ_CCCR(10, MSR_P4_FLAME_CCCR2);
    READ_CCCR(11, MSR_P4_FLAME_CCCR3);

    READ_CCCR(12, MSR_P4_IQ_CCCR0);
    READ_CCCR(13, MSR_P4_IQ_CCCR1);
    READ_CCCR(14, MSR_P4_IQ_CCCR2);
    READ_CCCR(15, MSR_P4_IQ_CCCR3);
    READ_CCCR(16, MSR_P4_IQ_CCCR4);
    READ_CCCR(17, MSR_P4_IQ_CCCR5);

    READ_ESCR(0x00, MSR_P4_BSU_ESCR0);
    READ_ESCR(0x02, MSR_P4_FSB_ESCR0);
    READ_ESCR(0x0a, MSR_P4_MOB_ESCR0);
    READ_ESCR(0x0c, MSR_P4_PMH_ESCR0);
    READ_ESCR(0x12, MSR_P4_BPU_ESCR0);
    READ_ESCR(0x14, MSR_P4_IS_ESCR0);
    READ_ESCR(0x16, MSR_P4_ITLB_ESCR0);
    READ_ESCR(0x28, MSR_P4_IX_ESCR0);
    READ_ESCR(0x01, MSR_P4_BSU_ESCR1);
    READ_ESCR(0x03, MSR_P4_FSB_ESCR1);
    READ_ESCR(0x0b, MSR_P4_MOB_ESCR1);
    READ_ESCR(0x0d, MSR_P4_PMH_ESCR1);
    READ_ESCR(0x13, MSR_P4_BPU_ESCR1);
    READ_ESCR(0x15, MSR_P4_IS_ESCR1);
    READ_ESCR(0x17, MSR_P4_ITLB_ESCR1);
    READ_ESCR(0x29, MSR_P4_IX_ESCR1);
    READ_ESCR(0x20, MSR_P4_MS_ESCR0);
    READ_ESCR(0x22, MSR_P4_TBPU_ESCR0);
    READ_ESCR(0x24, MSR_P4_TC_ESCR0);
    READ_ESCR(0x21, MSR_P4_MS_ESCR1);
    READ_ESCR(0x23, MSR_P4_TBPU_ESCR1);
    READ_ESCR(0x25, MSR_P4_TC_ESCR1);
    READ_ESCR(0x04, MSR_P4_FIRM_ESCR0);
    READ_ESCR(0x06, MSR_P4_FLAME_ESCR0);
    READ_ESCR(0x08, MSR_P4_DAC_ESCR0);
    READ_ESCR(0x0e, MSR_P4_SAAT_ESCR0);
    READ_ESCR(0x10, MSR_P4_U2L_ESCR0);
    READ_ESCR(0x05, MSR_P4_FIRM_ESCR1);
    READ_ESCR(0x07, MSR_P4_FLAME_ESCR1);
    READ_ESCR(0x09, MSR_P4_DAC_ESCR1);
    READ_ESCR(0x0f, MSR_P4_SAAT_ESCR1);
    READ_ESCR(0x11, MSR_P4_U2L_ESCR1);
    READ_ESCR(0x18, MSR_P4_CRU_ESCR0);
    READ_ESCR(0x2c, MSR_P4_CRU_ESCR2);
    READ_ESCR(0x40, MSR_P4_CRU_ESCR4);
    READ_ESCR(0x1a, MSR_P4_IQ_ESCR0);
    READ_ESCR(0x1c, MSR_P4_RAT_ESCR0);
    READ_ESCR(0x1e, MSR_P4_SSU_ESCR0);
    READ_ESCR(0x2a, MSR_P4_ALF_ESCR0);
    READ_ESCR(0x19, MSR_P4_CRU_ESCR1);
    READ_ESCR(0x2d, MSR_P4_CRU_ESCR3);
    READ_ESCR(0x41, MSR_P4_CRU_ESCR5);
    READ_ESCR(0x1b, MSR_P4_IQ_ESCR1);
    READ_ESCR(0x1d, MSR_P4_RAT_ESCR1);
    READ_ESCR(0x2b, MSR_P4_ALF_ESCR1);

    return;    
}

static char *escr_names[] = {
    "BSU_ESCR0",
    "BSU_ESCR1",
    "FSB_ESCR0",
    "FSB_ESCR1",
    "FIRM_ESCR0",
    "FIRM_ESCR1",
    "FLAME_ESCR0",
    "FLAME_ESCR1",
    "DAC_ESCR0",
    "DAC_ESCR1",
    "MOB_ESCR0",
    "MOB_ESCR1",
    "PMH_ESCR0",
    "PMH_ESCR1",
    "SAAT_ESCR0",
    "SAAT_ESCR1",
    "U2L_ESCR0",
    "U2L_ESCR1",
    "BPU_ESCR0",
    "BPU_ESCR1",
    "IS_ESCR0",
    "IS_ESCR1",
    "ITLB_ESCR0",
    "ITLB_ESCR1",
    "CRU_ESCR0",
    "CRU_ESCR1",
    "IQ_ESCR0",
    "IQ_ESCR1",
    "RAT_ESCR0",
    "RAT_ESCR1",
    "SSU_ESCR0",
    "SSU_ESCR1",
    "MS_ESCR0",
    "MS_ESCR1",
    "TBPU_ESCR0",
    "TBPU_ESCR1",
    "TC_ESCR0",
    "TC_ESCR1",
    "0x3c6",
    "0x3c7",
    "IX_ESCR0",
    "IX_ESCR1",
    "ALF_ESCR0",
    "ALF_ESCR1",
    "CRU_ESCR2",
    "CRU_ESCR3",
    "0x3ce",
    "0x3cf",
    "0x3d0",
    "0x3d1",
    "0x3d2",
    "0x3d3",
    "0x3d4",
    "0x3d5",
    "0x3d6",
    "0x3d7",
    "0x3d8",
    "0x3d9",
    "0x3da",
    "0x3db",
    "0x3dc",
    "0x3dd",
    "0x3de",
    "0x3df",
    "CRU_ESCR4",
    "CRU_ESCR5"
};

static unsigned long escr_map_0[] = 
{MSR_P4_BPU_ESCR0, MSR_P4_IS_ESCR0,
 MSR_P4_MOB_ESCR0, MSR_P4_ITLB_ESCR0,
 MSR_P4_PMH_ESCR0, MSR_P4_IX_ESCR0,
 MSR_P4_FSB_ESCR0, MSR_P4_BSU_ESCR0}; //BPU even
static unsigned long escr_map_1[] = 
    {MSR_P4_BPU_ESCR1, MSR_P4_IS_ESCR1,
     MSR_P4_MOB_ESCR1, MSR_P4_ITLB_ESCR1,
     MSR_P4_PMH_ESCR1, MSR_P4_IX_ESCR1,
     MSR_P4_FSB_ESCR1, MSR_P4_BSU_ESCR1}; //BPU odd
static unsigned long escr_map_2[] = 
    {MSR_P4_MS_ESCR0, MSR_P4_TC_ESCR0, MSR_P4_TBPU_ESCR0,
     0, 0, 0, 0, 0}; //MS even
static unsigned long escr_map_3[] = 
    {MSR_P4_MS_ESCR1, MSR_P4_TC_ESCR1, MSR_P4_TBPU_ESCR1,
     0, 0, 0, 0, 0}; //MS odd
static unsigned long escr_map_4[] = 
    {MSR_P4_FLAME_ESCR0, MSR_P4_FIRM_ESCR0, MSR_P4_SAAT_ESCR0,
     MSR_P4_U2L_ESCR0, 0, MSR_P4_DAC_ESCR0, 0, 0}; //FLAME even
static unsigned long escr_map_5[] = 
    {MSR_P4_FLAME_ESCR1, MSR_P4_FIRM_ESCR1, MSR_P4_SAAT_ESCR1,
     MSR_P4_U2L_ESCR1, 0, MSR_P4_DAC_ESCR1, 0, 0}; //FLAME odd
static unsigned long escr_map_6[] = 
    {MSR_P4_IQ_ESCR0, MSR_P4_ALF_ESCR0,
     MSR_P4_RAT_ESCR0, MSR_P4_SSU_ESCR0,
     MSR_P4_CRU_ESCR0, MSR_P4_CRU_ESCR2, MSR_P4_CRU_ESCR4, 0}; //IQ even
static unsigned long escr_map_7[] = 
    {MSR_P4_IQ_ESCR1, MSR_P4_ALF_ESCR1,
     MSR_P4_RAT_ESCR1, 0,
     MSR_P4_CRU_ESCR1, MSR_P4_CRU_ESCR3, MSR_P4_CRU_ESCR5, 0}; //IQ odd

static unsigned long *escr_map[] = {
    escr_map_0,
    escr_map_1,
    escr_map_2,
    escr_map_3,
    escr_map_4,
    escr_map_5,
    escr_map_6,
    escr_map_7,
};

unsigned long get_escr_msr(int c, int e)
{
    int index = -1;

    // Get the ESCR MSR address from the counter number and the ESCR number.
    switch (c) {
    case P4_BPU_COUNTER0_NUMBER:
    case P4_BPU_COUNTER1_NUMBER:
	index = 0;
	break;
    case P4_BPU_COUNTER2_NUMBER:
    case P4_BPU_COUNTER3_NUMBER:	
	index = 1;
	break;
    case P4_MS_COUNTER0_NUMBER:
    case P4_MS_COUNTER1_NUMBER:
	index = 2; // probably !
	break;
    case P4_MS_COUNTER2_NUMBER:
    case P4_MS_COUNTER3_NUMBER:
	index = 3; // probably !
	break;
    case P4_FLAME_COUNTER0_NUMBER:
    case P4_FLAME_COUNTER1_NUMBER:
	index = 4; // probably !
	break;
    case P4_FLAME_COUNTER2_NUMBER:
    case P4_FLAME_COUNTER3_NUMBER:
	index = 5; // probably !
	break;
    case P4_IQ_COUNTER0_NUMBER:
    case P4_IQ_COUNTER1_NUMBER:
    case P4_IQ_COUNTER4_NUMBER:
	index = 6;
	break;
    case P4_IQ_COUNTER2_NUMBER:
    case P4_IQ_COUNTER3_NUMBER:
    case P4_IQ_COUNTER5_NUMBER:
	index = 7;
	break;
    }

    if (index != -1) {
	return escr_map[index][e];
    }

    return 0;
}

static char null_string[] = "";
static char *get_escr(int c, int e)
{
    unsigned long msr = get_escr_msr(c, e);

    if ((msr >= 0x3a0) && (msr <= 0x3e1))
	return escr_names[(int)(msr - 0x3a0)];
    return null_string;
}

static int show_perfcfg(struct seq_file *m, void *v)
{
    int i, j;

    // Get each physical cpu to read configs
    perfcfgs.cpu_mask = CPUMASK;

    smp_call_function(show_perfcfg_for, NULL, 1, 1);
    show_perfcfg_for(NULL);

    for (i = 0; i < 32; i++) {
        if (((1 << i) & (perfcfgs.cpu_mask = CPUMASK))) {
            configs_t *c = &perfcfgs.cpus[i];
            seq_printf(m, "----------------------------------------\n");
            seq_printf(m, "%u %llu\n", c->processor, c->tsc);
            for (j = 0; j < 18; j++) {
                seq_printf(m, "%08lx", c->cccr[j].lo);

		if (!(c->cccr[j].lo & P4_CCCR_ENABLE))
		    seq_printf(m, " DISABLED");
		else {
		    unsigned long escr_msr =
			get_escr_msr(i, (int)((c->cccr[j].lo >> 13)&7));
		    seq_printf(m, " ESCR=%s",
			       get_escr(i, (int)((c->cccr[j].lo >> 13)&7)));
		    if ((escr_msr >= 0x3a0) && (escr_msr <= 0x3e1)) {
			unsigned long e = c->escr[(int)(escr_msr - 0x3a0)].lo;
			seq_printf(m, "(%08lx es=%lx mask=%lx", e,
				   (e >> 25) & 0x7f,
				   (e >> 9) & 0xffff);
			if ((e & P4_ESCR_T0_USR))
			    seq_printf(m, " T(0)USR");
			if ((e & P4_ESCR_T0_OS))
			    seq_printf(m, " T(0)OS");
			if ((e & P4_ESCR_T1_USR))
			    seq_printf(m, " T1USR");
			if ((e & P4_ESCR_T1_OS))
			    seq_printf(m, " T1OS");
			seq_printf(m, ")");
		    }
		    seq_printf(m, " AT=%u", (int)((c->cccr[j].lo >> 16)&3));

		    if ((c->cccr[j].lo & P4_CCCR_OVF))
			seq_printf(m, " OVF");
		    if ((c->cccr[j].lo & P4_CCCR_CASCADE))
			seq_printf(m, " CASC");
		    if ((c->cccr[j].lo & P4_CCCR_FORCE_OVF))
			seq_printf(m, " F-OVF");
		    if ((c->cccr[j].lo & P4_CCCR_EDGE))
			seq_printf(m, " EDGE");
		    if ((c->cccr[j].lo & P4_CCCR_COMPLEMENT))
			seq_printf(m, " COMPL");
		    if ((c->cccr[j].lo & P4_CCCR_COMPARE))
			seq_printf(m, " CMP");
		    if ((c->cccr[j].lo & P4_CCCR_OVF_PMI_T0))
			seq_printf(m, " OVF_PMI(_T0)");
		    if ((c->cccr[j].lo & P4_CCCR_OVF_PMI_T1))
			seq_printf(m, " OVF_PMI_T1");
		}
		seq_printf(m, "\n");
            }
        }
    }

    return 0;
}

/*****************************************************************************
 * Handle writes                                                             *
 *****************************************************************************/

static int set_msr_cpu_mask;
static unsigned long set_msr_addr;
static unsigned long set_msr_lo;
static unsigned long set_msr_hi;

static void perfcntr_write_for(void *unused)
{
#ifdef NOHT
    if (((1 << smp_processor_id()) & set_msr_cpu_mask)) {
#endif
        //printk("perfcntr: wrmsr(%08lx, %08lx, %08lx)\n",
        //     set_msr_addr, set_msr_lo, set_msr_hi);
        wrmsr(set_msr_addr, set_msr_lo, set_msr_hi);
#ifdef NOHT
    }
#endif
}

ssize_t perfcntr_write(struct file *f,
                       const  char *data,
                       size_t       size,
                       loff_t      *pos)
{
    char         *endp;
    ssize_t       ret = 0;
    //unsigned long l, h, msr;
    unsigned long long v;

    set_msr_cpu_mask = (int)simple_strtoul(data, &endp, 16);
    endp++; // skip past space
    if ((endp - data) >= size) {
        ret = -EINVAL;
        goto out;
    }

    set_msr_addr = simple_strtoul(endp, &endp, 16);
    endp++; // skip past space
    if ((endp - data) >= size) {
        ret = -EINVAL;
        goto out;
    }
    
    v = simple_strtoul(endp, &endp, 16);
    set_msr_lo = (unsigned long)(v & 0xffffffffULL);
    set_msr_hi = (unsigned long)(v >> 32);

    smp_call_function(perfcntr_write_for, NULL, 1, 1);
    perfcntr_write_for(NULL);    

#if 0
    wrmsr(msr, l, h);
    last_l   = l;
    last_h   = h;
    last_msr = msr;
    last_cpu = smp_processor_id();
#endif
    ret = size;

 out:
    return ret;
}

/*****************************************************************************
 * /proc stuff                                                               *
 *****************************************************************************/

static void *c_start(struct seq_file *m, loff_t *pos)
{
    //return *pos < NR_CPUS ? cpu_data + *pos : NULL;
    return *pos == 0 ? foobar : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
    ++*pos;
    return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
}

struct seq_operations perfcntr_op = {
    start:  c_start,
    next:   c_next,
    stop:   c_stop,
    show:   show_perfcntr,
};

struct seq_operations perfcfg_op = {
    start:  c_start,
    next:   c_next,
    stop:   c_stop,
    show:   show_perfcfg,
};

static int perfcntr_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &perfcntr_op);
}

static int perfcfg_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &perfcfg_op);
}

static struct file_operations proc_perfcntr_operations = {
    open:           perfcntr_open,
    read:           seq_read,
    write:          perfcntr_write,
    llseek:         seq_lseek,
    release:        seq_release,
};

static struct file_operations proc_perfcfg_operations = {
    open:           perfcfg_open,
    read:           seq_read,
    write:          perfcntr_write,
    llseek:         seq_lseek,
    release:        seq_release,
};

static void create_seq_entry(char *name, mode_t mode, struct file_operations *f)
{
    struct proc_dir_entry *entry;
    entry = create_proc_entry(name, mode, NULL);
    if (entry)
        entry->proc_fops = f;
}

/*****************************************************************************
 * Module init and cleanup                                                   *
 *****************************************************************************/

static int __init perfcntr_init(void)
{
    printk(version);

    create_seq_entry("perfcntr", 0777, &proc_perfcntr_operations);
    create_seq_entry("perfcntr_config", 0777, &proc_perfcfg_operations);

    return 0;
}

static void __exit perfcntr_exit(void)
{
    remove_proc_entry("perfcntr", NULL);
    remove_proc_entry("perfcntr_config", NULL);
}

module_init(perfcntr_init);
module_exit(perfcntr_exit);

/* End of $RCSfile$ */
