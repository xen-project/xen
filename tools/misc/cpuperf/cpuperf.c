/*
 * User mode program to program performance counters.
 *
 * JRB/IAP October 2003.
 *
 * $Id: cpuperf.c,v 1.2 2003/10/14 11:00:59 jrb44 Exp $
 *
 * $Log: cpuperf.c,v $
 * Revision 1.2  2003/10/14 11:00:59  jrb44
 * Added dcefault CPU. Added NONE CCCR.
 *
 * Revision 1.1  2003/10/13 16:49:44  jrb44
 * Initial revision
 *
 */

#include <sys/types.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "p4perf.h"

static inline void cpus_wrmsr(int cpu_mask,
                              int msr,
                              unsigned int low,
                              unsigned int high )
{
    fprintf(stderr, "No backend to write MSR 0x%x <= 0x%08x%08x on %08x\n",
            msr, high, low, cpu_mask);
}

static inline unsigned long long cpus_rdmsr( int cpu_mask, int msr )
{
    fprintf(stderr, "No backend to read MSR 0x%x on %08x\n", msr, cpu_mask);
    return 0;
}

#ifdef PERFCNTR
#include "cpuperf_perfcntr.h"
#define cpus_wrmsr perfcntr_wrmsr
#define cpus_rdmsr perfcntr_rdmsr
#endif

#ifdef XENO
#include "cpuperf_xeno.h"
#define cpus_wrmsr dom0_wrmsr
#define cpus_rdmsr dom0_rdmsr
#endif

struct macros {
    char         *name;
    unsigned long msr_addr;
    int           number;
};

#define NO_CCCR 0xfffffffe

struct macros msr[] = {
    {"BPU_COUNTER0", 0x300, 0},
    {"BPU_COUNTER1", 0x301, 1},
    {"BPU_COUNTER2", 0x302, 2},
    {"BPU_COUNTER3", 0x303, 3},
    {"MS_COUNTER0", 0x304, 4},
    {"MS_COUNTER1", 0x305, 5},
    {"MS_COUNTER2", 0x306, 6},
    {"MS_COUNTER3", 0x307, 7},
    {"FLAME_COUNTER0", 0x308, 8},
    {"FLAME_COUNTER1", 0x309, 9},
    {"FLAME_COUNTER2", 0x30a, 10},
    {"FLAME_COUNTER3", 0x30b, 11},
    {"IQ_COUNTER0", 0x30c, 12},
    {"IQ_COUNTER1", 0x30d, 13},
    {"IQ_COUNTER2", 0x30e, 14},
    {"IQ_COUNTER3", 0x30f, 15},
    {"IQ_COUNTER4", 0x310, 16},
    {"IQ_COUNTER5", 0x311, 17},
    {"BPU_CCCR0", 0x360, 0},
    {"BPU_CCCR1", 0x361, 1},
    {"BPU_CCCR2", 0x362, 2},
    {"BPU_CCCR3", 0x363, 3},
    {"MS_CCCR0", 0x364, 4},
    {"MS_CCCR1", 0x365, 5},
    {"MS_CCCR2", 0x366, 6},
    {"MS_CCCR3", 0x367, 7},
    {"FLAME_CCCR0", 0x368, 8},
    {"FLAME_CCCR1", 0x369, 9},
    {"FLAME_CCCR2", 0x36a, 10},
    {"FLAME_CCCR3", 0x36b, 11},
    {"IQ_CCCR0", 0x36c, 12},
    {"IQ_CCCR1", 0x36d, 13},
    {"IQ_CCCR2", 0x36e, 14},
    {"IQ_CCCR3", 0x36f, 15},
    {"IQ_CCCR4", 0x370, 16},
    {"IQ_CCCR5", 0x371, 17},
    {"BSU_ESCR0", 0x3a0, 7},
    {"BSU_ESCR1", 0x3a1, 7},
    {"FSB_ESCR0", 0x3a2, 6},
    {"FSB_ESCR1", 0x3a3, 6},
    {"MOB_ESCR0", 0x3aa, 2},
    {"MOB_ESCR1", 0x3ab, 2},
    {"PMH_ESCR0", 0x3ac, 4},
    {"PMH_ESCR1", 0x3ad, 4},
    {"BPU_ESCR0", 0x3b2, 0},
    {"BPU_ESCR1", 0x3b3, 0},
    {"IS_ESCR0", 0x3b4, 1},
    {"IS_ESCR1", 0x3b5, 1},
    {"ITLB_ESCR0", 0x3b6, 3},
    {"ITLB_ESCR1", 0x3b7, 3},
    {"IX_ESCR0", 0x3c8, 5},
    {"IX_ESCR1", 0x3c9, 5},
    {"MS_ESCR0", 0x3c0, 0},
    {"MS_ESCR1", 0x3c1, 0},
    {"TBPU_ESCR0", 0x3c2, 2},
    {"TBPU_ESCR1", 0x3c3, 2},
    {"TC_ESCR0", 0x3c4, 1},
    {"TC_ESCR1", 0x3c5, 1},
    {"FIRM_ESCR0", 0x3a4, 1},
    {"FIRM_ESCR1", 0x3a5, 1},
    {"FLAME_ESCR0", 0x3a6, 0},
    {"FLAME_ESCR1", 0x3a7, 0},
    {"DAC_ESCR0", 0x3a8, 5},
    {"DAC_ESCR1", 0x3a9, 5},
    {"SAAT_ESCR0", 0x3ae, 2},
    {"SAAT_ESCR1", 0x3af, 2},
    {"U2L_ESCR0", 0x3b0, 3},
    {"U2L_ESCR1", 0x3b1, 3},
    {"CRU_ESCR0", 0x3b8, 4},
    {"CRU_ESCR1", 0x3b9, 4},
    {"CRU_ESCR2", 0x3cc, 5},
    {"CRU_ESCR3", 0x3cd, 5},
    {"CRU_ESCR4", 0x3e0, 6},
    {"CRU_ESCR5", 0x3e1, 6},
    {"IQ_ESCR0", 0x3ba, 0},
    {"IQ_ESCR1", 0x3bb, 0},
    {"RAT_ESCR0", 0x3bc, 2},
    {"RAT_ESCR1", 0x3bd, 2},
    {"SSU_ESCR0", 0x3be, 3},
    {"SSU_ESCR1", 0x3bf, 3},
    {"ALF_ESCR0", 0x3ca, 1},
    {"ALF_ESCR1", 0x3cb, 1},
    {"PEBS_ENABLE", 0x3f1, 0},
    {"PEBS_MATRIX_VERT", 0x3f2, 0},
    {"NONE", NO_CCCR, 0},
    {NULL, 0, 0}
};

struct macros *lookup_macro(char *str)
{
    struct macros *m;

    m = msr;
    while (m->name) {
        if (strcmp(m->name, str) == 0)
            return m;
        m++;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    int c, t = 0xc, es = 0, em = 0, tv = 0, te = 0;
    unsigned int cpu_mask = 1;
    struct macros *escr = NULL, *cccr = NULL;
    unsigned long escr_val, cccr_val;
    int debug = 0;
    unsigned long pebs = 0, pebs_vert = 0;
    int pebs_x = 0, pebs_vert_x = 0;
    int read = 0;
    int compare = 0;
    int complement = 0;
    int edge = 0;
    
#ifdef XENO
    xen_init();
#endif


    while ((c = getopt(argc, argv, "dc:t:e:m:T:E:C:P:V:rkng")) != -1) {
        switch((char)c) {
        case 'P':
            pebs |= 1 << atoi(optarg);
            pebs_x = 1;
            break;
        case 'V':
            pebs_vert |= 1 << atoi(optarg);
            pebs_vert_x = 1;
            break;
        case 'd':
            debug = 1;
            break;
        case 'c':
            {
                int cpu = atoi(optarg);
                cpu_mask  = (cpu == -1)?(~0):(1<<cpu);
            }
            break;
        case 't': // ESCR thread bits
            t = atoi(optarg);
            break;
        case 'e': // eventsel
            es = atoi(optarg);
            break;
        case 'm': // eventmask
            em = atoi(optarg);
            break;
        case 'T': // tag value
            tv = atoi(optarg);
            te = 1;
            break;
        case 'E':
            escr = lookup_macro(optarg);
            if (!escr) {
                fprintf(stderr, "Macro '%s' not found.\n", optarg);
                exit(1);
            }
            break;
        case 'C':
            cccr = lookup_macro(optarg);
            if (!cccr) {
                fprintf(stderr, "Macro '%s' not found.\n", optarg);
                exit(1);
            }
            break;
        case 'r':
            read = 1;
            break;
        case 'k':
            compare = 1;
            break;
        case 'n':
            complement = 1;
            break;
        case 'g':
            edge = 1;
            break;
        }
    }

    if (read) {
        int i;
        for (i=0x300;i<0x312;i++)
            printf("%010llu ",cpus_rdmsr( cpu_mask, i ) );
        printf("\n");
        exit(1);
    }
    
    if (!escr) {
        fprintf(stderr, "Need an ESCR.\n");
        exit(1);
    }
    if (!cccr) {
        fprintf(stderr, "Need a counter number.\n");
        exit(1);
    }

    escr_val = P4_ESCR_THREADS(t) | P4_ESCR_EVNTSEL(es) |
        P4_ESCR_EVNTMASK(em) | P4_ESCR_TV(tv) | ((te)?P4_ESCR_TE:0);
    cccr_val = P4_CCCR_ENABLE | P4_CCCR_ESCR(escr->number) |
        ((compare)?P4_CCCR_COMPARE:0) |
        ((complement)?P4_CCCR_COMPLEMENT:0) |
        ((edge)?P4_CCCR_EDGE:0) |
        P4_CCCR_ACTIVE_THREAD(3)/*reserved*/;

    if (debug) {
        fprintf(stderr, "ESCR 0x%lx <= 0x%08lx\n", escr->msr_addr, escr_val);
        if (cccr->msr_addr != NO_CCCR)
            fprintf(stderr, "CCCR 0x%lx <= 0x%08lx (%u)\n",
                    cccr->msr_addr, cccr_val, cccr->number);
        if (pebs_x)
            fprintf(stderr, "PEBS 0x%x <= 0x%08lx\n",
                    MSR_P4_PEBS_ENABLE, pebs);
        if (pebs_vert_x)
            fprintf(stderr, "PMV  0x%x <= 0x%08lx\n",
                    MSR_P4_PEBS_MATRIX_VERT, pebs_vert);
    }
    
    cpus_wrmsr( cpu_mask, escr->msr_addr, escr_val, 0 );
    if (cccr->msr_addr != NO_CCCR)
        cpus_wrmsr( cpu_mask, cccr->msr_addr, cccr_val, 0 );
    
    if (pebs_x)
        cpus_wrmsr( cpu_mask, MSR_P4_PEBS_ENABLE, pebs, 0 );
    
    if (pebs_vert_x)
        cpus_wrmsr( cpu_mask, MSR_P4_PEBS_MATRIX_VERT, pebs_vert, 0 );
    
    return 0;
}

// End of $RCSfile: cpuperf.c,v $

