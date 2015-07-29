/*
 * xenalyze.c: Analyzing xentrace output
 *
 * Written by George Dunlap.
 *
 * Copyright (c) 2006-2007, XenSource Inc.
 * Copyright (c) 2007-2008, Citrix Systems R&D Ltd, UK
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
#define _XOPEN_SOURCE 600
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <xen/trace.h>
#include "analyze.h"
#include "mread.h"
#include "pv.h"
#include <errno.h>
#include <strings.h>
#include <string.h>
#include <assert.h>

struct mread_ctrl;


#define DEFAULT_CPU_HZ 2400000000LL
#define QHZ_FROM_HZ(_hz) (((_hz) << 10)/ 1000000000)

#define ADDR_SPACE_BITS 48
#define DEFAULT_SAMPLE_SIZE 10240
#define DEFAULT_INTERVAL_LENGTH 1000

struct array_struct {
    unsigned long long *values;
    int count;
};

#define warn_once(_x...)                          \
    do {                                          \
        static int _w=1;                          \
        if ( _w ) {                               \
            _w=0;                                 \
            fprintf(warn, ##_x);                  \
        }                                         \
    } while(0)                                    \

/* -- Global variables -- */
struct {
    int fd;
    struct mread_ctrl *mh;
    struct symbol_struct * symbols;
    char * symbol_file;
    char * trace_file;
    int output_defined;
    off_t file_size;
    struct {
        off_t update_offset;
        int pipe[2];
        FILE* out;
        int pid;
    } progress;
} G = {
    .fd=-1,
    .symbols = NULL,
    .symbol_file = NULL,
    .trace_file = NULL,
    .output_defined = 0,
    .file_size = 0,
    .progress = { .update_offset = 0 },
};

/*
  Kinds of errors:
   Unexpected values
    - RIP with information in high bits (not all 0 or 1)
    - exit reason too high
   Unexpected record layout
    - x64 bit set in PIO,PV_PTWR_EMULATION_PAE,
    - Unknown minor type (PV_PTWR_EMULATION, RUNSTATE_CHANGE
    - Wrong record size
    - More than one bit set in evt.main field
   Unexpected sequences
    - wake tsc tracking
    - TSC dependency loop
    - Mismatch between non-running old event states
    - Runstate continue while running on another pcpu
    - lost_record_end seen in non-lost pcpu
    - Unexpected non-CPU_CHANGE record during new_pcpu scan
    - record tsc < interval start tsc
    - lost_record tsc !> order tsc
   Limited resources
    - interrupt interval slots
    - record cpu > MAX_CPUS
   Algorithm asserts
    - Duplicate CR3/domain values
    - Logic holes
     - domain runstates
     - runstate / tsc skew
    - vcpu_{prev,next}_update p->current{==,!=}null
    - vcpu start conditions
    - lost_cpu count higher than # of seen cpus / < 0
    - lost cpu has non-null p->current
   Symbol file
    -file doesn't open
    -file not ordered
   System
    - short read
    - malloc failed
   Args
    - Invalid cpu_hz value / suffix
    - No trace file
    - Can't open trace file
*/
enum error_level {
    ERR_NONE=0,
    ERR_STRICT, /* Be unreasonably picky */
    ERR_WARN,   /* Something midly unexpected */
    ERR_SANITY, /* Sanity checks: RIP with info in high bits */
    ERR_RECORD, /* Something that keeps you from processing the record */
    ERR_FILE,   /* Probably caused by a corrupt file */
    ERR_LIMIT,  /* Exceeded limits; data will be lost */
    ERR_MAX_TOLERABLE=ERR_LIMIT,
    /* -- Unrecoverable past this point -- */
    ERR_ASSERT, /* Algoritm assert */
    ERR_SYSTEM, /* System error: cannot allocate memory, short read, &c */
};

int verbosity = 5;

struct {
    unsigned
        scatterplot_interrupt_eip:1,
        scatterplot_cpi:1,
        scatterplot_unpin_promote:1,
        scatterplot_cr3_switch:1,
        scatterplot_wake_to_halt:1,
        scatterplot_io:1,
        scatterplot_vmexit_eip:1,
        scatterplot_runstate:1,
        scatterplot_runstate_time:1,
        scatterplot_pcpu:1,
        scatterplot_extint_cycles:1,
        scatterplot_rdtsc:1,
        scatterplot_irq:1,
        histogram_interrupt_eip:1,
        interval_mode:1,
        dump_all:1,
        dump_raw_process:1,
        dump_raw_reads:1,
        dump_no_processing:1,
        dump_ipi_latency:1,
        dump_trace_volume_on_lost_record:1,
        dump_show_power_states:1,
        with_cr3_enumeration:1,
        with_pio_enumeration:1,
        with_mmio_enumeration:1,
        with_interrupt_eip_enumeration:1,
        show_default_domain_summary:1,
        mmio_enumeration_skip_vga:1,
        progress:1,
        svm_mode:1,
        summary:1,
        report_pcpu:1,
        tsc_loop_fatal:1,
        summary_info;
    long long cpu_qhz, cpu_hz;
    int scatterplot_interrupt_vector;
    int scatterplot_extint_cycles_vector;
    int scatterplot_io_port;
    int histogram_interrupt_vector;
    unsigned long long histogram_interrupt_increment;
    int interrupt_eip_enumeration_vector;
    int default_guest_paging_levels;
    int sample_size;
    enum error_level tolerance; /* Tolerate up to this level of error */
    struct {
        tsc_t cycles;
        /* Used if interval is specified in seconds to delay calculating
         * time_interval until all arguments have been processed (specifically,
         * cpu_hz). */
        unsigned msec;
        enum {
            INTERVAL_CR3_SCHEDULE_TIME,
            INTERVAL_CR3_SCHEDULE_ORDERED,
            INTERVAL_CR3_SHORT_SUMMARY,
            INTERVAL_DOMAIN_TOTAL_TIME,
            INTERVAL_DOMAIN_SHORT_SUMMARY,
            INTERVAL_DOMAIN_GUEST_INTERRUPT,
            INTERVAL_DOMAIN_GRANT_MAPS
        } output;
        enum {
            INTERVAL_MODE_CUSTOM,
            INTERVAL_MODE_ARRAY,
            INTERVAL_MODE_LIST
        } mode;
        enum {
            INTERVAL_CHECK_NONE,
            INTERVAL_CHECK_CR3,
            INTERVAL_CHECK_DOMAIN
        } check;
        /* Options for specific interval output types */
        union {
            struct array_struct array;
        };
        int count;
    } interval;
} opt = {
    .scatterplot_interrupt_eip=0,
    .scatterplot_cpi=0,
    .scatterplot_unpin_promote=0,
    .scatterplot_cr3_switch=0,
    .scatterplot_wake_to_halt=0,
    .scatterplot_vmexit_eip=0,
    .scatterplot_runstate=0,
    .scatterplot_runstate_time=0,
    .scatterplot_pcpu=0,
    .scatterplot_extint_cycles=0,
    .scatterplot_rdtsc=0,
    .scatterplot_irq=0,
    .histogram_interrupt_eip=0,
    .dump_all = 0,
    .dump_raw_process = 0,
    .dump_raw_reads = 0,
    .dump_no_processing = 0,
    .dump_ipi_latency = 0,
    .dump_trace_volume_on_lost_record = 0,
    .dump_show_power_states = 0,
    .with_cr3_enumeration = 0,
    .with_pio_enumeration = 1,
    .with_mmio_enumeration = 0,
    .with_interrupt_eip_enumeration = 0,
    .show_default_domain_summary = 0,
    .mmio_enumeration_skip_vga = 1,
    .progress = 0,
    .svm_mode = 0,
    .summary = 0,
    .report_pcpu = 0,
    .tsc_loop_fatal = 0,
    .cpu_hz = DEFAULT_CPU_HZ,
    /* Pre-calculate a multiplier that makes the rest of the
     * calculations easier */
    .cpu_qhz = QHZ_FROM_HZ(DEFAULT_CPU_HZ),
    .default_guest_paging_levels = 2,
    .sample_size = DEFAULT_SAMPLE_SIZE,
    .tolerance = ERR_SANITY,
    .interval = { .msec = DEFAULT_INTERVAL_LENGTH },
};

FILE *warn = NULL;

/* -- Summary data -- */
struct cycle_framework {
    tsc_t first_tsc, last_tsc, total_cycles;
};

struct interval_element {
    int count;
    long long cycles;
    long long instructions;
};

struct event_cycle_summary {
    int count, cycles_count;
    long long cycles;
    long long *cycles_sample;
    struct interval_element interval;
};

struct cycle_summary {
    int count;
    unsigned long long cycles;
    long long *sample;
    struct interval_element interval;
};

struct weighted_cpi_summary {
    int count;
    unsigned long long instructions;
    unsigned long long cycles;
    float *cpi;
    unsigned long long *cpi_weight;
    struct interval_element interval;
};

/* -- Symbol list information -- */
#define SYMBOL_ENTRIES_PER_STRUCT 1023
#define SYMBOL_NAME_SIZE 124
struct symbol_struct {
    int count;
    struct {
        unsigned long long addr;
        char name[SYMBOL_NAME_SIZE];
    } symbols[SYMBOL_ENTRIES_PER_STRUCT];
    struct symbol_struct *next;
};

void error(enum error_level l, struct record_info *ri);

void parse_symbol_file(char *fn) {
    unsigned long long last_addr = 0;
    FILE * symbol_file;
    struct symbol_struct ** p=&G.symbols;

    if((symbol_file=fopen(fn, "rb"))==NULL) {
        fprintf(stderr, "Could not open symbol file %s\n", fn);
        perror("open");
        error(ERR_SYSTEM, NULL);
    }
    while(!feof(symbol_file)) {
        /* Allocate a new struct if we need it */
        if(!*p) {
            *p = malloc(sizeof(**p));
            if(!*p) {
                fprintf(stderr, "Malloc failed!\n");
                error(ERR_SYSTEM, NULL);
            }
            (*p)->count=0;
            (*p)->next=NULL;
        }

        /* FIXME -- use SYMBOL_NAME_SIZE */
        /* FIXME -- use regexp.  This won't work for symbols with spaces (yes they exist) */
        (*p)->symbols[(*p)->count].addr = 0xDEADBEEF;
        if ( fscanf(symbol_file, "%llx %128s",
               &(*p)->symbols[(*p)->count].addr,
                    (*p)->symbols[(*p)->count].name) == 0 )
            break;


        if( ((*p)->symbols[(*p)->count].addr > 0)
            && ((*p)->symbols[(*p)->count].addr < last_addr) )  {
            fprintf(stderr, "Symbol file not properly ordered: %llx %s < %llx!\n",
                    (*p)->symbols[(*p)->count].addr,
                    (*p)->symbols[(*p)->count].name,
                    last_addr);
            /* Could be recovered from; just free existing strings and set symbols to NULL */
            error(ERR_ASSERT, NULL);
        } else
            last_addr = (*p)->symbols[(*p)->count].addr;

        (*p)->count++;

        /* If this struct is full, point to the next.  It will be allocated
           if needed. */
        if((*p)->count == SYMBOL_ENTRIES_PER_STRUCT) {
            p=&((*p)->next);
        }
    }
}

/* WARNING not thread safe */
char * find_symbol(unsigned long long addr) {
    struct symbol_struct * p=G.symbols;
    int i;
    char * lastname="ZERO";
    unsigned long long offset=addr;
    static char name[128];

    if(!p) {
        name[0]=0;
        return name;
    }

    while(1) {
        if(!p)
            goto finish;
        for(i=0; i<p->count; i++) {
            if(p->symbols[i].addr > addr)
                goto finish;
            else {
                lastname=p->symbols[i].name;
                offset=addr - p->symbols[i].addr;
            }
        }
        p=p->next;
    }
 finish:
    snprintf(name, 128, "(%s +%llx)",
             lastname, offset);
    return name;
}

/* -- Eip list data -- */
enum {
    EIP_LIST_TYPE_NONE=0,
    EIP_LIST_TYPE_MAX
};

struct eip_list_struct {
    struct eip_list_struct *next;
    unsigned long long eip;
    struct event_cycle_summary summary;
    int type;
    void * extra;
};

struct {
    void (*update)(struct eip_list_struct *, void *);
    void (*new)(struct eip_list_struct *, void *);
    void (*dump)(struct eip_list_struct *);
} eip_list_type[EIP_LIST_TYPE_MAX] = {
    [EIP_LIST_TYPE_NONE] = {
        .update=NULL,
        .new=NULL,
        .dump=NULL },
};


/* --- HVM class of events --- */

/*
 *  -- Algorithms --
 *
 * Interrupt Wake-to-halt detection
 *
 * Purpose: To correlate device interrupts to vcpu runtime.
 *
 * Diagram:
 *  ...
 *  blocked  -> runnable     <- set to waking
 *  ...
 *  runnable -> running
 *  inj_virq A               <- Note "waking" interrupt
 *  vmenter                  <- Start tsc of "wake-to-halt" interval.
                                Turn off 'waking'.
 *  ...
 *  inj_virq B               <- Note alternate interrupt
 *  vmenter                  <- Start tsc of "interrupt-to-halt" interval
 *  ...
 *  vmexit                   <- End tsc of "x-to-halt" interval
 *  running -> blocked       <- Process
 *
 *  The "waking" interrupts we want to sub-classify into
 *  "wake-only" (when interrupt was the only interrupt from wake to halt) and
 *  "wake-all"  (whether this was the only interrupt or not).
 */

/* VMX data */
#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_IO_SMI              5
#define EXIT_REASON_OTHER_SMI           6
#define EXIT_REASON_PENDING_INTERRUPT   7
#define EXIT_REASON_PENDING_VIRT_NMI    8
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_GETSEC              11
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM                 17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMOFF               26
#define EXIT_REASON_VMON                27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_GUEST_STATE 33
#define EXIT_REASON_MSR_LOADING         34
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_TRAP_FLAG   37
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MACHINE_CHECK       41
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_ACCESS_GDTR_OR_IDTR 46
#define EXIT_REASON_ACCESS_LDTR_OR_TR   47
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_RDTSCP              51
#define EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED 52
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55

#define HVM_VMX_EXIT_REASON_MAX (EXIT_REASON_XSETBV+1)

char * hvm_vmx_exit_reason_name[HVM_VMX_EXIT_REASON_MAX] = {
    [0] = "NONE",
    [EXIT_REASON_EXCEPTION_NMI]="EXCEPTION_NMI",
    [EXIT_REASON_EXTERNAL_INTERRUPT]="EXTERNAL_INTERRUPT",
    [EXIT_REASON_TRIPLE_FAULT]="TRIPLE_FAULT",
    [EXIT_REASON_INIT]="INIT",
    [EXIT_REASON_SIPI]="SIPI",
    [EXIT_REASON_IO_SMI]="IO_SMI",
    [EXIT_REASON_OTHER_SMI]="OTHER_SMI",
    [EXIT_REASON_PENDING_INTERRUPT]="PENDING_INTERRUPT",
    [EXIT_REASON_PENDING_VIRT_NMI]="PENDING_VIRT_NMI",
    [EXIT_REASON_TASK_SWITCH]="TASK_SWITCH",
    [EXIT_REASON_CPUID]="CPUID",
    [EXIT_REASON_GETSEC]="GETSEC",
    [EXIT_REASON_HLT]="HLT",
    [EXIT_REASON_INVD]="INVD",
    [EXIT_REASON_INVLPG]="INVLPG",
    [EXIT_REASON_RDPMC]="RDPMC",
    [EXIT_REASON_RDTSC]="RDTSC",
    [EXIT_REASON_RSM]="RSM",
    [EXIT_REASON_VMCALL]="VMCALL",
    [EXIT_REASON_VMCLEAR]="VMCLEAR",
    [EXIT_REASON_VMLAUNCH]="VMLAUNCH",
    [EXIT_REASON_VMPTRLD]="VMPTRLD",
    [EXIT_REASON_VMPTRST]="VMPTRST",
    [EXIT_REASON_VMREAD]="VMREAD",
    [EXIT_REASON_VMRESUME]="VMRESUME",
    [EXIT_REASON_VMWRITE]="VMWRITE",
    [EXIT_REASON_VMOFF]="VMOFF",
    [EXIT_REASON_VMON]="VMON",
    [EXIT_REASON_CR_ACCESS]="CR_ACCESS",
    [EXIT_REASON_DR_ACCESS]="DR_ACCESS",
    [EXIT_REASON_IO_INSTRUCTION]="IO_INSTRUCTION",
    [EXIT_REASON_MSR_READ]="MSR_READ",
    [EXIT_REASON_MSR_WRITE]="MSR_WRITE",
    [EXIT_REASON_INVALID_GUEST_STATE]="INVALID_GUEST_STATE",
    [EXIT_REASON_MSR_LOADING]="MSR_LOADING",
    [EXIT_REASON_MWAIT_INSTRUCTION]="MWAIT_INSTRUCTION",
    [EXIT_REASON_MONITOR_TRAP_FLAG]="MONITOR_TRAP_FLAG",
    [EXIT_REASON_MONITOR_INSTRUCTION]="MONITOR_INSTRUCTION",
    [EXIT_REASON_PAUSE_INSTRUCTION]="PAUSE_INSTRUCTION",
    [EXIT_REASON_MACHINE_CHECK]="MACHINE_CHECK",
    [EXIT_REASON_TPR_BELOW_THRESHOLD]="TPR_BELOW_THRESHOLD",
    [EXIT_REASON_APIC_ACCESS]="APIC_ACCESS",
    [EXIT_REASON_EPT_VIOLATION]="EPT_VIOLATION",
    [EXIT_REASON_EPT_MISCONFIG]="EPT_MISCONFIG",
    [EXIT_REASON_INVEPT]="INVEPT",
    [EXIT_REASON_RDTSCP]="RDTSCP",
    [EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED]="VMX_PREEMPTION_TIMER_EXPIRED",
    [EXIT_REASON_INVVPID]="INVVPID",
    [EXIT_REASON_WBINVD]="WBINVD",
    [EXIT_REASON_XSETBV]="XSETBV",
};

/* SVM data */
enum VMEXIT_EXITCODE
{
    /* control register read exitcodes */
    VMEXIT_CR0_READ    =   0,
    VMEXIT_CR1_READ    =   1,
    VMEXIT_CR2_READ    =   2,
    VMEXIT_CR3_READ    =   3,
    VMEXIT_CR4_READ    =   4,
    VMEXIT_CR5_READ    =   5,
    VMEXIT_CR6_READ    =   6,
    VMEXIT_CR7_READ    =   7,
    VMEXIT_CR8_READ    =   8,
    VMEXIT_CR9_READ    =   9,
    VMEXIT_CR10_READ   =  10,
    VMEXIT_CR11_READ   =  11,
    VMEXIT_CR12_READ   =  12,
    VMEXIT_CR13_READ   =  13,
    VMEXIT_CR14_READ   =  14,
    VMEXIT_CR15_READ   =  15,

    /* control register write exitcodes */
    VMEXIT_CR0_WRITE   =  16,
    VMEXIT_CR1_WRITE   =  17,
    VMEXIT_CR2_WRITE   =  18,
    VMEXIT_CR3_WRITE   =  19,
    VMEXIT_CR4_WRITE   =  20,
    VMEXIT_CR5_WRITE   =  21,
    VMEXIT_CR6_WRITE   =  22,
    VMEXIT_CR7_WRITE   =  23,
    VMEXIT_CR8_WRITE   =  24,
    VMEXIT_CR9_WRITE   =  25,
    VMEXIT_CR10_WRITE  =  26,
    VMEXIT_CR11_WRITE  =  27,
    VMEXIT_CR12_WRITE  =  28,
    VMEXIT_CR13_WRITE  =  29,
    VMEXIT_CR14_WRITE  =  30,
    VMEXIT_CR15_WRITE  =  31,

    /* debug register read exitcodes */
    VMEXIT_DR0_READ    =  32,
    VMEXIT_DR1_READ    =  33,
    VMEXIT_DR2_READ    =  34,
    VMEXIT_DR3_READ    =  35,
    VMEXIT_DR4_READ    =  36,
    VMEXIT_DR5_READ    =  37,
    VMEXIT_DR6_READ    =  38,
    VMEXIT_DR7_READ    =  39,
    VMEXIT_DR8_READ    =  40,
    VMEXIT_DR9_READ    =  41,
    VMEXIT_DR10_READ   =  42,
    VMEXIT_DR11_READ   =  43,
    VMEXIT_DR12_READ   =  44,
    VMEXIT_DR13_READ   =  45,
    VMEXIT_DR14_READ   =  46,
    VMEXIT_DR15_READ   =  47,

    /* debug register write exitcodes */
    VMEXIT_DR0_WRITE   =  48,
    VMEXIT_DR1_WRITE   =  49,
    VMEXIT_DR2_WRITE   =  50,
    VMEXIT_DR3_WRITE   =  51,
    VMEXIT_DR4_WRITE   =  52,
    VMEXIT_DR5_WRITE   =  53,
    VMEXIT_DR6_WRITE   =  54,
    VMEXIT_DR7_WRITE   =  55,
    VMEXIT_DR8_WRITE   =  56,
    VMEXIT_DR9_WRITE   =  57,
    VMEXIT_DR10_WRITE  =  58,
    VMEXIT_DR11_WRITE  =  59,
    VMEXIT_DR12_WRITE  =  60,
    VMEXIT_DR13_WRITE  =  61,
    VMEXIT_DR14_WRITE  =  62,
    VMEXIT_DR15_WRITE  =  63,

    /* processor exception exitcodes (VMEXIT_EXCP[0-31]) */
    VMEXIT_EXCEPTION_DE  =  64, /* divide-by-zero-error */
    VMEXIT_EXCEPTION_DB  =  65, /* debug */
    VMEXIT_EXCEPTION_NMI =  66, /* non-maskable-interrupt */
    VMEXIT_EXCEPTION_BP  =  67, /* breakpoint */
    VMEXIT_EXCEPTION_OF  =  68, /* overflow */
    VMEXIT_EXCEPTION_BR  =  69, /* bound-range */
    VMEXIT_EXCEPTION_UD  =  70, /* invalid-opcode*/
    VMEXIT_EXCEPTION_NM  =  71, /* device-not-available */
    VMEXIT_EXCEPTION_DF  =  72, /* double-fault */
    VMEXIT_EXCEPTION_09  =  73, /* unsupported (reserved) */
    VMEXIT_EXCEPTION_TS  =  74, /* invalid-tss */
    VMEXIT_EXCEPTION_NP  =  75, /* segment-not-present */
    VMEXIT_EXCEPTION_SS  =  76, /* stack */
    VMEXIT_EXCEPTION_GP  =  77, /* general-protection */
    VMEXIT_EXCEPTION_PF  =  78, /* page-fault */
    VMEXIT_EXCEPTION_15  =  79, /* reserved */
    VMEXIT_EXCEPTION_MF  =  80, /* x87 floating-point exception-pending */
    VMEXIT_EXCEPTION_AC  =  81, /* alignment-check */
    VMEXIT_EXCEPTION_MC  =  82, /* machine-check */
    VMEXIT_EXCEPTION_XF  =  83, /* simd floating-point */

    /* exceptions 20-31 (exitcodes 84-95) are reserved */

    /* ...and the rest of the #VMEXITs */
    VMEXIT_INTR             =  96,
    VMEXIT_NMI              =  97,
    VMEXIT_SMI              =  98,
    VMEXIT_INIT             =  99,
    VMEXIT_VINTR            = 100,
    VMEXIT_CR0_SEL_WRITE    = 101,
    VMEXIT_IDTR_READ        = 102,
    VMEXIT_GDTR_READ        = 103,
    VMEXIT_LDTR_READ        = 104,
    VMEXIT_TR_READ          = 105,
    VMEXIT_IDTR_WRITE       = 106,
    VMEXIT_GDTR_WRITE       = 107,
    VMEXIT_LDTR_WRITE       = 108,
    VMEXIT_TR_WRITE         = 109,
    VMEXIT_RDTSC            = 110,
    VMEXIT_RDPMC            = 111,
    VMEXIT_PUSHF            = 112,
    VMEXIT_POPF             = 113,
    VMEXIT_CPUID            = 114,
    VMEXIT_RSM              = 115,
    VMEXIT_IRET             = 116,
    VMEXIT_SWINT            = 117,
    VMEXIT_INVD             = 118,
    VMEXIT_PAUSE            = 119,
    VMEXIT_HLT              = 120,
    VMEXIT_INVLPG           = 121,
    VMEXIT_INVLPGA          = 122,
    VMEXIT_IOIO             = 123,
    VMEXIT_MSR              = 124,
    VMEXIT_TASK_SWITCH      = 125,
    VMEXIT_FERR_FREEZE      = 126,
    VMEXIT_SHUTDOWN         = 127,
    VMEXIT_VMRUN            = 128,
    VMEXIT_VMMCALL          = 129,
    VMEXIT_VMLOAD           = 130,
    VMEXIT_VMSAVE           = 131,
    VMEXIT_STGI             = 132,
    VMEXIT_CLGI             = 133,
    VMEXIT_SKINIT           = 134,
    VMEXIT_RDTSCP           = 135,
    VMEXIT_ICEBP            = 136,
    VMEXIT_WBINVD           = 137,
    VMEXIT_MONITOR          = 138,
    VMEXIT_MWAIT            = 139,
    VMEXIT_MWAIT_CONDITIONAL= 140,
    VMEXIT_NPF              = 1024, /* nested paging fault */
    VMEXIT_INVALID          =  -1
};

#define HVM_SVM_EXIT_REASON_MAX 1025
char * hvm_svm_exit_reason_name[HVM_SVM_EXIT_REASON_MAX] = {
    /* 0-15 */
    "VMEXIT_CR0_READ",
    "VMEXIT_CR1_READ",
    "VMEXIT_CR2_READ",
    "VMEXIT_CR3_READ",
    "VMEXIT_CR4_READ",
    "VMEXIT_CR5_READ",
    "VMEXIT_CR6_READ",
    "VMEXIT_CR7_READ",
    "VMEXIT_CR8_READ",
    "VMEXIT_CR9_READ",
    "VMEXIT_CR10_READ",
    "VMEXIT_CR11_READ",
    "VMEXIT_CR12_READ",
    "VMEXIT_CR13_READ",
    "VMEXIT_CR14_READ",
    "VMEXIT_CR15_READ",
    /* 16-31 */
    "VMEXIT_CR0_WRITE",
    "VMEXIT_CR1_WRITE",
    "VMEXIT_CR2_WRITE",
    "VMEXIT_CR3_WRITE",
    "VMEXIT_CR4_WRITE",
    "VMEXIT_CR5_WRITE",
    "VMEXIT_CR6_WRITE",
    "VMEXIT_CR7_WRITE",
    "VMEXIT_CR8_WRITE",
    "VMEXIT_CR9_WRITE",
    "VMEXIT_CR10_WRITE",
    "VMEXIT_CR11_WRITE",
    "VMEXIT_CR12_WRITE",
    "VMEXIT_CR13_WRITE",
    "VMEXIT_CR14_WRITE",
    "VMEXIT_CR15_WRITE",
    /* 32-47 */
    "VMEXIT_DR0_READ",
    "VMEXIT_DR1_READ",
    "VMEXIT_DR2_READ",
    "VMEXIT_DR3_READ",
    "VMEXIT_DR4_READ",
    "VMEXIT_DR5_READ",
    "VMEXIT_DR6_READ",
    "VMEXIT_DR7_READ",
    "VMEXIT_DR8_READ",
    "VMEXIT_DR9_READ",
    "VMEXIT_DR10_READ",
    "VMEXIT_DR11_READ",
    "VMEXIT_DR12_READ",
    "VMEXIT_DR13_READ",
    "VMEXIT_DR14_READ",
    "VMEXIT_DR15_READ",
    /* 48-63 */
    "VMEXIT_DR0_WRITE",
    "VMEXIT_DR1_WRITE",
    "VMEXIT_DR2_WRITE",
    "VMEXIT_DR3_WRITE",
    "VMEXIT_DR4_WRITE",
    "VMEXIT_DR5_WRITE",
    "VMEXIT_DR6_WRITE",
    "VMEXIT_DR7_WRITE",
    "VMEXIT_DR8_WRITE",
    "VMEXIT_DR9_WRITE",
    "VMEXIT_DR10_WRITE",
    "VMEXIT_DR11_WRITE",
    "VMEXIT_DR12_WRITE",
    "VMEXIT_DR13_WRITE",
    "VMEXIT_DR14_WRITE",
    "VMEXIT_DR15_WRITE",
    /* 64-83 */
    "VMEXIT_EXCEPTION_DE",
    "VMEXIT_EXCEPTION_DB",
    "VMEXIT_EXCEPTION_NMI",
    "VMEXIT_EXCEPTION_BP",
    "VMEXIT_EXCEPTION_OF",
    "VMEXIT_EXCEPTION_BR",
    "VMEXIT_EXCEPTION_UD",
    "VMEXIT_EXCEPTION_NM",
    "VMEXIT_EXCEPTION_DF",
    "VMEXIT_EXCEPTION_09",
    "VMEXIT_EXCEPTION_TS",
    "VMEXIT_EXCEPTION_NP",
    "VMEXIT_EXCEPTION_SS",
    "VMEXIT_EXCEPTION_GP",
    "VMEXIT_EXCEPTION_PF",
    "VMEXIT_EXCEPTION_15",
    "VMEXIT_EXCEPTION_MF",
    "VMEXIT_EXCEPTION_AC",
    "VMEXIT_EXCEPTION_MC",
    "VMEXIT_EXCEPTION_XF",
    /* 84-95 */
    "VMEXIT_EXCEPTION_20",
    "VMEXIT_EXCEPTION_21",
    "VMEXIT_EXCEPTION_22",
    "VMEXIT_EXCEPTION_23",
    "VMEXIT_EXCEPTION_24",
    "VMEXIT_EXCEPTION_25",
    "VMEXIT_EXCEPTION_26",
    "VMEXIT_EXCEPTION_27",
    "VMEXIT_EXCEPTION_28",
    "VMEXIT_EXCEPTION_29",
    "VMEXIT_EXCEPTION_30",
    "VMEXIT_EXCEPTION_31",
    /* 96-99 */
    "VMEXIT_INTR",
    "VMEXIT_NMI",
    "VMEXIT_SMI",
    "VMEXIT_INIT",
    /* 100-109 */
    "VMEXIT_VINTR",
    "VMEXIT_CR0_SEL_WRITE",
    "VMEXIT_IDTR_READ",
    "VMEXIT_GDTR_READ",
    "VMEXIT_LDTR_READ",
    "VMEXIT_TR_READ",
    "VMEXIT_IDTR_WRITE",
    "VMEXIT_GDTR_WRITE",
    "VMEXIT_LDTR_WRITE",
    "VMEXIT_TR_WRITE",
    /* 110-119 */
    "VMEXIT_RDTSC",
    "VMEXIT_RDPMC",
    "VMEXIT_PUSHF",
    "VMEXIT_POPF",
    "VMEXIT_CPUID",
    "VMEXIT_RSM",
    "VMEXIT_IRET",
    "VMEXIT_SWINT",
    "VMEXIT_INVD",
    "VMEXIT_PAUSE",
    /* 120-129 */
    "VMEXIT_HLT",
    "VMEXIT_INVLPG",
    "VMEXIT_INVLPGA",
    "VMEXIT_IOIO",
    "VMEXIT_MSR",
    "VMEXIT_TASK_SWITCH",
    "VMEXIT_FERR_FREEZE",
    "VMEXIT_SHUTDOWN",
    "VMEXIT_VMRUN",
    "VMEXIT_VMMCALL",
    /* 130-139 */
    "VMEXIT_VMLOAD",
    "VMEXIT_VMSAVE",
    "VMEXIT_STGI",
    "VMEXIT_CLGI",
    "VMEXIT_SKINIT",
    "VMEXIT_RDTSCP",
    "VMEXIT_ICEBP",
    "VMEXIT_WBINVD",
    "VMEXIT_MONITOR",
    "VMEXIT_MWAIT",
    /* 140 */
    "VMEXIT_MWAIT_CONDITIONAL",
    [VMEXIT_NPF] = "VMEXIT_NPF", /* nested paging fault */
};


#if ( HVM_VMX_EXIT_REASON_MAX > HVM_SVM_EXIT_REASON_MAX )
# define HVM_EXIT_REASON_MAX HVM_VMX_EXIT_REASON_MAX
# error - Strange!
#else
# define HVM_EXIT_REASON_MAX HVM_SVM_EXIT_REASON_MAX
#endif

/* General hvm information */
#define SPURIOUS_APIC_VECTOR  0xff
#define ERROR_APIC_VECTOR     0xfe
#define INVALIDATE_TLB_VECTOR 0xfd
#define EVENT_CHECK_VECTOR    0xfc
#define CALL_FUNCTION_VECTOR  0xfb
#define THERMAL_APIC_VECTOR   0xfa
#define LOCAL_TIMER_VECTOR    0xf9

#define EXTERNAL_INTERRUPT_MAX 256

/* Stringify numbers */
char * hvm_extint_vector_name[EXTERNAL_INTERRUPT_MAX] = {
    [SPURIOUS_APIC_VECTOR] = "SPURIOS_APIC",
    [ERROR_APIC_VECTOR] =    "ERROR_APIC",
    [INVALIDATE_TLB_VECTOR]= "INVALIDATE_TLB",
    [EVENT_CHECK_VECTOR]=    "EVENT_CHECK",
    [CALL_FUNCTION_VECTOR]=  "CALL_FUNCTION",
    [THERMAL_APIC_VECTOR]=   "THERMAL_APIC",
    [LOCAL_TIMER_VECTOR] =   "LOCAL_TIMER",
};

#define HVM_TRAP_MAX 20

char * hvm_trap_name[HVM_TRAP_MAX] = {
    [0] =  "Divide",
    [1] =  "RESERVED",
    [2] =  "NMI",
    [3] =  "Breakpoint",
    [4] =  "Overflow",
    [5] =  "BOUND",
    [6] =  "Invalid Op",
    [7] =  "Coprocessor not present",
    [8] =  "Double Fault",
    [9] =  "Coprocessor segment overrun",
    [10] = "TSS",
    [11] = "Segment not present",
    [12] = "Stack-segment fault",
    [13] = "GP",
    [14] = "Page fault",
    [15] = "RESERVED",
    [16] = "FPU",
    [17] = "Alignment check",
    [18] = "Machine check",
    [19] = "SIMD",
};


enum {
    HVM_EVENT_HANDLER_NONE = 0,
    HVM_EVENT_HANDLER_PF_XEN = 1,
    HVM_EVENT_HANDLER_PF_INJECT,
    HVM_EVENT_HANDLER_INJ_EXC,
    HVM_EVENT_HANDLER_INJ_VIRQ,
    HVM_EVENT_HANDLER_REINJ_VIRQ,
    HVM_EVENT_HANDLER_IO_READ,
    HVM_EVENT_HANDLER_IO_WRITE,
    HVM_EVENT_HANDLER_CR_READ, /* 8 */
    HVM_EVENT_HANDLER_CR_WRITE,
    HVM_EVENT_HANDLER_DR_READ,
    HVM_EVENT_HANDLER_DR_WRITE,
    HVM_EVENT_HANDLER_MSR_READ,
    HVM_EVENT_HANDLER_MSR_WRITE,
    HVM_EVENT_HANDLER_CPUID,
    HVM_EVENT_HANDLER_INTR,
    HVM_EVENT_HANDLER_NMI, /* 16 */
    HVM_EVENT_HANDLER_SMI,
    HVM_EVENT_HANDLER_VMCALL,
    HVM_EVENT_HANDLER_HLT,
    HVM_EVENT_HANDLER_INVLPG,
    HVM_EVENT_HANDLER_MCE,
    HVM_EVENT_HANDLER_IO_ASSIST,
    HVM_EVENT_HANDLER_MMIO_ASSIST,
    HVM_EVENT_HANDLER_CLTS,
    HVM_EVENT_HANDLER_LMSW,
    HVM_EVENT_RDTSC,
    HVM_EVENT_INTR_WINDOW=0x20, /* Oops... skipped 0x1b-1f */
    HVM_EVENT_NPF,
    HVM_EVENT_REALMODE_EMULATE,
    HVM_EVENT_TRAP,
    HVM_EVENT_TRAP_DEBUG,
    HVM_EVENT_VLAPIC,
    HVM_EVENT_HANDLER_MAX
};
char * hvm_event_handler_name[HVM_EVENT_HANDLER_MAX] = {
    "(no handler)",
    "pf_xen",
    "pf_inject",
    "inj_exc",
    "inj_virq",
    "reinj_virq",
    "io_read",
    "io_write",
    "cr_read", /* 8 */
    "cr_write",
    "dr_read",
    "dr_write",
    "msr_read",
    "msr_write",
    "cpuid",
    "intr",
    "nmi", /* 16 */
    "smi",
    "vmcall",
    "hlt",
    "invlpg",
    "mce",
    "io_assist",
    "mmio_assist",
    "clts", /* 24 */
    "lmsw",
    "rdtsc",
    [HVM_EVENT_INTR_WINDOW]="intr_window",
    "npf",
    "realmode_emulate",
    "trap",
    "trap_debug",
    "vlapic"
};

enum {
    HVM_VOL_VMENTRY,
    HVM_VOL_VMEXIT,
    HVM_VOL_HANDLER,
    HVM_VOL_MAX
};

enum {
    GUEST_INTERRUPT_CASE_NONE,
    /* This interrupt woke, no other interrupts until halt */
    GUEST_INTERRUPT_CASE_WAKE_TO_HALT_ALONE,
    /* This interrupt woke, maybe another interrupt before halt */
    GUEST_INTERRUPT_CASE_WAKE_TO_HALT_ANY,
    /* Time from interrupt (running) to halt */
    GUEST_INTERRUPT_CASE_INTERRUPT_TO_HALT,
    GUEST_INTERRUPT_CASE_MAX,
};

char *guest_interrupt_case_name[] = {
    [GUEST_INTERRUPT_CASE_WAKE_TO_HALT_ALONE]="wake to halt alone",
    /* This interrupt woke, maybe another interrupt before halt */
    [GUEST_INTERRUPT_CASE_WAKE_TO_HALT_ANY]  ="wake to halt any  ",
    /* Time from interrupt (running) to halt */
    [GUEST_INTERRUPT_CASE_INTERRUPT_TO_HALT] ="intr to halt      ",
};

char *hvm_vol_name[HVM_VOL_MAX] = {
    [HVM_VOL_VMENTRY]="vmentry",
    [HVM_VOL_VMEXIT] ="vmexit",
    [HVM_VOL_HANDLER]="handler",
};

enum {
    HYPERCALL_set_trap_table = 0,
    HYPERCALL_mmu_update,
    HYPERCALL_set_gdt,
    HYPERCALL_stack_switch,
    HYPERCALL_set_callbacks,
    HYPERCALL_fpu_taskswitch,
    HYPERCALL_sched_op_compat,
    HYPERCALL_platform_op,
    HYPERCALL_set_debugreg,
    HYPERCALL_get_debugreg,
    HYPERCALL_update_descriptor,
    HYPERCALL_memory_op=12,
    HYPERCALL_multicall,
    HYPERCALL_update_va_mapping,
    HYPERCALL_set_timer_op,
    HYPERCALL_event_channel_op_compat,
    HYPERCALL_xen_version,
    HYPERCALL_console_io,
    HYPERCALL_physdev_op_compat,
    HYPERCALL_grant_table_op,
    HYPERCALL_vm_assist,
    HYPERCALL_update_va_mapping_otherdomain,
    HYPERCALL_iret,
    HYPERCALL_vcpu_op,
    HYPERCALL_set_segment_base,
    HYPERCALL_mmuext_op,
    HYPERCALL_acm_op,
    HYPERCALL_nmi_op,
    HYPERCALL_sched_op,
    HYPERCALL_callback_op,
    HYPERCALL_xenoprof_op,
    HYPERCALL_event_channel_op,
    HYPERCALL_physdev_op,
    HYPERCALL_hvm_op,
    HYPERCALL_sysctl,
    HYPERCALL_domctl,
    HYPERCALL_kexec_op,
    HYPERCALL_MAX
};

char *hypercall_name[HYPERCALL_MAX] = {
    [HYPERCALL_set_trap_table]="set_trap_table",
    [HYPERCALL_mmu_update]="mmu_update",
    [HYPERCALL_set_gdt]="set_gdt",
    [HYPERCALL_stack_switch]="stack_switch",
    [HYPERCALL_set_callbacks]="set_callbacks",
    [HYPERCALL_fpu_taskswitch]="fpu_taskswitch",
    [HYPERCALL_sched_op_compat]="sched_op(compat)",
    [HYPERCALL_platform_op]="platform_op",
    [HYPERCALL_set_debugreg]="set_debugreg",
    [HYPERCALL_get_debugreg]="get_debugreg",
    [HYPERCALL_update_descriptor]="update_descriptor",
    [HYPERCALL_memory_op]="memory_op",
    [HYPERCALL_multicall]="multicall",
    [HYPERCALL_update_va_mapping]="update_va_mapping",
    [HYPERCALL_set_timer_op]="set_timer_op",
    [HYPERCALL_event_channel_op_compat]="evtchn_op(compat)",
    [HYPERCALL_xen_version]="xen_version",
    [HYPERCALL_console_io]="console_io",
    [HYPERCALL_physdev_op_compat]="physdev_op(compat)",
    [HYPERCALL_grant_table_op]="grant_table_op",
    [HYPERCALL_vm_assist]="vm_assist",
    [HYPERCALL_update_va_mapping_otherdomain]="update_va_mapping_otherdomain",
    [HYPERCALL_iret]="iret",
    [HYPERCALL_vcpu_op]="vcpu_op",
    [HYPERCALL_set_segment_base]="set_segment_base",
    [HYPERCALL_mmuext_op]="mmuext_op",
    [HYPERCALL_acm_op]="acm_op",
    [HYPERCALL_nmi_op]="nmi_op",
    [HYPERCALL_sched_op]="sched_op",
    [HYPERCALL_callback_op]="callback_op",
    [HYPERCALL_xenoprof_op]="xenoprof_op",
    [HYPERCALL_event_channel_op]="evtchn_op",
    [HYPERCALL_physdev_op]="physdev_op",
    [HYPERCALL_hvm_op]="hvm_op",
    [HYPERCALL_sysctl]="sysctl",
    [HYPERCALL_domctl]="domctl",
    [HYPERCALL_kexec_op]="kexec_op"
};

enum {
    PF_XEN_EMUL_LVL_0,
    PF_XEN_EMUL_LVL_1,
    PF_XEN_EMUL_LVL_2,
    PF_XEN_EMUL_LVL_3,
    PF_XEN_EMUL_LVL_4,
    PF_XEN_EMUL_EARLY_UNSHADOW,
    PF_XEN_EMUL_SET_CHANGED,
    PF_XEN_EMUL_SET_UNCHANGED,
    PF_XEN_EMUL_SET_FLUSH,
    PF_XEN_EMUL_SET_ERROR,
    PF_XEN_EMUL_PROMOTE,
    PF_XEN_EMUL_DEMOTE,
    PF_XEN_EMUL_PREALLOC_UNPIN,
    PF_XEN_EMUL_PREALLOC_UNHOOK,
    PF_XEN_EMUL_MAX,
};

char * pf_xen_emul_name[PF_XEN_EMUL_MAX] = {
    [PF_XEN_EMUL_LVL_0]="non-linmap",
    [PF_XEN_EMUL_LVL_1]="linmap l1",
    [PF_XEN_EMUL_LVL_2]="linmap l2",
    [PF_XEN_EMUL_LVL_3]="linmap l3",
    [PF_XEN_EMUL_LVL_4]="linmap l4",
    [PF_XEN_EMUL_EARLY_UNSHADOW]="early unshadow",
    [PF_XEN_EMUL_SET_UNCHANGED]="set unchanged",
    [PF_XEN_EMUL_SET_CHANGED]="set changed",
    [PF_XEN_EMUL_SET_FLUSH]="set changed",
    [PF_XEN_EMUL_SET_ERROR]="set changed",
    [PF_XEN_EMUL_PROMOTE]="promote",
    [PF_XEN_EMUL_DEMOTE]="demote",
    [PF_XEN_EMUL_PREALLOC_UNPIN]="unpin",
    [PF_XEN_EMUL_PREALLOC_UNHOOK]="unhook",
};

/* Rio only */
enum {
    PF_XEN_NON_EMUL_VA_USER,
    PF_XEN_NON_EMUL_VA_KERNEL,
    PF_XEN_NON_EMUL_EIP_USER,
    PF_XEN_NON_EMUL_EIP_KERNEL,
    PF_XEN_NON_EMUL_MAX,
};

char * pf_xen_non_emul_name[PF_XEN_NON_EMUL_MAX] = {
    [PF_XEN_NON_EMUL_VA_USER]="va user",
    [PF_XEN_NON_EMUL_VA_KERNEL]="va kernel",
    [PF_XEN_NON_EMUL_EIP_USER]="eip user",
    [PF_XEN_NON_EMUL_EIP_KERNEL]="eip kernel",
};

enum {
    PF_XEN_FIXUP_PREALLOC_UNPIN,
    PF_XEN_FIXUP_PREALLOC_UNHOOK,
    PF_XEN_FIXUP_UNSYNC,
    PF_XEN_FIXUP_OOS_ADD,
    PF_XEN_FIXUP_OOS_EVICT,
    PF_XEN_FIXUP_PROMOTE,
    PF_XEN_FIXUP_UPDATE_ONLY,
    PF_XEN_FIXUP_WRMAP,
    PF_XEN_FIXUP_BRUTE_FORCE,
    PF_XEN_FIXUP_MAX,
};

char * pf_xen_fixup_name[PF_XEN_FIXUP_MAX] = {
    [PF_XEN_FIXUP_PREALLOC_UNPIN] = "unpin",
    [PF_XEN_FIXUP_PREALLOC_UNHOOK] = "unhook",
    [PF_XEN_FIXUP_UNSYNC] = "unsync",
    [PF_XEN_FIXUP_OOS_ADD] = "oos-add",
    [PF_XEN_FIXUP_OOS_EVICT] = "oos-evict",
    [PF_XEN_FIXUP_PROMOTE] = "promote",
    [PF_XEN_FIXUP_UPDATE_ONLY] = "update",
    [PF_XEN_FIXUP_WRMAP] = "wrmap",
    [PF_XEN_FIXUP_BRUTE_FORCE] = "wrmap-bf",
};

enum {
    PF_XEN_NOT_SHADOW = 1,
    PF_XEN_FAST_PROPAGATE,
    PF_XEN_FAST_MMIO,
    PF_XEN_FALSE_FAST_PATH,
    PF_XEN_MMIO,
    PF_XEN_FIXUP,
    PF_XEN_DOMF_DYING,
    PF_XEN_EMULATE,
    PF_XEN_EMULATE_UNSHADOW_USER,
    PF_XEN_EMULATE_UNSHADOW_EVTINJ,
    PF_XEN_EMULATE_UNSHADOW_UNHANDLED,
    PF_XEN_LAST_FAULT=PF_XEN_EMULATE_UNSHADOW_UNHANDLED,
    PF_XEN_NON_EMULATE,
    PF_XEN_NO_HANDLER,
    PF_XEN_MAX,
};

#define SHADOW_WRMAP_BF       12
#define SHADOW_PREALLOC_UNPIN 13
#define SHADOW_RESYNC_FULL    14
#define SHADOW_RESYNC_ONLY    15

char * pf_xen_name[PF_XEN_MAX] = {
    [PF_XEN_NOT_SHADOW]="propagate",
    [PF_XEN_FAST_PROPAGATE]="fast propagate",
    [PF_XEN_FAST_MMIO]="fast mmio",
    [PF_XEN_FALSE_FAST_PATH]="false fast path",
    [PF_XEN_MMIO]="mmio",
    [PF_XEN_FIXUP]="fixup",
    [PF_XEN_DOMF_DYING]="dom dying",
    [PF_XEN_EMULATE]="emulate",
    [PF_XEN_EMULATE_UNSHADOW_USER]="unshadow:user-mode",
    [PF_XEN_EMULATE_UNSHADOW_EVTINJ]="unshadow:evt inj",
    [PF_XEN_EMULATE_UNSHADOW_UNHANDLED]="unshadow:unhandled instr",
    [PF_XEN_NON_EMULATE]="fixup|mmio",
    [PF_XEN_NO_HANDLER]="(no handler)",
};

#define CORR_VA_INVALID (0ULL-1)

enum {
    NONPF_MMIO_APIC,
    NONPF_MMIO_NPF,
    NONPF_MMIO_UNKNOWN,
    NONPF_MMIO_MAX
};

struct mmio_info {
    unsigned long long gpa;
    unsigned long long va; /* Filled only by shadow */
    unsigned data;
    unsigned data_valid:1, is_write:1;
};

struct pf_xen_extra {
    unsigned long long va;
    union {
        unsigned flags;
        struct {
            unsigned flag_set_ad:1,
                flag_set_a:1,
                flag_shadow_l1_get_ref:1,
                flag_shadow_l1_put_ref:1,
                flag_l2_propagate:1,
                flag_set_changed:1,
                flag_set_flush:1,
                flag_set_error:1,
                flag_demote:1,
                flag_promote:1,
                flag_wrmap:1,
                flag_wrmap_guess_found:1,
                flag_wrmap_brute_force:1,
                flag_early_unshadow:1,
                flag_emulation_2nd_pt_written:1,
                flag_emulation_last_failed:1,
                flag_emulate_full_pt:1,
                flag_prealloc_unhook:1,
                flag_unsync:1,
                flag_oos_fixup_add:1,
                flag_oos_fixup_evict:1;
        };
    }; /* Miami + ; fixup & emulate */
    unsigned int error_code; /* Rio only */

    /* Calculated */
    int pf_case; /* Rio */

    /* MMIO only */
    unsigned long long gpa;
    unsigned int data;

    /* Emulate only */
    unsigned long long gl1e; /* Miami + */
    unsigned long long wval; /* Miami */
    unsigned long long corresponding_va;
    unsigned int pt_index[5], pt_is_lo;
    int pt_level;

    /* Other */
    unsigned long long gfn;

    /* Flags */
    unsigned corr_valid:1,
        corr_is_kernel:1,
        va_is_kernel:1;
};

struct pcpu_info;

#define GUEST_INTERRUPT_MAX 350
#define FAKE_VECTOR 349
#define CR_MAX 9
#define RESYNCS_MAX 17
#define PF_XEN_FIXUP_UNSYNC_RESYNC_MAX 2

struct hvm_data;

struct hvm_summary_handler_node {
    void (*handler)(struct hvm_data *, void* data);
    void *data;
    struct hvm_summary_handler_node *next;
};

struct hvm_data {
    /* Summary information */
    int init;
    int vmexit_valid;
    int summary_info;
    struct vcpu_data *v; /* up-pointer */

    /* SVM / VMX compatibility. FIXME - should be global */
    char ** exit_reason_name;
    int exit_reason_max;
    struct hvm_summary_handler_node *exit_reason_summary_handler_list[HVM_EXIT_REASON_MAX];

    /* Information about particular exit reasons */
    struct {
        struct event_cycle_summary exit_reason[HVM_EXIT_REASON_MAX];
        int extint[EXTERNAL_INTERRUPT_MAX+1];
        int *extint_histogram;
        struct event_cycle_summary trap[HVM_TRAP_MAX];
        struct event_cycle_summary pf_xen[PF_XEN_MAX];
        struct event_cycle_summary pf_xen_emul[PF_XEN_EMUL_MAX];
        struct event_cycle_summary pf_xen_emul_early_unshadow[5];
        struct event_cycle_summary pf_xen_non_emul[PF_XEN_NON_EMUL_MAX];
        struct event_cycle_summary pf_xen_fixup[PF_XEN_FIXUP_MAX];
        struct event_cycle_summary pf_xen_fixup_unsync_resync[PF_XEN_FIXUP_UNSYNC_RESYNC_MAX+1];
        struct event_cycle_summary cr_write[CR_MAX];
        struct event_cycle_summary cr3_write_resyncs[RESYNCS_MAX+1];
        struct event_cycle_summary vmcall[HYPERCALL_MAX+1];
        struct event_cycle_summary generic[HVM_EVENT_HANDLER_MAX];
        struct event_cycle_summary mmio[NONPF_MMIO_MAX];
        struct hvm_gi_struct {
            int count;
            struct cycle_summary runtime[GUEST_INTERRUPT_CASE_MAX];
            /* OK, not summary info, but still... */
            int is_wake;
            tsc_t start_tsc;
        } guest_interrupt[GUEST_INTERRUPT_MAX + 1];
        /* IPI Latency */
        struct event_cycle_summary ipi_latency;
        int ipi_count[256];
        struct {
            struct io_address *mmio, *pio;
        } io;
    } summary;

    /* In-flight accumulation information */
    struct {
        union {
            struct {
                unsigned port:31,
                    is_write:1;
                unsigned int val;
            } io;
            struct pf_xen_extra pf_xen;
            struct {
                unsigned cr;
                unsigned long long val;
                int repromote;
            } cr_write;
            struct {
                unsigned addr;
                unsigned long long val;
            } msr;
            struct {
                unsigned int event;
                uint32_t d[4];
            } generic;
            struct {
                unsigned eax;
            } vmcall;
            struct {
                unsigned vec;
            } intr;
        };
        /* MMIO gets its separate area, since many exits may use it */
        struct mmio_info mmio;
    }inflight;
    int resyncs;
    void (*post_process)(struct hvm_data *);
    tsc_t exit_tsc, arc_cycles, entry_tsc;
    unsigned long long rip;
    unsigned exit_reason, event_handler;
    int short_summary_done:1, prealloc_unpin:1, wrmap_bf:1;

    /* Immediate processing */
    void *d;

    /* Wake-to-halt detection.  See comment above. */
    struct {
        unsigned waking:1;
        /* Wake vector: keep track of time from vmentry until:
           next halt, or next interrupt */
        int vector, interrupts, interrupts_wanting_tsc;
    } w2h;

    /* Historical info */
    tsc_t last_rdtsc;
};

enum {
    HVM_SHORT_SUMMARY_EMULATE,
    HVM_SHORT_SUMMARY_UNSYNC,
    HVM_SHORT_SUMMARY_FIXUP,
    HVM_SHORT_SUMMARY_MMIO,
    HVM_SHORT_SUMMARY_PROPAGATE,
    HVM_SHORT_SUMMARY_CR3,
    HVM_SHORT_SUMMARY_VMCALL,
    HVM_SHORT_SUMMARY_INTERRUPT,
    HVM_SHORT_SUMMARY_HLT,
    HVM_SHORT_SUMMARY_OTHER,
    HVM_SHORT_SUMMARY_MAX,
};

char *hvm_short_summary_name[HVM_SHORT_SUMMARY_MAX] = {
    [HVM_SHORT_SUMMARY_EMULATE]  ="emulate",
    [HVM_SHORT_SUMMARY_UNSYNC]   ="unsync",
    [HVM_SHORT_SUMMARY_FIXUP]    ="fixup",
    [HVM_SHORT_SUMMARY_MMIO]     ="mmio",
    [HVM_SHORT_SUMMARY_PROPAGATE]="propagate",
    [HVM_SHORT_SUMMARY_CR3]      ="cr3",
    [HVM_SHORT_SUMMARY_VMCALL]   ="vmcall",
    [HVM_SHORT_SUMMARY_INTERRUPT]="intr",
    [HVM_SHORT_SUMMARY_HLT]      ="hlt",
    [HVM_SHORT_SUMMARY_OTHER]    ="other",
};

struct hvm_short_summary_struct {
    struct cycle_summary s[HVM_SHORT_SUMMARY_MAX];
};

void init_hvm_data(struct hvm_data *h, struct vcpu_data *v) {
    int i;

    if(h->init)
        return;

    h->v = v;

    h->init = 1;

    if(opt.svm_mode) {
        h->exit_reason_max = HVM_SVM_EXIT_REASON_MAX;
        h->exit_reason_name = hvm_svm_exit_reason_name;
    } else {
        h->exit_reason_max = HVM_VMX_EXIT_REASON_MAX;
        h->exit_reason_name = hvm_vmx_exit_reason_name;
    }

    if(opt.histogram_interrupt_eip) {
        int count = ((1ULL<<ADDR_SPACE_BITS)/opt.histogram_interrupt_increment);
        size_t size = count * sizeof(int);
        h->summary.extint_histogram = malloc(size);
        if(h->summary.extint_histogram)
            bzero(h->summary.extint_histogram, size);
        else {
            fprintf(stderr, "FATAL: Could not allocate %zd bytes for interrupt histogram!\n",
                    size);
            error(ERR_SYSTEM, NULL);
        }

    }
    for(i=0; i<GUEST_INTERRUPT_MAX+1; i++)
        h->summary.guest_interrupt[i].count=0;
}

/* PV data */
enum {
    PV_HYPERCALL=1,
    PV_TRAP=3,
    PV_PAGE_FAULT,
    PV_FORCED_INVALID_OP,
    PV_EMULATE_PRIVOP,
    PV_EMULATE_4GB,
    PV_MATH_STATE_RESTORE,
    PV_PAGING_FIXUP,
    PV_GDT_LDT_MAPPING_FAULT,
    PV_PTWR_EMULATION,
    PV_PTWR_EMULATION_PAE,
    PV_HYPERCALL_V2 = 13,
    PV_HYPERCALL_SUBCALL = 14,
    PV_MAX
};

char *pv_name[PV_MAX] = {
    [PV_HYPERCALL]="hypercall",
    [PV_TRAP]="trap",
    [PV_PAGE_FAULT]="page_fault",
    [PV_FORCED_INVALID_OP]="forced_invalid_op",
    [PV_EMULATE_PRIVOP]="emulate privop",
    [PV_EMULATE_4GB]="emulate 4g",
    [PV_MATH_STATE_RESTORE]="math state restore",
    [PV_PAGING_FIXUP]="paging fixup",
    [PV_GDT_LDT_MAPPING_FAULT]="gdt/ldt mapping fault",
    [PV_PTWR_EMULATION]="ptwr",
    [PV_PTWR_EMULATION_PAE]="ptwr(pae)",
    [PV_HYPERCALL_V2]="hypercall",
    [PV_HYPERCALL_SUBCALL]="hypercall (subcall)",
};

#define PV_HYPERCALL_MAX 56
#define PV_TRAP_MAX 20

struct pv_data {
    unsigned summary_info:1;
    int count[PV_MAX];
    int hypercall_count[PV_HYPERCALL_MAX];
    int trap_count[PV_TRAP_MAX];
};

/* Sched data */

enum {
    SCHED_DOM_ADD=1,
    SCHED_DOM_REM,
    SCHED_SLEEP,
    SCHED_WAKE,
    SCHED_YIELD,
    SCHED_BLOCK,
    SCHED_SHUTDOWN,
    SCHED_CTL,
    SCHED_ADJDOM,
    SCHED_SWITCH,
    SCHED_S_TIMER_FN,
    SCHED_T_TIMER_FN,
    SCHED_DOM_TIMER_FN,
    SCHED_SWITCH_INFPREV,
    SCHED_SWITCH_INFNEXT,
    SCHED_SHUTDOWN_CODE,
    SCHED_MAX
};

enum {
    RUNSTATE_RUNNING=0,
    RUNSTATE_RUNNABLE,
    RUNSTATE_BLOCKED,
    RUNSTATE_OFFLINE,
    RUNSTATE_LOST,
    RUNSTATE_QUEUED,
    RUNSTATE_INIT,
    RUNSTATE_MAX
};

int runstate_graph[RUNSTATE_MAX] =
{
    [RUNSTATE_BLOCKED]=0,
    [RUNSTATE_OFFLINE]=1,
    [RUNSTATE_RUNNABLE]=2,
    [RUNSTATE_RUNNING]=3,
    [RUNSTATE_LOST]=-1,
    [RUNSTATE_QUEUED]=-2,
    [RUNSTATE_INIT]=-2,
};

char * runstate_name[RUNSTATE_MAX]={
    [RUNSTATE_RUNNING]= "running",
    [RUNSTATE_RUNNABLE]="runnable",
    [RUNSTATE_BLOCKED]= "blocked", /* to be blocked */
    [RUNSTATE_OFFLINE]= "offline",
    [RUNSTATE_QUEUED]=  "queued",
    [RUNSTATE_INIT]=    "init",
    [RUNSTATE_LOST]=    "lost",
};

enum {
    RUNNABLE_STATE_INVALID,
    RUNNABLE_STATE_WAKE,
    RUNNABLE_STATE_PREEMPT,
    RUNNABLE_STATE_OTHER,
    RUNNABLE_STATE_MAX
};

char * runnable_state_name[RUNNABLE_STATE_MAX]={
    [RUNNABLE_STATE_INVALID]="invalid", /* Should never show up */
    [RUNNABLE_STATE_WAKE]="wake",
    [RUNNABLE_STATE_PREEMPT]="preempt",
    [RUNNABLE_STATE_OTHER]="other",
};

/* Memory data */
enum {
    MEM_PAGE_GRANT_MAP = 1,
    MEM_PAGE_GRANT_UNMAP,
    MEM_PAGE_GRANT_TRANSFER,
    MEM_SET_P2M_ENTRY,
    MEM_DECREASE_RESERVATION,
    MEM_POD_POPULATE = 16,
    MEM_POD_ZERO_RECLAIM,
    MEM_POD_SUPERPAGE_SPLINTER,
    MEM_MAX
};

char *mem_name[MEM_MAX] = {
    [MEM_PAGE_GRANT_MAP]         = "grant-map",
    [MEM_PAGE_GRANT_UNMAP]       = "grant-unmap",
    [MEM_PAGE_GRANT_TRANSFER]    = "grant-transfer",
    [MEM_SET_P2M_ENTRY]          = "set-p2m",
    [MEM_DECREASE_RESERVATION]   = "decrease-reservation",
    [MEM_POD_POPULATE]           = "pod-populate",
    [MEM_POD_ZERO_RECLAIM]       = "pod-zero-reclaim",
    [MEM_POD_SUPERPAGE_SPLINTER] = "pod-superpage-splinter",
};

/* Per-unit information. */

struct cr3_value_struct {
    struct cr3_value_struct * next;
    struct cr3_value_struct * gnext;
    unsigned long long gmfn;
    int cr3_id;
    unsigned long long first_time, last_time, run_time;
    struct cycle_summary total_time, guest_time, hv_time;
    int switch_count, flush_count;

    struct hvm_short_summary_struct hvm;

    struct {
        int now;
        int count;
    } prealloc_unpin;

    struct {
        unsigned callback:1;
        unsigned flush_count, switch_count;
        unsigned fixup_user, emulate_corr_user;
    } destroy;
};

#ifndef MAX_CPUS
#define MAX_CPUS 256
#endif
typedef uint32_t cpu_mask_t;

#define IDLE_DOMAIN 32767
#define DEFAULT_DOMAIN 32768

#define MAX_VLAPIC_LIST 8
struct vlapic_struct {
    struct {
        struct outstanding_ipi {
            tsc_t first_tsc;
            int vec, count;
            int injected, valid;
        } list[MAX_VLAPIC_LIST];
    } outstanding;
};

struct vcpu_data {
    int vid;
    struct domain_data *d; /* up-pointer */
    unsigned activated:1;

    int guest_paging_levels;

    /* Schedule info */
    struct {
        int state;
        int runnable_state; /* Only valid when state==RUNSTATE_RUNNABLE */
        tsc_t tsc;
        /* TSC skew detection/correction */
        struct last_oldstate_struct {
            int wrong, actual, pid;
            tsc_t tsc;
        } last_oldstate;
        /* Performance counters */
        unsigned long long p1_start, p2_start;
    } runstate;
    struct pcpu_info *p;
    tsc_t pcpu_tsc;

    /* Hardware tracking */
    struct {
        long long val;
        tsc_t start_time;
        struct cr3_value_struct *data;
    } cr3;

    /* IPI latency tracking */
    struct vlapic_struct vlapic;

    /* Summary info */
    struct cycle_framework f;
    struct cycle_summary runstates[RUNSTATE_MAX];
    struct cycle_summary runnable_states[RUNNABLE_STATE_MAX];
    struct weighted_cpi_summary cpi;
    struct cycle_summary cpu_affinity_all,
        cpu_affinity_pcpu[MAX_CPUS];
    enum {
        VCPU_DATA_NONE=0,
        VCPU_DATA_HVM,
        VCPU_DATA_PV
    } data_type;
    union {
        struct hvm_data hvm;
        struct pv_data pv;
    };
};

enum {
    DOMAIN_RUNSTATE_BLOCKED=0,
    DOMAIN_RUNSTATE_PARTIAL_RUN,
    DOMAIN_RUNSTATE_FULL_RUN,
    DOMAIN_RUNSTATE_PARTIAL_CONTENTION,
    DOMAIN_RUNSTATE_CONCURRENCY_HAZARD,
    DOMAIN_RUNSTATE_FULL_CONTENTION,
    DOMAIN_RUNSTATE_LOST,
    DOMAIN_RUNSTATE_MAX
};

char * domain_runstate_name[] = {
    [DOMAIN_RUNSTATE_BLOCKED]="blocked",
    [DOMAIN_RUNSTATE_PARTIAL_RUN]="partial run",
    [DOMAIN_RUNSTATE_FULL_RUN]="full run",
    [DOMAIN_RUNSTATE_PARTIAL_CONTENTION]="partial contention",
    [DOMAIN_RUNSTATE_CONCURRENCY_HAZARD]="concurrency_hazard",
    [DOMAIN_RUNSTATE_FULL_CONTENTION]="full_contention",
    [DOMAIN_RUNSTATE_LOST]="lost",
};

enum {
    POD_RECLAIM_CONTEXT_UNKNOWN=0,
    POD_RECLAIM_CONTEXT_FAULT,
    POD_RECLAIM_CONTEXT_BALLOON,
    POD_RECLAIM_CONTEXT_MAX
};

char * pod_reclaim_context_name[] = {
    [POD_RECLAIM_CONTEXT_UNKNOWN]="unknown",
    [POD_RECLAIM_CONTEXT_FAULT]="fault",
    [POD_RECLAIM_CONTEXT_BALLOON]="balloon",
};

#define POD_ORDER_MAX 4

struct domain_data {
    struct domain_data *next;
    int did;
    struct vcpu_data *vcpu[MAX_CPUS];

    int max_vid;

    int runstate;
    tsc_t runstate_tsc;
    struct cycle_summary total_time;
    struct cycle_summary runstates[DOMAIN_RUNSTATE_MAX];
    struct cr3_value_struct *cr3_value_head;
    struct eip_list_struct *emulate_eip_list;
    struct eip_list_struct *interrupt_eip_list;

    int guest_interrupt[GUEST_INTERRUPT_MAX+1];
    struct hvm_short_summary_struct hvm_short;
    struct {
        int done[MEM_MAX];
        int done_interval[MEM_MAX];

        int done_for[MEM_MAX];
        int done_for_interval[MEM_MAX];
    } memops;

    struct {
        int reclaim_order[POD_ORDER_MAX];
        int reclaim_context[POD_RECLAIM_CONTEXT_MAX];
        int reclaim_context_order[POD_RECLAIM_CONTEXT_MAX][POD_ORDER_MAX];
        /* FIXME: Do a full cycle summary */
        int populate_order[POD_ORDER_MAX];
    } pod;
};

struct domain_data * domain_list=NULL;

struct domain_data default_domain;

enum {
    TOPLEVEL_GEN=0,
    TOPLEVEL_SCHED,
    TOPLEVEL_DOM0OP,
    TOPLEVEL_HVM,
    TOPLEVEL_MEM,
    TOPLEVEL_PV,
    TOPLEVEL_SHADOW,
    TOPLEVEL_HW,
    TOPLEVEL_MAX=TOPLEVEL_HW+1,
};

char * toplevel_name[TOPLEVEL_MAX] = {
    [TOPLEVEL_GEN]="gen",
    [TOPLEVEL_SCHED]="sched",
    [TOPLEVEL_DOM0OP]="dom0op",
    [TOPLEVEL_HVM]="hvm",
    [TOPLEVEL_MEM]="mem",
    [TOPLEVEL_PV]="pv",
    [TOPLEVEL_SHADOW]="shadow",
    [TOPLEVEL_HW]="hw",
};

struct trace_volume {
    unsigned long long toplevel[TOPLEVEL_MAX];
    unsigned long long sched_verbose;
    unsigned long long hvm[HVM_VOL_MAX];
} volume;

#define UPDATE_VOLUME(_p,_x,_s) \
    do {                        \
        (_p)->volume.total._x += _s;          \
        (_p)->volume.last_buffer._x += _s;    \
    } while(0)

void volume_clear(struct trace_volume *vol)
{
    bzero(vol, sizeof(*vol));
}

void volume_summary(struct trace_volume *vol)
{
    int j, k;
    for(j=0; j<TOPLEVEL_MAX; j++)
        if(vol->toplevel[j]) {
            printf(" %-6s: %10lld\n",
                   toplevel_name[j], vol->toplevel[j]);
            switch(j) {
            case TOPLEVEL_SCHED:
                if(vol->sched_verbose)
                    printf(" +-verbose: %10lld\n",
                           vol->sched_verbose);
                break;
            case TOPLEVEL_HVM:
                for(k=0; k<HVM_VOL_MAX; k++) {
                    if(vol->hvm[k])
                        printf(" +-%-7s: %10lld\n",
                               hvm_vol_name[k], vol->hvm[k]);
                }

                break;
            }
        }
}

struct pcpu_info {
    /* Information about this pcpu */
    unsigned active:1, summary:1;
    int pid;

    /* Information related to scanning thru the file */
    tsc_t first_tsc, last_tsc, order_tsc;
    off_t file_offset;
    off_t next_cpu_change_offset;
    struct record_info ri;
    int last_cpu_change_pid;
    int power_state;

    /* Information related to tsc skew detection / correction */
    struct {
        tsc_t offset;
        cpu_mask_t downstream; /* To detect cycles in dependencies */
    } tsc_skew;

    /* Information related to domain tracking */
    struct vcpu_data * current;
    struct {
        unsigned active:1,
            domain_valid:1,
            seen_valid_schedule:1; /* Seen an actual schedule since lost records */
        unsigned did:16,vid:16;
        tsc_t tsc;
    } lost_record;

    /* Record volume */
    struct {
        tsc_t buffer_first_tsc,
            buffer_dom0_runstate_tsc,
            buffer_dom0_runstate_cycles[RUNSTATE_MAX];
        int buffer_dom0_runstate;
        unsigned buffer_size;
        struct trace_volume total, last_buffer;
    } volume;

    /* Time report */
    struct {
        tsc_t tsc;
        struct cycle_summary idle, running, lost;
    } time;
};

void __fill_in_record_info(struct pcpu_info *p);

#define INTERVAL_DOMAIN_GUEST_INTERRUPT_MAX 10

struct {
    int max_active_pcpu;
    off_t last_epoch_offset;
    int early_eof;
    int lost_cpus;
    tsc_t now;
    struct cycle_framework f;
    tsc_t buffer_trace_virq_tsc;
    struct pcpu_info pcpu[MAX_CPUS];

    struct {
        int id;
        /* Invariant: head null => tail null; head !null => tail valid */
        struct cr3_value_struct *head, **tail;
    } cr3;

    struct {
        tsc_t start_tsc;
        /* Information about specific interval output types */
        union {
            struct {
                struct interval_element ** values;
                int count;
            } array;
            struct {
                struct interval_list *head, **tail;
            } list;
            struct cr3_value_struct *cr3;
            struct {
                struct domain_data *d;
                int guest_vector[INTERVAL_DOMAIN_GUEST_INTERRUPT_MAX];
            } domain;
        };
    } interval;
} P = { 0 };

/* Function prototypes */
char * pcpu_string(int pcpu);
void pcpu_string_draw(struct pcpu_info *p);
void process_generic(struct record_info *ri);
void dump_generic(FILE *f, struct record_info *ri);
ssize_t __read_record(struct trace_record *rec, off_t offset);
void error(enum error_level l, struct record_info *ri);
void update_io_address(struct io_address ** list, unsigned int pa, int dir,
                       tsc_t arc_cycles, unsigned int va);
int check_extra_words(struct record_info *ri, int expected_size, const char *record);
int vcpu_set_data_type(struct vcpu_data *v, int type);

void cpumask_init(cpu_mask_t *c) {
    *c = 0UL;
}

void cpumask_clear(cpu_mask_t *c, int cpu) {
    *c &= ~(1UL << cpu);
}

void cpumask_set(cpu_mask_t *c, int cpu) {
    *c |= (1UL << cpu);
}

int cpumask_isset(const cpu_mask_t *c, int cpu) {
    if(*c & (1UL<<cpu))
        return 1;
    else
        return 0;
}

void cpumask_union(cpu_mask_t *d, const cpu_mask_t *s) {
    *d |= *s;
}

/* -- Time code -- */

void cycles_to_time(unsigned long long c, struct time_struct *t) {
    t->time = ((c - P.f.first_tsc) << 10) / opt.cpu_qhz;
    t->s = t->time / 1000000000;
    t->ns = t->time - (t->s * 1000000000);
}

void abs_cycles_to_time(unsigned long long ac, struct time_struct *t) {
    if(ac > P.f.first_tsc) {
        /* t->time = ((ac - P.f.first_tsc) * 1000) / (opt.cpu_hz / 1000000 );     */
        /* t->s = t->time / 1000000000;                         */
        /* t->ns = t->time % 1000000000; */
        t->time = ((ac - P.f.first_tsc) << 10) / opt.cpu_qhz;
        t->s = t->time / 1000000000;
        t->ns = t->time - (t->s * 1000000000);
    } else {
        t->time = t->s = t->ns = 0;
    }
}

tsc_t abs_cycles_to_global(unsigned long long ac) {
    if(ac > P.f.first_tsc)
        return ac - P.f.first_tsc;
    else
        return 0;
}

void scatterplot_vs_time(tsc_t atsc, long long y) {
    struct time_struct t;

    abs_cycles_to_time(atsc, &t);

    printf("%u.%09u %lld\n", t.s, t.ns, y);
}

/* -- Summary Code -- */

/* With compliments to "Numerical Recipes in C", which provided the algorithm
 * and basic template for this function. */
long long percentile(long long * A, int N, int ple) {
    int I, J, L, R, K;

    long long X, W;

    /* No samples! */
    if ( N == 0 )
        return 0;

    /* Find K, the element # we want */
    K=N*ple/100;

    /* Set the left and right boundaries of the current search space */
    L=0; R=N-1;

    while(L < R) {
        /* X: The value to order everything higher / lower than */
        X=A[K];

        /* Starting at the left and the right... */
        I=L;
        J=R;

        do {
            /* Find the first element on the left that is out-of-order w/ X */
            while(A[I]<X)
                I++;
            /* Find the first element on the right that is out-of-order w/ X */
            while(X<A[J])
                J--;

            /* If we found something out-of-order */
            if(I<=J) {
                /* Switch the values */
                W=A[I];
                A[I]=A[J];
                A[J]=W;

                /* And move on */
                I++; J--;
            }
        } while (I <= J); /* Keep going until our pointers meet or pass */

        /* Re-adjust L and R, based on which element we're looking for */
        if(J<K)
            L=I;
        if(K<I)
            R=J;
    }

    return A[K];
}

float weighted_percentile(float * A, /* values */
                                       unsigned long long * w, /* weights */
                                       int N,                  /* total */
                                       int ple)                /* percentile */
{
    int L, R, I, J, K;
    unsigned long long L_weight, R_weight, I_weight, J_weight,
        K_weight, N_weight;

    float X, t1;
    unsigned long long t2;

    /* Calculate total weight */
    N_weight=0;

    for(I=0; I<N; I++) {
        assert(w[I]!=0);
        N_weight += w[I];
    }

    /* Find K_weight, the target weight we want */
    K_weight = N_weight * ple / 100;

    /* Set the left and right boundaries of the current search space */
    L=0;
    L_weight = 0;
    R=N-1;
    R_weight = N_weight - w[R];

    /* Search between L and R, narrowing down until we're done */
    while(L < R) {
        /* Chose an ordering value from right in the middle */
        K = (L + R) >> 1;
        /* X: The value to order everything higher / lower than */
        X=A[K];

        /* Starting at the left and the right... */
        I=L; I_weight = L_weight;
        J=R; J_weight = R_weight;

        do {
            /* Find the first element on the left that is out-of-order w/ X */
            while(A[I]<X) {
                I_weight += w[I];
                I++;
            }
            /* Find the first element on the right that is out-of-order w/ X */
            while(X<A[J]) {
                J_weight -= w[J];
                J--;
            }

            /* If we actually found something... */
            if(I<=J) {
                /* Switch the values */
                t1=A[I];
                A[I]=A[J];
                A[J]=t1;

                t2=w[I];
                w[I]=w[J];
                w[J]=t2;

                /* And move in */
                I_weight += w[I];
                I++;

                J_weight -= w[J];
                J--;
            }
        } while (I <= J); /* Keep going until our pointers meet or pass */

        /* Re-adjust L and R, based on which element we're looking for */
        if(J_weight<K_weight)
            L=I; L_weight = I_weight;
        if(K_weight<I_weight)
            R=J; R_weight = J_weight;
    }

    return A[L];
}

long long self_weighted_percentile(long long * A,
                                   int N,            /* total */
                                   int ple)          /* percentile */
{
    int L, R, I, J, K;
    long long L_weight, R_weight, I_weight, J_weight,
        K_weight, N_weight;

    long long X, t1;

    /* Calculate total weight */
    N_weight=0;

    for(I=0; I<N; I++) {
        if(A[I] < 0)
            fprintf(warn, "%s: Value %lld less than zero!\n",
                    __func__, A[I]);
        assert(A[I]!=0);
        N_weight += A[I];
    }

    /* Find K_weight, the target weight we want */
    K_weight = N_weight * ple / 100;

    /* Set the left and right boundaries of the current search space */
    L=0;
    L_weight = 0;
    R=N-1;
    R_weight = N_weight - A[R];

    /* Search between L and R, narrowing down until we're done */
    while(L < R) {
        /* Chose an ordering value from right in the middle */
        K = (L + R) >> 1;
        /* X: The value to order everything higher / lower than */
        X=A[K];

        /* Starting at the left and the right... */
        I=L; I_weight = L_weight;
        J=R; J_weight = R_weight;

        do {
            /* Find the first element on the left that is out-of-order w/ X */
            while(A[I]<X) {
                I_weight += A[I];
                I++;
            }
            /* Find the first element on the right that is out-of-order w/ X */
            while(X<A[J]) {
                J_weight -= A[J];
                J--;
            }

            /* If we actually found something... */
            if(I<=J) {
                /* Switch the values */
                t1=A[I];
                A[I]=A[J];
                A[J]=t1;

                /* And move in */
                I_weight += A[I];
                I++;

                J_weight -= A[J];
                J--;
            }
        } while (I <= J); /* Keep going until our pointers meet or pass */

        /* Re-adjust L and R, based on which element we're looking for */
        if(J_weight<K_weight)
            L=I; L_weight = I_weight;
        if(K_weight<I_weight)
            R=J; R_weight = J_weight;
    }

    return A[L];
}

static inline double __cycles_percent(long long cycles, long long total) {
    return (double)(cycles*100) / total;
}

static inline double __summary_percent(struct event_cycle_summary *s,
                                       struct cycle_framework *f) {
    return __cycles_percent(s->cycles, f->total_cycles);
}

static inline double summary_percent_global(struct event_cycle_summary *s) {
    return __summary_percent(s, &P.f);
}

static inline void update_summary(struct event_cycle_summary *s, long long c) {
/* We don't know ahead of time how many samples there are, and working
 * with dynamic stuff is a pain, and unnecessary.  This algorithm will
 * generate a sample set that approximates an even sample.  We can
 * then take the percentiles on this, and get an approximate value. */
    if(c) {
        if(opt.sample_size) {
            int lap = (s->cycles_count/opt.sample_size)+1,
                index =s->cycles_count % opt.sample_size;
            if((index - (lap/3))%lap == 0) {
                if(!s->cycles_sample) {
                    s->cycles_sample = malloc(sizeof(*s->cycles_sample) * opt.sample_size);
                    if(!s->cycles_sample) {
                        fprintf(stderr, "%s: malloc failed!\n", __func__);
                        error(ERR_SYSTEM, NULL);
                    }
                }
                s->cycles_sample[index]=c;
            }
        }
        s->cycles_count++;
        s->cycles += c;

        s->interval.count++;
        s->interval.cycles += c;
    }
    s->count++;
}

static inline void clear_interval_summary(struct event_cycle_summary *s) {
    s->interval.count = 0;
    s->interval.cycles = 0;
}

static inline void update_cycles(struct cycle_summary *s, long long c) {
/* We don't know ahead of time how many samples there are, and working
 * with dynamic stuff is a pain, and unnecessary.  This algorithm will
 * generate a sample set that approximates an even sample.  We can
 * then take the percentiles on this, and get an approximate value. */
    int lap, index;

    if ( c == 0 )
    {
        fprintf(warn, "%s: cycles 0! Not updating...\n",
                __func__);
        return;
    }

    if ( opt.sample_size ) {
        lap = (s->count/opt.sample_size)+1;
        index =s->count % opt.sample_size;

        if((index - (lap/3))%lap == 0) {
            if(!s->sample) {
                s->sample = malloc(sizeof(*s->sample) * opt.sample_size);
                if(!s->sample) {
                    fprintf(stderr, "%s: malloc failed!\n", __func__);
                    error(ERR_SYSTEM, NULL);
                }
            }
            s->sample[index] = c;
        }
    }

    if(c > 0) {
        s->cycles += c;
        s->interval.cycles += c;
    } else {
        s->cycles += -c;
        s->interval.cycles += -c;
    }
    s->count++;
    s->interval.count++;
}

static inline void clear_interval_cycles(struct interval_element *e) {
    e->cycles = 0;
    e->count = 0;
    e->instructions = 0;
}

static inline void update_cpi(struct weighted_cpi_summary *s,
                              unsigned long long i,
                              unsigned long long c) {
/* We don't know ahead of time how many samples there are, and working
 * with dynamic stuff is a pain, and unnecessary.  This algorithm will
 * generate a sample set that approximates an even sample.  We can
 * then take the percentiles on this, and get an approximate value. */
    int lap, index;

    if ( opt.sample_size ) {
        lap = (s->count/opt.sample_size)+1;
        index =s->count % opt.sample_size;

        if((index - (lap/3))%lap == 0) {
            if(!s->cpi) {
                assert(!s->cpi_weight);

                s->cpi = malloc(sizeof(*s->cpi) * opt.sample_size);
                s->cpi_weight = malloc(sizeof(*s->cpi_weight) * opt.sample_size);
                if(!s->cpi || !s->cpi_weight) {
                    fprintf(stderr, "%s: malloc failed!\n", __func__);
                    error(ERR_SYSTEM, NULL);
                }
            }
            assert(s->cpi_weight);

            s->cpi[index] = (float) c / i;
            s->cpi_weight[index]=c;
        }
    }

    s->instructions += i;
    s->cycles += c;
    s->count++;

    s->interval.instructions += i;
    s->interval.cycles += c;
    s->interval.count++;
}

static inline void clear_interval_cpi(struct weighted_cpi_summary *s) {
    s->interval.cycles = 0;
    s->interval.count = 0;
    s->interval.instructions = 0;
}

static inline void print_cpu_affinity(struct cycle_summary *s, char *p) {
    if(s->count) {
        long long avg;

        avg = s->cycles / s->count;

        if ( opt.sample_size ) {
            long long  p5, p50, p95;
            int data_size = s->count;
           if(data_size > opt.sample_size)
                data_size = opt.sample_size;

            p50 = percentile(s->sample, data_size, 50);
            p5 = percentile(s->sample, data_size, 5);
            p95 = percentile(s->sample, data_size, 95);

            printf("%s: %7d %6lld {%6lld|%6lld|%6lld}\n",
                   p, s->count, avg, p5, p50, p95);
        } else {
            printf("%s: %7d %6lld\n",
                   p, s->count, avg);
        }
    }
}

static inline void print_cpi_summary(struct weighted_cpi_summary *s) {
    if(s->count) {
        float avg;

        avg = (float)s->cycles / s->instructions;

        if ( opt.sample_size ) {
            float p5, p50, p95;
            int data_size = s->count;

            if(data_size > opt.sample_size)
                data_size = opt.sample_size;

            p50 = weighted_percentile(s->cpi, s->cpi_weight, data_size, 50);
            p5 = weighted_percentile(s->cpi, s->cpi_weight, data_size, 5);
            p95 = weighted_percentile(s->cpi, s->cpi_weight, data_size, 95);

            printf("  CPI summary: %2.2f {%2.2f|%2.2f|%2.2f}\n",
                   avg, p5, p50, p95);
        } else {
            printf("  CPI summary: %2.2f\n", avg);
        }
    }
}

static inline void print_cycle_percent_summary(struct cycle_summary *s,
                                               tsc_t total, char *p) {
    if(s->count) {
        long long avg;
        double percent, seconds;

        avg = s->cycles / s->count;

        seconds = ((double)s->cycles) / opt.cpu_hz;

        percent = ((double)(s->cycles * 100)) / total;

        if ( opt.sample_size ) {
            long long p5, p50, p95;
            int data_size = s->count;

            if(data_size > opt.sample_size)
                data_size = opt.sample_size;

            p50 = self_weighted_percentile(s->sample, data_size, 50);
            p5 = self_weighted_percentile(s->sample, data_size, 5);
            p95 = self_weighted_percentile(s->sample, data_size, 95);

            printf("%s: %7d %5.2lfs %5.2lf%% %6lld {%6lld|%6lld|%6lld}\n",
                   p, s->count,
                   seconds,
                   percent,
                   avg, p5, p50, p95);
        } else {
            printf("%s: %7d %5.2lfs %5.2lf%% %6lld\n",
                   p, s->count,
                   seconds,
                   percent,
                   avg);
        }
    }
}

static inline void print_cycle_summary(struct cycle_summary *s, char *p) {
    if(s->count) {
        long long avg;

        avg = s->cycles / s->count;

        if ( opt.sample_size ) {
            long long p5, p50, p95;
            int data_size = s->count;

            if(data_size > opt.sample_size)
                data_size = opt.sample_size;

            p50 = self_weighted_percentile(s->sample, data_size, 50);
            p5 = self_weighted_percentile(s->sample, data_size, 5);
            p95 = self_weighted_percentile(s->sample, data_size, 95);

            printf("%s: %7d %5.2lfs %6lld {%6lld|%6lld|%6lld}\n",
                   p, s->count, ((double)s->cycles)/opt.cpu_hz,
                   avg, p5, p50, p95);
        } else {
            printf("%s: %7d %5.2lfs %6lld\n",
                   p, s->count, ((double)s->cycles)/opt.cpu_hz, avg);
        }
    }
}

#define PRINT_SUMMARY(_s, _p...)                                        \
    do {                                                                \
        if((_s).count) {                                                \
            if ( opt.sample_size ) {                                    \
                unsigned long long p5, p50, p95;                        \
                int data_size=(_s).cycles_count;                        \
                if(data_size > opt.sample_size)                         \
                    data_size=opt.sample_size;                          \
                p50=percentile((_s).cycles_sample, data_size, 50);      \
                p5=percentile((_s).cycles_sample, data_size, 5);        \
                p95=percentile((_s).cycles_sample, data_size, 95);      \
                printf(_p);                                             \
                printf(" %7d %5.2lfs %5.2lf%% %5lld cyc {%5lld|%5lld|%5lld}\n", \
                       (_s).count,                                      \
                       ((double)(_s).cycles)/opt.cpu_hz,                \
                       summary_percent_global(&(_s)),                   \
                       (_s).cycles_count ? (_s).cycles / (_s).cycles_count:0, \
                       p5, p50, p95);                                   \
            } else {                                                    \
                printf(_p);                                             \
                printf(" %7d %5.2lfs %5.2lf%% %5lld cyc\n",             \
                       (_s).count,                                      \
                       ((double)(_s).cycles)/opt.cpu_hz,                \
                       summary_percent_global(&(_s)),                   \
                       (_s).cycles_count ? (_s).cycles / (_s).cycles_count:0); \
            }                                                           \
        }                                                               \
    } while(0)

#define INTERVAL_DESC_MAX 31
struct interval_list {
    struct interval_element *elem;
    struct interval_list *next;
    char desc[INTERVAL_DESC_MAX+1]; /* +1 for the null terminator */
};

void __interval_cycle_percent_output(struct interval_element *e, tsc_t cycles) {
    printf(" %.02lf",
           __cycles_percent(e->cycles, cycles));
    clear_interval_cycles(e);
}

void interval_cycle_percent_output(struct interval_element *e) {
    __interval_cycle_percent_output(e, opt.interval.cycles);
}

void interval_time_output(void) {
    struct time_struct t;
    abs_cycles_to_time(P.interval.start_tsc, &t);

    printf("%u.%09u", t.s, t.ns);
}

void interval_table_output(void) {
    int i;

    interval_time_output();

    if(opt.interval.mode == INTERVAL_MODE_ARRAY) {
        for(i=0; i<P.interval.array.count; i++) {
            struct interval_element *e = P.interval.array.values[i];
            if(e) {
                interval_cycle_percent_output(e);
            } else {
                printf(" 0.0");
            }
        }
    } else if(opt.interval.mode == INTERVAL_MODE_LIST) {
        struct interval_list *p;
        for(p = P.interval.list.head; p; p = p->next)
            interval_cycle_percent_output(p->elem);
    }
    printf("\n");
}

void interval_table_tail(void) {
    struct interval_list *p;

    printf("time");

    for(p=P.interval.list.head; p; p = p->next)
        printf(" %s", p->desc);

    printf("\n");
}

void interval_table_alloc(int count) {
    P.interval.array.count = count;
    P.interval.array.values = malloc(count * sizeof(struct interval_list *));

    if(!P.interval.array.values) {
        fprintf(stderr, "Malloc failed!\n");
        error(ERR_SYSTEM, NULL);
    }

    bzero(P.interval.array.values, count*sizeof(struct interval_list *));
}

void interval_list_add(struct interval_element *e, char *desc) {
    struct interval_list *p;

    fprintf(warn, "%s: Adding element '%s'\n", __func__, desc);

    if((p=malloc(sizeof(*p)))==NULL) {
        fprintf(stderr, "malloc() failed.\n");
        error(ERR_SYSTEM, NULL);
    }

    bzero(p, sizeof(*p));

    p->elem = e;
    strncpy(p->desc, desc, INTERVAL_DESC_MAX);

    p->next=NULL;

    if(P.interval.list.head)
        *P.interval.list.tail = p;
    else
        P.interval.list.head = p;
    P.interval.list.tail = &p->next;
}

void interval_cr3_schedule_time_header(void) {
    if( opt.interval.mode == INTERVAL_MODE_ARRAY ) {
        int i;

        printf("time");
        for(i=0; i<opt.interval.array.count; i++) {
            printf(" %llx", opt.interval.array.values[i]);
        }
        printf("\n");
    }
    /* Can't see into the future, so no header if cr3 values are
       not specified. */
}

void interval_cr3_value_check(struct cr3_value_struct *cr3) {
    if( opt.interval.mode == INTERVAL_MODE_ARRAY ) {
        int i;

        for(i=0; i<opt.interval.array.count; i++) {
            if(cr3->gmfn == opt.interval.array.values[i]) {
                if(P.interval.array.values[i]) {
                    fprintf(stderr, "Fatal: duplicate cr3 value %llx!\n",
                            cr3->gmfn);
                    error(ERR_ASSERT, NULL);
                }
                fprintf(stderr, "%s: found gmfn %llx\n",
                        __func__, cr3->gmfn);

                P.interval.array.values[i] = &cr3->total_time.interval;
            }
        }
    } else if(opt.interval.mode == INTERVAL_MODE_LIST) {
        char desc[32];
        snprintf(desc, 32, "%llx", cr3->gmfn);
        interval_list_add(&cr3->total_time.interval, desc);
    } else {
        /* Custom */
        if(cr3->gmfn == opt.interval.array.values[0])
            P.interval.cr3 = cr3;
    }
}

void interval_cr3_schedule_ordered_output(void) {
    struct cr3_value_struct *p;
    int i;

    struct cr3_value_struct **qsort_array;
    int N=0;

    int cr3_time_compare(const void *_a, const void *_b) {
        struct cr3_value_struct *a=*(typeof(&a))_a;
        struct cr3_value_struct *b=*(typeof(&a))_b;

        if(a->total_time.interval.cycles < b->total_time.interval.cycles)
            return 1;
        else if(b->total_time.interval.cycles == a->total_time.interval.cycles) {
            if(a->total_time.interval.count < b->total_time.interval.count)
                return 1;
            else if(a->total_time.interval.count == b->total_time.interval.count)
                return 0;
            else
                return -1;
        } else
            return -1;
    }

    for(p=P.cr3.head; p; p=p->gnext)
        N++;

    if(!N)
        return;

    qsort_array = malloc(N * sizeof(struct eip_list_struct *));

    for(i=0, p=P.cr3.head; p; p=p->gnext, i++)
        qsort_array[i]=p;

    qsort(qsort_array, N, sizeof(struct eip_list_struct *),
          cr3_time_compare);

    interval_time_output();

    for(i=0; i<N; i++) {
        p = qsort_array[i];
        /* Rounding down means this will get ..1]% */
        if(p->total_time.interval.cycles > 0) {
            printf(" %8llx: %.02lf %c\n",
                   p->gmfn,
                   __cycles_percent(p->total_time.interval.cycles,
                                    opt.interval.cycles),
                   (p->first_time > P.interval.start_tsc)?'*':' ');
        }
        clear_interval_cycles(&p->total_time.interval);
    }

    free(qsort_array);
}

void interval_cr3_short_summary_header(void) {
    int i;

    printf("time guest");
    for(i=0; i<HVM_SHORT_SUMMARY_MAX; i++)
        printf(" %s", hvm_short_summary_name[i]);
    printf("\n");
}

void interval_cr3_short_summary_output(void) {
    struct cycle_summary *hss_array;
    int i;

    if(P.interval.cr3) {
        struct cr3_value_struct *p = P.interval.cr3;

        interval_time_output();

        hss_array = p->hvm.s;

        printf(" %.02lf",
               __cycles_percent(p->total_time.interval.cycles,
                                opt.interval.cycles));

        for(i=0; i<HVM_SHORT_SUMMARY_MAX; i++)
            __interval_cycle_percent_output(&hss_array[i].interval,
                                            p->total_time.interval.cycles);

        clear_interval_cycles(&p->total_time.interval);

        printf("\n");
    }
}

void interval_domain_value_check(struct domain_data *d) {
    if( opt.interval.mode == INTERVAL_MODE_ARRAY ) {
        int i;

        for(i=0; i<opt.interval.array.count; i++) {
            if(d->did == opt.interval.array.values[i]) {
                if(P.interval.array.values[i]) {
                    fprintf(stderr, "Fatal: duplicate domain value %d!\n",
                            d->did);
                    error(ERR_ASSERT, NULL);
                }

                P.interval.array.values[i] = &d->total_time.interval;
            }
        }
    } else if(opt.interval.mode == INTERVAL_MODE_LIST) {
        char desc[32];
        snprintf(desc, 32, "%d", d->did);
        interval_list_add(&d->total_time.interval, desc);
    } else {
        if(d->did == opt.interval.array.values[0])
            P.interval.domain.d = d;
    }
}

void interval_domain_short_summary_header(void) {
    int i;

    printf("time running");
    for(i=0; i<HVM_SHORT_SUMMARY_MAX; i++)
        printf(" %s", hvm_short_summary_name[i]);
    printf("\n");
}

void interval_domain_short_summary_output(void) {

    if(P.interval.domain.d) {
        struct domain_data *d;
        int i;

        d=P.interval.domain.d;

        interval_time_output();

        interval_cycle_percent_output(&d->total_time.interval);

        for(i=0; i<HVM_SHORT_SUMMARY_MAX; i++)
            interval_cycle_percent_output(&d->hvm_short.s[i].interval);

        printf("\n");
    }
}

void interval_domain_guest_interrupt(struct hvm_data *h, int vector) {
    struct domain_data *d = h->v->d;
    int i;

    /* Check to see if this vector is in the "print list" */
    for(i=0; i<INTERVAL_DOMAIN_GUEST_INTERRUPT_MAX; i++) {
        if(P.interval.domain.guest_vector[i] == 0) {
            P.interval.domain.guest_vector[i] = vector;
            break;
        }
        if(P.interval.domain.guest_vector[i] == vector)
            break;
    }

    if(i == INTERVAL_DOMAIN_GUEST_INTERRUPT_MAX) {
        fprintf(stderr, "FATAL: used up all %d guest interrupt slots!\n",
                INTERVAL_DOMAIN_GUEST_INTERRUPT_MAX);
        error(ERR_LIMIT, NULL);
    } else {
        d->guest_interrupt[vector]++;
    }
}

void interval_domain_guest_interrupt_tail(void) {
    int i;

    printf("time running");
    for(i=0; i<INTERVAL_DOMAIN_GUEST_INTERRUPT_MAX; i++) {
        if(P.interval.domain.guest_vector[i] == 0)
            break;
        printf(" %d", P.interval.domain.guest_vector[i]);
    }
    printf("\n");
}

void interval_domain_guest_interrupt_output(void) {

    if(P.interval.domain.d) {
        struct domain_data *d;
        int i;

        d=P.interval.domain.d;

        interval_time_output();

        for(i=0; i<INTERVAL_DOMAIN_GUEST_INTERRUPT_MAX; i++) {
            int v = P.interval.domain.guest_vector[i];

            if(v == 0)
                break;

            printf(" %d", d->guest_interrupt[v]);

            d->guest_interrupt[v]=0;
        }

        printf("\n");
    }

}

void interval_domain_grant_maps_output(void) {

    if(P.interval.domain.d) {
        struct domain_data *d;

        d=P.interval.domain.d;

        interval_time_output();

        printf(" %d", d->memops.done_for_interval[MEM_PAGE_GRANT_MAP]);

        d->memops.done_for_interval[MEM_PAGE_GRANT_MAP] = 0;

        printf("\n");
    }
}

/* General interval gateways */

void interval_callback(void) {
    /* First, see if we're in generic mode. */
    switch(opt.interval.mode) {
    case INTERVAL_MODE_LIST:
    case INTERVAL_MODE_ARRAY:
        interval_table_output();
        return;
    default:
        break;
    }

    switch(opt.interval.output) {
    case INTERVAL_CR3_SCHEDULE_ORDERED:
        interval_cr3_schedule_ordered_output();
        break;
    case INTERVAL_CR3_SHORT_SUMMARY:
        interval_cr3_short_summary_output();
        break;
    case INTERVAL_DOMAIN_SHORT_SUMMARY:
        interval_domain_short_summary_output();
        break;
    case INTERVAL_DOMAIN_GUEST_INTERRUPT:
        interval_domain_guest_interrupt_output();
        break;
    case INTERVAL_DOMAIN_GRANT_MAPS:
        interval_domain_grant_maps_output();
        break;
    default:
        break;
    }
}

void interval_header(void) {
    switch(opt.interval.output) {
    case INTERVAL_CR3_SHORT_SUMMARY:
        interval_cr3_short_summary_header();
        break;
    case INTERVAL_DOMAIN_SHORT_SUMMARY:
        interval_domain_short_summary_header();
        break;
    default:
        break;
    }
}

void interval_tail(void) {
    if(opt.interval.mode == INTERVAL_MODE_LIST) {
        interval_table_tail();
        return;
    }

    switch(opt.interval.output) {
    case INTERVAL_DOMAIN_GUEST_INTERRUPT:
        interval_domain_guest_interrupt_tail();
        break;
    default:
        break;
    }
}

/* -- Eip list data -- */

void update_eip(struct eip_list_struct **head, unsigned long long eip,
                unsigned long long cycles, int type, void * extra) {
    struct eip_list_struct *p, **last=head;

    for(p=*head; p; last = (&p->next), p=p->next)
        if(p->eip >= eip)
            break;

    if(!p || p->eip != eip) {
        p=malloc(sizeof(*p));
        if(!p) {
            perror("malloc failed");
            error(ERR_SYSTEM, NULL);
        }

        bzero(p, sizeof(*p));

        p->eip=eip;
        p->type = type;

        if(eip_list_type[type].new) {
            eip_list_type[type].new(p, extra);
        }
        p->next = *last;
        *last=p;
    } else if(p->type != type) {
        fprintf(stderr, "WARNING, mixed types! %d %d\n", p->type, type);
    } else if(eip_list_type[type].update) {
        eip_list_type[type].update(p, extra);
    }

    update_summary(&p->summary, cycles);
}

void dump_eip(struct eip_list_struct *head) {
    struct eip_list_struct *p;
    int i;
    int total = 0;

    struct eip_list_struct **qsort_array;
    int N=0;

    int eip_compare(const void *_a, const void *_b) {
        struct eip_list_struct *a=*(typeof(&a))_a;
        struct eip_list_struct *b=*(typeof(&a))_b;

        if(a->summary.cycles < b->summary.cycles)
            return 1;
        else if(b->summary.cycles == a->summary.cycles) {
            if(a->summary.count < b->summary.count)
                return 1;
            else if(a->summary.count == b->summary.count)
                return 0;
            else
                return -1;
        } else
            return -1;
    }

    for(p=head; p; p=p->next)
    {
        total += p->summary.count;
        N++;
    }

    if(!N)
        return;

    qsort_array = malloc(N * sizeof(struct eip_list_struct *));

    for(i=0, p=head; p; p=p->next, i++)
        qsort_array[i]=p;

    qsort(qsort_array, N, sizeof(struct eip_list_struct *),
          eip_compare);

    /* WARNING: don't use N after this point unless you copy this variable */
#if 0
    if(opt.summary_eip_limit && opt.summary_eip_limit < N)
        N=opt.summary_eip_limit;
#endif

    printf("   Total samples: %d\n", total);

    for(i=0; i<N; i++) {
        p = qsort_array[i];
        if ( p->summary.cycles )
            PRINT_SUMMARY(p->summary, "   %12llx%-45s: ",
                          p->eip,
                          find_symbol(p->eip));
        else
        {
            printf("   %12llx%-45s: ",
                          p->eip,
                          find_symbol(p->eip));
            printf(" %7d %5.2lf%%\n",
                   p->summary.count,
                   ((double)p->summary.count*100)/total);
        }


        if(eip_list_type[p->type].dump) {
            eip_list_type[p->type].dump(p);
        }
    }

    free(qsort_array);
}

/* -- HVM code -- */
struct hvm_pf_xen_record {
    //unsigned vcpu:16, domain:16;
    union {
        struct {
            unsigned long long va;
            unsigned int error_code;
        } x64;
        struct {
            unsigned int va;
            unsigned int error_code;
        } x32;
    };
};

void hvm_update_short_summary(struct hvm_data *h, int element) {
    struct vcpu_data *v = h->v;

    if(v->cr3.data)
        update_cycles(&v->cr3.data->hvm.s[element], h->arc_cycles);

    update_cycles(&v->d->hvm_short.s[element], h->arc_cycles);

    h->short_summary_done=1;
}

void hvm_short_summary(struct hvm_short_summary_struct *hss,
                       tsc_t total, char *prefix) {
    char desc[80];
    int i;

    for(i=0; i<HVM_SHORT_SUMMARY_MAX; i++) {
        snprintf(desc, 80, "%s%s", prefix, hvm_short_summary_name[i]);
        print_cycle_percent_summary(hss->s + i, total, desc);
    }
}

/* Wrapper to try to make sure this is only called once per
 * call site, rather than walking through the list each time */
#define hvm_set_summary_handler(_h, _s, _d)                             \
    do {                                                                \
        static int done=0;                                              \
        int ret;                                                        \
        if(!done) {                                                     \
            if ((ret=__hvm_set_summary_handler(_h, _s, _d)))            \
                fprintf(stderr, "%s: hvm_set_summary_handler returned %d\n", \
                        __func__, ret);                                 \
            done=1;                                                     \
        }                                                               \
    } while(0)

int __hvm_set_summary_handler(struct hvm_data *h, void (*s)(struct hvm_data *h, void*d), void*d) {
    /* Set summary handler */
    if(h->exit_reason < h->exit_reason_max)
    {
        struct hvm_summary_handler_node *p, **q;

        /* Find the end of the list, checking to make sure there are no
         * duplicates along the way */
        q=&h->exit_reason_summary_handler_list[h->exit_reason];
        p = *q;
        while(p)
        {
            if(p->handler == s && p->data == d)
            {
                fprintf(stderr, "%s: Unexpected duplicate handler %p,%p\n",
                        __func__, s, d);
                error(ERR_STRICT, NULL);
            return -EBUSY;
            }
            q=&p->next;
            p=*q;
        }

        assert(p==NULL);

        /* Insert the new handler */
        p=malloc(sizeof(*p));
        if (!p) {
            fprintf(stderr, "%s: Malloc failed!\n", __func__);
            error(ERR_SYSTEM, NULL);
        }
        p->handler=s;
        p->data = d;
        p->next=*q;
        *q=p;
        return 0;
    }
    return -EINVAL;
}

void hvm_generic_postprocess(struct hvm_data *h);

static int hvm_set_postprocess(struct hvm_data *h, void (*s)(struct hvm_data *h))
{
    if ( h->post_process == NULL
        || h->post_process == hvm_generic_postprocess )
    {
        h->post_process = s;
        return 0;
    }
    else
        return 1;
}

#define SIGN_EXTENDED_BITS (~((1ULL<<48)-1))
#define HIGH_BIT(_v) ((_v) & (1ULL<<47))
static inline int is_valid_addr64(unsigned long long va)
{
    if(HIGH_BIT(va))
        return ((va & SIGN_EXTENDED_BITS) == SIGN_EXTENDED_BITS);
    else
        return ((va & SIGN_EXTENDED_BITS) == 0);
}

void hvm_pf_xen_summary(struct hvm_data *h, void *d) {
    int i,j, k;

    printf("   page_fault\n");
    for(i=0; i<PF_XEN_MAX; i++)
    {
        if( pf_xen_name[i] )
        {
            PRINT_SUMMARY(h->summary.pf_xen[i],
                          "     %-25s ", pf_xen_name[i]);
        }
        else
        {
            PRINT_SUMMARY(h->summary.pf_xen[i],
                          "     [%23d] ", i);
        }
        switch(i){
        case PF_XEN_NON_EMULATE:
            for(j=0; j<PF_XEN_NON_EMUL_MAX; j++)
                PRINT_SUMMARY(h->summary.pf_xen_non_emul[j],
                              "      *%-13s ", pf_xen_non_emul_name[j]);
            break;
        case PF_XEN_EMULATE:
            for(j=0; j<PF_XEN_EMUL_MAX; j++) {
                PRINT_SUMMARY(h->summary.pf_xen_emul[j],
                              "      *%-13s ", pf_xen_emul_name[j]);
                if(j == PF_XEN_EMUL_EARLY_UNSHADOW) {
                    int k;
                    for(k=0; k<5; k++) {
                        PRINT_SUMMARY(h->summary.pf_xen_emul_early_unshadow[k],
                                      "        +[%d] ", k);
                    }
                }
            }
            break;
        case PF_XEN_FIXUP:
            for(j=0; j<PF_XEN_FIXUP_MAX; j++) {
                PRINT_SUMMARY(h->summary.pf_xen_fixup[j],
                              "      *%-13s ", pf_xen_fixup_name[j]);
                if(j == PF_XEN_FIXUP_UNSYNC ) {
                    for(k=0; k<PF_XEN_FIXUP_UNSYNC_RESYNC_MAX; k++) {
                        PRINT_SUMMARY(h->summary.pf_xen_fixup_unsync_resync[k],
                                      "       +[%3d] ", k);
                    }
                    PRINT_SUMMARY(h->summary.pf_xen_fixup_unsync_resync[k],
                                  "        +[max] ");
                }
            }
            break;
        }
    }
}

void pf_preprocess(struct pf_xen_extra *e, int guest_paging_levels)
{
    switch(guest_paging_levels) {
        /* Select a subfield of _bits bits starting at bit _shift from _x */
#define _SUBFIELD(_bits, _shift, _x)                \
        (((_x)>>(_shift)) & ((1ULL<<(_bits))-1))
    case 4:
        /* Verify sign-extension */
        if((HIGH_BIT(e->va)
            &&((e->va & SIGN_EXTENDED_BITS) != SIGN_EXTENDED_BITS))
           || (!HIGH_BIT(e->va)
               && ((e->va & SIGN_EXTENDED_BITS) != 0))) {
            fprintf(warn, "Strange, va %llx not properly sign extended for 4-level pagetables\n",
                    e->va);
        }
        e->pt_index[4]=_SUBFIELD(9,39,e->va);
        e->pt_index[3]=_SUBFIELD(9,30,e->va);
        e->pt_index[2]=_SUBFIELD(9,21,e->va);
        e->pt_index[1]=_SUBFIELD(9,12,e->va);
        /* These are only useful for the linear-pagetable code */
        e->pt_index[0]=_SUBFIELD(9,3,e->va);
        if(e->va & 0x4)
            e->pt_is_lo=0;
        break;
    case 3:
        e->pt_index[3]=_SUBFIELD(2,30,e->va);
        e->pt_index[2]=_SUBFIELD(9,21,e->va);
        e->pt_index[1]=_SUBFIELD(9,12,e->va);
        /* These are only useful for the linear-pagetable code */
        e->pt_index[0]=_SUBFIELD(9,3,e->va);
        if(e->va & 0x4)
            e->pt_is_lo=0;
        break;
    case 2:
        e->pt_index[2]=_SUBFIELD(10,22,e->va);
        e->pt_index[1]=_SUBFIELD(10,12,e->va);
        /* This is only useful for the linear pagetable code */
        e->pt_index[0]=_SUBFIELD(10,2,e->va);
        break;
    case 0:
        break;
    default:
        fprintf(warn, "Don't know how to handle %d-level pagetables\n",
                guest_paging_levels);
    }

    e->corresponding_va = CORR_VA_INVALID;
    e->pt_level = 0;

    /* Detect accesses to Windows linear pagetables */
    switch(guest_paging_levels)
    {
    case 2:
        if(e->pt_index[2] == 768) {
            if(e->pt_index[1] == 768)
            {
                e->pt_level = 2;
                e->corresponding_va=((1UL<<22)-1)
                    | e->pt_index[0]<<22;
            }
            else
            {
                e->pt_level = 1;
                e->corresponding_va = ((1UL<<12)-1)
                    | e->pt_index[1]<<22
                    | e->pt_index[0]<<12;
            }
        }
        break;
    case 3:
        if(e->pt_index[3]==3 && (e->pt_index[2]>>2==0))
        {
            if(e->pt_index[2]==3 && e->pt_index[1]>>2==0)
            {
                if(e->pt_index[1] == 3 && e->pt_index[0]>>2==0)
                {
                    e->pt_level = 3;
                    e->corresponding_va=((1UL<<30)-1)
                        | e->pt_index[0]<<30;
                }
                else
                {
                    e->pt_level = 2;
                    e->corresponding_va=((1UL<<21)-1)
                        | e->pt_index[1]<<30
                        | e->pt_index[2]<<21;
                }
            }
            else
            {
                e->pt_level = 1;
                e->corresponding_va = ((1UL<<12)-1)
                    | e->pt_index[0]<<12
                    | e->pt_index[1]<<21
                    | e->pt_index[2]<<30;
            }
        }
        break;
    case 4:
        if(e->pt_index[4] == 0x1ed)
        {
            if(e->pt_index[3] == 0x1ed)
            {
                if(e->pt_index[2] == 0x1ed)
                {
                    if(e->pt_index[1] == 0x1ed)
                    {
                        e->pt_level = 4;
                        e->corresponding_va = ((1ULL<<39)-1)
                            | (unsigned long long)e->pt_index[0]<<39;
                    }
                    else
                    {
                        e->pt_level = 3;
                        e->corresponding_va = ((1ULL<<30)-1)
                            | (unsigned long long)e->pt_index[0]<<30
                            | (unsigned long long)e->pt_index[1]<<39;
                    }
                }
                else
                {
                    e->pt_level = 2;
                    e->corresponding_va = ((1ULL<<21)-1)
                        | (unsigned long long)e->pt_index[0]<<21
                        | (unsigned long long)e->pt_index[1]<<30
                        | (unsigned long long)e->pt_index[2]<<39;
                }
            }
            else
            {
                e->pt_level = 1;
                e->corresponding_va = ((1ULL<<12)-1)
                    | (unsigned long long)e->pt_index[0]<<12
                    | (unsigned long long)e->pt_index[1]<<21
                    | (unsigned long long)e->pt_index[2]<<30
                    | (unsigned long long)e->pt_index[3]<<39;
            }

            if(HIGH_BIT(e->corresponding_va))
                e->corresponding_va |= SIGN_EXTENDED_BITS;
        }
        break;
    default:
        break;
    }
}

void hvm_pf_xen_preprocess(unsigned event, struct hvm_data *h) {
    struct pf_xen_extra *e = &h->inflight.pf_xen;
    struct mmio_info *m = &h->inflight.mmio;
    struct hvm_pf_xen_record *r = (typeof(r))h->d;

    if(event == TRC_HVM_PF_XEN64)
    {
        if(!is_valid_addr64(r->x64.va))
            fprintf(warn, "%s: invalid va %llx",
                    __func__, r->x64.va);
        e->va = r->x64.va;
        e->error_code = r->x64.error_code;
    }
    else
    {
        e->va = r->x32.va;
        e->error_code = r->x32.error_code;
    }

    if(m->data_valid)
        e->pf_case = PF_XEN_MMIO;
    else
    {
        pf_preprocess(e, h->v->guest_paging_levels);

        /* On rio traces, we try to infer emulation by looking for accesses
           in the linear pagetable */
        if(e->pt_level > 0)
            e->pf_case = PF_XEN_EMULATE;
        else
            e->pf_case = PF_XEN_NON_EMULATE;
    }
}

static inline int is_kernel(int paging_levels, unsigned long long va) {
    switch(paging_levels) {
    case 2:
    case 3:
        if(va & 0x80000000)
            return 1;
        else
            return 0;
        break;
    case 4:
        if(HIGH_BIT(va))
            return 1;
        else return 0;
    default:
        return 0;
    }

}

void hvm_pf_xen_postprocess(struct hvm_data *h) {
    struct pf_xen_extra *e = &h->inflight.pf_xen;

    if(opt.summary_info) {
        if(e->pf_case)
            update_summary(&h->summary.pf_xen[e->pf_case],
                           h->arc_cycles);
        else
            fprintf(warn, "Strange, pf_case 0!\n");
        switch(e->pf_case)
        {
        case PF_XEN_EMULATE:
            update_eip(&h->v->d->emulate_eip_list,
                       h->rip,
                       h->arc_cycles,
                       0, NULL);
            break;
        case PF_XEN_NON_EMULATE:
            if(is_kernel(h->v->guest_paging_levels, h->rip))
                update_summary(&h->summary.pf_xen_non_emul[PF_XEN_NON_EMUL_EIP_KERNEL],
                               h->arc_cycles);
            else
                update_summary(&h->summary.pf_xen_non_emul[PF_XEN_NON_EMUL_EIP_USER],
                               h->arc_cycles);
            if(is_kernel(h->v->guest_paging_levels, e->va))
                update_summary(&h->summary.pf_xen_non_emul[PF_XEN_NON_EMUL_VA_KERNEL],
                               h->arc_cycles);

            else
                update_summary(&h->summary.pf_xen_non_emul[PF_XEN_NON_EMUL_VA_USER],
                               h->arc_cycles);
        }

        /* Set summary handler */
        hvm_set_summary_handler(h, hvm_pf_xen_summary, NULL);
    }
}

void hvm_pf_xen_process(struct record_info *ri, struct hvm_data *h) {
    struct pf_xen_extra *e = &h->inflight.pf_xen;

    if(ri->event == TRC_HVM_PF_XEN64
        && h->v->guest_paging_levels != 4)
        fprintf(warn, "Strange, PF_XEN64 but guest_paging_levels %d!\n",
                h->v->guest_paging_levels);
    else if(ri->event == TRC_HVM_PF_XEN
            && h->v->guest_paging_levels == 4)
        fprintf(warn, "Strange, PF_XEN but guest_paging_levels %d!\n",
                h->v->guest_paging_levels);

    hvm_pf_xen_preprocess(ri->event, h);

    if(opt.dump_all)
    {
        if(e->pf_case == PF_XEN_EMULATE)
            printf("]%s pf_xen:emulate va %llx ec %x level %d corr %llx e->pt_index[%d %d %d %d %d]\n",
                   ri->dump_header, e->va, e->error_code,
                   e->pt_level, e->corresponding_va,
                   e->pt_index[0], e->pt_index[1], e->pt_index[2],
                   e->pt_index[3],
                   e->pt_index[4]);
        else
            printf("]%s pf_xen va %llx ec %x e->pt_index[%d %d %d %d %d]\n",
                   ri->dump_header, e->va, e->error_code,
                   e->pt_index[0], e->pt_index[1], e->pt_index[2],
                   e->pt_index[3],
                   e->pt_index[4]);
    }

    if ( hvm_set_postprocess(h, hvm_pf_xen_postprocess) )
         fprintf(warn, "%s: Strange, postprocess already set\n", __func__);
}

char * hvm_vlapic_icr_dest_shorthand_name[4] = {
    "dest_field", "self", "all-inc", "all-exc"
};

void hvm_vlapic_vmentry_cleanup(struct vcpu_data *v, tsc_t tsc)
{
    int i;

    struct vlapic_struct *vla = &v->vlapic;

    for(i=0; i<MAX_VLAPIC_LIST; i++)
    {
        unsigned long long lat=0;
        struct outstanding_ipi *o = vla->outstanding.list + i;

        if(!(o->valid && o->injected))
            continue;

        if(tsc >= o->first_tsc)
            lat = tsc - o->first_tsc;
        else
            fprintf(warn, "Strange, vec %d first_tsc %lld > ri->tsc %lld!\n",
                    o->vec, o->first_tsc, tsc);

        if(opt.dump_ipi_latency
           || (opt.dump_all && o->count > 1)) {
            struct time_struct t;
            cycles_to_time(lat, &t);
            printf(" [vla] d%dv%d vec %d ipis %d, latency %lld (%u.%09u s)\n",
                   v->d->did, v->vid, o->vec, o->count, lat,
                   t.s, t.ns);
        }

#if 0
        /* FIXME: make general somehow */
        if(opt.summary_info)
        {
            update_summary(&h->summary.ipi_latency, lat);
            h->summary.ipi_count[vla->outstanding_ipis]++;
        }
#endif

        o->vec = o->count = o->injected = o->valid = o->first_tsc = 0;
    }
}

void hvm_vlapic_clear(struct vlapic_struct *vla)
{
    bzero(vla, sizeof(*vla));
}

struct outstanding_ipi *find_vec(struct vlapic_struct *vla, int vec)
{
    struct outstanding_ipi *o = NULL;
    int i;

    /* Find the entry for this vector, or the first empty one. */
    for(i=0; i<MAX_VLAPIC_LIST; i++)
    {
        if(vla->outstanding.list[i].valid && vla->outstanding.list[i].vec == vec)
        {
            o = vla->outstanding.list + i;
            break;
        } else if(!vla->outstanding.list[i].valid && !o)
            o = vla->outstanding.list + i;
    }

    if(!o->valid) {
        o->vec = vec;
        o->valid = 1;
    }

    return o;
}

void hvm_vlapic_icr_handler(struct hvm_data *h)
{
    struct mmio_info *m = &h->inflight.mmio;
    union {
        unsigned int val;
        struct {
            unsigned vec:8,
                delivery_mode:3,
                dest_mode:1,
                delivery_status:1,
                _res1:1,
                level:1,
                trigger:1,
                _res2:2,
                dest_shorthand:2;
        };
    } icr = { .val = m->data };

    void ipi_send(struct vcpu_data *ov, int vec)
    {
        struct vlapic_struct *vla;
        struct outstanding_ipi *o = NULL;

        if(ov->runstate.state == RUNSTATE_LOST) {
            if(opt.dump_all)
                fprintf(warn, "%s: v%d in state RUNSTATE_LOST, not counting ipi\n",
                        __func__, ov->vid);
            return;
        }

        vla = &ov->vlapic;

        o = find_vec(vla, vec);

        if(!o)
        {
            fprintf(warn, "%s: Couldn't find an open slot!\n",
                    __func__);
            return;
        }

        if(!o->first_tsc)
            o->first_tsc = P.now;

        if(opt.dump_all && o->count == 0 && o->injected)
            printf(" [vla] Pre-injection\n");

        o->count++;

        if((opt.dump_all)
#if 0
           && (ov->runstate.state != RUNSTATE_RUNNING
               || ov->hvm.vmexit_valid)
#endif
            )
            printf(" [vla] d%dv%d vec %d state %s (outstanding ipis %d)\n",
                   ov->d->did, ov->vid,
                   o->vec,
                   runstate_name[ov->runstate.state],
                   o->count);
    }

    if(m->is_write) {
        if(opt.dump_all) {
            printf("              [vla] d%dv%d icr vec %d %s\n",
                   h->v->d->did, h->v->vid,
                   icr.vec,
                   hvm_vlapic_icr_dest_shorthand_name[icr.dest_shorthand]);
        }

        if(icr.dest_shorthand == 3)
        {
            struct vcpu_data *ov, *v = h->v;
            struct domain_data *d = v->d;
            int i;

            for(i=0; i<MAX_CPUS; i++)
            {
                ov = d->vcpu[i];
                if(!ov || ov == v)
                    continue;

                ipi_send(ov, icr.vec);

            }
        } else if(icr.dest_shorthand != 1) {
#if 0
            fprintf(warn, "Strange, vlapic icr %s vec %d!\n",
                    hvm_vlapic_icr_dest_shorthand_name[icr.dest_shorthand],
                    icr.vec);
#endif
        }
    } else {
        /* Read */
        if(opt.dump_all) {
            printf("              [vla] d%dv%d icr status %s\n",
                   h->v->d->did, h->v->vid,
                   icr.delivery_status?"pending":"idle");
        }
    }

}

void hvm_vlapic_inject(struct vcpu_data *v, int vec)
{
    struct vlapic_struct *vla = &v->vlapic;
    struct outstanding_ipi *o = NULL;

    o = find_vec(vla, vec);

    if(o) {
        if(opt.dump_all)
            printf("  [vla] d%dv%d vec %d injecting\n",
                   v->d->did, v->vid, vec);
        o->injected=1;
    } else {
        fprintf(stderr, "%s: Couldn't find an open ipi slot!\n",
                __func__);
    }
}

void hvm_vlapic_eoi_handler(struct hvm_data *h) {
    if(opt.dump_all)
        printf("              [vla] d%dv%d eoi\n",
               h->v->d->did, h->v->vid);
}

void hvm_vlapic_handler(struct hvm_data *h)
{
    struct mmio_info *m = &h->inflight.mmio;

    switch(m->gpa) {
    case 0xfee00300:
        hvm_vlapic_icr_handler(h);
        break;
    case 0xfee000b0:
        hvm_vlapic_eoi_handler(h);
        break;
    }

}

/* Also called by shadow_mmio_postprocess */
#define MMIO_VGA_START (0xa0000)
#define MMIO_VGA_END   (0xbffff)
void enumerate_mmio(struct hvm_data *h)
{
    struct mmio_info *m = &h->inflight.mmio;

    /* Skip vga area */
    if ( opt.mmio_enumeration_skip_vga
         && m->gpa >= MMIO_VGA_START
         && m->gpa <  MMIO_VGA_END)
    {
        warn_once("WARNING: Not enumerationg MMIO in VGA range.  Use --mmio-enumeration-skip-vga=0 to override.\n");
        return;
    }

    if ( m->data_valid )
        update_io_address(&h->summary.io.mmio, m->gpa, m->is_write, h->arc_cycles, m->va);
}

void hvm_mmio_summary(struct hvm_data *h, void *data)
{
    long reason=(long)data;

    PRINT_SUMMARY(h->summary.mmio[reason],
                  "   mmio ");
}

void hvm_mmio_assist_postprocess(struct hvm_data *h)
{
    long reason;

    switch(h->exit_reason)
    {
    case VMEXIT_NPF:
    case EXIT_REASON_EPT_VIOLATION:
        reason=NONPF_MMIO_NPF;
        hvm_set_summary_handler(h, hvm_mmio_summary, (void *)reason);
        break;
    case EXIT_REASON_APIC_ACCESS:
        reason=NONPF_MMIO_APIC;
        hvm_set_summary_handler(h, hvm_mmio_summary, (void *)reason);
        break;
    default:
    {
        static int warned = 0;
        if (!warned)
        {
            fprintf(warn, "%s: Strange, MMIO with unexpected exit reason %d\n",
                    __func__, h->exit_reason);
            warned=1;
        }
        reason=NONPF_MMIO_UNKNOWN;
        hvm_set_summary_handler(h, hvm_mmio_summary, (void *)reason);
        break;
    }
    }

    if(opt.summary_info)
    {
        update_summary(&h->summary.mmio[reason],
                       h->arc_cycles);
    }

    if ( opt.with_mmio_enumeration )
        enumerate_mmio(h);
}

#define HVM_IO_ASSIST_WRITE 0x200
void hvm_mmio_assist_process(struct record_info *ri, struct hvm_data *h)
{
    struct mmio_info *m = &h->inflight.mmio;
    union {
        struct {
            unsigned int gpa;
            unsigned int data;
        } x32;
        struct {
            unsigned long long gpa;
            unsigned int data;
        } x64;
    } *r = (typeof(r))h->d;

    union {
        unsigned event;
        struct {
            unsigned minor:8,
                x64:1,
                write:2;
        };
    } mevt = { .event = ri->event };

    if(mevt.x64) {
        m->gpa = r->x64.gpa;
        m->data = r->x64.data;
        if(ri->extra_words*(sizeof(unsigned int))==sizeof(r->x64))
            m->data_valid=1;
    } else {
        m->gpa = r->x32.gpa;
        m->data = r->x32.data;
        if(ri->extra_words*(sizeof(unsigned int))==sizeof(r->x32))
            m->data_valid=1;
    }

    m->is_write = mevt.write;

    if(opt.dump_all)
    {
        if(m->data_valid)
            printf("]%s mmio_assist %c gpa %llx data %x\n",
                   ri->dump_header,
                   mevt.write?'w':'r',
                   m->gpa, m->data);
        else
            printf("]%s mmio_assist %c gpa %llx (no data)\n", ri->dump_header,
                   mevt.write?'w':'r', m->gpa);
    }

    if((m->gpa & 0xfffff000) == 0xfee00000)
        hvm_vlapic_handler(h);

    /* Catch MMIOs that don't go through the shadow code; tolerate
     * failures to set (probably shadow_mmio) */
    hvm_set_postprocess(h, hvm_mmio_assist_postprocess);
}

void hvm_inj_virq_process(struct record_info *ri, struct hvm_data *h) {
    struct {
        int vector, fake;
    } *r = (typeof(r))h->d;

    if(opt.dump_all) {
        printf(" %s inj_virq vec %u  %s\n",
               ri->dump_header,
               r->vector, r->fake?"fake":"real");
    }

    if(opt.summary_info)
    {
        int vector = r->vector;

        if(vector >= GUEST_INTERRUPT_MAX)
            vector = GUEST_INTERRUPT_MAX;
        h->summary.guest_interrupt[vector].count++;

        if(opt.interval.output == INTERVAL_DOMAIN_GUEST_INTERRUPT)
            interval_domain_guest_interrupt(h, vector);
    }

    /* If we're waking, make this the wake vector */
    if(r->vector < GUEST_INTERRUPT_MAX ) {
        int vector = r->vector;
        if ( h->w2h.waking && h->w2h.vector == 0 ) {
            if(h->summary.guest_interrupt[vector].start_tsc) {
                fprintf(warn, "Strange, d%dv%d waking && wake_vector 0 but vec %d start_tsc %lld!\n",
                        h->v->d->did, h->v->vid,
                        vector,
                        h->summary.guest_interrupt[vector].start_tsc);
                error(ERR_WARN, NULL);
            }
            if(h->w2h.interrupts)
                fprintf(warn, "Strange, waking && wake_vector 0 but interrupts_this_wait_to_halt %d!\n",
                        h->w2h.interrupts);

            if(opt.dump_all)
                printf(" [w2h] d%dv%d Setting wake_vector %d\n",
                       h->v->d->did, h->v->vid, vector);

            /* In svm mode, vector information is invalid */
            if ( opt.svm_mode && r->fake )
                h->w2h.vector = FAKE_VECTOR;
            else
                h->w2h.vector = vector;
            h->summary.guest_interrupt[vector].is_wake = 1;
        }

        if( h->summary.guest_interrupt[vector].start_tsc == 0 ) {
            /* Note that we want start_tsc set at the next vmentry */
            h->summary.guest_interrupt[vector].start_tsc = 1;
            h->w2h.interrupts_wanting_tsc++;
            h->w2h.interrupts++;

            if(opt.dump_all)
                printf(" [w2h] d%dv%d Starting vec %d\n",
                       h->v->d->did, h->v->vid, vector);
        }
    }

    hvm_vlapic_inject(h->v, r->vector);
}

/* I/O Handling */
struct io_address {
    struct io_address *next;
    unsigned int pa;
    unsigned int va;
    struct event_cycle_summary summary[2];
};

void update_io_address(struct io_address ** list, unsigned int pa, int dir,
                       tsc_t arc_cycles, unsigned int va) {
    struct io_address *p, *q=NULL;

    /* Keep list in order */
    for(p=*list; p && (p->pa != pa) && (p->pa < pa); q=p, p=p->next);

    /* If we didn't find it, make a new element. */
    if(!p || (p->pa != pa)) {
        if((p=malloc(sizeof(*p)))==NULL) {
            fprintf(stderr, "malloc() failed.\n");
            error(ERR_SYSTEM, NULL);
        }

        bzero(p, sizeof(*p));

        p->pa=pa;
        p->va=va;

        /* If we stopped in the middle or at the end, add it in */
        if(q) {
            p->next=q->next;
            q->next=p;
        } else {
            /* Otherwise, we stopped after the first element; put it at the beginning */
            p->next = *list;
            *list = p;
        }
    }
    update_summary(&p->summary[dir], arc_cycles);
}

void hvm_io_address_summary(struct io_address *list, char * s) {
    if(!list)
        return;

    printf("%s\n", s);

    for(; list; list=list->next) {
        if ( list->va )
        {
            PRINT_SUMMARY(list->summary[0], "%8x@%8x:[r] ", list->pa, list->va);
            PRINT_SUMMARY(list->summary[1], "%8x@%8x:[w] ", list->pa, list->va);
        }
        else
        {
            PRINT_SUMMARY(list->summary[0], "%8x:[r] ", list->pa);
            PRINT_SUMMARY(list->summary[1], "%8x:[w] ", list->pa);
        }
    }
}

void hvm_io_write_postprocess(struct hvm_data *h)
{
    if(opt.with_pio_enumeration)
        update_io_address(&h->summary.io.pio, h->inflight.io.port, 1, h->arc_cycles, 0);
}

void hvm_io_read_postprocess(struct hvm_data *h)
{
    if(opt.with_pio_enumeration)
        update_io_address(&h->summary.io.pio, h->inflight.io.port, 0, h->arc_cycles, 0);
    if(opt.scatterplot_io && h->inflight.io.port == opt.scatterplot_io_port)
        scatterplot_vs_time(h->exit_tsc, P.now - h->exit_tsc);
}

void hvm_io_assist_process(struct record_info *ri, struct hvm_data *h)
{
    union {
        struct {
            unsigned int port;
            unsigned int data;
        } x32;
    } *r = (typeof(r))h->d;

    union {
        unsigned event;
        struct {
            unsigned minor:8,
                x64:1,
                write:2;
        };
    } mevt = { .event = ri->event };

    if(mevt.x64) {
        fprintf(stderr, "FATAL: Unexpected 64-bit PIO\n");
        error(ERR_RECORD, ri);
        return;
    }

    h->inflight.io.port = r->x32.port;
    h->inflight.io.val = r->x32.data;

    if(mevt.write) {
        h->inflight.io.is_write = 1;
        if ( hvm_set_postprocess(h, hvm_io_write_postprocess) )
             fprintf(warn, "%s: Strange, postprocess already set\n", __func__);
    } else {
        h->inflight.io.is_write = 0;
        if ( hvm_set_postprocess(h, hvm_io_read_postprocess) )
             fprintf(warn, "%s: Strange, postprocess already set\n", __func__);
    }

    if(opt.dump_all)
    {
        printf(" %s io %s port %x val %x\n",
               ri->dump_header,
               mevt.write?"write":"read",
               r->x32.port,
               r->x32.data);
    }
}

/* cr_write */
/* CR3 list */
void cr3_switch(unsigned long long val, struct hvm_data *h) {
    struct vcpu_data *v = h->v;
    /* Really only need absolute tsc here.  Later change to global time. */
    unsigned long long now = P.now;
    unsigned long long gmfn = val >> 12;

    if ( !h->init )
        return;

    if(opt.with_cr3_enumeration) {
        if(v->cr3.data) {
            struct cr3_value_struct *cur = v->cr3.data;
            unsigned long long cycles = now - v->cr3.start_time;

            if(opt.summary_info)
                update_cycles(&cur->total_time, cycles);

            cur->last_time = now;
        }

        if(gmfn) {
            struct cr3_value_struct *p, **last=&v->d->cr3_value_head;

            /* Always add to tail, so that we get consistent interval
               ouptut as the number of cr3s grow */
            for(p=*last; p; last = (&p->next), p=p->next)
                if(p->gmfn == gmfn)
                    break;

            if(!p) {
                if((p=malloc(sizeof(*p)))==NULL) {
                    fprintf(stderr, "malloc() failed.\n");
                    error(ERR_SYSTEM, NULL);
                }

                bzero(p, sizeof(*p));

                p->gmfn = gmfn;
                p->cr3_id = P.cr3.id;
                p->first_time = now;

                p->next=*last;
                *last=p;

                p->gnext = NULL;
                if(P.cr3.head)
                    *P.cr3.tail = p;
                else
                    P.cr3.head = p;
                P.cr3.tail = &p->gnext;

                P.cr3.id++;

                /* Add to the interval list if appropriate */
                if(opt.interval.check == INTERVAL_CHECK_CR3
                   && v->d->did != DEFAULT_DOMAIN)
                    interval_cr3_value_check(p);
            }

            if(p->prealloc_unpin.now) {
                fprintf(warn, "Re-promoting previously unpinned cr3 %llx!\n",
                        p->gmfn);
                p->prealloc_unpin.now = 0;
                h->inflight.cr_write.repromote = 1;
            }

            /* Accounting for new toplevel */
            v->cr3.start_time = now;
            p->switch_count++;
            if(p->destroy.callback)
                p->destroy.switch_count++;
            v->cr3.data = p;
        } else {
            v->cr3.data = NULL;
        }

        if (opt.scatterplot_cr3_switch) {
            scatterplot_vs_time(h->exit_tsc,
                                v->cr3.data ? (v->cr3.data->cr3_id) : 0);
        }
    } else {
        if (opt.scatterplot_cr3_switch)
            scatterplot_vs_time(h->exit_tsc, gmfn);
    }

    v->cr3.val = val;
};

void cr3_prealloc_unpin(struct vcpu_data *v, unsigned long long gmfn) {
    struct cr3_value_struct *cr3;

    /* Look for it in the list */
    for(cr3 = v->d->cr3_value_head; cr3; cr3=cr3->next)
        if(cr3->gmfn == gmfn)
            break;

    if(!cr3)
        return;

    if(cr3->prealloc_unpin.now)
        fprintf(warn, "Strange, gmfn %llx multiple unpins w/o access!\n",
                gmfn);

    cr3->prealloc_unpin.now = 1;
    cr3->prealloc_unpin.count++;

    if(opt.dump_all)
        printf(" cr3 %llx unpinned %d times\n",
               gmfn, cr3->prealloc_unpin.count);
}

void cr3_dump_list(struct cr3_value_struct *head){
    struct cr3_value_struct *p;
    struct cr3_value_struct **qsort_array;
    int i, N=0;

    int cr3_compare_total(const void *_a, const void *_b) {
        struct cr3_value_struct *a=*(typeof(&a))_a;
        struct cr3_value_struct *b=*(typeof(&a))_b;

        if(a->total_time.cycles < b->total_time.cycles)
            return 1;
        else if(b->total_time.cycles == a->total_time.cycles) {
            if(a->total_time.count < b->total_time.count)
                return 1;
            else if(a->total_time.count == b->total_time.count)
                return 0;
            else
                return -1;
        } else
            return -1;
    }

    int cr3_compare_start(const void *_a, const void *_b) {
        struct cr3_value_struct *a=*(typeof(&a))_a;
        struct cr3_value_struct *b=*(typeof(&a))_b;

        if(a->first_time > b->first_time)
            return 1;
        else if(b->first_time == a->first_time)
            return 0;
        else
            return -1;
    }

    if(!head)
        return;

    /* Count the number of elements */
    for(p=head; p; p=p->next)
        N++;

    if(!N)
        return;

    /* Alloc a struct of the right size */
    qsort_array = malloc(N * sizeof(struct eip_list_struct *));

    /* Point the array into it */
    for(i=0, p=head; p; p=p->next, i++)
        qsort_array[i]=p;

    /* Sort the array by time */
    qsort(qsort_array, N, sizeof(struct eip_list_struct *),
          cr3_compare_start);

    /* WARNING: don't use N after this point unless you copy this variable */
#if 0
    if(opt.summary_eip_limit && opt.summary_eip_limit < N)
        N=opt.summary_eip_limit;
#endif

    /* Now print the results */
    printf("    cr3 values:\n");
    for(i=0; i<N; i++) {
        char desc[30];
        struct time_struct first, last;

        p = qsort_array[i];

        abs_cycles_to_time(p->first_time, &first);
        abs_cycles_to_time(p->last_time, &last);


        snprintf(desc, 30, "  %8llx (id %d)", p->gmfn, p->cr3_id);
        print_cycle_summary(&p->total_time, desc);
        snprintf(desc, 30, "          guest");
        print_cycle_percent_summary(&p->guest_time, p->run_time, desc);
        snprintf(desc, 30, "          hv   ");
        print_cycle_percent_summary(&p->hv_time, p->run_time, desc);

        hvm_short_summary(&p->hvm, p->run_time, "           + ");
        printf("            Seen: %4u.%09u-%4u.%09u switch %d flush %d\n",
               first.s, first.ns,
               last.s, last.ns,
               p->switch_count, p->flush_count);
        if(p->destroy.callback)
            printf("          destroy: flush %u switch %u fixup %u emulate %u\n",
                   p->destroy.flush_count,
                   p->destroy.switch_count,
                   p->destroy.fixup_user,
                   p->destroy.emulate_corr_user);
    }

    free(qsort_array);
}

void hvm_cr3_write_summary(struct hvm_data *h) {
    int j;

    for(j=0; j<RESYNCS_MAX; j++)
        PRINT_SUMMARY(h->summary.cr3_write_resyncs[j],
                      "     *[%3d] ", j);
    PRINT_SUMMARY(h->summary.cr3_write_resyncs[j],
                  "     *[MAX] ");
}

void hvm_cr_write_summary(struct hvm_data *h, void *data)
{
    long cr=(long)data;

    PRINT_SUMMARY(h->summary.cr_write[cr],
                  "   cr%ld ", cr);
    if ( cr==3 )
        hvm_cr3_write_summary(h);
}

void hvm_cr_write_postprocess(struct hvm_data *h)
{
    if(h->inflight.cr_write.cr == 3) {
        struct vcpu_data *v = h->v;
        unsigned long long new_val = h->inflight.cr_write.val;
        unsigned long long oval;
        int flush=0;

        if(v->cr3.val) {
            oval = v->cr3.val;

            if(new_val == oval) {
                if(v->cr3.data) {
                    v->cr3.data->flush_count++;
                    if(v->cr3.data->destroy.callback)
                        v->cr3.data->destroy.flush_count++;
                }
                flush=1;
            }
        }

        if(opt.summary_info) {
            int resyncs = h->resyncs;

            if(resyncs > RESYNCS_MAX)
                resyncs = RESYNCS_MAX;

            update_summary(&h->summary.cr3_write_resyncs[resyncs],
                           h->arc_cycles);

            update_summary(&h->summary.cr_write[3],
                           h->arc_cycles);

            hvm_update_short_summary(h, HVM_SHORT_SUMMARY_CR3);
        }

        if(!flush)
            cr3_switch(new_val, h);
    } else {
        if(opt.summary_info)
        {
            if(h->inflight.cr_write.cr < CR_MAX)
                update_summary(&h->summary.cr_write[h->inflight.cr_write.cr],
                               h->arc_cycles);

        }
    }

    /* Set summary handler */
    /* FIXME - deal with cr_read_summary */
    if(h->exit_reason < h->exit_reason_max)
    {
        /* Want a different "set" for each cr */
        switch(h->inflight.cr_write.cr)
        {
#define case_cr(_x)                                                     \
            case (_x):                                                  \
                hvm_set_summary_handler(h, hvm_cr_write_summary, (void *)(_x)); \
                break
            case_cr(0);
            case_cr(1);
            case_cr(2);
            case_cr(3);
            case_cr(4);
            case_cr(5);
            case_cr(6);
            case_cr(7);
            case_cr(8);
            case_cr(9);
            case_cr(10);
            case_cr(11);
            case_cr(12);
            case_cr(13);
            case_cr(14);
            case_cr(15);
#undef case_cr
        default:
            fprintf(stderr, "Unexpected cr: %d\n", h->inflight.cr_write.cr);
            error(ERR_SANITY, NULL);
            break;
        }
    }
}

void hvm_cr_write_process(struct record_info *ri, struct hvm_data *h)
{
    union {
        struct {
            unsigned cr;
            unsigned int val;
        } x32;
        struct {
            unsigned cr;
            unsigned long long val;
        } __attribute__((packed)) x64;
    } *r = (typeof(r))h->d;
    unsigned cr;
    unsigned long long val;

    if(ri->event & TRC_64_FLAG) {
        h->inflight.cr_write.cr = cr = r->x64.cr;
        h->inflight.cr_write.val = val = r->x64.val;
    } else {
        h->inflight.cr_write.cr = cr = r->x32.cr;
        h->inflight.cr_write.val = val = r->x32.val;
    }

    /* In vmx, in real mode, cr accesses may cause EXNMI vmexits.
     * Account them under that heading; otherwise, complain */
    if ( hvm_set_postprocess(h, hvm_cr_write_postprocess) )
        fprintf(warn, "%s: Strange, h->postprocess already set!\n",
            __func__);

    if(opt.dump_all)
    {
        if(cr == 3 && h->v->cr3.val) {
            printf("]%s cr_write cr3 val %llx oval %llx %s\n",
                   ri->dump_header,
                   val,
                   h->v->cr3.val,
                   (h->v->cr3.val == val)?"flush":"switch");
        } else {
            printf(" %s cr_write cr%d val %llx\n",
                   ri->dump_header,
                   cr, val);

        }
    }

}

/* msr_write */
void hvm_msr_write_summary(struct hvm_data *h, void *d)
{
}

void hvm_msr_write_postprocess(struct hvm_data *h)
{
    if(opt.summary_info) {
    }

    /* Set summary handler */
    hvm_set_summary_handler(h, hvm_msr_write_summary, NULL);
}

void hvm_msr_write_process(struct record_info *ri, struct hvm_data *h)
{
    struct {
        unsigned int addr;
        unsigned long long val;
    } __attribute__((packed)) *r = (typeof(r))h->d;

    if(check_extra_words(ri, sizeof(*r), "msr_write"))
        return;

    h->inflight.msr.addr = r->addr;
    h->inflight.msr.val = r->val;

    if(opt.dump_all)
    {
        printf(" %s msr_write addr %x val %llx\n",
               ri->dump_header,
               r->addr, r->val);
    }

    if ( hvm_set_postprocess(h, hvm_msr_write_postprocess) )
        fprintf(warn, "%s: Strange, postprocess already set\n", __func__);
}

/* msr_read */
void hvm_msr_read_summary(struct hvm_data *h, void *d)
{
}

void hvm_msr_read_postprocess(struct hvm_data *h)
{
    if(opt.summary_info) {
    }

    /* Set summary handler */
    hvm_set_summary_handler(h, hvm_msr_read_summary, NULL);
}

void hvm_msr_read_process(struct record_info *ri, struct hvm_data *h)
{
    struct {
        unsigned int addr;
        unsigned long long val;
    } __attribute__((packed)) *r = (typeof(r))h->d;

    if(check_extra_words(ri, sizeof(*r), "msr_read"))
        return;

    h->inflight.msr.addr = r->addr;
    h->inflight.msr.val = r->val;

    if(opt.dump_all)
    {
        printf(" %s msr_read addr %x val %llx\n",
               ri->dump_header,
               r->addr, r->val);
    }

    if ( hvm_set_postprocess(h, hvm_msr_read_postprocess) )
        fprintf(warn, "%s: Strange, postprocess already set\n", __func__);
}

void hvm_vmcall_summary(struct hvm_data *h, void *d)
{
    int i;

    for ( i=0; i<HYPERCALL_MAX ; i++)
    {
        PRINT_SUMMARY(h->summary.vmcall[i],
                      "    [%10s] ", hypercall_name[i]);
    }
    PRINT_SUMMARY(h->summary.vmcall[HYPERCALL_MAX],
                  "    [%10s] ", "max");
}

void hvm_vmcall_postprocess(struct hvm_data *h)
{
    unsigned eax = h->inflight.vmcall.eax ;

    if(opt.summary)
    {
        if ( eax < HYPERCALL_MAX )
            update_summary(&h->summary.vmcall[eax],
                       h->arc_cycles);
        else
            update_summary(&h->summary.vmcall[HYPERCALL_MAX],
                       h->arc_cycles);
        hvm_set_summary_handler(h, hvm_vmcall_summary, NULL);
    }
}

void hvm_vmcall_process(struct record_info *ri, struct hvm_data *h)
{
    struct {
        unsigned int eax;
    } *r = (typeof(r))h->d;

    if(opt.dump_all) {
        if(r->eax < HYPERCALL_MAX)
            printf(" %s vmcall %2x (%s)\n",
                   ri->dump_header,
                   r->eax,
                   hypercall_name[r->eax]);
        else
            printf(" %s vmcall %2x\n",
                   ri->dump_header,
                   r->eax);
    }

    h->inflight.vmcall.eax = r->eax;

    if ( hvm_set_postprocess(h, hvm_vmcall_postprocess) )
        fprintf(warn, "%s: Strange, postprocess already set\n", __func__);
}

void hvm_inj_exc_process(struct record_info *ri, struct hvm_data *h)
{
    struct {
        unsigned vec, ec;
    } *r = (typeof(r))h->d;

    if ( opt.dump_all )
    {
        if(r->vec < HVM_TRAP_MAX)
            printf(" %3u.%09u %s inj_exc trap %s ec %x\n",
                   ri->t.s, ri->t.ns, pcpu_string(ri->cpu),
                   hvm_trap_name[r->vec], r->ec);
        else
            printf(" %3u.%09u %s inj_exc trap %u ec %x\n",
                   ri->t.s, ri->t.ns, pcpu_string(ri->cpu),
                   r->vec, r->ec);
    }

}

void hvm_intr_summary(struct hvm_data *h, void *d)
{
    int i;

    for(i=0; i<EXTERNAL_INTERRUPT_MAX; i++)
        if(h->summary.extint[i])
        {
            if(hvm_extint_vector_name[i])
                printf("  %10s(%3d): %d\n",
                       hvm_extint_vector_name[i],
                       i,
                       h->summary.extint[i]);
            else
                printf("            [%3d]: %d\n",
                       i,
                       h->summary.extint[i]);
        }
    if(h->summary.extint[EXTERNAL_INTERRUPT_MAX])
        printf("  Other:         : %d\n",
               h->summary.extint[EXTERNAL_INTERRUPT_MAX]);
}


void hvm_intr_process(struct record_info *ri, struct hvm_data *h)
{
    unsigned vec = *(unsigned *)h->d;

    /* Vector is difficult to get in SVM mode */
    if ( opt.svm_mode )
        vec = 0;

    if( (h->rip >> ADDR_SPACE_BITS) != 00
        && (h->rip >> ADDR_SPACE_BITS) != ((0ULL-1)>> ADDR_SPACE_BITS) ) {
        fprintf(stderr, "Unexpected rip %llx (shift %llx)\n",
                h->rip,
                h->rip >> ADDR_SPACE_BITS);
        error(ERR_RECORD, NULL);
        /* Can process with strange rip */
    }

    h->inflight.intr.vec = vec;

    if ( opt.dump_all )
    {
        if ( vec < EXTERNAL_INTERRUPT_MAX &&
             hvm_extint_vector_name[vec] )
            printf(" %s intr vec %s(%x)\n",
                   ri->dump_header,
                   hvm_extint_vector_name[vec],
                   vec);
        else
            printf(" %s intr vec %x\n",
                   ri->dump_header, vec);
    }

    if(opt.scatterplot_interrupt_eip
       && vec == opt.scatterplot_interrupt_vector)
    {
        struct time_struct t;
        /* Truncate to 40 bits */
        unsigned long long rip = h->rip & ((1ULL << ADDR_SPACE_BITS)-1);

        /* Want absolute tsc to global tsc */
        abs_cycles_to_time(h->exit_tsc, &t);
        printf("d%dv%d %u.%09u %lld\n",
               h->v->d->did, h->v->vid,
               t.s, t.ns,
               rip);
    }

    if(opt.histogram_interrupt_eip
       && vec == opt.histogram_interrupt_vector)
    {
        /* Truncate to 40 bits */
        unsigned long long rip = h->rip & ((1ULL << ADDR_SPACE_BITS)-1);
        unsigned index = rip / opt.histogram_interrupt_increment;

        h->summary.extint_histogram[index]++;
    }

    if(opt.with_interrupt_eip_enumeration
       && vec == opt.interrupt_eip_enumeration_vector)
    {
        /* Truncate to 40 bits */
        unsigned long long rip = h->rip & ((1ULL << ADDR_SPACE_BITS)-1);

        /* Want absolute tsc to global tsc */
        update_eip(&h->v->d->interrupt_eip_list, rip, 0, 0, NULL);
    }

    /* Disable generic postprocessing */
    /* FIXME: Do the summary stuff in a post-processor */
    h->post_process = NULL;

    if(opt.summary_info) {
        if(opt.summary)
            hvm_set_summary_handler(h, hvm_intr_summary, NULL);

        if(vec < EXTERNAL_INTERRUPT_MAX)
            h->summary.extint[vec]++;
        else
            h->summary.extint[EXTERNAL_INTERRUPT_MAX]++;
    }
}


void hvm_intr_window_process(struct record_info *ri, struct hvm_data *h)
{
    struct {
        uint32_t vector;
        uint32_t source;
        int32_t intr;
    } *r = (typeof(r))h->d;

    char *intsrc_name[] = {
        "none",
        "pic",
        "lapic",
        "nmi",
        "mce",
        "vector"
    };

    if ( opt.dump_all )
    {
        printf(" %s intr_window vec %u src %u(%s) ",
               ri->dump_header,
               (unsigned)r->vector,
               (unsigned)r->source,
               r->source < 6 ? intsrc_name[r->source]: "?");

        if ( r->intr > 0 )
            printf("intr %x\n",
                   (unsigned)r->intr);
        else
            printf("intr #\n");
    }
}

void hvm_pf_inject_process(struct record_info *ri, struct hvm_data *h)
{
    union {
        struct {
            unsigned ec;
            unsigned int cr2;
        } x32;
        struct {
            unsigned ec;
            unsigned long long cr2;
        } __attribute__((packed)) x64;
    } *r = (typeof(r))h->d;
    unsigned int ec;
    unsigned long long cr2;
    int is_64 = 0;

    if(ri->event & TRC_64_FLAG) {
        is_64 = 1;
        cr2 = r->x64.cr2;
        ec = r->x64.ec;
    } else {
        cr2 = r->x32.cr2;
        ec = r->x32.ec;
    }

    if ( opt.dump_all )
    {
            printf(" %3u.%09u %s pf_inject%s guest_cr2 %llx  guest_ec %x\n",
                   ri->t.s, ri->t.ns, pcpu_string(ri->cpu),
                   is_64?"64":"",
                   cr2, ec);
    }
}

void hvm_generic_postprocess_init(struct record_info *ri, struct hvm_data *h);

void hvm_npf_process(struct record_info *ri, struct hvm_data *h)
{
    struct {
        uint64_t gpa;
        uint64_t mfn;
        uint32_t qualification;
        uint32_t p2mt;
    } *r = (typeof(r))h->d;

    if ( opt.dump_all )
        printf(" %s npf gpa %llx q %x mfn %llx t %d\n",
               ri->dump_header,
               (unsigned long long)r->gpa, r->qualification,
               (unsigned long long)r->mfn, r->p2mt);

    if ( opt.summary_info )
        hvm_generic_postprocess_init(ri, h);
}

void hvm_rdtsc_process(struct record_info *ri, struct hvm_data *h)
{
    struct {
        unsigned long long tsc;
    } *r = (typeof(r))h->d;

    if ( opt.dump_all )
        printf(" %s rdtsc %llx %lld %s\n",
               ri->dump_header,
               (unsigned long long)r->tsc,
               (unsigned long long)r->tsc,
               h->last_rdtsc > r->tsc ? "BACKWARDS" : "");

    if ( opt.scatterplot_rdtsc )
    {
        struct time_struct t;

        abs_cycles_to_time(ri->tsc, &t);

        printf("%dv%d %u.%09u %llu\n",
               h->v->d->did, h->v->vid,
               t.s, t.ns,
               r->tsc);
    }

    h->last_rdtsc = r->tsc;
}

void hvm_generic_summary(struct hvm_data *h, void *data)
{
    long evt = (long)data;

    assert(evt < HVM_EVENT_HANDLER_MAX);

    PRINT_SUMMARY(h->summary.generic[evt],
                  "   %s ", hvm_event_handler_name[evt]);

}

void hvm_generic_postprocess_init(struct record_info *ri, struct hvm_data *h)
{
    if ( h->post_process != hvm_generic_postprocess )
        fprintf(warn, "%s: Strange, h->postprocess set!\n",
                __func__);
    h->inflight.generic.event = ri->event;
    bcopy(h->d, h->inflight.generic.d, sizeof(unsigned int) * 4);
}

void hvm_generic_postprocess(struct hvm_data *h)
{
    long evt = 0;
    static unsigned registered[HVM_EVENT_HANDLER_MAX] = { 0 };

    if ( h->inflight.generic.event )
        evt = (h->inflight.generic.event - TRC_HVM_HANDLER)
            & ~(TRC_64_FLAG|HVM_IO_ASSIST_WRITE);
    else  {
        static unsigned warned[HVM_EXIT_REASON_MAX] = { 0 };
        /* Some exits we don't expect a handler; just return */
        if(opt.svm_mode)
        {
        }
        else
        {
            switch(h->exit_reason)
            {
                /* These just need us to go through the return path */
            case EXIT_REASON_PENDING_INTERRUPT:
            case EXIT_REASON_TPR_BELOW_THRESHOLD:
                /* Not much to log now; may need later */
            case EXIT_REASON_WBINVD:
                return;
            default:
                break;
            }
        }
        if ( !warned[h->exit_reason] )
        {
            /* If we aren't a known exception, warn and log results */
            fprintf(warn, "%s: Strange, exit %x(%s) missing a handler\n",
                    __func__, h->exit_reason,
                    (h->exit_reason > h->exit_reason_max)
                      ? "[clipped]"
                      : h->exit_reason_name[h->exit_reason]);
            warned[h->exit_reason]=1;
        }
    }

    if ( evt >= HVM_EVENT_HANDLER_MAX || evt < 0)
    {
        fprintf(warn, "%s: invalid hvm event %lx(%x)\n",
                __func__, evt, h->inflight.generic.event);
        error(ERR_RECORD, NULL);
        return;
    }

    if(opt.summary_info) {
        update_summary(&h->summary.generic[evt],
                       h->arc_cycles);

        /* NB that h->exit_reason may be 0, so we offset by 1 */
        if ( registered[evt] )
        {
            static unsigned warned[HVM_EXIT_REASON_MAX] = { 0 };
            if ( registered[evt] != h->exit_reason+1 && !warned[h->exit_reason])
            {
                fprintf(warn, "%s: HVM evt %lx in %x and %x!\n",
                        __func__, evt, registered[evt]-1, h->exit_reason);
                warned[h->exit_reason]=1;
            }
        }
        else
        {
            int ret;
            if((ret=__hvm_set_summary_handler(h, hvm_generic_summary, (void *)evt)))
                fprintf(stderr, "%s: hvm_set_summary_handler returned %d\n",
                        __func__, ret);
            registered[evt]=h->exit_reason+1;
        }
        /* HLT checked at hvm_vmexit_close() */
    }
}

void hvm_generic_dump(struct record_info *ri, char * prefix)
{
    struct {
        unsigned vcpu:16, domain:16;
        unsigned d[4];
    } *cr = (typeof(cr))ri->d;

    char *evt_string, evt_number[256];
    int i, evt, is_64 = 0;

    evt = ri->event - TRC_HVM_HANDLER;

    if(evt & TRC_64_FLAG) {
        evt &= ~(TRC_64_FLAG);
        is_64=1;
    }

    if(evt < HVM_EVENT_HANDLER_MAX)
    {
        evt_string = hvm_event_handler_name[evt];
    }
    else
    {
        snprintf(evt_number, 256, "hvm_handler %d", evt);
        evt_string = evt_number;
    }

    printf("%s%s %s%s [",
           prefix,
           ri->dump_header,
           evt_string,
           is_64?"64":"");

    for(i=0; i<ri->extra_words; i++) {
        printf(" %x", ri->d[i]);
    }

    printf(" ]\n");
}

void hvm_handler_process(struct record_info *ri, struct hvm_data *h) {
    /* Wait for first vmexit to initialize */
    if(!h->init)
    {
        if(opt.dump_all)
            hvm_generic_dump(ri,"!");
        return;
    }

    h->d = ri->d;

    /* Handle things that don't need a vmexit */
    switch(ri->event) {
    default:
        goto needs_vmexit;
        /* Records about changing guest state */
    case TRC_HVM_PF_INJECT:
    case TRC_HVM_PF_INJECT64:
        hvm_pf_inject_process(ri, h);
        break;
    case TRC_HVM_REINJ_VIRQ:
        if ( opt.dump_all )
        {
            printf(" %3u.%09u %s inj_virq vec %u\n",
                   ri->t.s, ri->t.ns, pcpu_string(ri->cpu),
                   *(unsigned*)h->d);
        }
        break;
    case TRC_HVM_INJ_EXC:
        hvm_inj_exc_process(ri, h);
        break;
    case TRC_HVM_INJ_VIRQ:
        hvm_inj_virq_process(ri, h);
        break;
    case TRC_HVM_INTR_WINDOW:
        hvm_intr_window_process(ri, h);
        break;
    case TRC_HVM_OP_DESTROY_PROC:
        if(h->v->cr3.data) {
            struct cr3_value_struct *cur = h->v->cr3.data;
            if(cur->destroy.callback)
                fprintf(warn, "Strange, double callback for cr3 gmfn %llx!\n",
                    cur->gmfn);
            cur->destroy.callback = 1;
        } else if(opt.with_cr3_enumeration) {
            fprintf(warn, "Warning: destroy_proc: don't know current cr3\n");
        }
        if ( opt.dump_all )
        {
            printf(" %3u.%09u %s destroy_proc cur_cr3 %llx\n",
                   ri->t.s, ri->t.ns, pcpu_string(ri->cpu), h->v->cr3.val);
        }
        break;
    }

    return;

needs_vmexit:
    /* Wait for the next vmexit */
    if(!h->vmexit_valid)
    {
        if(opt.dump_all)
            hvm_generic_dump(ri,"!");
        return;
    }

    /* Keep generic "event handler" info */
    h->event_handler = ri->event - TRC_HVM_HANDLER;

    switch(ri->event) {
        /* Records adding to the vmexit reason */
    case TRC_HVM_INTR:
        hvm_intr_process(ri, h);
        break;
    case TRC_HVM_PF_XEN:
    case TRC_HVM_PF_XEN64:
        hvm_pf_xen_process(ri, h);
        break;
    case TRC_HVM_IOPORT_READ:
    case TRC_HVM_IOPORT_WRITE:
        hvm_io_assist_process(ri, h);
        break;
    case TRC_HVM_IOMEM_READ:
    case TRC_HVM_IOMEM_WRITE:
    case TRC_HVM_IOMEM_READ|TRC_64_FLAG:
    case TRC_HVM_IOMEM_WRITE|TRC_64_FLAG:
        hvm_mmio_assist_process(ri, h);
        break;
    case TRC_HVM_CR_WRITE:
    case TRC_HVM_CR_WRITE64:
        hvm_cr_write_process(ri, h);
        break;
    case TRC_HVM_MSR_WRITE:
      hvm_msr_write_process(ri, h);
      break;
    case TRC_HVM_MSR_READ:
        hvm_msr_read_process(ri, h);
      break;
    case TRC_HVM_VMMCALL:
        hvm_vmcall_process(ri, h);
        break;
    case TRC_HVM_NPF:
        hvm_npf_process(ri, h);
        break;
    case TRC_HVM_RDTSC:
        hvm_rdtsc_process(ri, h);
        break;
    case TRC_HVM_DR_READ:
    case TRC_HVM_DR_WRITE:
    case TRC_HVM_CPUID:
    case TRC_HVM_SMI:
    case TRC_HVM_HLT:
    case TRC_HVM_INVLPG:
    case TRC_HVM_INVLPG64:
    case TRC_HVM_MCE:
    case TRC_HVM_CLTS:
    case TRC_HVM_LMSW:
    case TRC_HVM_LMSW64:
    case TRC_HVM_NMI:
    case TRC_HVM_REALMODE_EMULATE:
    case TRC_HVM_TRAP:
    case TRC_HVM_TRAP_DEBUG:
    case TRC_HVM_CR_READ:
    case TRC_HVM_CR_READ64:
    default:
        if(opt.dump_all)
            hvm_generic_dump(ri, "]");
        if(opt.summary_info)
            hvm_generic_postprocess_init(ri, h);
        break;
    }
}

void vcpu_next_update(struct pcpu_info *p, struct vcpu_data *next, tsc_t tsc);
void vcpu_prev_update(struct pcpu_info *p, struct vcpu_data *prev,
                      tsc_t tsc, int new_runstate);
struct vcpu_data * vcpu_find(int did, int vid);
void lose_vcpu(struct vcpu_data *v, tsc_t tsc);

int domain_runstate(struct domain_data *d) {
    int i;
    int runstates[RUNSTATE_MAX];
    int ret=-1;
    int max_vcpus = 0;

    if(d->did == DEFAULT_DOMAIN)
        return 0;

    for(i=0; i<RUNSTATE_MAX; i++)
        runstates[i]=0;

    for(i=0; i<=d->max_vid; i++)
        if(d->vcpu[i] && d->vcpu[i]->runstate.state != RUNSTATE_INIT) {
            max_vcpus++;
            runstates[d->vcpu[i]->runstate.state]++;
        }

    if(runstates[RUNSTATE_LOST] == max_vcpus)
        ret=DOMAIN_RUNSTATE_LOST;
    else if(runstates[RUNSTATE_RUNNING])
    {
        if(runstates[RUNSTATE_RUNNABLE])
            ret=DOMAIN_RUNSTATE_CONCURRENCY_HAZARD;
        else if(runstates[RUNSTATE_BLOCKED]||runstates[RUNSTATE_OFFLINE])
            ret= DOMAIN_RUNSTATE_PARTIAL_RUN;
        else
            ret= DOMAIN_RUNSTATE_FULL_RUN;
    }
    else if(runstates[RUNSTATE_RUNNABLE])
    {
        if(runstates[RUNSTATE_BLOCKED]||runstates[RUNSTATE_OFFLINE])
            ret= DOMAIN_RUNSTATE_PARTIAL_CONTENTION;
        else
            ret= DOMAIN_RUNSTATE_FULL_CONTENTION;
    }
    else if(runstates[RUNSTATE_BLOCKED]||runstates[RUNSTATE_OFFLINE])
    {
        ret= DOMAIN_RUNSTATE_BLOCKED;
    } else {
        fprintf(warn, "Strange, no meaningful runstates for d%d!\n",
                d->did);
    }

    if ( ret < 0 )
    {
        printf(" Max vid: %d (max_vcpus %d)\n", d->max_vid, max_vcpus);
        for(i=0; i<=d->max_vid; i++)
            if(d->vcpu[i])
                fprintf(warn, " v%d: %s\n",
                        i, runstate_name[d->vcpu[i]->runstate.state]);

        for(i=0; i<RUNSTATE_MAX; i++)
            fprintf(warn, " %s: %d\n",
                    runstate_name[i], runstates[i]);
    }

    if(ret >= 0)
        return ret;

    error(ERR_ASSERT, NULL);
    return -1; /* Never happens */
}

static inline void runstate_update(struct vcpu_data *v, int new_runstate,
                                   tsc_t tsc)
{
    struct domain_data *d = v->d;

    if ( opt.scatterplot_runstate )
    {
        struct time_struct t;

        abs_cycles_to_time(tsc, &t);

        printf("%dv%d %u.%09u %d\n",
               d->did, v->vid,
               t.s, t.ns,
               runstate_graph[v->runstate.state]);
        printf("%dv%d %u.%09u %d\n",
               d->did, v->vid,
               t.s, t.ns,
               runstate_graph[new_runstate]);
    }

    if(v->runstate.tsc > 0 && v->runstate.tsc < tsc) {
        update_cycles(v->runstates + v->runstate.state, tsc - v->runstate.tsc);

        if ( opt.scatterplot_runstate_time )
        {
            struct time_struct t, dt;

            abs_cycles_to_time(tsc, &t);
            cycles_to_time(tsc - v->runstate.tsc, &dt);

            printf("%dv%d %u.%09u %u.%09u\n",
                   d->did, v->vid,
                   t.s, t.ns,
                   dt.s, dt.ns);
        }

        if(v->runstate.state == RUNSTATE_RUNNING)
            update_cycles(&v->d->total_time, tsc - v->runstate.tsc);

        if(v->runstate.state == RUNSTATE_RUNNABLE)
            update_cycles(v->runnable_states + v->runstate.runnable_state, tsc - v->runstate.tsc);

        /* How much did dom0 run this buffer? */
        if(v->d->did == 0) {
            int i;
            for(i=0; i<MAX_CPUS; i++) {
                struct pcpu_info * p = P.pcpu + i;
                tsc_t start_tsc;
                if(!p->active)
                    continue;
                start_tsc = (p->volume.buffer_first_tsc > v->runstate.tsc) ?
                    p->volume.buffer_first_tsc :
                    v->runstate.tsc;
                p->volume.buffer_dom0_runstate_cycles[v->runstate.state]
                    += tsc - start_tsc;
#if 0
                printf(" - updated p%d dom0_runstate %s to %lld cycles (+%lld)\n",
                       p->pid, runstate_name[v->runstate.state],
                       p->volume.buffer_dom0_runstate_cycles[v->runstate.state],
                       tsc - start_tsc);
#endif
                p->volume.buffer_dom0_runstate = new_runstate;
                p->volume.buffer_dom0_runstate_tsc = tsc;
            }
        }
    }

    /* Detect "runnable" states */
    if ( new_runstate == RUNSTATE_RUNNABLE )
    {
        switch(v->runstate.state)
        {
        case RUNSTATE_RUNNING:
            v->runstate.runnable_state=RUNNABLE_STATE_PREEMPT;
            break;
        case RUNSTATE_BLOCKED:
        case RUNSTATE_OFFLINE:
            v->runstate.runnable_state=RUNNABLE_STATE_WAKE;
            break;
        default:
            v->runstate.runnable_state=RUNNABLE_STATE_OTHER;
            break;
        }
    } else
        v->runstate.runnable_state=RUNNABLE_STATE_INVALID;

    v->runstate.state = new_runstate;
    v->runstate.tsc = tsc;

    /* Determine the domain runstate */
    if(d->runstate_tsc > 0 && d->runstate_tsc < tsc)
        update_cycles(d->runstates + d->runstate, tsc - d->runstate_tsc);

    d->runstate = domain_runstate(d);

    d->runstate_tsc = tsc;
}

void hvm_vmexit_process(struct record_info *ri, struct hvm_data *h,
                        struct vcpu_data *v) {
    struct {
        union {
            struct {
                unsigned int exit_reason;
                unsigned long long rip;
            } __attribute__((packed)) x64;
            struct {
                unsigned int exit_reason;
                unsigned int eip;
            } x32;
        };
    } *r;

    if ( ri->event & TRC_64_FLAG )
    {
        if (check_extra_words(ri, sizeof(r->x64), "vmexit"))
            return;
    }
    else
    {
        if (check_extra_words(ri, sizeof(r->x32), "vmexit"))
            return;
    }

    r = (typeof(r))ri->d;

    if(!h->init)
        init_hvm_data(h, v);

    h->vmexit_valid=1;
    bzero(&h->inflight, sizeof(h->inflight));

    if(ri->event == TRC_HVM_VMEXIT64) {
        if(v->guest_paging_levels != 4)
        {
            if ( verbosity >= 6 )
                fprintf(warn, "%s: VMEXIT64, but guest_paging_levels %d.  Switching to 4.\n",
                        __func__, v->guest_paging_levels);
            v->guest_paging_levels = 4;
        }
        if(!is_valid_addr64(r->x64.rip))
            fprintf(warn, "%s: invalid va %llx\n",
                    __func__, r->x64.rip);
        h->rip = r->x64.rip;
        h->exit_reason = r->x64.exit_reason;
    } else {
        if(v->guest_paging_levels == 4)
        {
            int new_paging_levels = opt.default_guest_paging_levels;

            if(new_paging_levels == 4)
                new_paging_levels = 2; /* Wild guess */

            if ( verbosity >= 6 )
                fprintf(warn, "%s: VMEXIT, but guest_paging_levels %d.  Switching to %d(default).\n",
                        __func__, v->guest_paging_levels, new_paging_levels);

            v->guest_paging_levels = new_paging_levels;
        }
        h->rip = r->x32.eip;
        h->exit_reason = r->x32.exit_reason;
    }

    if(opt.scatterplot_vmexit_eip)
        scatterplot_vs_time(ri->tsc, h->rip);

    if(h->exit_reason > h->exit_reason_max)
    {
        fprintf(warn, "h->exit_reason %x > exit_reason_max %x!\n",
                (unsigned int)h->exit_reason,
                (unsigned int)h->exit_reason_max);
        error(ERR_RECORD, ri);
        return;
    }

    if(opt.dump_all) {
        if ( h->exit_reason < h->exit_reason_max
             && h->exit_reason_name[h->exit_reason] != NULL)
            printf("]%s vmexit exit_reason %s eip %llx%s\n",
                   ri->dump_header,
                   h->exit_reason_name[h->exit_reason],
                   h->rip,
                   find_symbol(h->rip));
        else
            printf("]%s vmexit exit_reason %x eip %llx%s\n",
                   ri->dump_header,
                   h->exit_reason,
                   h->rip,
                   find_symbol(h->rip));
    }

    if(h->v->cr3.data && h->entry_tsc) {
        update_cycles(&h->v->cr3.data->guest_time,
                      ri->tsc - h->entry_tsc);
        h->v->cr3.data->run_time += (ri->tsc - h->entry_tsc);
    }

    h->exit_tsc = ri->tsc;
    h->entry_tsc = 0;
    h->resyncs = 0;
    h->prealloc_unpin = 0;
    h->wrmap_bf = 0;
    h->short_summary_done = 0;

    h->post_process = hvm_generic_postprocess;
    h->inflight.generic.event = 0;
}

void hvm_close_vmexit(struct hvm_data *h, tsc_t tsc) {

    if(h->exit_tsc) {
        if(h->exit_tsc > tsc)
            h->arc_cycles = 0;
        else {
            h->arc_cycles = tsc - h->exit_tsc;

            if(opt.summary_info) {
                update_summary(&h->summary.exit_reason[h->exit_reason],
                               h->arc_cycles);
                h->summary_info = 1;
            }

            if ( opt.scatterplot_extint_cycles
                 && h->exit_reason == EXIT_REASON_EXTERNAL_INTERRUPT
                 && h->inflight.intr.vec == opt.scatterplot_extint_cycles_vector )
            {
                struct time_struct t;

                abs_cycles_to_time(tsc, &t);

                printf("d%dv%d %u.%09u %lld\n",
                       h->v->d->did,
                       h->v->vid,
                       t.s, t.ns,
                       h->arc_cycles);
            }
        }
    }

    if(h->post_process)
        (h->post_process)(h);

    if(h->arc_cycles) {
        if(opt.summary_info && !h->short_summary_done) {
            switch(h->event_handler) {
            case HVM_EVENT_HANDLER_VMCALL:
                hvm_update_short_summary(h, HVM_SHORT_SUMMARY_VMCALL);
                break;
            case HVM_EVENT_HANDLER_INTR:
                hvm_update_short_summary(h, HVM_SHORT_SUMMARY_INTERRUPT);
                break;
            case HVM_EVENT_HANDLER_HLT:
                hvm_update_short_summary(h, HVM_SHORT_SUMMARY_HLT);
                break;
            default:
                hvm_update_short_summary(h, HVM_SHORT_SUMMARY_OTHER);
                break;
            }
        }


        if(h->v->cr3.data) {
            h->v->cr3.data->run_time += h->arc_cycles;

            if(opt.summary_info)
                update_cycles(&h->v->cr3.data->hv_time,
                              h->arc_cycles);
        }
    }

    h->exit_tsc = 0;
    h->vmexit_valid = 0;
    h->post_process = NULL;

}

void hvm_vmentry_process(struct record_info *ri, struct hvm_data *h) {
    if(!h->init)
    {
        if(opt.dump_all)
            printf("!%s vmentry\n",
                   ri->dump_header);
        return;
    }

    /* Vista bug
     * This has to be done here because irqs are injected on the path out
     * to vmexit. */
    hvm_vlapic_vmentry_cleanup(h->v, ri->tsc);

    if(h->w2h.waking && opt.dump_all)
        printf(" [w2h] d%dv%d Finishing waking\n",
               h->v->d->did, h->v->vid);

    h->w2h.waking = 0;

    if ( h->w2h.interrupts_wanting_tsc ) {
        int i;
        for(i=0; i<GUEST_INTERRUPT_MAX; i++)
        {
            if ( h->summary.guest_interrupt[i].start_tsc == 1 )
            {
                if(opt.dump_all)
                    printf(" [w2h] d%dv%d Setting vec %d tsc to %lld\n",
                           h->v->d->did, h->v->vid, i, ri->tsc);
                h->summary.guest_interrupt[i].start_tsc = ri->tsc;
                h->w2h.interrupts_wanting_tsc--;
                if ( h->w2h.interrupts_wanting_tsc == 0 )
                    break;
            }
        }
    }

    if(!h->vmexit_valid)
    {
        if(opt.dump_all)
            printf("!%s vmentry\n",
                   ri->dump_header);
        return;
    }

    if(opt.dump_all) {
        unsigned long long arc_cycles = ri->tsc - h->exit_tsc;
        printf("]%s vmentry cycles %lld %s\n",
               ri->dump_header, arc_cycles, (arc_cycles>10000)?"!":"");
    }

    hvm_close_vmexit(h, ri->tsc);
    h->entry_tsc = ri->tsc;
}

void hvm_process(struct pcpu_info *p)
{
    struct record_info *ri = &p->ri;
    struct vcpu_data *v = p->current;
    struct hvm_data *h = &v->hvm;

    assert(p->current);

    if(vcpu_set_data_type(p->current, VCPU_DATA_HVM))
        return;

    if(ri->evt.sub == 2)
    {
        UPDATE_VOLUME(p, hvm[HVM_VOL_HANDLER], ri->size);
        hvm_handler_process(ri, h);
    }
    else
    {
        switch(ri->event) {
            /* HVM */
        case TRC_HVM_VMEXIT:
        case TRC_HVM_VMEXIT64:
            UPDATE_VOLUME(p, hvm[HVM_VOL_VMEXIT], ri->size);
            hvm_vmexit_process(ri, h, v);
            break;
        case TRC_HVM_VMENTRY:
            UPDATE_VOLUME(p, hvm[HVM_VOL_VMENTRY], ri->size);
            hvm_vmentry_process(ri, &p->current->hvm);
            break;
        default:
            fprintf(warn, "Unknown hvm event: %x\n", ri->event);
        }
    }
}

void hvm_summary(struct hvm_data *h) {
   int i;

   if(!h->summary_info)
       return;

   printf("Exit reasons:\n");
   for(i=0; i<h->exit_reason_max; i++) {
       struct hvm_summary_handler_node *p;

       if ( h->exit_reason_name[i] )
           PRINT_SUMMARY(h->summary.exit_reason[i],
                         " %-20s ", h->exit_reason_name[i]);
       else
           PRINT_SUMMARY(h->summary.exit_reason[i],
                         " %20d ", i);

       p=h->exit_reason_summary_handler_list[i];
       while(p)
       {
           p->handler(h, p->data);
           p=p->next;
       }
   }

   printf("Guest interrupt counts:\n");
   for(i=0; i<GUEST_INTERRUPT_MAX; i++)
       if(h->summary.guest_interrupt[i].count) {
           int j;
           printf("  [%3d] %d\n",
                  i, h->summary.guest_interrupt[i].count);
           for(j=1; j<GUEST_INTERRUPT_CASE_MAX; j++) {
               char desc[80];
               snprintf(desc, 80, "   * %s", guest_interrupt_case_name[j]);
               print_cycle_summary(h->summary.guest_interrupt[i].runtime+j, desc);
           }
       }
   if(h->summary.guest_interrupt[i].count)
       printf("  [%d+] %d\n",
              i, h->summary.guest_interrupt[i].count);

   if(opt.histogram_interrupt_eip)
   {
       unsigned max = ((1ULL<<ADDR_SPACE_BITS)/opt.histogram_interrupt_increment);
       printf("Interrupt eip histogram:\n");
       for(i=0; i<max; i++)
           if(h->summary.extint_histogram[i])
           {
               printf("[%llx-%llx]: %d\n",
                      opt.histogram_interrupt_increment * i,
                      (opt.histogram_interrupt_increment * (i+1)) - 1,
                      h->summary.extint_histogram[i]);
           }
   }

   PRINT_SUMMARY(h->summary.ipi_latency,
                 "IPI latency \n");
   for(i=0; i<256; i++)
       if(h->summary.ipi_count[i])
           printf("    [%3d] %10d\n",
                  i, h->summary.ipi_count[i]);
   hvm_io_address_summary(h->summary.io.pio, "IO address summary:");
   hvm_io_address_summary(h->summary.io.mmio, "MMIO address summary:");
}

/* ---- Shadow records ---- */
union shadow_event
{
    unsigned event;
    struct {
        unsigned minor:8,
            paging_levels:4;
    };
};

/* WARNING - not thread safe */
#define FLAGSTRING(_name, _char) \
    if(e->flag_ ## _name)        \
        flagstring[i] = _char; \
    i++;

char * flag_string(struct pf_xen_extra *e)
{
    static char flagstring[32];
    int i=0;

    for(i=0; i<32; i++)
        flagstring[i]='-';

    i=0;

    if(e->flag_set_ad)
        flagstring[i]='d';
    else if(e->flag_set_a)
        flagstring[i]='a';
    i++;

    FLAGSTRING(shadow_l1_get_ref,  'g');
    FLAGSTRING(shadow_l1_put_ref,  'p');
    //FLAGSTRING(l2_propagate,      '2');
    FLAGSTRING(demote,             'D');
    FLAGSTRING(promote,            'P');
    FLAGSTRING(wrmap,              'w');
    FLAGSTRING(wrmap_guess_found,  'G');
    //FLAGSTRING(wrmap_brute_force, 'b');
    FLAGSTRING(early_unshadow,     'e');
    FLAGSTRING(prealloc_unhook,    'H');
    FLAGSTRING(unsync,             'u');
    FLAGSTRING(oos_fixup_add,      'a');
    FLAGSTRING(oos_fixup_evict,    'x');

    flagstring[i]=0;

    return flagstring;
}

void shadow_emulate_postprocess(struct hvm_data *h)
{
    struct pf_xen_extra *e = &h->inflight.pf_xen;

    if ( opt.summary_info )
    {
        update_eip(&h->v->d->emulate_eip_list,
                   h->rip,
                   h->arc_cycles,
                   0, NULL);
        update_summary(&h->summary.pf_xen[PF_XEN_EMULATE], h->arc_cycles);
        update_summary(&h->summary.pf_xen_emul[e->pt_level], h->arc_cycles);
        if(h->prealloc_unpin)
            update_summary(&h->summary.pf_xen_emul[PF_XEN_EMUL_PREALLOC_UNPIN], h->arc_cycles);
        if(e->flag_prealloc_unhook)
            update_summary(&h->summary.pf_xen_emul[PF_XEN_EMUL_PREALLOC_UNHOOK], h->arc_cycles);
        if(e->flag_early_unshadow)
            update_summary(&h->summary.pf_xen_emul[PF_XEN_EMUL_EARLY_UNSHADOW], h->arc_cycles);
        if(e->flag_set_changed)
            update_summary(&h->summary.pf_xen_emul[PF_XEN_EMUL_SET_CHANGED], h->arc_cycles);
        else
            update_summary(&h->summary.pf_xen_emul[PF_XEN_EMUL_SET_UNCHANGED], h->arc_cycles);
        if(e->flag_set_flush)
            update_summary(&h->summary.pf_xen_emul[PF_XEN_EMUL_SET_FLUSH], h->arc_cycles);
        if(e->flag_set_error)
            update_summary(&h->summary.pf_xen_emul[PF_XEN_EMUL_SET_ERROR], h->arc_cycles);
        if(e->flag_promote)
            update_summary(&h->summary.pf_xen_emul[PF_XEN_EMUL_PROMOTE], h->arc_cycles);
        if(e->flag_demote)
            update_summary(&h->summary.pf_xen_emul[PF_XEN_EMUL_DEMOTE], h->arc_cycles);
        /* more summary info */

        hvm_update_short_summary(h, HVM_SHORT_SUMMARY_EMULATE);
    }

    if(opt.scatterplot_unpin_promote) {
        if(e->flag_early_unshadow)
            scatterplot_vs_time(h->exit_tsc, -10);
        if(h->prealloc_unpin)
            scatterplot_vs_time(h->exit_tsc, 0);
        if(e->flag_promote) {
            if(opt.with_cr3_enumeration) {
                if(h->v->cr3.data)
                    scatterplot_vs_time(h->exit_tsc, h->v->cr3.data->cr3_id);
            } else
                scatterplot_vs_time(h->exit_tsc, 2);
        }
    }


}

void shadow_emulate_process(struct record_info *ri, struct hvm_data *h)
{
    struct pf_xen_extra *e = &h->inflight.pf_xen;
    union {
        /* for PAE, guest_l1e may be 64 while guest_va may be 32;
           so put it first for alignment sake. */
        struct {
            unsigned gl1e, write_val;
            unsigned va;
            unsigned flags:29, emulation_count:3;
        } gpl2;
        struct {
            unsigned long long gl1e, write_val;
            unsigned va;
            unsigned flags:29, emulation_count:3;
        } gpl3;
        struct {
            unsigned long long gl1e, write_val;
            unsigned long long va;
            unsigned flags:29, emulation_count:3;
        } gpl4;
    } *r = (typeof(r))ri->d;

    union shadow_event sevt = { .event = ri->event };
    int rec_gpl = sevt.paging_levels + 2;

    if ( rec_gpl != h->v->guest_paging_levels )
    {
        fprintf(warn, "%s: record paging levels %d, guest paging levels %d.  Switching.\n",
                __func__, rec_gpl, h->v->guest_paging_levels);
        h->v->guest_paging_levels = rec_gpl;
    }

    /* Fill in extended information */
    switch(rec_gpl)
    {
    case 2:
        if(sizeof(r->gpl2) != ri->extra_words * 4)
        {
            fprintf(warn, "%s: expected %zd bytes for %d-level guest, got %d!\n",
                    __func__, sizeof(r->gpl2), h->v->guest_paging_levels,
                    ri->extra_words * 4);

            error(ERR_RECORD, ri);
            return;
        }
        e->va = r->gpl2.va;
        e->flags = r->gpl2.flags;
        e->gl1e = r->gpl2.gl1e;
        e->wval = r->gpl2.write_val;
        break;
    case 3:
        if(sizeof(r->gpl3) != ri->extra_words * 4)
        {
            fprintf(warn, "%s: expected %zd bytes for %d-level guest, got %d!\n",
                    __func__, sizeof(r->gpl3), h->v->guest_paging_levels,
                    ri->extra_words * 4);
            error(ERR_RECORD, ri);
            return;
        }
        e->va = r->gpl3.va;
        e->flags = r->gpl3.flags;
        e->gl1e = r->gpl3.gl1e;
        e->wval = r->gpl3.write_val;
        break;
    case 4:
        if(sizeof(r->gpl4) != ri->extra_words * 4)
        {
            fprintf(warn, "%s: expected %zd bytes for %d-level guest, got %d!\n",
                    __func__, sizeof(r->gpl4), h->v->guest_paging_levels,
                    ri->extra_words * 4);
            error(ERR_RECORD, ri);
            return;
        }
        e->va = r->gpl4.va;
        e->flags = r->gpl4.flags;
        e->gl1e = r->gpl4.gl1e;
        e->wval = r->gpl4.write_val;
        break;
    }

    pf_preprocess(e,rec_gpl);

    if(opt.dump_all)
        printf("]%s emulate va %llx gl1e %8llx wval %8llx flags %s(%x) pt_level %d corr %8llx\n",
               ri->dump_header,
               e->va,
               e->gl1e, e->wval,
               flag_string(e), e->flags,
               e->pt_level, e->corresponding_va);

    if ( hvm_set_postprocess(h, shadow_emulate_postprocess) )
        fprintf(warn, "%s: Strange, postprocess already set\n", __func__);
}

struct shadow_emulate_other {
    unsigned long long gfn, va;
};

#define SHADOW_OTHER_LOGS_GFN_NOT_GMFN 1

void shadow_parse_other(struct record_info *ri,
                        struct shadow_emulate_other *o,
                        struct hvm_data *h) {
    union {
        /* for PAE, guest_l1e may be 64 while guest_va may be 32;
           so put it first for alignment sake. */
#if SHADOW_OTHER_LOGS_GFN_NOT_GMFN
        /* D'OH!  Accidentally used mfn_t in the struct, so gmfns are always
           64-bit... :-/ */
        struct {
            unsigned int gfn, va;
        } gpl2;
#endif
        struct {
            unsigned long long gfn;
            unsigned int va;
        } gpl3;
        struct {
            unsigned long long gfn, va;
        } gpl4;
    } *r = (typeof(r))ri->d;


    union shadow_event sevt = { .event = ri->event };
    int rec_gpl = sevt.paging_levels + 2;

    if ( rec_gpl != h->v->guest_paging_levels )
    {
        fprintf(warn, "%s: record paging levels %d, guest paging levels %d.  Switching.\n",
                __func__, rec_gpl, h->v->guest_paging_levels);
        h->v->guest_paging_levels = rec_gpl;
    }

    switch(rec_gpl)
    {
#if SHADOW_OTHER_LOGS_GFN_NOT_GMFN
    case 2:
        if(sizeof(r->gpl2) != ri->extra_words * 4)
        {
            fprintf(warn, "%s: expected %zd bytes for %d-level guest, got %d!\n",
                    __func__, sizeof(r->gpl2), rec_gpl,
                    ri->extra_words * 4);
            error(ERR_RECORD, ri);
            return;
        }
        o->va = r->gpl2.va;
        o->gfn = r->gpl2.gfn;
        break;
#else
    case 2:
        /* FALLTHRU */
#endif
    case 3:
        if(sizeof(r->gpl3) != ri->extra_words * 4)
        {
            fprintf(warn, "%s: expected %zd bytes for %d-level guest, got %d!\n",
                    __func__, sizeof(r->gpl3), rec_gpl,
                    ri->extra_words * 4);
            error(ERR_RECORD, ri);
            return;
        }
        o->va = r->gpl3.va;
        o->gfn = r->gpl3.gfn;
        break;
    case 4:
        if(sizeof(r->gpl4) != ri->extra_words * 4)
        {
            fprintf(warn, "%s: expected %zd bytes for %d-level guest, got %d!\n",
                    __func__, sizeof(r->gpl4), rec_gpl,
                    ri->extra_words * 4);
            error(ERR_RECORD, ri);
            return;
        }
        o->va = r->gpl4.va;
        o->gfn = r->gpl4.gfn;
        break;
    }
}

#if 0
void shadow_unsync_postprocess(struct hvm_data *h)
{
    struct pf_xen_extra *e = &h->inflight.pf_xen;

    if(h->resyncs > 1)
        fprintf(warn, "Strange, %d resyncs for an unsync!\n",
                h->resyncs);

    if(opt.summary_info) {
        update_summary(&h->summary.pf_xen[PF_XEN_EMULATE_UNSYNC],
                       h->arc_cycles);
        if(h->resyncs <= 1)
            update_summary(&h->summary.pf_xen_unsync[h->resyncs],
                           h->arc_cycles);
    }
}


void shadow_unsync_process(struct record_info *ri, struct hvm_data *h)
{
    struct pf_xen_extra *e = &h->inflight.pf_xen;
    struct shadow_emulate_other r;

    shadow_parse_other(ri, &r, h);

    e->gmfn = r.gmfn;
    e->va = r.va;

    pf_preprocess(e, h->v->guest_paging_levels);

    if(opt.dump_all)
        printf("]%s shadow unsync gmfn %llx va %llx pt_level %d corr %llx\n",
               ri->dump_header,
               e->gmfn,
               e->va,
               e->pt_level,
               e->corresponding_va);

    if ( hvm_set_postprocess(h, shadow_unsync_postprocess) )
        fprintf(warn, "%s: Strange, postprocess already set\n", __func__);
}
#endif

void shadow_fault_generic_postprocess(struct hvm_data *h);

void shadow_emulate_other_process(struct record_info *ri, struct hvm_data *h)
{
    struct pf_xen_extra *e = &h->inflight.pf_xen;
    struct shadow_emulate_other r;
    union shadow_event sevt = { .event = ri->event };

    shadow_parse_other(ri, &r, h);

    e->gfn = r.gfn;
    e->va = r.va;
    e->pf_case = sevt.minor;

    pf_preprocess(e, h->v->guest_paging_levels);

    if(opt.dump_all)
        printf("]%s shadow %s gfn %llx va %llx\n",
               ri->dump_header,
               pf_xen_name[sevt.minor],
               e->gfn,
               e->va);

    if ( hvm_set_postprocess(h, shadow_fault_generic_postprocess) )
        fprintf(warn, "%s: Strange, postprocess already set\n", __func__);
}

void shadow_fixup_postprocess(struct hvm_data *h)
{
    struct pf_xen_extra *e = &h->inflight.pf_xen;

    if ( opt.summary_info )
    {
        update_summary(&h->summary.pf_xen[PF_XEN_FIXUP], h->arc_cycles);
        if(h->prealloc_unpin) {
            update_summary(&h->summary.pf_xen_fixup[PF_XEN_FIXUP_PREALLOC_UNPIN], h->arc_cycles);
        }
        if(e->flag_unsync) {
            update_summary(&h->summary.pf_xen_fixup[PF_XEN_FIXUP_UNSYNC], h->arc_cycles);
            if(h->resyncs < PF_XEN_FIXUP_UNSYNC_RESYNC_MAX)
                update_summary(&h->summary.pf_xen_fixup_unsync_resync[h->resyncs],
                               h->arc_cycles);
            else
                update_summary(&h->summary.pf_xen_fixup_unsync_resync[PF_XEN_FIXUP_UNSYNC_RESYNC_MAX],
                               h->arc_cycles);
        }
        if(e->flag_oos_fixup_add)
            update_summary(&h->summary.pf_xen_fixup[PF_XEN_FIXUP_OOS_ADD], h->arc_cycles);
        if(e->flag_oos_fixup_evict)
            update_summary(&h->summary.pf_xen_fixup[PF_XEN_FIXUP_OOS_EVICT], h->arc_cycles);
        if(e->flag_promote)
            update_summary(&h->summary.pf_xen_fixup[PF_XEN_FIXUP_PROMOTE], h->arc_cycles);
        if(e->flag_wrmap) {
            update_summary(&h->summary.pf_xen_fixup[PF_XEN_FIXUP_WRMAP], h->arc_cycles);
            if(e->flag_wrmap_brute_force || h->wrmap_bf)
                update_summary(&h->summary.pf_xen_fixup[PF_XEN_FIXUP_BRUTE_FORCE], h->arc_cycles);
        } else if(e->flag_wrmap_brute_force || h->wrmap_bf) {
            fprintf(warn, "Strange: wrmap_bf but not wrmap!\n");
        }


        if(!(e->flag_promote || h->prealloc_unpin || e->flag_unsync))
            update_summary(&h->summary.pf_xen_fixup[PF_XEN_FIXUP_UPDATE_ONLY], h->arc_cycles);
        /* more summary info */

        if(e->flag_unsync)
            hvm_update_short_summary(h, HVM_SHORT_SUMMARY_UNSYNC);
        else
            hvm_update_short_summary(h, HVM_SHORT_SUMMARY_FIXUP);
    }

    if(opt.scatterplot_unpin_promote) {
        if(h->prealloc_unpin)
            scatterplot_vs_time(h->exit_tsc, 0);
        if(e->flag_promote) {
            if(opt.with_cr3_enumeration) {
                if(h->v->cr3.data)
                    scatterplot_vs_time(h->exit_tsc, h->v->cr3.data->cr3_id);
            } else
                scatterplot_vs_time(h->exit_tsc, 2);
        }
    }
}

void shadow_fixup_process(struct record_info *ri, struct hvm_data *h)
{
    struct pf_xen_extra *e = &h->inflight.pf_xen;
    union {
        /* for PAE, guest_l1e may be 64 while guest_va may be 32;
           so put it first for alignment sake. */
        struct {
            unsigned int gl1e, va, flags;
        } gpl2;
        struct {
            unsigned long long gl1e;
            unsigned int va, flags;
        } gpl3;
        struct {
            unsigned long long gl1e, va;
            unsigned int flags;
        } gpl4;
    } *r = (typeof(r))ri->d;
    union shadow_event sevt = { .event = ri->event };
    int rec_gpl = sevt.paging_levels + 2;

    if ( rec_gpl != h->v->guest_paging_levels )
    {
        fprintf(warn, "%s: record paging levels %d, guest paging levels %d.  Switching.\n",
                __func__, rec_gpl, h->v->guest_paging_levels);
        h->v->guest_paging_levels = rec_gpl;
    }

    switch(rec_gpl)
    {
    case 2:
        if(sizeof(r->gpl2) != ri->extra_words * 4)
        {
            fprintf(warn, "%s: expected %zd bytes for %d-level guest, got %d!\n",
                    __func__, sizeof(r->gpl2), h->v->guest_paging_levels,
                    ri->extra_words * 4);
            error(ERR_RECORD, ri);
            return;
        }
        e->va = r->gpl2.va;
        e->flags = r->gpl2.flags;
        e->gl1e = r->gpl2.gl1e;
        break;
    case 3:
        if(sizeof(r->gpl3) != ri->extra_words * 4)
        {
            fprintf(warn, "%s: expected %zd bytes for %d-level guest, got %d!\n",
                    __func__, sizeof(r->gpl3), h->v->guest_paging_levels,
                    ri->extra_words * 4);
            error(ERR_RECORD, ri);
            return;
        }
        e->va = r->gpl3.va;
        e->flags = r->gpl3.flags;
        e->gl1e = r->gpl3.gl1e;
        break;
    case 4:
        if(sizeof(r->gpl4) != ri->extra_words * 4)
        {
            fprintf(warn, "%s: expected %zd bytes for %d-level guest, got %d!\n",
                    __func__, sizeof(r->gpl4), h->v->guest_paging_levels,
                    ri->extra_words * 4);
            error(ERR_RECORD, ri);
            return;
        }
        e->va = r->gpl4.va;
        e->flags = r->gpl4.flags;
        e->gl1e = r->gpl4.gl1e;
        break;
    }

    pf_preprocess(e,rec_gpl);

    if(opt.dump_all)
    {
        if ( e->flag_unsync )
            printf("]%s fixup:unsync va %llx gl1e %llx corr %llx flags (%x)%s\n",
                   ri->dump_header,
                   e->va, e->gl1e,
                   e->corresponding_va,
                   e->flags,
                   flag_string(e));
        else
            printf("]%s fixup va %llx gl1e %llx flags (%x)%s\n",
                   ri->dump_header,
                   e->va, e->gl1e, e->flags,
                   flag_string(e));
    }

    if ( hvm_set_postprocess(h, shadow_fixup_postprocess) )
        fprintf(warn, "%s: Strange, postprocess already set\n", __func__);
}

void shadow_mmio_postprocess(struct hvm_data *h)
{
    struct pf_xen_extra *e = &h->inflight.pf_xen;
    if ( opt.summary_info )
    {
        if(e->pf_case)
            update_summary(&h->summary.pf_xen[e->pf_case],
                           h->arc_cycles);
        else
            fprintf(warn, "Strange, pf_case 0!\n");

        hvm_update_short_summary(h, HVM_SHORT_SUMMARY_MMIO);
    }

    if(opt.with_mmio_enumeration)
        enumerate_mmio(h);
}

void shadow_mmio_process(struct record_info *ri, struct hvm_data *h)
{
    struct pf_xen_extra *e = &h->inflight.pf_xen;
    struct mmio_info *m = &h->inflight.mmio;
    union {
        /* for PAE, guest_l1e may be 64 while guest_va may be 32;
           so put it first for alignment sake. */
        struct {
            unsigned int va;
        } gpl2;
        struct {
            unsigned long long va;
        } gpl4;
    } *r = (typeof(r))ri->d;
    union shadow_event sevt = { .event = ri->event };
    int rec_gpl = sevt.paging_levels + 2;

    if ( rec_gpl != h->v->guest_paging_levels )
    {
        fprintf(warn, "%s: record paging levels %d, guest paging levels %d.  Switching.\n",
                __func__, rec_gpl, h->v->guest_paging_levels);
        h->v->guest_paging_levels = rec_gpl;
    }

    switch(rec_gpl)
    {
    case 2:
    case 3:
        if(sizeof(r->gpl2) != ri->extra_words * 4)
        {
            fprintf(warn, "%s: expected %zd bytes for %d-level guest, got %d!\n",
                    __func__, sizeof(r->gpl2), h->v->guest_paging_levels,
                    ri->extra_words * 4);
            error(ERR_RECORD, ri);
            return;
        }
        e->va = m->va = r->gpl2.va;
        break;
    case 4:
        if(sizeof(r->gpl4) != ri->extra_words * 4)
        {
            fprintf(warn, "%s: expected %zd bytes for %d-level guest, got %d!\n",
                    __func__, sizeof(r->gpl4), h->v->guest_paging_levels,
                    ri->extra_words * 4);
            error(ERR_RECORD, ri);
            return;
        }
        e->va = m->va = r->gpl4.va;
        break;
    }

    if(opt.dump_all)
        printf("]%s %smmio va %llx\n",
                ri->dump_header,
                (e->pf_case==PF_XEN_FAST_MMIO)?"fast ":"",
                e->va);

    if ( hvm_set_postprocess(h, shadow_mmio_postprocess) )
        fprintf(warn, "%s: Strange, postprocess already set\n", __func__);
}

void shadow_propagate_postprocess(struct hvm_data *h)
{
    struct pf_xen_extra *e = &h->inflight.pf_xen;

    if ( opt.summary_info )
    {
        if(e->pf_case)
            update_summary(&h->summary.pf_xen[e->pf_case],
                           h->arc_cycles);
        else
            fprintf(warn, "Strange, pf_case 0!\n");

        hvm_update_short_summary(h, HVM_SHORT_SUMMARY_PROPAGATE);
    }
}

void shadow_propagate_process(struct record_info *ri, struct hvm_data *h)
{
    struct pf_xen_extra *e = &h->inflight.pf_xen;
    union {
        /* for PAE, guest_l1e may be 64 while guest_va may be 32;
           so put it first for alignment sake. */
        struct {
            unsigned int gl1e, va, flags;
        } gpl2;
        struct {
            unsigned long long gl1e;
            unsigned int va, flags;
        } gpl3;
        struct {
            unsigned long long gl1e, va;
            unsigned int flags;
        } gpl4;
    } *r = (typeof(r))ri->d;
    union shadow_event sevt = { .event = ri->event };
    int rec_gpl = sevt.paging_levels + 2;

    if ( rec_gpl != h->v->guest_paging_levels )
    {
        fprintf(warn, "%s: record paging levels %d, guest paging levels %d.  Switching.\n",
                __func__, rec_gpl, h->v->guest_paging_levels);
        h->v->guest_paging_levels = rec_gpl;
    }

    switch(rec_gpl)
    {
    case 2:
        if(sizeof(r->gpl2) != ri->extra_words * 4)
        {
            fprintf(warn, "%s: expected %zd bytes for %d-level guest, got %d!\n",
                    __func__, sizeof(r->gpl2), h->v->guest_paging_levels,
                    ri->extra_words * 4);
            error(ERR_RECORD, ri);
            return;
        }
        e->va = r->gpl2.va;
        e->flags = r->gpl2.flags;
        e->gl1e = r->gpl2.gl1e;
        break;
    case 3:
        if(sizeof(r->gpl3) != ri->extra_words * 4)
        {
            fprintf(warn, "%s: expected %zd bytes for %d-level guest, got %d!\n",
                    __func__, sizeof(r->gpl3), h->v->guest_paging_levels,
                    ri->extra_words * 4);
            error(ERR_RECORD, ri);
            return;
        }
        e->va = r->gpl3.va;
        e->flags = r->gpl3.flags;
        e->gl1e = r->gpl3.gl1e;
        break;
    case 4:
        if(sizeof(r->gpl4) != ri->extra_words * 4)
        {
            fprintf(warn, "%s: expected %zd bytes for %d-level guest, got %d!\n",
                    __func__, sizeof(r->gpl4), h->v->guest_paging_levels,
                    ri->extra_words * 4);
            error(ERR_RECORD, ri);
            return;
        }
        e->va = r->gpl4.va;
        e->flags = r->gpl4.flags;
        e->gl1e = r->gpl4.gl1e;
        break;
    }

    if(opt.dump_all)
        printf("]%s propagate va %llx gl1e %llx flags (%x)%s\n",
               ri->dump_header,
               e->va, e->gl1e, e->flags,
               flag_string(e));

    if ( hvm_set_postprocess(h, shadow_propagate_postprocess) )
        fprintf(warn, "%s: Strange, postprocess already set\n", __func__);
}

void shadow_fault_generic_dump(unsigned int event, uint32_t *d, char *prefix,
                         char * dump_header)
{
    char *evt_string, evt_number[10];
    union shadow_event sevt = { .event = event };
    int i;

    if(sevt.minor < PF_XEN_MAX && pf_xen_name[sevt.minor])
    {
        evt_string = pf_xen_name[sevt.minor];
    }
    else
    {
        snprintf(evt_number, 10, "%d", sevt.minor);
        evt_string = evt_number;
    }

    printf("%s%s shadow %s gl %d [",
           prefix,
           dump_header,
           evt_string,
           sevt.paging_levels);

    for(i=0; i<4; i++)
    {
        printf(" %x", d[i]);
    }

    printf(" ]\n");
}

void shadow_fault_generic_postprocess(struct hvm_data *h)
{
    struct pf_xen_extra *e = &h->inflight.pf_xen;
    if ( e->pf_case < PF_XEN_NOT_SHADOW || e->pf_case > PF_XEN_LAST_FAULT )
    {
        fprintf(warn, "%s: Strange, unexpected case %d\n",
                __func__, e->pf_case);
        return;
    }

    if(opt.summary_info) {
        update_summary(&h->summary.pf_xen[e->pf_case],
                           h->arc_cycles);

        hvm_update_short_summary(h, HVM_SHORT_SUMMARY_PROPAGATE);
    }
}

void shadow_fault_generic_process(struct record_info *ri, struct hvm_data *h)
{
    union shadow_event sevt = { .event = ri->event };

    /* pf-case traces, vs others */
    h->inflight.generic.event = ri->event;
    bcopy(ri->d, h->inflight.generic.d, sizeof(unsigned int) * 4);

    if(opt.dump_all)
        shadow_fault_generic_dump(h->inflight.generic.event,
                                  h->inflight.generic.d,
                                  "]", ri->dump_header);

    h->inflight.pf_xen.pf_case = sevt.minor;
    if ( hvm_set_postprocess(h, shadow_fault_generic_postprocess) )
        fprintf(warn, "%s: Strange, postprocess already set\n", __func__);
}

void shadow_resync_process(struct record_info *ri, struct hvm_data *h)
{
    struct {
        unsigned long long gfn;
    } *r = (typeof(r))ri->d;

    if(opt.dump_all)
        printf(" %s oos resync %s gfn %llx\n",
               ri->dump_header,
               (ri->event == TRC_SHADOW_RESYNC_FULL)?"full":"only",
               r->gfn);

    h->resyncs++;
}

void shadow_prealloc_unpin_process(struct record_info *ri, struct hvm_data *h) {
    struct {
        unsigned long long gfn;
    } *r = (typeof(r))ri->d;

    if(opt.dump_all)
        printf(" %s prealloc-unpin gfn %llx\n",
               ri->dump_header, r->gfn);

    if(h->prealloc_unpin)
        fprintf(warn, "Strange, more than one prealloc_unpin per arc!\n");

    h->prealloc_unpin = 1;

    if(opt.with_cr3_enumeration)
        cr3_prealloc_unpin(h->v, r->gfn);
}

void shadow_wrmap_bf_process(struct record_info *ri, struct hvm_data *h) {
    struct {
        unsigned long long gfn;
    } *r = (typeof(r))ri->d;

    if(opt.dump_all)
        printf(" %s wrmap-bf gfn %llx\n",
               ri->dump_header, r->gfn);

    h->wrmap_bf = 1;
}

void shadow_process(struct pcpu_info *p)
{
    struct record_info *ri = &p->ri;
    struct hvm_data *h;

    union shadow_event sevt = { .event = ri->event };

    int gpl = sevt.paging_levels + 2;

    assert(p->current);
    if(vcpu_set_data_type(p->current, VCPU_DATA_HVM))
        return;

    h = &p->current->hvm;

    if(!h->init || !h->vmexit_valid)
    {
        if(opt.dump_all)
            shadow_fault_generic_dump(ri->event,
                                      ri->d,
                                      "!", ri->dump_header);
        return;
    }

    if(sevt.minor <= PF_XEN_NOT_SHADOW) {
        if(p->current->guest_paging_levels != gpl)
        {
            fprintf(warn, "%s: Changing guest paging levels to %d\n",
                    __func__, gpl);
            p->current->guest_paging_levels = gpl;
        }
    }

    if(sevt.minor <= PF_XEN_LAST_FAULT)  {
        h->inflight.pf_xen.pf_case = sevt.minor;
        if(opt.summary) {
            hvm_set_summary_handler(h, hvm_pf_xen_summary, NULL);
        }
    }

    /* FIXME - mask out paging levels */
    switch(sevt.minor)
    {
    case PF_XEN_NOT_SHADOW:
        shadow_propagate_process(ri, h);
        break;
    case PF_XEN_EMULATE:
        shadow_emulate_process(ri, h);
        break;
    case PF_XEN_FIXUP:
        shadow_fixup_process(ri, h);
        break;
    case PF_XEN_MMIO:
    case PF_XEN_FAST_MMIO:
        shadow_mmio_process(ri, h);
        break;
    case PF_XEN_EMULATE_UNSHADOW_USER:
    case PF_XEN_EMULATE_UNSHADOW_EVTINJ:
    case PF_XEN_EMULATE_UNSHADOW_UNHANDLED:
        shadow_emulate_other_process(ri, h);
        break;
#if 0
    case PF_XEN_EMULATE_UNSYNC:
        shadow_unsync_process(ri, h);
        break;
#endif
    case SHADOW_RESYNC_FULL:
    case SHADOW_RESYNC_ONLY:
        shadow_resync_process(ri, h);
        break;
    case SHADOW_PREALLOC_UNPIN:
        shadow_prealloc_unpin_process(ri, h);
        break;
    case SHADOW_WRMAP_BF:
        shadow_wrmap_bf_process(ri, h);
        break;
    default:
        if(sevt.minor <= PF_XEN_LAST_FAULT) {
            shadow_fault_generic_process(ri, h);
        } else {
            warn_once("Warning: processing shadow as generic\n");
            process_generic(ri);
        }
        break;
    }
}

/* ---- PV guests ---- */
union pv_event {
    unsigned event;
    struct {
        unsigned minor:8,
            x64:1,
            unused1:3,
            sub:4,
            main:12,
            unused:4;
    };
};

void pv_hypercall_process(struct record_info *ri, struct pv_data *pv) {
    union {
        struct {
            uint32_t eip, eax;
        } x32;
        struct {
            uint64_t eip;
            uint32_t eax;
        } x64;
    } * r = (typeof(r)) ri->d;
    union pv_event pevt = { .event = ri->event };
    unsigned long long eip;
    unsigned int eax;

    if(pevt.x64) {
        eip = r->x64.eip;
        eax = r->x64.eax;
    } else {
        eip = r->x32.eip;
        eax = r->x32.eax;
    }

    if(opt.summary_info) {
        if(eax < PV_HYPERCALL_MAX)
            pv->hypercall_count[eax]++;
    }

    if(opt.dump_all) {
        if(eax < HYPERCALL_MAX)
            printf(" %s hypercall %2x (%s) eip %llx\n",
                   ri->dump_header, eax,
                   hypercall_name[eax], eip);
        else
            printf(" %s hypercall %x eip %llx\n",
                   ri->dump_header, eax, eip);
    }
}

void pv_trap_process(struct record_info *ri, struct pv_data *pv) {
    union {
        struct {
            unsigned int eip;
            unsigned trapnr:15,
                use_error_code:1,
                error_code:16;
        } x32;
        struct {
            unsigned long long eip;
            unsigned trapnr:15,
                use_error_code:1,
                error_code:16;
        } x64;
    } * r = (typeof(r)) ri->d;
    union pv_event pevt = { .event = ri->event };
    unsigned long long eip;
    unsigned trapnr, use_ec, ec;

    if(pevt.x64) {
        eip = r->x64.eip;
        trapnr = r->x64.trapnr;
        use_ec = r->x64.use_error_code;
        ec = r->x64.error_code;
    } else {
        eip = r->x32.eip;
        trapnr = r->x32.trapnr;
        use_ec = r->x32.use_error_code;
        ec = r->x32.error_code;
    }

    if(opt.summary_info) {
        if(trapnr < PV_TRAP_MAX)
            pv->trap_count[trapnr]++;
    }

    if(opt.dump_all) {
        printf(" %s trap %x eip %llx",
               ri->dump_header, trapnr, eip);
        if(use_ec)
            printf(" ec %x\n", ec);
        else
            printf("\n");
    }
}

void pv_ptwr_emulation_process(struct record_info *ri, struct pv_data *pv) {
    union pv_event pevt = { .event = ri->event };
    union {
        /* gpl2 is deprecated */
        struct {
            unsigned long long pte;
            unsigned int addr, eip;
        } gpl3;
        struct {
            unsigned long long pte;
            unsigned long long addr, eip;
        } gpl4;
    } *r = (typeof(r))ri->d;
    struct {
        unsigned long long pte, addr, eip;
    } e;

    switch ( pevt.minor ) {
    case PV_PTWR_EMULATION_PAE:
        if ( pevt.x64 )
        {
            fprintf(warn, "Strange: PV_PTWR_EMULATION, but x64! %x\n",
                    ri->event);
            error(ERR_RECORD, ri);
        }
        e.pte = r->gpl3.pte;
        e.addr = r->gpl3.addr;
        e.eip = r->gpl3.eip;
        break;
    case PV_PTWR_EMULATION:
        if ( !pevt.x64 )
        {
            fprintf(warn, "Strange: PV_PTWR_EMULATION, but !x64! %x\n",
                    ri->event);
            error(ERR_RECORD, ri);
        }
        e.pte = r->gpl4.pte;
        e.addr = r->gpl4.addr;
        e.eip = r->gpl4.eip;
        break;
    default:
        fprintf(warn, "ERROR: Unknown PV_PTRW minor type %d!\n",
                pevt.minor);
        error(ERR_RECORD, ri);
        return;
    }

    if ( opt.dump_all )
    {
        printf(" %s ptwr l1e %llx eip %llx addr %llx\n",
               ri->dump_header,
               e.pte, e.eip, e.addr);
    }
}

void pv_generic_process(struct record_info *ri, struct pv_data *pv) {
    union pv_event pevt = { .event = ri->event };
    if ( opt.dump_all ) {
        if(pevt.minor < PV_MAX && pv_name[pevt.minor])
            printf(" %s %s",
                   ri->dump_header,
                   pv_name[pevt.minor]);
        else
            printf(" %s PV-%d ",
                   ri->dump_header, pevt.minor);
        if (ri->extra_words) {
            int i;
            printf("[ ");
            for(i=0; i<ri->extra_words; i++) {
                printf("%x ", (unsigned)ri->d[i]);
            }
            printf("]");

        }
        printf("\n");
    }
}

void pv_summary(struct pv_data *pv) {
    int i, j;

    if(!pv->summary_info)
        return;

    printf("PV events:\n");
    for(i=0; i<PV_MAX; i++) {
        int count;

        count = pv->count[i];
        if (i == PV_HYPERCALL_V2)
            count += pv->count[PV_HYPERCALL_SUBCALL];

        if (count == 0)
            continue;

        printf("  %s  %d\n", pv_name[i], count);

        switch(i) {
        case PV_HYPERCALL:
        case PV_HYPERCALL_V2:
            for(j=0; j<PV_HYPERCALL_MAX; j++) {
                if(pv->hypercall_count[j])
                    printf("    %-29s[%2d]: %6d\n",
                           hypercall_name[j],
                           j,
                           pv->hypercall_count[j]);
            }
            break;
        case PV_TRAP:
            for(j=0; j<PV_TRAP_MAX; j++) {
                if(pv->trap_count[j])
                    printf("    [%d] %d\n",
                           j, pv->trap_count[j]);
            }
            break;
        }
    }
}

static const char *grant_table_op_str[] = {
    "map_grant_ref", "unmap_grant_ref", "setup_table", "dump_table",
    "transfer", "copy", "query_size", "unmap_and_replace",
    "set_version", "get_status_frames", "get_version", "swap_grant_ref",
};

static const char *vcpu_op_str[] = {
    "initialise", "up", "down", "is_up", "get_runstate_info",
    "register_runstate_memory_area", "set_periodic_timer",
    "stop_periodic_timer", "set_singleshot_timer", "stop_singleshot_timer",
    "register_vcpu_info", "send_nmi", "get_physid",
    "register_vcpu_time_memory_area",
};

static const char *sched_op_str[] = {
    "yield", "block", "shutdown", "poll", "remote_shutdown", "shutdown_code",
    "watchdog",
};

static const char *cmd_to_str(const char *strings[], size_t n, uint32_t cmd)
{
    static char buf[32];

    if (cmd < n)
        return strings[cmd];

    snprintf(buf, sizeof(buf), "unknown (%d)", cmd);
    return buf;
}

#define CMD_TO_STR(op)                                                  \
    static const char * op ## _to_str(uint32_t cmd) {                   \
        return cmd_to_str(op ## _str, ARRAY_SIZE(op ## _str), cmd);     \
    }

CMD_TO_STR(grant_table_op);
CMD_TO_STR(vcpu_op);
CMD_TO_STR(sched_op);

void pv_hypercall_gather_args(const struct record_info *ri, uint64_t *args)
{
    int i, word;

    /* Missing arguments are zeroed. */
    memset(args, 0, 6 * sizeof(uint64_t));

    for (i = 0, word = 1; i < 6 && word < ri->extra_words; i++) {
        int present = pv_hypercall_arg_present(ri, i);

        switch (present) {
        case ARG_32BIT:
            args[i] = ri->d[word];
            break;
        case ARG_64BIT:
            args[i] = ((uint64_t)ri->d[word + 1] << 32) | ri->d[word];
            break;
        }

        /* Skip over any words for this argument. */
        word += present;
    }
}

static void pv_hypercall_print_args(const struct record_info *ri)
{
    int i, word;

    for (i = 0, word = 1; i < 6 && word < ri->extra_words; i++) {
        int present = pv_hypercall_arg_present(ri, i);

        switch (present) {
        case ARG_MISSING:
            printf(" ??");
            break;
        case ARG_32BIT:
            printf(" %08x", ri->d[word]);
            break;
        case ARG_64BIT:
            printf(" %016"PRIu64"", ((uint64_t)ri->d[word + 1] << 32) | ri->d[word]);
            break;
        }

        word += present;
    }
}

void pv_hypercall_v2_process(struct record_info *ri, struct pv_data *pv,
                             const char *indent)
{
    int op = pv_hypercall_op(ri);

    if(opt.summary_info) {
        if(op < PV_HYPERCALL_MAX)
            pv->hypercall_count[op]++;
    }

    if(opt.dump_all) {
        uint64_t args[6];

        if(op < HYPERCALL_MAX)
            printf(" %s%s hypercall %2x (%s)",
                   ri->dump_header, indent, op, hypercall_name[op]);
        else
            printf(" %s%s hypercall %2x",
                   ri->dump_header, indent, op);

        switch(op) {
        case HYPERCALL_mmu_update:
            pv_hypercall_gather_args(ri, args);
            printf(" %d updates%s", (uint32_t)args[1] & ~MMU_UPDATE_PREEMPTED,
                   (args[1] & MMU_UPDATE_PREEMPTED) ? " (preempted)" : "");
            break;
        case HYPERCALL_multicall:
            pv_hypercall_gather_args(ri, args);
            printf(" %d calls", (uint32_t)args[1]);
            break;
        case HYPERCALL_grant_table_op:
            pv_hypercall_gather_args(ri, args);
            printf(" %s %d ops", grant_table_op_to_str(args[0]), (uint32_t)args[2]);
            break;
        case HYPERCALL_vcpu_op:
            pv_hypercall_gather_args(ri, args);
            printf(" %s vcpu %d", vcpu_op_to_str(args[0]), (uint32_t)args[1]);
            break;
        case HYPERCALL_mmuext_op:
            pv_hypercall_gather_args(ri, args);
            printf(" %d ops", (uint32_t)args[1]);
            break;
        case HYPERCALL_sched_op:
            pv_hypercall_gather_args(ri, args);
            printf(" %s", sched_op_to_str(args[0]));
            break;
        default:
            pv_hypercall_print_args(ri);
            break;
        }
        printf("\n");
    }
}

void pv_process(struct pcpu_info *p)
{
    struct record_info *ri = &p->ri;
    struct vcpu_data *v = p->current;
    struct pv_data *pv = &v->pv;

    union pv_event pevt = { .event = ri->event };

    if(vcpu_set_data_type(p->current, VCPU_DATA_PV))
        return;

    if(opt.summary_info) {
        pv->summary_info=1;

        if(pevt.minor == PV_PTWR_EMULATION_PAE)
            pv->count[PV_PTWR_EMULATION]++;
        else
            pv->count[pevt.minor]++;
    }

    switch(pevt.minor)
    {
    case PV_HYPERCALL:
        pv_hypercall_process(ri, pv);
        break;
    case PV_TRAP:
        pv_trap_process(ri, pv);
        break;
    case PV_PTWR_EMULATION:
    case PV_PTWR_EMULATION_PAE:
        pv_ptwr_emulation_process(ri, pv);
        break;
    case PV_HYPERCALL_V2:
        pv_hypercall_v2_process(ri, pv, "");
        break;
    case PV_HYPERCALL_SUBCALL:
        pv_hypercall_v2_process(ri, pv, " ");
        break;
    default:
        pv_generic_process(ri, pv);
        break;
    }
}

/* ---- Schedule ---- */
struct vcpu_data * vcpu_create(struct domain_data *d, int vid)
{
    struct vcpu_data *v;

    assert(d->vcpu[vid] == NULL);

    fprintf(warn, "Creating vcpu %d for dom %d\n", vid, d->did);

    if((v=malloc(sizeof(*v)))==NULL)
    {
        fprintf(stderr, "%s: malloc %zd failed!\n", __func__, sizeof(*d));
        error(ERR_SYSTEM, NULL);
    }

    bzero(v, sizeof(*v));

    v->vid = vid;
    v->d = d;
    v->p = NULL;
    v->runstate.state = RUNSTATE_INIT;
    v->runstate.last_oldstate.wrong = RUNSTATE_INIT;

    d->vcpu[vid] = v;

    assert(v == v->d->vcpu[v->vid]);

    if(vid > d->max_vid)
        d->max_vid = vid;

    return v;
}

/* Called by both domain_create and sched_default_domain_init */
void domain_init(struct domain_data *d, int did)
{
    bzero(d, sizeof(*d));

    d->did = did;
    d->next = NULL;

    if(opt.interval.check == INTERVAL_CHECK_DOMAIN)
        interval_domain_value_check(d);
}

struct domain_data * domain_create(int did)
{
    struct domain_data *d;

    fprintf(warn, "Creating domain %d\n", did);

    if((d=malloc(sizeof(*d)))==NULL)
    {
        fprintf(stderr, "%s: malloc %zd failed!\n", __func__, sizeof(*d));
        error(ERR_SYSTEM, NULL);
    }

    /* Initialize domain & vcpus */
    domain_init(d, did);

    return d;
 }

struct domain_data * domain_find(int did)
{
    struct domain_data *d, *n, **q;

    /* Look for domain, keeping track of the last pointer so we can add
       a domain if we need to. */
    for ( d = domain_list, q=&domain_list ;
          d && (d->did < did) ;
          q = &d->next, d=d->next ) ;

    if(d && d->did == did)
        return d;

    /* Make a new domain */
    n = domain_create(did);

    /* Insert it into the list */
    n->next = d;
    *q = n;

    return n;
}

struct vcpu_data * vcpu_find(int did, int vid)
{
    struct domain_data *d;
    struct vcpu_data *v;

    d = domain_find(did);

    v = d->vcpu[vid];

    if(!v)
        v = vcpu_create(d, vid);

    return v;
}

void pcpu_runstate_update(struct pcpu_info *p, tsc_t tsc)
{
    if ( p->time.tsc )
    {
        if ( p->current->d->did == IDLE_DOMAIN )
            update_cycles(&p->time.idle, tsc - p->time.tsc);
        else
            update_cycles(&p->time.running, tsc - p->time.tsc);
        p->time.tsc = 0;
    }
}

void vcpu_prev_update(struct pcpu_info *p, struct vcpu_data *prev,
                      tsc_t tsc, int new_runstate)
{
    assert(prev == prev->d->vcpu[prev->vid]);

    if(prev->p != p)
    {
        fprintf(warn, "Strange, sched_switch on pcpu %d, prev->pcpu %d!\n",
                p->pid, prev->p->pid);
        prev->runstate.tsc = 0;
        goto set;
    }

    //assert(p->current);

   if ( !p->current )
    {
        fprintf(warn, "%s: FATAL: p->current NULL!\n", __func__);
        error(ERR_ASSERT, NULL);
    }

    if(p->current != prev)
    {
        fprintf(warn, "Strange, sched_switch prev d%dv%d, pcpu %d current d%dv%d!\n",
                prev->d->did, prev->vid,
                p->pid, p->current->d->did, p->current->vid);
        prev->runstate.tsc = 0;
        goto set;
    }

    if(prev->runstate.state != RUNSTATE_RUNNING)
    {
        fprintf(warn, "Strange, prev d%dv%d not running!\n",
                prev->d->did, prev->vid);
        prev->runstate.tsc = 0;
        goto set;
    }

set:
    pcpu_runstate_update(p, tsc);
    p->current = NULL;
    pcpu_string_draw(p);
    runstate_update(prev, new_runstate, tsc);
}

void vcpu_next_update(struct pcpu_info *p, struct vcpu_data *next, tsc_t tsc)
{
    assert(next == next->d->vcpu[next->vid]);
    //assert(p->current == NULL);

    if ( p->current != NULL )
    {
        if ( p->lost_record.seen_valid_schedule == 0 )
        {
            fprintf(warn, "%s: p->current non-NULL, but seen_valid_schedule 0.  Ignoring.\n",
                    __func__);
            runstate_update(p->current, RUNSTATE_LOST, tsc);
            p->current = NULL;
        }
        else
        {
            fprintf(warn, "%s: FATAL: p->current not NULL! (d%dv%d, runstate %s)\n",
                    __func__,
                    p->current->d->did,
                    p->current->vid,
                    runstate_name[p->current->runstate.state]);
            error(ERR_ASSERT, NULL);
        }
    }

    if(next->activated)
    {
        /* We may get lost records at start-of-day, so ignore
           setting runstate of default vcpus */
        if(next->runstate.state == RUNSTATE_RUNNING
           && next->d->did != DEFAULT_DOMAIN)
        {
            fprintf(warn, "Strange, next d%dv%d already running on proc %d!\n",
                    next->d->did, next->vid,
                    next->p->pid);
            next->runstate.tsc = 0;
        }

        /* If we're moving from one pcpu to another, record change & update tsc */
        if(next->p != p) {
            if(next->pcpu_tsc)
            {
                update_cycles(&next->cpu_affinity_all, tsc - next->pcpu_tsc);
                update_cycles(&next->cpu_affinity_pcpu[p->pid], tsc - next->pcpu_tsc);
            }
            next->pcpu_tsc = tsc;
        }
    }
    else
    {
        next->guest_paging_levels = opt.default_guest_paging_levels;
        next->activated = 1;
        next->pcpu_tsc = tsc;
    }

    runstate_update(next, RUNSTATE_RUNNING, tsc);

    if ( opt.scatterplot_pcpu
         && next->d->did != IDLE_DOMAIN
         && next->d->did != DEFAULT_DOMAIN )
    {
        struct time_struct t;

        abs_cycles_to_time(tsc, &t);

        if ( next->p )
            printf("%dv%d %u.%09u %d\n",
                   next->d->did, next->vid,
                   t.s, t.ns,
                   next->p->pid);
        printf("%dv%d %u.%09u %d\n",
               next->d->did, next->vid,
               t.s, t.ns,
               p->pid);
    }

    next->p = p;
    p->current = next;
    pcpu_string_draw(p);
    p->time.tsc = tsc;
    p->lost_record.seen_valid_schedule = 1;
}

/* If current is the default domain, we're fixing up from something
 * like start-of-day.  Update what we can. */
void vcpu_start(struct pcpu_info *p, struct vcpu_data *v) {
    /* If vcpus are created, or first show up, in a "dead zone", this will
     * fail. */
    if( !p->current || p->current->d->did != DEFAULT_DOMAIN) {
        fprintf(stderr, "Strange, p->current not default domain!\n");
        error(ERR_FILE, NULL);
        return;
    }

    if(!p->first_tsc) {
        fprintf(stderr, "Strange, p%d first_tsc 0!\n", p->pid);
        error(ERR_FILE, NULL);
    }

    if(p->first_tsc <= p->current->runstate.tsc) {
        fprintf(stderr, "Strange, first_tsc %llx < default_domain runstate tsc %llx!\n",
                p->first_tsc,
                p->current->runstate.tsc);
        error(ERR_FILE, NULL);
    }

    /* Change default domain to 'queued' */
    runstate_update(p->current, RUNSTATE_QUEUED, p->first_tsc);

    /* FIXME: Copy over data from the default domain this interval */
    fprintf(warn, "Using first_tsc for d%dv%d (%lld cycles)\n",
            v->d->did, v->vid, p->last_tsc - p->first_tsc);

    /* Simulate the time since the first tsc */
    runstate_update(v, RUNSTATE_RUNNING, p->first_tsc);
    p->time.tsc = p->first_tsc;
    p->current = v;
    pcpu_string_draw(p);
    v->p = p;
}

void sched_runstate_process(struct pcpu_info *p)
{
    enum {
        CHANGE=0,
        CONTINUE
    } type;
    struct vcpu_data *v;
    struct record_info *ri = &p->ri;
    struct {
        unsigned vcpu:16, dom:16;
        unsigned long long p1, p2;
    } __attribute__((packed)) * r = (typeof(r))ri->d;
    union {
        unsigned int event;
        struct {
            unsigned lo:4,
                new_runstate:4,
                old_runstate:4,
                sub:4,
                main:12,
                unused:4;
        };
    } _sevt = { .event = ri->event };
    struct {
        int new_runstate, old_runstate;
    } sevt;
    int perfctrs;
    struct last_oldstate_struct last_oldstate;

    switch(_sevt.lo)
    {
    case 1:
        type = CHANGE;
        sevt.new_runstate = _sevt.new_runstate;
        sevt.old_runstate = _sevt.old_runstate;
        break;
    case 2:
        type = CONTINUE;
        sevt.new_runstate = sevt.old_runstate = RUNSTATE_RUNNING;
        break;
    default:
        fprintf(warn, "FATAL: Unexpected runstate change type %d!\n",
                _sevt.lo);
        error(ERR_RECORD, NULL);
        return;
    }

    perfctrs = (ri->extra_words == 5);

    if(opt.dump_all) {
        if( perfctrs ) {
            printf(" %s %s {%lld,%lld} d%uv%u %s->%s\n",
                   ri->dump_header,
                   type?"runstate_continue":"runstate_change",
                   r->p1, r->p2,
                   r->dom, r->vcpu,
                   runstate_name[sevt.old_runstate],
                   runstate_name[sevt.new_runstate]);
        } else {
            printf(" %s %s d%uv%u %s->%s\n",
                   ri->dump_header,
                   type?"runstate_continue":"runstate_change",
                   r->dom, r->vcpu,
                   runstate_name[sevt.old_runstate],
                   runstate_name[sevt.new_runstate]);
        }
    }

    /* Sanity check: expected transitions */
    if ( type == CHANGE )
    {
        if( (sevt.new_runstate == RUNSTATE_RUNNING
             && sevt.old_runstate != RUNSTATE_RUNNABLE)
            || (sevt.new_runstate == RUNSTATE_BLOCKED
                && sevt.old_runstate == RUNSTATE_RUNNABLE ) )
        {
            fprintf(warn, "Strange, d%dv%d unexpected runstate transition %s->%s\n",
                    r->dom, r->vcpu,
                    runstate_name[sevt.old_runstate],
                    runstate_name[sevt.new_runstate]);
        }
    }

    if(r->vcpu > MAX_CPUS)
    {
        fprintf(warn, "%s: vcpu %u > MAX_VCPUS %d!\n",
                __func__, r->vcpu, MAX_CPUS);
        return;
    }

    v = vcpu_find(r->dom, r->vcpu);

    /* We want last_oldstate reset every time; so copy the last one and use
     * that locally, clobbering the one in the vcpu struct.  If it needs to
     * be reset, it will be reset below. */
    last_oldstate = v->runstate.last_oldstate;
    v->runstate.last_oldstate.wrong = RUNSTATE_INIT;

    /* Close vmexits when the putative reason for blocking / &c stops.
     * This way, we don't account cpu contention to some other overhead. */
    if(sevt.new_runstate == RUNSTATE_RUNNABLE
       && v->data_type == VCPU_DATA_HVM
       && v->hvm.vmexit_valid) {
        hvm_close_vmexit(&v->hvm, ri->tsc);
    }

    /* Track waking state */
    if ( v->data_type == VCPU_DATA_HVM && v->runstate.state != RUNSTATE_LOST ) {
        if ( sevt.new_runstate == RUNSTATE_RUNNABLE
             && sevt.old_runstate == RUNSTATE_BLOCKED )
        {
            /* Hmm... want to make sure we're not in some weird
               vmexit state... have to look later. */
            if(opt.dump_all)
                printf(" [w2h] d%dv%d Setting waking\n", v->d->did, v->vid);
            v->hvm.w2h.waking = 1;
        }
        else if ( sevt.new_runstate != RUNSTATE_RUNNING
                  || sevt.old_runstate != RUNSTATE_RUNNABLE )
        {
            if( v->hvm.w2h.waking
                && sevt.old_runstate == RUNSTATE_RUNNING
                && sevt.new_runstate != RUNSTATE_OFFLINE )
            {
                /* NB: This is printed a lot unnecessairly when there is TSC skew */
                if ( sevt.old_runstate != v->runstate.state )
                    fprintf(warn, "Strange, unexpected waking transition for d%dv%d: %s -> %s\n",
                            v->d->did, v->vid,
                            runstate_name[sevt.old_runstate],
                            runstate_name[sevt.new_runstate]);
                v->hvm.w2h.waking = 0;
            }

            /* Close wake-to-halt summary */
            /* FIXME: Need to think about handling preemption. */
            if (sevt.new_runstate == RUNSTATE_BLOCKED
                && sevt.old_runstate == RUNSTATE_RUNNING
                && v->hvm.w2h.interrupts ) {
                int i;
                for(i=0; i<GUEST_INTERRUPT_MAX; i++) {
                    struct hvm_gi_struct *g=v->hvm.summary.guest_interrupt + i;
                    tsc_t start_tsc = g->start_tsc;
                    if(start_tsc) {
                        tsc_t t = (start_tsc == 1) ? 0 : ri->tsc - start_tsc;
                        if(opt.dump_all)
                            printf(" [w2h] Halting vec %d is_wake %d time %lld\n",
                                   i,
                                   g->is_wake,
                                   t);

                        if(opt.scatterplot_wake_to_halt
                           && t
                           && g->is_wake)
                            scatterplot_vs_time(ri->tsc, t);

                        if(opt.summary && t) {
                            if(g->is_wake) {
                                if(v->hvm.w2h.interrupts==1)
                                    update_cycles(&g->runtime[GUEST_INTERRUPT_CASE_WAKE_TO_HALT_ALONE],
                                                  t);
                                update_cycles(&g->runtime[GUEST_INTERRUPT_CASE_WAKE_TO_HALT_ANY],
                                              t);
                            } else {
                                update_cycles(&g->runtime[GUEST_INTERRUPT_CASE_INTERRUPT_TO_HALT],
                                              t);
                            }
                        }
                        g->start_tsc = 0;
                        g->is_wake = 0;
                    }
                }
                v->hvm.w2h.interrupts = 0;
                v->hvm.w2h.vector = 0;
            }
        }
    }

    /* Sanity checks / tsc skew detection */
    if( v->runstate.state != sevt.old_runstate
        && v->runstate.state != RUNSTATE_INIT )
    {
        if(v->runstate.state == RUNSTATE_LOST) {
            if( sevt.new_runstate == RUNSTATE_RUNNING )
                goto update;
            else if(opt.dump_all)
                fprintf(warn, "%s: d%dv%d in runstate lost, not updating to %s\n",
                        __func__, v->d->did, v->vid,
                        runstate_name[sevt.new_runstate]);
            goto no_update;
        } else if (last_oldstate.wrong == sevt.new_runstate
                   && last_oldstate.actual == sevt.old_runstate) {
            tsc_t lag, old_offset;
            struct pcpu_info *p2;

            if(ri->tsc < last_oldstate.tsc) {
                fprintf(warn, "WARNING: new tsc %lld < detected runstate tsc %lld! Not updating\n",
                        ri->tsc, last_oldstate.tsc);
                goto no_update;
            }

            p2 = P.pcpu + last_oldstate.pid;

            lag = ri->tsc
                - last_oldstate.tsc;

            old_offset = p2->tsc_skew.offset;

            cpumask_union(&p2->tsc_skew.downstream, &p->tsc_skew.downstream);
            cpumask_set(&p2->tsc_skew.downstream, p->pid);

            if(cpumask_isset(&p2->tsc_skew.downstream, p2->pid)) {
                if ( opt.tsc_loop_fatal )
                {
                    fprintf(stderr, "FATAL: tsc skew dependency loop detected!\n");
                    error(ERR_FILE, NULL);
                }
                else
                {
                    int i;
                    fprintf(warn, "Tsc skew dependency loop detected!  Resetting...\n");
                    for ( i=0; i<=P.max_active_pcpu; i++)
                    {
                        struct pcpu_info *p = P.pcpu + i;

                        p->tsc_skew.offset = 0;
                        cpumask_init(&p->tsc_skew.downstream);
                    }
                    goto no_update;
                }
            }

            p2->tsc_skew.offset += lag * 2;

            fprintf(warn, "TSC skew detected p%d->p%d, %lld cycles. Changing p%d offset from %lld to %lld\n",
                    p->pid, p2->pid, lag,
                    p2->pid,
                    old_offset,
                    p2->tsc_skew.offset);

            goto no_update;
        } else {
            fprintf(warn, "runstate_change old_runstate %s, d%dv%d runstate %s.  Possible tsc skew.\n",
                    runstate_name[sevt.old_runstate],
                    v->d->did, v->vid,
                    runstate_name[v->runstate.state]);

            v->runstate.last_oldstate.wrong = sevt.old_runstate;
            v->runstate.last_oldstate.actual = v->runstate.state;
            v->runstate.last_oldstate.tsc = ri->tsc;
            v->runstate.last_oldstate.pid = p->pid;

            if ( v->runstate.state == RUNSTATE_RUNNING )
            {
                fprintf(warn, " Not updating.\n");
                goto no_update;
            }
            goto update;
        }
        fprintf(stderr, "FATAL: Logic hole in %s\n", __func__);
        error(ERR_ASSERT, NULL);
    }

update:
    /* Actually update the runstate.  Special things to do if we're starting
     * or stopping actually running on a physical cpu. */
    if ( type == CONTINUE )
    {
        if( v->runstate.state == RUNSTATE_INIT ) {
            /* Start-of-day; account first tsc -> now to v */
            vcpu_start(p, v);
        } else {
            /* Continue running.  First, do some sanity checks */
            if ( v->runstate.state == RUNSTATE_LOST ) {
                fprintf(warn, "WARNING: continue with d%dv%d in RUNSTATE_LOST.  Resetting current.\n",
                        v->d->did, v->vid);
                if ( p->current )
                    vcpu_prev_update(p, p->current, ri->tsc, RUNSTATE_LOST);
                vcpu_next_update(p, v, ri->tsc);
            }
            else if( v->runstate.state != RUNSTATE_RUNNING ) {
                /* This should never happen. */
                fprintf(warn, "FATAL: sevt.old_runstate running, but d%dv%d runstate %s!\n",
                        v->d->did, v->vid, runstate_name[v->runstate.state]);
                error(ERR_FILE, NULL);
            } else if ( v->p != p ) {
                fprintf(warn, "FATAL: continue on p%d, but d%dv%d p%d!\n",
                        p->pid, v->d->did, v->vid,
                        v->p ? v->p->pid : -1);
                error(ERR_FILE, NULL);
            }

            runstate_update(v, RUNSTATE_RUNNING, ri->tsc);
        }
    }
    else if ( sevt.old_runstate == RUNSTATE_RUNNING
              || v->runstate.state == RUNSTATE_RUNNING )
    {
#if 0
        /* A lot of traces include cpi that shouldn't... */
        if(perfctrs && v->runstate.tsc) {
            unsigned long long run_cycles, run_instr;
            double cpi;

            //run_cycles = r->p1 - v->runstate_p1_start;
            run_cycles = ri->tsc - v->runstate.tsc;
            run_instr  = r->p2 - v->runstate.p2_start;

            cpi = ((double)run_cycles) / run_instr;

            if(opt.dump_all) {
                printf("   cpi: %2.2lf ( %lld / %lld )\n",
                       cpi, run_cycles, run_instr);
            }

            if(opt.scatterplot_cpi && v->d->did == 1)
                printf("%lld,%2.2lf\n",
                       ri->tsc, cpi);

            if(opt.summary_info)
                update_cpi(&v->cpi, run_instr, run_cycles);
        }
#endif
        /*
         * Cases:
         * old running, v running:
         *   normal (prev update p, lost record check)
         * v running, old ! running:
         *   tsc skew (prev update v->p, lost record check)
         * old running, v init:
         start-of-day (fake update, prev p, lost record)
         * old running, v !{running,init}:
         *   # (should never happen)
         */
        if( sevt.old_runstate == RUNSTATE_RUNNING ) {
            if( v->runstate.state == RUNSTATE_INIT ) {
                /* Start-of-day; account first tsc -> now to v */
                vcpu_start(p, v);
            } else if( v->runstate.state != RUNSTATE_RUNNING
                       && v->runstate.state != RUNSTATE_LOST ) {
                /* This should never happen. */
                fprintf(warn, "FATAL: sevt.old_runstate running, but d%dv%d runstate %s!\n",
                        v->d->did, v->vid, runstate_name[v->runstate.state]);
                error(ERR_FILE, NULL);
            }

            vcpu_prev_update(p, v, ri->tsc, sevt.new_runstate);
        } else {
            vcpu_prev_update(v->p, v, ri->tsc, sevt.new_runstate);
        }

        if(P.lost_cpus && v->d->did != IDLE_DOMAIN) {
            if(opt.dump_all)
                fprintf(warn, "%s: %d lost cpus, setting d%dv%d runstate to RUNSTATE_LOST\n",
                        __func__, P.lost_cpus, v->d->did, v->vid);
            lose_vcpu(v, ri->tsc);
        }
    }
    else if ( sevt.new_runstate == RUNSTATE_RUNNING )
    {
        if(perfctrs) {
            v->runstate.p1_start = r->p1;
            v->runstate.p2_start = r->p2;
        }

        vcpu_next_update(p, v, ri->tsc);
    }
    else if ( v->runstate.state != RUNSTATE_INIT )
    {
        /* TSC skew at start-of-day is hard to deal with.  Don't
         * bring a vcpu out of INIT until it's seen to be actually
         * running somewhere. */
        runstate_update(v, sevt.new_runstate, ri->tsc);
    }

no_update:
    return;
}

void sched_switch_process(struct pcpu_info *p)
{
    struct vcpu_data *prev, *next;
    struct record_info *ri = &p->ri;
    struct {
        unsigned int prev_dom, prev_vcpu, next_dom, next_vcpu;
    } * r = (typeof(r))ri->d;

    if(opt.dump_all)
        printf("%s sched_switch prev d%uv%u next d%uv%u\n",
               ri->dump_header,
               r->prev_dom, r->prev_vcpu,
               r->next_dom, r->next_vcpu);

    if(r->prev_vcpu > MAX_CPUS)
    {
        fprintf(warn, "%s: prev_vcpu %u > MAX_VCPUS %d!\n",
                __func__, r->prev_vcpu, MAX_CPUS);
        return;
    }

    if(r->next_vcpu > MAX_CPUS)
    {
        fprintf(warn, "%s: next_vcpu %u > MAX_VCPUS %d!\n",
                __func__, r->next_vcpu, MAX_CPUS);
        return;
    }

    prev = vcpu_find(r->prev_dom, r->prev_vcpu);
    next = vcpu_find(r->next_dom, r->next_vcpu);

    vcpu_prev_update(p, prev, ri->tsc, RUNSTATE_QUEUED); /* FIXME */

    vcpu_next_update(p, next, ri->tsc);
}

void sched_default_vcpu_activate(struct pcpu_info *p)
{
    struct vcpu_data *v = default_domain.vcpu[p->pid];

    if(!v)
        v = vcpu_create(&default_domain, p->pid);

    assert(v == v->d->vcpu[v->vid]);

    v->activated = 1;
    v->guest_paging_levels = opt.default_guest_paging_levels;
    v->p = p;
    v->runstate.state = RUNSTATE_RUNNING;

    p->current = v;
    pcpu_string_draw(p);
}

void sched_default_domain_init(void)
{
    struct domain_data *d = &default_domain;

    domain_init(d, DEFAULT_DOMAIN);
}

void runstate_clear(tsc_t * runstate_cycles)
{
    int i;
    for(i=0; i<RUNSTATE_MAX; i++)
        runstate_cycles[i]=0;
}

void runstate_summary(tsc_t * runstate_cycles)
{
    int i;
    for(i=0; i<RUNSTATE_MAX; i++)
        if(runstate_cycles[i]) {
            struct time_struct t;
            cycles_to_time(runstate_cycles[i], &t);
            printf("  %s: %u.%09u s\n",
                   runstate_name[i], t.s, t.ns);
        }
}

void sched_summary_vcpu(struct vcpu_data *v)
{
    int i;
    char desc[30];

    /* FIXME: Update all records like this */
    if ( v->pcpu_tsc )
    {
        update_cycles(&v->cpu_affinity_all, P.f.last_tsc - v->pcpu_tsc);
        update_cycles(&v->cpu_affinity_pcpu[v->p->pid], P.f.last_tsc - v->pcpu_tsc);
    }

    printf(" Runstates:\n");
    for(i=0; i<RUNSTATE_MAX; i++) {
        snprintf(desc,30, "  %8s", runstate_name[i]);
        print_cycle_summary(v->runstates+i, desc);
        if ( i==RUNSTATE_RUNNABLE )
        {
            int j;
            for(j=0; j<RUNNABLE_STATE_MAX; j++) {
                if ( j == RUNNABLE_STATE_INVALID )
                    continue;
                snprintf(desc,30, "    %8s", runnable_state_name[j]);
                print_cycle_summary(v->runnable_states+j, desc);
            }
        }
    }
    print_cpi_summary(&v->cpi);
    print_cpu_affinity(&v->cpu_affinity_all, " cpu affinity");
    for ( i = 0; i < MAX_CPUS ; i++)
    {
        snprintf(desc,30, "   [%d]", i);
        print_cpu_affinity(v->cpu_affinity_pcpu+i, desc);
    }
}

void sched_summary_domain(struct domain_data *d)
{
    int i;
    char desc[30];

    printf(" Runstates:\n");
    for(i=0; i<DOMAIN_RUNSTATE_MAX; i++) {
        snprintf(desc,30, "  %8s", domain_runstate_name[i]);
        print_cycle_summary(d->runstates+i, desc);
    }
}


void sched_process(struct pcpu_info *p)
{
    struct record_info *ri = &p->ri;

    if(ri->evt.sub == 0xf) {
        switch(ri->event)
        {
        case TRC_SCHED_SWITCH:
            sched_switch_process(p);
            break;
        default:
            process_generic(&p->ri);
        }
    } else {
        if(ri->evt.sub == 1)
            sched_runstate_process(p);
        else {
            UPDATE_VOLUME(p, sched_verbose, ri->size);
            process_generic(&p->ri);
        }
    }
}

/* ---- Memory ---- */
void mem_summary_domain(struct domain_data *d) {
    int i, j;

    printf(" Grant table ops:\n");

    printf("  Done by:\n");
    for(i=0; i<MEM_MAX; i++)
        if(d->memops.done[i])
            printf("   %-14s: %d\n",
                   mem_name[i],
                   d->memops.done[i]);

    printf("  Done for:\n");
    for(i=0; i<MEM_MAX; i++)
        if(d->memops.done_for[i])
            printf("   %-14s: %d\n",
                   mem_name[i],
                   d->memops.done_for[i]);

    printf(" Populate-on-demand:\n");
    printf("  Populated:\n");
    for(i=0; i<4; i++)
    {
        if ( d->pod.populate_order[i] )
            printf("   [%d] %d\n", i,
                   d->pod.populate_order[i]);
    }
    printf("  Reclaim order:\n");
    for(i=0; i<4; i++)
    {
        if ( d->pod.reclaim_order[i] )
            printf("   [%d] %d\n", i,
                   d->pod.reclaim_order[i]);
    }
    printf("  Reclaim contexts:\n");
    for(j=0; j<POD_RECLAIM_CONTEXT_MAX; j++)
    {
        if ( d->pod.reclaim_context[j] )
        {
            printf("   * [%s] %d\n",
                   pod_reclaim_context_name[j],
                   d->pod.reclaim_context[j]);
            for(i=0; i<4; i++)
            {
                if ( d->pod.reclaim_context_order[j][i] )
                    printf("    [%d] %d\n", i,
                           d->pod.reclaim_context_order[j][i]);
            }
        }
    }
}

int p2m_canonical_order(int order)
{
    if ( order % 9
         || (order / 9) > 2 )
    {
        fprintf(warn, "%s: Strange, non-canonical order %d\n",
                __func__, order);
        order = 4;
    } else {
        order /= 9;
    }
    return order;
}

void mem_pod_zero_reclaim_process(struct pcpu_info *p)
{
    struct record_info *ri = &p->ri;
    int context = POD_RECLAIM_CONTEXT_UNKNOWN;
    struct vcpu_data *v = p->current;

    struct {
        uint64_t gfn, mfn;
        int d:16,order:16;
    } *r = (typeof(r))ri->d;

    if ( v && v->hvm.vmexit_valid )
    {
        switch(v->hvm.exit_reason)
        {
        case EXIT_REASON_EPT_VIOLATION:
        case EXIT_REASON_EXCEPTION_NMI:
            context = POD_RECLAIM_CONTEXT_FAULT;
            break;
        case EXIT_REASON_VMCALL:
            context = POD_RECLAIM_CONTEXT_BALLOON;
            break;
        }
    }

    if ( opt.dump_all )
    {
        printf(" %s pod_zero_reclaim d%d o%d g %llx m %llx ctx %s\n",
               ri->dump_header,
               r->d, r->order,
               (unsigned long long)r->gfn, (unsigned long long)r->mfn,
               pod_reclaim_context_name[context]);

    }

    if ( opt.summary_info )
    {
        struct domain_data *d;

        if ( v && (d=v->d) )
        {
            int order;

            order = p2m_canonical_order(r->order);

            d->pod.reclaim_order[order]++;
            d->pod.reclaim_context[context]++;
            d->pod.reclaim_context_order[context][order]++;
        }
    }
}

void mem_pod_populate_process(struct pcpu_info *p)
{
    struct record_info *ri = &p->ri;

    struct {
        uint64_t gfn, mfn;
        int d:16,order:16;
    } *r = (typeof(r))ri->d;

    if ( opt.dump_all )
    {
        printf(" %s pod_populate d%d o%d g %llx m %llx\n",
               ri->dump_header,
               r->d, r->order,
               (unsigned long long)r->gfn, (unsigned long long)r->mfn);
    }

    if ( opt.summary_info )
    {
        struct vcpu_data *v = p->current;
        struct domain_data *d;

        if ( v && (d=v->d) )
        {
            int order;

            order = p2m_canonical_order(r->order);

            d->pod.populate_order[order]++;
        }
    }
}

void mem_pod_superpage_splinter_process(struct pcpu_info *p)
{
    struct record_info *ri = &p->ri;

    struct {
        uint64_t gfn;
        int d:16;
    } *r = (typeof(r))ri->d;

    if ( opt.dump_all )
    {
        printf(" %s pod_spage_splinter d%d g %llx\n",
               ri->dump_header,
               r->d, (unsigned long long)r->gfn);
    }
}

void mem_page_grant(struct pcpu_info *p)
{
    struct record_info *ri = &p->ri;

    struct {
        unsigned domain;
    } *r = (typeof(r))ri->d;
    union pv_event pevt = { .event = ri->event };

    if ( opt.dump_all )
    {
        printf(" %s %s domain %u\n", ri->dump_header, mem_name[pevt.minor], r->domain);
    }
}
void mem_set_p2m_entry_process(struct pcpu_info *p)
{
    struct record_info *ri = &p->ri;

    struct {
        uint64_t gfn, mfn;
        int p2mt;
        int d:16,order:16;
    } *r = (typeof(r))ri->d;

    if ( opt.dump_all )
    {
        printf(" %s set_p2m_entry d%d o%d t %d g %llx m %llx\n",
               ri->dump_header,
               r->d, r->order,
               r->p2mt,
               (unsigned long long)r->gfn, (unsigned long long)r->mfn);
    }
}

void mem_decrease_reservation_process(struct pcpu_info *p)
{
    struct record_info *ri = &p->ri;

    struct {
        uint64_t gfn;
        int d:16,order:16;
    } *r = (typeof(r))ri->d;

    if ( opt.dump_all )
    {
        printf(" %s decrease_reservation d%d o%d g %llx\n",
               ri->dump_header,
               r->d, r->order,
               (unsigned long long)r->gfn);
    }
}

void mem_process(struct pcpu_info *p) {
    struct record_info *ri = &p->ri;
    struct {
        int dom;
    } *r = (typeof(r))ri->d;

    int minor = ri->evt.minor;

    switch ( minor )
    {
    case MEM_PAGE_GRANT_MAP:
    case MEM_PAGE_GRANT_UNMAP:
    case MEM_PAGE_GRANT_TRANSFER:
        mem_page_grant(p);
        break;
    case MEM_SET_P2M_ENTRY:
        mem_set_p2m_entry_process(p);
        break;
    case MEM_DECREASE_RESERVATION:
        mem_decrease_reservation_process(p);
        break;
    case MEM_POD_POPULATE:
        mem_pod_populate_process(p);
        break;
    case MEM_POD_ZERO_RECLAIM:
        mem_pod_zero_reclaim_process(p);
        break;
    case MEM_POD_SUPERPAGE_SPLINTER:
        mem_pod_superpage_splinter_process(p);
        break;
    default:
        if(opt.dump_all) {
            dump_generic(stdout, ri);
        }

        if(opt.summary_info && minor < MEM_MAX) {
            struct domain_data *d;

            if(p->current) {
                if (p->current->d) {
                    p->current->d->memops.done[minor]++;
                    p->current->d->memops.done_interval[minor]++;
                }
                if((d=domain_find(r->dom))) {
                    d->memops.done_for[minor]++;
                    d->memops.done_for_interval[minor]++;
                }
            }
        }
        break;
    }

}

/* ---- PM ---- */
#define CSTATE_MAX 5
#define CSTATE_INVALID ((CSTATE_MAX)+1)
void pm_process(struct pcpu_info *p) {
    struct record_info *ri = &p->ri;

    switch ( ri->event )
    {
    case TRC_PM_FREQ_CHANGE:
        if (opt.dump_all )
            printf(" %s pm_freq_change o%d n%d\n",
                   ri->dump_header,
                   ri->d[0],
                   ri->d[1]);
        break;
    case TRC_PM_IDLE_ENTRY:
        if (opt.dump_all )
            printf(" %s pm_idle_start c%d\n",
                   ri->dump_header,
                   ri->d[0]);
        if ( ri->d[0] <= CSTATE_MAX )
        {
            p->power_state=ri->d[0];
            pcpu_string_draw(p);
        }
        break;
    case TRC_PM_IDLE_EXIT:
        if (opt.dump_all )
            printf(" %s pm_idle_end c%d\n",
                   ri->dump_header,
                   ri->d[0]);
        if ( p->power_state != ri->d[0]
             && p->power_state != CSTATE_INVALID )
            printf("Strange, pm_idle_end %d, power_state %d!\n",
                   ri->d[0], p->power_state);
        p->power_state = 0;
        pcpu_string_draw(p);
        break;
    default:
        if(opt.dump_all) {
            dump_generic(stdout, ri);
        }
        break;
    }

}

/*
 * IRQ related stuff
 */

#define MAX_VECTOR 256
int global_vector_used[256] = {0};
struct pci_dev {
    uint8_t bus;
    uint8_t devfn;
    int vector_used[MAX_VECTOR];
    struct pci_dev *next;
} *pdev_list;

#define MAX_IRQ 512
struct irq_desc {
    enum {
        IRQ_NONE,
        IRQ_MSI,
        IRQ_GSI
    } type;
    struct pci_dev *dev;
} irq_table[MAX_IRQ];

struct pci_dev * pdev_find(uint8_t bus, uint8_t devfn)
{
    struct pci_dev *d, *n, **q;

    /* Look for domain, keeping track of the last pointer so we can add
       a domain if we need to. */
    for ( d = pdev_list, q=&pdev_list ;
          d &&  ( (d->bus < bus)
                  || (d->bus == bus && d->devfn < devfn) ) ;
          q = &d->next, d=d->next ) ;

    if(d && d->bus == bus && d->devfn == devfn)
        return d;

    /* Make a new domain */
    fprintf(warn, "Creating pdev %02x:%02x.%x\n", bus, devfn>>4, devfn&3);

    if((n=malloc(sizeof(*n)))==NULL)
    {
        fprintf(stderr, "%s: malloc %zd failed!\n", __func__, sizeof(*n));
        error(ERR_SYSTEM, NULL);
    }

    bzero(n, sizeof(*n));

    n->bus=bus;
    n->devfn=devfn;

    /* Insert it into the list */
    n->next = d;
    *q = n;

    return n;
}

void irq_process(struct pcpu_info *p) {
    struct record_info *ri = &p->ri;

    switch ( ri->event )
    {
    case TRC_HW_IRQ_BIND_VECTOR:
    {
        struct {
            int irq, vec;
            unsigned mask[4];
        } *r = (typeof(r))ri->d;
        if ( opt.dump_all )
        {
            printf(" %s irq_bind_vector irq %x vec %x mask %04x %04x %04x %04x\n",
                   ri->dump_header,
                   r->irq, r->vec,
                   r->mask[3],
                   r->mask[2],
                   r->mask[1],
                   r->mask[0]);
        }
        break;
    }
    case TRC_HW_IRQ_HANDLED:
    {
        struct {
            int irq, start_tsc, end_tsc;
        } *r = (typeof(r))ri->d;
        int arctime;

        arctime = r->end_tsc - r->start_tsc;
        if ( opt.dump_all )
        {
            printf(" %s irq_handled irq %x %d (%d,%d)\n",
                   ri->dump_header,
                   r->irq, arctime, r->start_tsc, r->end_tsc);
        }
        if ( opt.scatterplot_irq )
        {
            struct time_struct t;

            abs_cycles_to_time(ri->tsc, &t);

            printf("i%x %u.%09u %d\n",
                   (unsigned)r->irq,
                   t.s, t.ns,
                   p->pid);
        }
        break;
    }
    case TRC_HW_IRQ_ASSIGN_VECTOR:
    {
        struct {
            int irq, vec;
            unsigned mask[4];
        } *r = (typeof(r))ri->d;
        if ( opt.dump_all )
        {
            printf(" %s irq_assign_vector irq %x vec %x mask %04x %04x %04x %04x\n",
                   ri->dump_header,
                   r->irq, r->vec,
                   r->mask[3],
                   r->mask[2],
                   r->mask[1],
                   r->mask[0]);
        }
        if ( r->irq < MAX_IRQ
             && r->vec < MAX_VECTOR )
        {
            if ( irq_table[r->irq].type == IRQ_MSI )
            {
                if(global_vector_used[r->vec])
                    fprintf(warn, "  Vector collision on global table!\n");
                global_vector_used[r->vec]=1;
            }
            if( irq_table[r->irq].dev )
            {
                struct pci_dev * pdev=irq_table[r->irq].dev;

                if(pdev->vector_used[r->vec])
                    fprintf(warn, "  Vector collision on %02x.%02x!\n",
                            pdev->bus, pdev->devfn);
                pdev->vector_used[r->vec]=1;
            }
        }
        break;
    }
    case TRC_HW_IRQ_MOVE_CLEANUP_DELAY:
    {
        struct {
            int irq, vec, cpu;
        } *r = (typeof(r))ri->d;

        if ( opt.dump_all )
        {
            printf(" %s irq_move_cleanup_delay irq %x vec %x cpu %d\n",
                   ri->dump_header,
                   r->irq, r->vec, r->cpu);
        }
        break;
    }
    case TRC_HW_IRQ_MOVE_CLEANUP:
    {
        struct {
            int irq;
            int vec;
            int cpu;
        } *r = (typeof(r))ri->d;

        if ( opt.dump_all )
        {
            printf(" %s irq_move_cleanup irq %x vec %x cpu %d\n",
                   ri->dump_header,
                   r->irq, r->vec, r->cpu);
        }
        if ( r->irq < MAX_IRQ
             && r->vec < MAX_VECTOR )
        {
            if ( irq_table[r->irq].type == IRQ_MSI )
            {
                if(!global_vector_used[r->vec])
                    fprintf(warn,"  Strange, cleanup on non-used vector\n");
                global_vector_used[r->vec]=0;
            }
            if ( irq_table[r->irq].dev )
            {
                struct pci_dev * pdev=irq_table[r->irq].dev;

                if(!pdev->vector_used[r->vec])
                    fprintf(warn,"  Strange, cleanup on non-used vector\n");
                pdev->vector_used[r->vec]=0;
            }
        }
        break;
    }
    case TRC_HW_IRQ_UNMAPPED_VECTOR:
    {
        struct {
            int vec;
        } *r = (typeof(r))ri->d;

        if ( opt.dump_all )
        {
            printf(" %s irq_unmapped_vector vec %x\n",
                   ri->dump_header,
                   r->vec);
        }
        break;
    }
    case TRC_HW_IRQ_CLEAR_VECTOR:
    case TRC_HW_IRQ_MOVE_FINISH :
    default:
        if(opt.dump_all) {
            dump_generic(stdout, ri);
        }
        break;
    }
}

#define TRC_HW_SUB_PM 1
#define TRC_HW_SUB_IRQ 2
void hw_process(struct pcpu_info *p)
{
    struct record_info *ri = &p->ri;

    switch(ri->evt.sub)
    {
    case TRC_HW_SUB_PM:
        pm_process(p);
        break;
    case TRC_HW_SUB_IRQ:
        irq_process(p);
        break;
    }

}
/* ---- Base ----- */
void dump_generic(FILE * f, struct record_info *ri)
{
    int i;

    fprintf(f, "]%s %7x(%x:%x:%x) %u [",
           ri->dump_header,
           ri->event,
           ri->evt.main,
           ri->evt.sub,
           ri->evt.minor,
           ri->extra_words);

    for(i=0; i<ri->extra_words; i++) {
        fprintf(f, " %x", ri->d[i]);
    }

    fprintf(f, " ]\n");
}

void dump_raw(char * s, struct record_info *ri)
{
    int i;

    if(ri->rec.cycle_flag)
        printf("%s %7x %d %14lld [",
               s, ri->event, ri->extra_words, ri->tsc);
    else
        printf("%s %7x %d %14s [",
               s, ri->event, ri->extra_words, "-");

    for(i=0; i<7; i++) {
        if ( i < ri->extra_words )
            printf(" %8x", ri->d[i]);
        else
            printf("         ");
    }

    printf(" ] | ");

    for (i=0; i<8; i++) {
        printf(" %08x", ri->rec.raw[i]);
    }

    printf(" |\n");
}

void error(enum error_level l, struct record_info *ri)
{
    if ( l > opt.tolerance )
    {
        if ( ri )
            dump_generic(warn, ri);
        exit(1);
    }
}

int check_extra_words(struct record_info *ri,
                       int expected_size,
                       const char *record)
{
    static int off_by_one = 0;
    int expected_extra = expected_size / sizeof(unsigned int);

    if(ri->extra_words != expected_extra
       && !(off_by_one && ri->extra_words == expected_extra + 1) )
    {
        if ( !off_by_one && ri->extra_words == expected_extra + 1 )
        {
            fprintf(warn, "Detected off-by-one bug; relaxing expectations\n");
            off_by_one=1;
        }
        else {
            fprintf(warn, "ERROR: %s extra_words %d, expected %d!\n",
                    record,
                    ri->extra_words, expected_extra);
            error(ERR_RECORD, ri);
            return 1;
        }
    }
    return 0;
}

void process_generic(struct record_info *ri) {

    error(ERR_STRICT, ri);

    if(opt.dump_all) {
        dump_generic(stdout, ri);
    }
}

int vcpu_set_data_type(struct vcpu_data *v, int type)
{
    if (v->data_type == VCPU_DATA_NONE )
    {
        v->data_type = type;
        switch(type)
        {
        case VCPU_DATA_HVM:
            init_hvm_data(&v->hvm, v);
            break;
        default:
            break;
        }
    }
    else
        assert(v->data_type == type);
    return 0;
}


void lose_vcpu(struct vcpu_data *v, tsc_t tsc)
{
    if(v->data_type == VCPU_DATA_HVM)
        v->hvm.vmexit_valid=0;
    runstate_update(v, RUNSTATE_LOST, tsc);
    hvm_vlapic_clear(&v->vlapic);

    if(v->data_type == VCPU_DATA_HVM) {
        int i;
        if(opt.dump_all)
            printf(" [w2h] Clearing w2h state for d%dv%d\n",
                   v->d->did, v->vid);
        v->hvm.w2h.interrupts=0;
        v->hvm.w2h.vector=0;
        v->hvm.w2h.waking = 0;
        for(i=0; i<GUEST_INTERRUPT_MAX; i++)  {
            if(opt.dump_all && v->hvm.summary.guest_interrupt[i].start_tsc) {
                printf("  Interrupt %d clearing start_tsc %lld\n",
                       i, v->hvm.summary.guest_interrupt[i].start_tsc);
            }
            v->hvm.summary.guest_interrupt[i].start_tsc = 0;
        }
    }
}

struct lost_record_struct {
        int lost_records;
        unsigned did:16,vid:16;
        tsc_t first_tsc;
};

void process_lost_records(struct pcpu_info *p)
{
    struct record_info *ri = &p->ri;
    struct lost_record_struct *r = (typeof(r))ri->d;
    tsc_t first_tsc; /* TSC of first record that was lost */

    /* Sanity checks */
    if(ri->extra_words != 4)
    {
         fprintf(warn, "FATAL: Lost record has unexpected extra words %d!\n",
                 ri->extra_words);
         error(ERR_RECORD, ri);
         return;
    }

    first_tsc = r->first_tsc;

    if(opt.dump_all)
    {
        if(p->current)
            printf(" %s lost_records count %d d%uv%u (cur d%dv%d) first_tsc %lld\n",
                   ri->dump_header, r->lost_records,
                   r->did, r->vid,
                   p->current->d->did, p->current->vid,
                   r->first_tsc);
        else
            printf(" %s lost_records count %d d%uv%u (cur X) first_tsc %lld\n",
                   ri->dump_header, r->lost_records,
                   r->did, r->vid,
                   r->first_tsc);
    }

#if 0
    if(opt.dump_trace_volume_on_lost_record)
        volume_summary(&p->volume.last_buffer);
#endif

    if ( p->current ) {

        hvm_vlapic_clear(&p->current->vlapic);
        if(p->current->data_type == VCPU_DATA_HVM) {
            p->current->hvm.vmexit_valid=0;
            cr3_switch(0, &p->current->hvm);
        }

        /* We may lose scheduling records; so we need to:
         * - Point all records until now to the next schedule in the
         * "default" domain
         * - Make sure there are no warnings / strangeness with the
         * current vcpu (if it gets scheduled elsewhere).
         */
        vcpu_prev_update(p, p->current, first_tsc, RUNSTATE_LOST);
    }
#if 0
    vcpu_next_update(p, default_domain.vcpu[p->pid], first_tsc);
    if(p->current->data_type == VCPU_DATA_HVM) {
        p->current->hvm.vmexit_valid=0;
    }
#endif

    /* The lost record trace is processed early -- i.e.,
     * After the last good record, rather than when the next
     * record is processed.  Between the time it's processed and
     * the time it actually went in, the vcpu may be scheduled on
     * other processors.  So we can't switch vcpus until the first
     * TSC'd record after the lost record. */
    if(!p->lost_record.active) {
        P.lost_cpus++;
        if(P.lost_cpus > P.max_active_pcpu + 1) {
            fprintf(warn, "ERROR: P.lost_cpus %d > P.max_active_pcpu + 1 %d!\n",
                    P.lost_cpus, P.max_active_pcpu + 1);
            error(ERR_ASSERT, NULL);
        }
    } else
        fprintf(warn, "Strange, lost record for pcpu %d, but lost_record still active!\n",
                p->pid);

    p->lost_record.active = 1;
    p->lost_record.tsc = first_tsc;
    pcpu_string_draw(p);

    {
        /* Any vcpu which is not actively running may be scheduled on the
         * lost cpu.  To avoid mis-accounting, we need to reset */
        struct domain_data *d;
        int i;
        for(d=domain_list ; d; d=d->next)
        {
            if(d->did != DEFAULT_DOMAIN) {
                for(i=0; i<MAX_CPUS; i++)
                    if(d->vcpu[i] &&
                       d->vcpu[i]->runstate.state != RUNSTATE_RUNNING) {
                        if(opt.dump_all)
                            fprintf(warn, "%s: setting d%dv%d to RUNSTATE_LOST\n",
                                    __func__, d->did, i);
                        lose_vcpu(d->vcpu[i], first_tsc);
                    }
            }
        }
    }

    p->lost_record.domain_valid=1;
    p->lost_record.did=r->did;
    p->lost_record.vid=r->vid;
}


void process_lost_records_end(struct pcpu_info *p)
{
    struct record_info *ri = &p->ri;
    struct lost_record_struct *r = (typeof(r))ri->d;

    if(!p->lost_record.active) {
        fprintf(warn, "FATAL: lost_records_end but pid %d not lost!\n",
                p->pid);
        error(ERR_FILE, NULL);
        return;
    }

    /* Lost records.  If this is the first record on a pcpu after the loss,
     * Update the information. */
    if(ri->tsc > p->lost_record.tsc)
    {
        if(opt.dump_all)
            printf("               %s lost_records end ---\n",
                   pcpu_string(p->pid));

        update_cycles(&p->time.lost, ri->tsc - p->lost_record.tsc);

        if(p->lost_record.domain_valid) {
            int did = p->lost_record.did,
                vid = p->lost_record.vid;

            if(opt.dump_all)
                printf("               %s lost_records end d%dv%d---\n",
                       pcpu_string(p->pid),
                       did, vid);
            if(p->current)
            {
                fprintf(warn, "FATAL: lost_record valid (d%dv%d), but current d%dv%d!\n",
                        did, vid,
                        p->current->d->did, p->current->vid);
                error(ERR_FILE, NULL);
                return;
            }

            if(opt.dump_all)
                fprintf(warn, "Changing p%d current to d%dv%d\n",
                        p->pid, did, vid);
            vcpu_next_update(p,
                             vcpu_find(did, vid),
                             ri->tsc);
            p->lost_record.domain_valid=0;
            p->lost_record.seen_valid_schedule=0; /* Let next vcpu_next_update know that
                                                     this one was inferred */
        } else {
            if(opt.dump_all)
                printf("               %s lost_records end (domain invalid)---\n",
                       pcpu_string(p->pid));
        }


        p->lost_record.active = 0;
        pcpu_string_draw(p);
        P.lost_cpus--;
        if(P.lost_cpus < 0) {
            fprintf(warn, "ERROR: lost_cpus fell below 0 for pcpu %d!\n",
                    p->pid);
            error(ERR_ASSERT, NULL);
        }
    }
}

void base_process(struct pcpu_info *p) {
    struct record_info *ri = &p->ri;
    switch(ri->event)
    {
    case TRC_TRACE_WRAP_BUFFER:
        break;
    case TRC_LOST_RECORDS:
        process_lost_records(p);
        break;
    case TRC_LOST_RECORDS_END:
        process_lost_records_end(p);
        break;
    default:
        process_generic(ri);
    }
 }



/* Non-compat only */
void record_order_insert(struct pcpu_info *new);
void record_order_remove(struct pcpu_info *rem);
void record_order_bubble(struct pcpu_info *last);

struct cpu_change_data {
    int cpu;
    unsigned window_size;
};

void activate_early_eof(void) {
    struct pcpu_info *p;
    int i;

    fprintf(warn, "Short cpu_change window, activating early_eof\n");

    P.early_eof = 1;

    for(i=0; i<=P.max_active_pcpu; i++) {
        p = P.pcpu + i;
        if(p->active && p->file_offset > P.last_epoch_offset) {
            fprintf(warn, " deactivating pid %d\n",
                    p->pid);
            p->active = 0;
        }
    }
}

off_t scan_for_new_pcpu(off_t offset) {
    ssize_t r;
    struct trace_record rec;
    struct cpu_change_data *cd;

    r=__read_record(&rec, offset);

    if(r==0)
        return 0;

    if(rec.event != TRC_TRACE_CPU_CHANGE
       || rec.cycle_flag)
    {
        fprintf(stderr, "%s: Unexpected record event %x!\n",
                __func__, rec.event);
        error(ERR_ASSERT, NULL); /* Actually file, but can't recover */
    }

    cd = (typeof(cd))rec.u.notsc.data;

    if ( cd->cpu > MAX_CPUS )
    {
        fprintf(stderr, "%s: cpu %d exceeds MAX_CPU %d!\n",
                __func__, cd->cpu, MAX_CPUS);
        /* FIXME: Figure out if we could handle this more gracefully */
        error(ERR_ASSERT, NULL);
    }

    if(cd->cpu > P.max_active_pcpu || !P.pcpu[cd->cpu].active) {
        struct pcpu_info *p = P.pcpu + cd->cpu;

        fprintf(warn, "%s: Activating pcpu %d at offset %lld\n",
                __func__, cd->cpu, (unsigned long long)offset);

        p->active = 1;
        /* Process this cpu_change record first */
        p->ri.rec = rec;
        p->ri.size = r;
        __fill_in_record_info(p);

        p->file_offset = offset;
        p->next_cpu_change_offset = offset;

        record_order_insert(p);

        offset += r + cd->window_size;

        sched_default_vcpu_activate(p);

        if ( cd->cpu > P.max_active_pcpu )
            P.max_active_pcpu = cd->cpu;

        return offset;
    } else {
        return 0;
    }
}

/*
 * Conceptually, when we reach a cpu_change record that's not for our pcpu,
 * we want to scan forward through the file until we reach one that's for us.
 * However, looping through involves reading the file, which we'd rather
 * do in one place.  Because cpu_change records don't include a tsc,
 * the same pcpu will be processed repeatedly until the cpu_change
 * equals p->pid.
 *
 * There are two additional things we need to do in this algorithm:
 * + Detect new pcpus as they come online
 * + De-activate pcpus which don't have any more records
 *
 * Detecting new pcpus which are less than P.max_active_pcpu is straight-
 * forward: when max_active_pcpu is searching for its next cpu window,
 * it will pass by the new cpu's window, and can activate it then.
 *
 * Detecting new pcpus greater than P.max_active_pcpu is a little harder;
 * When max_active_pcpu is scanning for its next cpu window, after it's found
 * it, we need to scan one more window forward to see if its' an already-active
 * pcpu; if not, activate it.
 *
 * We also need to deal with truncated files, where records from one pcpu may
 * be present but not from another pcpu due to lack of disk space.  The best
 * thing to do is to find the last "epoch" and essentially truncate the file
 * to that.
 */
void deactivate_pcpu(struct pcpu_info *p)
{
    if ( p->current )
    {
        pcpu_runstate_update(p, p->last_tsc);

        fprintf(warn, "%s: setting d%dv%d to state LOST\n",
                __func__, p->current->d->did,
                p->current->vid);
        lose_vcpu(p->current, p->last_tsc);
    }
    p->active = 0;

    record_order_remove(p);

    if ( p->pid == P.max_active_pcpu )
    {
        int i, max_active_pcpu = -1;
        for(i=0; i<=P.max_active_pcpu; i++)
        {
            if(!P.pcpu[i].active)
                continue;

            max_active_pcpu = i;
        }
        P.max_active_pcpu = max_active_pcpu;
        fprintf(warn, "%s: Setting max_active_pcpu to %d\n",
                __func__, max_active_pcpu);
    }

}

/* Helper function to process tsc-related record info */
void process_record_tsc(tsc_t order_tsc, struct record_info *ri)
{
    /* Find the first tsc set */
    if(ri->tsc && ri->tsc >= P.f.first_tsc) {
        /* We use the order_tsc to account for the second processing of
         * a lost record.  */
        tsc_t tsc = order_tsc;

        if(P.f.first_tsc == 0) {
            P.f.first_tsc = tsc;
            if ( opt.interval_mode ) {
                P.interval.start_tsc = tsc;
            }
        } else {
            if ( opt.interval_mode ) {
                if(P.interval.start_tsc > tsc) {
                    fprintf(warn, "FATAL: order_tsc %lld < interval.start_tsc %lld!\n",
                            tsc, P.interval.start_tsc);
                    error(ERR_FILE, NULL);
                } else {
                    while ( tsc - P.interval.start_tsc > opt.interval.cycles ) {
                        interval_callback();
                        P.interval.start_tsc += opt.interval.cycles;
                    }
                }
            }
        }

        P.f.last_tsc=tsc;

        P.f.total_cycles = P.f.last_tsc - P.f.first_tsc;

        P.now = tsc;
    }
}

/* Standardized part of dump output */
void create_dump_header(struct record_info *ri, struct pcpu_info *p)
{
    char * c;
    int len, r;

    len = DUMP_HEADER_MAX;
    c = ri->dump_header;

    abs_cycles_to_time(ri->tsc, &ri->t);

    if ( ri->t.time )
    {
        r=snprintf(c, len, "%3u.%09u", ri->t.s, ri->t.ns);
        c+=r;
        len-=r;
    }
    else
    {
        r=snprintf(c,
                   len,
                   "              ");
        c+=r;
        len-=r;
    }

    r = snprintf(c, len, " %s", pcpu_string(ri->cpu));
    c+=r;
    len-=r;

    if ( p->current )
    {
        r = snprintf(c, len, " d%dv%d", p->current->d->did, p->current->vid);
        c+=r;
        len-=r;
    }
    else
    {
        r = snprintf(c, len, " d?v?");
        c+=r;
        len-=r;
    }
}

int find_toplevel_event(struct record_info *ri)
{
    int toplevel=0, i, count;

    for(i=0, count=0; i<TOPLEVEL_MAX; i++)
        if(ri->evt.main & (1UL<<i))
        {
            toplevel=i;
            count++;
        }

    /* Sanity check: One and only one bit should be set */
    if(count != 1)
    {
        fprintf(warn, "FATAL: unexpected number bits(%d) in evt.main! event %x main %x sub %x minor %x\n",
                count,
                ri->event,
                ri->evt.main, ri->evt.sub, ri->evt.minor);
        error(ERR_RECORD, NULL);
        return -1;
    }

    return toplevel;
}


void process_cpu_change(struct pcpu_info *p) {
    struct record_info *ri = &p->ri;
    struct cpu_change_data *r = (typeof(r))ri->d;

    if(opt.dump_all && verbosity >= 6) {
        printf("]%s cpu_change this-cpu %u record-cpu %u window_size %u(0x%08x)\n",
               ri->dump_header, p->pid, r->cpu, r->window_size,
               r->window_size);
    }

    /* File sanity check */
    if(p->file_offset != p->next_cpu_change_offset) {
        fprintf(warn, "Strange, pcpu %d expected offet %llx, actual %llx!\n",
                p->pid, (unsigned long long)p->next_cpu_change_offset,
                (unsigned long long)p->file_offset);
    }

    if(r->cpu > MAX_CPUS)
    {
        fprintf(stderr, "FATAL: cpu %d > MAX_CPUS %d.\n",
                r->cpu, MAX_CPUS);
        /* Actually file, but takes some work to skip */
        error(ERR_ASSERT, NULL);
    }

    /* Detect beginning of new "epoch" while scanning thru file */
    if((p->last_cpu_change_pid > r->cpu)
       && (p->file_offset > P.last_epoch_offset)) {
        P.last_epoch_offset = p->file_offset;
    }

    /* If that pcpu has never been activated, activate it. */
    if(!P.pcpu[r->cpu].active && P.pcpu[r->cpu].file_offset == 0)
    {
        struct pcpu_info * p2 = P.pcpu + r->cpu;

        p2->active = 1;
        if(r->cpu > P.max_active_pcpu)
            P.max_active_pcpu = r->cpu;

        /* Taking this record as the first record should make everything
         * run swimmingly. */
        p2->ri = *ri;
        p2->ri.cpu = r->cpu;
        p2->ri.d = p2->ri.rec.u.notsc.data;
        p2->file_offset = p->file_offset;
        p2->next_cpu_change_offset = p->file_offset;

        fprintf(warn, "%s: Activating pcpu %d at offset %lld\n",
                __func__, r->cpu, (unsigned long long)p->file_offset);

        record_order_insert(p2);

        sched_default_vcpu_activate(p2);
    }

    p->last_cpu_change_pid = r->cpu;

    /* If this isn't the cpu we're looking for, skip the whole bunch */
    if(p->pid != r->cpu)
    {
        p->file_offset += ri->size + r->window_size;
        p->next_cpu_change_offset = p->file_offset;

        if(p->file_offset > G.file_size) {
            activate_early_eof();
        } else if(P.early_eof && p->file_offset > P.last_epoch_offset) {
            fprintf(warn, "%s: early_eof activated, pcpu %d past last_epoch_offset %llx, deactivating.\n",
                    __func__, p->pid, (unsigned long long)P.last_epoch_offset);
            deactivate_pcpu(p);
        }
    }
    else
    {
        /* Track information about dom0 scheduling and records */
        if(opt.dump_trace_volume_on_lost_record) {
            tsc_t cycles;
            struct time_struct t;

            /* Update dom0 runstates */
            cycles = (p->volume.buffer_first_tsc > p->volume.buffer_dom0_runstate_tsc) ?
                p->volume.buffer_first_tsc :
                p->volume.buffer_dom0_runstate_tsc;
            p->volume.buffer_dom0_runstate_cycles[p->volume.buffer_dom0_runstate]
                += ri->tsc - cycles;

            printf(" - updated p%d dom0_runstate %s to %lld cycles (+%lld)\n",
                   p->pid, runstate_name[p->volume.buffer_dom0_runstate],
                   p->volume.buffer_dom0_runstate_cycles[p->volume.buffer_dom0_runstate],
                   ri->tsc - cycles);

            /* print info */
            cycles = ri->tsc - p->volume.buffer_first_tsc;
            cycles_to_time(cycles, &t);
            printf("Buffer time: %u.%09u (%lld cycles)\n",
                   t.s, t.ns, cycles);
            if(p->volume.buffer_size)
                printf("Rate: %lld cycles / byte\n",
                       cycles / p->volume.buffer_size);
            if(P.buffer_trace_virq_tsc)
            {
                cycles = ri->tsc - P.buffer_trace_virq_tsc;
                cycles_to_time(cycles, &t);
                printf("trace_virq latency: %u.%09u (%lld cycles)\n",
                       t.s, t.ns, cycles);
                P.buffer_trace_virq_tsc = 0;
            }
            else
            {
                printf("No trace_virq record found.\n");
            }
            printf("Dom0 runstates this buffer:\n");
            runstate_summary(p->volume.buffer_dom0_runstate_cycles);
            volume_summary(&p->volume.last_buffer);

            /* reset info */
            p->volume.buffer_first_tsc = 0;
            p->volume.buffer_size = r->window_size;
            runstate_clear(p->volume.buffer_dom0_runstate_cycles);
            volume_clear(&p->volume.last_buffer);
        }

        p->file_offset += ri->size;
        p->next_cpu_change_offset = p->file_offset + r->window_size;

        if(p->next_cpu_change_offset > G.file_size)
            activate_early_eof();
        else if(p->pid == P.max_active_pcpu)
            scan_for_new_pcpu(p->next_cpu_change_offset);

    }
}

struct tl_assert_mask {
    unsigned p_current:1,
        not_idle_domain:1;
    int vcpu_data_mode;
};
static struct tl_assert_mask tl_assert_checks[TOPLEVEL_MAX] = {
    [TRC_HVM_MAIN]={ .p_current=1, .not_idle_domain=1, .vcpu_data_mode=VCPU_DATA_HVM },
    [TRC_SHADOW_MAIN]={ .p_current=1, .not_idle_domain=1, .vcpu_data_mode=VCPU_DATA_HVM },
    [TRC_PV_MAIN]={ .p_current=1, .not_idle_domain=1, .vcpu_data_mode=VCPU_DATA_PV },
};

/* There are a lot of common assumptions for the various processing
 * routines.  Check them all in one place, doing something else if
 * they don't pass. */
int toplevel_assert_check(int toplevel, struct pcpu_info *p)
{
    struct tl_assert_mask mask;

    mask = tl_assert_checks[toplevel];

    if (mask.p_current && p->current == NULL)
    {
        fprintf(warn, "WARNING: p->current null!  Not processing\n");
        goto fail;
    }

    if( mask.not_idle_domain )
    {
        /* Can't do this check w/o first doing above check */
        assert(mask.p_current);

        if ( p->current->d->did == IDLE_DOMAIN) {
            fprintf(warn, "WARNING: Unexpected record for idle domain! Not processing\n");
            goto fail;
        }
    }

    if ( mask.vcpu_data_mode )
    {
        struct vcpu_data *v;
        assert(mask.p_current);

        v = p->current;

        if ( ! (v->data_type == VCPU_DATA_NONE
                || v->data_type == mask.vcpu_data_mode) )
        {
            /* This may happen for track_dirty_vram, which causes a SHADOW_WRMAP_BF trace f/ dom0 */
            fprintf(warn, "WARNING: Unexpected vcpu data type for d%dv%d on proc %d! Expected %d got %d. Not processing\n",
                    v->d->did, v->vid, p->pid,
                    mask.vcpu_data_mode,
                    v->data_type);
            goto fail;
        }
    }

    return 1;

fail:
    dump_generic(warn, &p->ri);
    return 0;
}

void process_record(struct pcpu_info *p) {
    struct record_info *ri = &p->ri;
    int toplevel;

    /* Process only TRC_TRACE_CPU_CHANGE */
    if(ri->event == TRC_TRACE_CPU_CHANGE) {
        process_cpu_change(p);
        return;
    }

    if ( opt.dump_no_processing )
        goto out;

    p->summary = 1;

    if( opt.dump_raw_process )
        dump_raw("* ", ri);

    process_record_tsc(p->order_tsc, ri);

    if(opt.dump_all)
        create_dump_header(ri, p);


    toplevel = find_toplevel_event(ri);
    if ( toplevel < 0 )
        return;

    /* Unify toplevel assertions */
    if ( toplevel_assert_check(toplevel, p) )
    {
        switch(toplevel) {
        case TRC_GEN_MAIN:
            base_process(p);
            break;
        case TRC_SCHED_MAIN:
            sched_process(p);
            break;
        case TRC_HVM_MAIN:
            hvm_process(p);
            break;
        case TRC_SHADOW_MAIN:
            shadow_process(p);
            break;
        case TRC_PV_MAIN:
            pv_process(p);
            break;
        case TRC_MEM_MAIN:
            mem_process(p);
            break;
        case TRC_HW_MAIN:
            hw_process(p);
            break;
        case TRC_DOM0OP_MAIN:
        default:
            process_generic(ri);
        }
    }

    UPDATE_VOLUME(p, toplevel[toplevel], ri->size);

    if(!p->volume.buffer_first_tsc)
        p->volume.buffer_first_tsc = ri->tsc;

 out:
    /* Lost records gets processed twice */
    if(ri->event != TRC_LOST_RECORDS)
        p->file_offset += ri->size;
}

static inline ssize_t get_rec_size(struct trace_record *rec) {
    ssize_t s;

    s = sizeof(uint32_t);

    if(rec->cycle_flag)
        s += sizeof(tsc_t);

    s += rec->extra_words * sizeof(uint32_t);

    return s;
}

#define STDIN 0

void progress_child_exec(void) {
    fclose(stdin);
    dup2(G.progress.pipe[0], STDIN);

    execlp("zenity", "zenity", "--progress", "--auto-close", "--title",
           "Analyzing", "--text", G.trace_file, "--auto-kill", NULL);
}

void progress_init(void) {
    int pid;

    if (pipe(G.progress.pipe) < 0)
        perror("pipe");

    if(!(pid = fork())) {
        progress_child_exec();

        fprintf(stderr, "%s: exec failed (%s), disabling progress bar\n",
                __func__, strerror(errno));
        opt.progress = 0;
        exit(1);
    } else if( pid < 0 ) {
        fprintf(stderr, "%s: could not fork: %s, disabling progress bar\n",
                __func__, strerror(errno));
        opt.progress = 0;
    }

    if( (G.progress.out = fdopen(G.progress.pipe[1], "w")) < 0 ) {
        fprintf(stderr, "%s: could not fdopen pipe: %s, disabling progress bar\n",
                __func__, strerror(errno));
        opt.progress = 0;
    }

}

void progress_update(off_t offset) {
    long long p;

    p = ( offset * 100 ) / G.file_size;

    fprintf(G.progress.out, "%lld\n", p);
    fflush(G.progress.out);

    p += 1;

    G.progress.update_offset = ( G.file_size * p ) / 100;

#if 0
    fprintf(stderr, "Progress: %lld %% Next update_offset: %lld\n",
            p-1,
            G.progress.update_offset);
#endif
}

void progress_finish(void) {
    int pid;

    fprintf(G.progress.out, "100\n");
    fflush(G.progress.out);
    fclose(G.progress.out);

    wait(NULL);

    if(!(pid = fork())) {
        /* Child */
        char text[128];

        snprintf(text, 128, "Finished analyzing %s",
                 G.trace_file);
        execlp("zenity", "zenity", "--info", "--text", text, NULL);
    }
}

ssize_t __read_record(struct trace_record *rec, off_t offset)
{
    ssize_t r, rsize;

    r=mread64(G.mh, rec, sizeof(*rec), offset);

    if(r < 0) {
        /* Read error */
        perror("read");
        fprintf(stderr, "offset %llx\n", (unsigned long long)offset);
        return 0;
    } else if(r==0) {
        /* End-of-file */
        return 0;
    } else if(r < sizeof(uint32_t)) {
        /* Full header not read */
        fprintf(stderr, "%s: short read (%zd bytes)\n",
                __func__, r);
        error(ERR_SYSTEM, NULL);
    }

    rsize=get_rec_size(rec);

    if(r < rsize) {
        /* Full record not read */
        fprintf(stderr, "%s: short read (%zd, expected %zd)\n",
                __func__, r, rsize);
        return 0;
    }

    return rsize;
}

void __fill_in_record_info(struct pcpu_info *p)
{
    struct record_info *ri;
    tsc_t tsc=0;

    ri = &p->ri;

    ri->event = ri->rec.event;
    ri->extra_words = ri->rec.extra_words;

    if(ri->rec.cycle_flag) {
        tsc = (((tsc_t)ri->rec.u.tsc.tsc_hi) << 32)
                | ri->rec.u.tsc.tsc_lo;

        tsc += p->tsc_skew.offset;

        ri->tsc = tsc;
        ri->d = ri->rec.u.tsc.data;

        if(p->first_tsc == 0)
            p->first_tsc = tsc;

        /* We process lost record twice: once at the first_tsc,
           once at the time it was placed in the log */
        if(ri->event == TRC_LOST_RECORDS && ri->extra_words == 4) {
            struct lost_record_struct *r = (typeof(r))ri->d;
            p->order_tsc = r->first_tsc + p->tsc_skew.offset;
        } else
            p->order_tsc = tsc;

        p->last_tsc = tsc;
    } else {
        ri->tsc = p->last_tsc;
        ri->d = ri->rec.u.notsc.data;
    }

    if ( opt.dump_raw_reads ) {
        char s[256];
        snprintf(s, 256, "R p%2d o%016llx ",
               p->pid, (unsigned long long)p->file_offset);
        dump_raw(s, ri);
    }

    /* Updated tracing uses CPU_CHANGE.  If we hit one of these,
     * it will process very next (since the tsc isn't updated), and
     * we'll skip forward appropriately. */
    ri->cpu = p->pid;
}

ssize_t read_record(struct pcpu_info * p) {
    off_t * offset;
    struct record_info *ri;

    offset = &p->file_offset;
    ri = &p->ri;

    ri->size = __read_record(&ri->rec, *offset);
    if(ri->size)
    {
        __fill_in_record_info(p);
    }
    else
    {
        fprintf(warn, "%s: read returned zero, deactivating pcpu %d\n",
                __func__, p->pid);
        deactivate_pcpu(p);
    }

    return ri->size;
}

/*
 * This funciton gets called for every record when doing dump.  Try to
 * make it efficient by changing the minimum amount from the last
 * call.  Do this by:
 * - Keeping track of the last pcpu called, so we can just set that to -
 * - Keeping track of how many pcpus we've "drawn", and only "drawing" new ones
 * - Updating the current one
 *
 * FIXME: Need to deal with pcpu states changing...
 *
 * WARNING not thread-safe
 */

char __pcpu_string[MAX_CPUS+1] = { 0 };
void pcpu_string_draw(struct pcpu_info *p)
{
    char *s = __pcpu_string;
    int i=p->pid;

    if(p->lost_record.active)
        s[i]='l';
    else if (!p->current)
        s[i]=' ';
    else if (p->current->d->did == DEFAULT_DOMAIN)
        s[i]='.';
    else if (p->current->d->did == IDLE_DOMAIN)
    {
        if ( opt.dump_show_power_states )
            s[i]=p->power_state+'0';
        else
            s[i]='-';
    }
    else
        s[i]='|';
}

char * pcpu_string(int pcpu)
{
    char *s = __pcpu_string;
    static int max_active_pcpu=-1, last_pcpu=-1;

    assert(P.max_active_pcpu < MAX_CPUS);
    assert(pcpu <= P.max_active_pcpu);

    if(last_pcpu >= 0)
        pcpu_string_draw(P.pcpu+last_pcpu);

    if(P.max_active_pcpu > max_active_pcpu)
    {
        int i;
        for(i=max_active_pcpu + 1; i<= P.max_active_pcpu; i++)
            pcpu_string_draw(P.pcpu+i);
        max_active_pcpu=P.max_active_pcpu;
    }

    s[pcpu]='x';
    last_pcpu = pcpu;

    return s;
}

/* Null terminated */
struct pcpu_info *record_order[MAX_CPUS+1] = { 0 };

/* In the case of identical tsc values, the old algorithm would favor the
 * pcpu with the lowest number.  By default the new algorithm favors the
 * pcpu which has been processed most recently.
 *
 * I think the second way is better; but it's good to be able to use the
 * old ordering, at very lest to verify that there are no (other) ordering
 * differences.  Enabling the below flag will cause the insertion / bubble
 * routines to order by pcpu id as well as tsc, preserving the old order. */
//#define PRESERVE_PCPU_ORDERING

/* Steady state:
 * + Entire list is in order, except (potentially) for the first entry
 * + last is pointing to the first entry.
 */
void record_order_bubble(struct pcpu_info *last)
{
    int i;

    /* Find the pcpu to "bubble".  This is usually the
     * first one, but if other pcpus have been activated, it may
     * not be. */
    for(i=0; record_order[i] && record_order[i]!=last; i++);

    assert(record_order[i]);

    /* Now bubble it down */
    for( ;
        record_order[i+1]
             && ( record_order[i+1]->order_tsc < last->order_tsc
#ifdef PRESERVE_PCPU_ORDERING
                  || ( record_order[i+1]->order_tsc == last->order_tsc
                       && record_order[i+1]->pid < last->pid )
#endif
                 ) ;
        i++)
        record_order[i]=record_order[i+1];
    record_order[i]=last;
}

void record_order_insert(struct pcpu_info *new)
{
    int i;
    struct pcpu_info *p=NULL, *t=NULL;

    /* Sanity check: Make sure it's not already in there */
    for(i=0; record_order[i]; i++)
        assert(record_order[i]!=new);

    /* Find where to insert it */
    for(i=0;
        record_order[i]
             && ( record_order[i]->order_tsc < new->order_tsc
#ifdef PRESERVE_PCPU_ORDERING
                  || ( record_order[i]->order_tsc == new->order_tsc
                       && record_order[i]->pid < new->pid )
#endif
                 ) ;
        i++)
        ;

    /* And insert it */
    for( p=new; p ; i++)
    {
        t=record_order[i];
        record_order[i]=p;
        p=t;
    }
}

void record_order_remove(struct pcpu_info *rem)
{
    int i;

    /* Find where the record is */
    for(i=0; record_order[i] && record_order[i]!=rem; i++)
        ;

    /* Sanity check: Make sure it's actually there! */
    assert(record_order[i]);

    /* And move everyone forward */
    for(; (record_order[i]=record_order[i+1]); i++)
        ;
}

struct pcpu_info * choose_next_record(void)
{
    struct pcpu_info *min_p=NULL;

    min_p=record_order[0];

    if(opt.progress && min_p && min_p->file_offset >= G.progress.update_offset)
        progress_update(min_p->file_offset);

    /* If there are active pcpus, make sure we chose one */
    assert(min_p || (P.max_active_pcpu==-1));

    return min_p;
}

void process_records(void) {
    while(1) {
        struct pcpu_info *p = NULL;

        if(!(p=choose_next_record()))
            return;

        process_record(p);

        /* Lost records gets processed twice. */
        if(p->ri.event == TRC_LOST_RECORDS) {
            p->ri.event = TRC_LOST_RECORDS_END;
            if(p->ri.tsc > p->order_tsc)
                p->order_tsc = p->ri.tsc;
            else {
                fprintf(warn, "Strange, lost_record ri->tsc %lld !> p->order_tsc %lld!\n",
                        p->ri.tsc, p->order_tsc);
                error(ERR_FILE, NULL);
            }
        }
        else
            read_record(p);

        /* Update this pcpu in the processing order */
        if ( p->active )
            record_order_bubble(p);
    }
}

void vcpu_summary(struct vcpu_data *v)
{
    printf("-- v%d --\n", v->vid);
    sched_summary_vcpu(v);
    switch(v->data_type) {
    case VCPU_DATA_HVM:
        hvm_summary(&v->hvm);
        break;
    case VCPU_DATA_PV:
        pv_summary(&v->pv);
        break;
    default:
        break;
    }
}

void domain_summary(void)
{
    struct domain_data * d;
    int i;

    if(opt.show_default_domain_summary) {
        d = &default_domain;
        printf("|-- Default domain --|\n");

        for( i = 0; i < MAX_CPUS ; i++ )
        {
            if(d->vcpu[i])
                vcpu_summary(d->vcpu[i]);
        }
    }

    for ( d = domain_list ; d ; d=d->next )
    {
        int i;
        printf("|-- Domain %d --|\n", d->did);

        sched_summary_domain(d);

        mem_summary_domain(d);

        for( i = 0; i < MAX_CPUS ; i++ )
        {
            if(d->vcpu[i])
                vcpu_summary(d->vcpu[i]);
        }

        printf("Emulate eip list\n");
        dump_eip(d->emulate_eip_list);

        if ( opt.with_interrupt_eip_enumeration )
        {
            printf("Interrupt eip list (vector %d)\n",
                   opt.interrupt_eip_enumeration_vector);
            dump_eip(d->interrupt_eip_list);
        }

        cr3_dump_list(d->cr3_value_head);
    }
}

char * stringify_cpu_hz(long long cpu_hz);

void summary(void) {
    int i;
    printf("Total time: %.2lf seconds (using cpu speed %s)\n",
           ((double)(P.f.total_cycles))/opt.cpu_hz,
           stringify_cpu_hz(opt.cpu_hz));
    printf("--- Log volume summary ---\n");
    for(i=0; i<MAX_CPUS; i++)
    {
        struct pcpu_info *p = P.pcpu+i;
        if(!p->summary)
            continue;
        printf(" - cpu %d -\n", i);
        volume_summary(&p->volume.total);
    }
    domain_summary();
}

void report_pcpu(void) {
    int i, active=0;

    for(i=0; i<MAX_CPUS; i++)
    {
        struct pcpu_info *p = P.pcpu+i;
        if(!p->summary)
            continue;
        printf("pcpu %d\n", i);

        print_cycle_summary(&p->time.running, " running");
        print_cycle_summary(&p->time.idle,    "    idle");
        print_cycle_summary(&p->time.lost,    "    lost");

        if ( p->time.running.count )
            active++;
    }
    printf("Total active cpus: %d\n", active);

}

void init_pcpus(void) {
    int i=0;
    off_t offset = 0;

    for(i=0; i<MAX_CPUS; i++)
    {
        P.pcpu[i].pid=i;
        P.pcpu[i].lost_record.seen_valid_schedule=1;
        P.pcpu[i].power_state=CSTATE_INVALID;
    }

    P.max_active_pcpu = -1;

    sched_default_domain_init();

    /* Scan through the cpu_change recs until we see a duplicate */
    do {
        offset = scan_for_new_pcpu(offset);

        if(!offset) {
            fprintf(warn, "%s: through first trace write, done for now.\n",
                   __func__);
        }
    } while(offset);

}

enum {
    OPT_NULL=0,
    /* Dumping info */
    OPT_DUMP_RAW_READS,
    OPT_DUMP_RAW_PROCESS,
    OPT_DUMP_NO_PROCESSING,
    OPT_DUMP_IPI_LATENCY,
    OPT_DUMP_TRACE_VOLUME_ON_LOST_RECORD,
    OPT_DUMP_SHOW_POWER_STATES,
    /* Extra tracking functionality */
    OPT_WITH_CR3_ENUMERATION,
    OPT_WITH_PIO_ENUMERATION,
    OPT_WITH_MMIO_ENUMERATION,
    OPT_WITH_INTERRUPT_EIP_ENUMERATION,
    OPT_SCATTERPLOT_INTERRUPT_EIP,
    OPT_SCATTERPLOT_CPI,
    OPT_SCATTERPLOT_UNPIN_PROMOTE,
    OPT_SCATTERPLOT_CR3_SWITCH,
    OPT_SCATTERPLOT_WAKE_TO_HALT,
    OPT_SCATTERPLOT_IO,
    OPT_SCATTERPLOT_VMEXIT_EIP,
    OPT_SCATTERPLOT_RUNSTATE,
    OPT_SCATTERPLOT_RUNSTATE_TIME,
    OPT_SCATTERPLOT_PCPU,
    OPT_SCATTERPLOT_EXTINT_CYCLES,
    OPT_SCATTERPLOT_RDTSC,
    OPT_SCATTERPLOT_IRQ,
    OPT_HISTOGRAM_INTERRUPT_EIP,
    /* Interval options */
    OPT_INTERVAL_CR3_SCHEDULE_TIME,
    OPT_INTERVAL_CR3_SCHEDULE_TIME_ALL,
    OPT_INTERVAL_CR3_SCHEDULE_ORDERED,
    OPT_INTERVAL_CR3_SHORT_SUMMARY,
    OPT_INTERVAL_DOMAIN_TOTAL_TIME,
    OPT_INTERVAL_DOMAIN_TOTAL_TIME_ALL,
    OPT_INTERVAL_DOMAIN_SHORT_SUMMARY,
    OPT_INTERVAL_DOMAIN_GUEST_INTERRUPT,
    OPT_INTERVAL_DOMAIN_GRANT_MAPS,
    /* Summary info */
    OPT_SHOW_DEFAULT_DOMAIN_SUMMARY,
    OPT_MMIO_ENUMERATION_SKIP_VGA,
    OPT_SAMPLE_SIZE,
    OPT_REPORT_PCPU,
    /* Guest info */
    OPT_DEFAULT_GUEST_PAGING_LEVELS,
    OPT_SYMBOL_FILE,
    /* Hardware info */
    OPT_SVM_MODE,
    OPT_CPU_HZ,
    /* Misc */
    OPT_PROGRESS,
    OPT_TOLERANCE,
    OPT_TSC_LOOP_FATAL,
    /* Specific letters */
    OPT_DUMP_ALL='a',
    OPT_INTERVAL_LENGTH='i',
    OPT_SUMMARY='s',
};

enum {
    OPT_GROUP_SUMMARY=1,
    OPT_GROUP_DUMP,
    OPT_GROUP_INTERVAL,
    OPT_GROUP_EXTRA,
    OPT_GROUP_GUEST,
    OPT_GROUP_HARDWARE
};

#define xstr(x) str(x)
#define str(x) #x

#define GHZ 1000000000LL
#define MHZ 1000000LL
#define KHZ 1000LL

void parse_cpu_hz(char * arg) {
    float hz_base;
    char * next_ptr;

    hz_base=strtof(arg, &next_ptr);
    if(next_ptr == arg) {
        fprintf(stderr, "Invalid cpu_hz %s\n", arg);
        exit(1);
    }
    switch(*next_ptr) {
    case '\0':
        opt.cpu_hz=(long long)hz_base;
        break;
    case 'G':
        opt.cpu_hz= hz_base * GHZ;
        break;
    case 'M':
        opt.cpu_hz=hz_base * MHZ;
        break;
    case 'K':
        opt.cpu_hz=hz_base * KHZ;
        break;
    default:
        fprintf(stderr, "Unknown suffix %c\n", *next_ptr);
        exit(1);
    }
    /* Just a convenient pre-calculation */
    opt.cpu_qhz = QHZ_FROM_HZ(opt.cpu_hz);
}

/* WARNING not thread-safe */
char * stringify_cpu_hz(long long cpu_hz) {
    static char cpu_string[20], suffix;
    float hz;

    if(cpu_hz > GHZ) {
        hz = (float)cpu_hz / GHZ;
        suffix = 'G';
    } else if(cpu_hz > MHZ) {
        hz = (float)cpu_hz / MHZ;
        suffix = 'M';
    } else if(cpu_hz > KHZ) {
        hz = (float)cpu_hz / KHZ;
        suffix = 'k';
    } else {
        hz = cpu_hz;
        suffix = ' ';
    }

    snprintf(cpu_string, 20, "%1.2lf %cHz", hz, suffix);

    return cpu_string;
}

int parse_array(char *arg, struct array_struct *a) {
    char *p, *q;
    int n=1, i;

    /* Count the number of commas (and thus the number of elements) */
    for(p=arg; *p; p++)
        if(*p == ',')
            n++;

    fprintf(warn, "%s: Found %d elements\n", __func__, n);
    fflush(warn);
    a->count = n;
    a->values = malloc(n * sizeof(unsigned long long));

    if(!a->values) {
        fprintf(stderr, "Malloc failed!\n");
        error(ERR_SYSTEM, NULL);
    }

    /* Now parse the elements */
    p = q = arg;
    for(i=0; i<n; i++) {
        a->values[i] = strtoull(p, &q, 0);
        if(p == q) {
            fprintf(stderr, "Bad format: %s\n", q);
            return -1;
        }
        fprintf(warn, "%s: Found element 0x%llx (%lld)\n",
                __func__, a->values[i],
                a->values[i]);
        fflush(warn);
        if(*q == ',')
            q++;
        else if(*q != '\0') {
            fprintf(stderr, "Bad format: %s\n", q);
            return -1;
        }
        p=q;
    }

    return n;
}

error_t cmd_parser(int key, char *arg, struct argp_state *state)
{
    switch (key)
    {
        /* Dump group */
    case OPT_DUMP_ALL:
        opt.dump_all = 1;
        G.output_defined = 1;
        break;
    case OPT_DUMP_RAW_READS:
        opt.dump_raw_reads = 1;
        G.output_defined = 1;
        break;
    case OPT_DUMP_NO_PROCESSING:
        opt.dump_no_processing = 1;
        opt.dump_raw_reads = 1;
        G.output_defined = 1;
        break;
    case OPT_DUMP_RAW_PROCESS:
        opt.dump_raw_process = 1;
        G.output_defined = 1;
        break;
    case OPT_DUMP_IPI_LATENCY:
        opt.dump_ipi_latency = 1;
        break;
    case OPT_DUMP_TRACE_VOLUME_ON_LOST_RECORD:
        opt.dump_trace_volume_on_lost_record = 1;
        break;
    case OPT_DUMP_SHOW_POWER_STATES:
        opt.dump_show_power_states = 1;
        break;
        /* Extra group */
    case OPT_WITH_CR3_ENUMERATION:
        opt.with_cr3_enumeration=1;
        break;
    case OPT_WITH_PIO_ENUMERATION:
        opt.with_pio_enumeration=1;
        break;
    case OPT_WITH_MMIO_ENUMERATION:
        opt.with_mmio_enumeration=1;
        break;
    case OPT_SHOW_DEFAULT_DOMAIN_SUMMARY:
        opt.show_default_domain_summary=1;
        break;
    case OPT_SAMPLE_SIZE:
    {
        char * inval;
        opt.sample_size = (int)strtol(arg, &inval, 0);
        if( inval == arg )
            argp_usage(state);
        break;
    }
    case OPT_MMIO_ENUMERATION_SKIP_VGA:
    {
        char * inval;
        opt.mmio_enumeration_skip_vga = (int)strtol(arg, &inval, 0);
        if( inval == arg )
            argp_usage(state);
        break;
    }
    case OPT_SCATTERPLOT_INTERRUPT_EIP:
    {
        char * inval;
        G.output_defined = 1;
        opt.scatterplot_interrupt_eip=1;
        opt.scatterplot_interrupt_vector = (int)strtol(arg, &inval, 0);
        if( inval == arg )
            argp_usage(state);
    }
    break;
    case OPT_WITH_INTERRUPT_EIP_ENUMERATION:
    {
        char * inval;
        opt.with_interrupt_eip_enumeration=1;
        opt.interrupt_eip_enumeration_vector = (int)strtol(arg, &inval, 0);
        if( inval == arg )
            argp_usage(state);
    }
    break;
    case OPT_SCATTERPLOT_CPI:
        G.output_defined = 1;
        opt.scatterplot_cpi=1;
        break;
    case OPT_SCATTERPLOT_UNPIN_PROMOTE:
        G.output_defined = 1;
        opt.scatterplot_unpin_promote=1;
        break;
    case OPT_SCATTERPLOT_CR3_SWITCH:
        G.output_defined = 1;
        opt.scatterplot_cr3_switch=1;
        break;
    case OPT_SCATTERPLOT_WAKE_TO_HALT:
        G.output_defined = 1;
        opt.scatterplot_wake_to_halt=1;
        break;
    case OPT_SCATTERPLOT_VMEXIT_EIP:
        G.output_defined = 1;
        opt.scatterplot_vmexit_eip=1;
    break;
    case OPT_SCATTERPLOT_EXTINT_CYCLES:
    {
        char * inval;
        G.output_defined = 1;
        opt.scatterplot_extint_cycles=1;
        opt.scatterplot_extint_cycles_vector = (int)strtol(arg, &inval, 0);
        if( inval == arg )
            argp_usage(state);
    }
    break;
    case OPT_SCATTERPLOT_RDTSC:
        G.output_defined = 1;
        opt.scatterplot_rdtsc=1;
        break;
    case OPT_SCATTERPLOT_IRQ:
        G.output_defined = 1;
        opt.scatterplot_irq=1;
        break;
    case OPT_SCATTERPLOT_IO:
    {
        char * inval;
        G.output_defined = 1;
        opt.scatterplot_io=1;
        opt.scatterplot_io_port = (int)strtol(arg, &inval, 0);
        if( inval == arg )
            argp_usage(state);
    }
    break;
    case OPT_SCATTERPLOT_RUNSTATE:
        G.output_defined = 1;
        opt.scatterplot_runstate=1;
        break;
    case OPT_SCATTERPLOT_RUNSTATE_TIME:
        G.output_defined = 1;
        opt.scatterplot_runstate_time=1;
        break;
    case OPT_SCATTERPLOT_PCPU:
        G.output_defined = 1;
        opt.scatterplot_pcpu=1;
        break;
    case OPT_HISTOGRAM_INTERRUPT_EIP:
    {
        char * inval, *p;

        opt.histogram_interrupt_eip=1;
        opt.histogram_interrupt_vector = (int)strtol(arg, &inval, 0);

        if( inval == arg )
            argp_usage(state);

        p = inval;

        if(*p == ',')
            opt.histogram_interrupt_increment = (unsigned long long)strtoull(p+1, &inval, 0);
        else
            opt.histogram_interrupt_increment = 0x1000000;

        printf("Making histogram of eips at interrupt %d, increment %llx\n",
               opt.histogram_interrupt_vector,
               opt.histogram_interrupt_increment);
    }
    break;

    case OPT_INTERVAL_LENGTH:
    {
        char * inval;

        opt.interval.msec = (unsigned) (strtof(arg, &inval) * 1000);

        if ( inval == arg )
            argp_usage(state);

        break;
    }

    case OPT_INTERVAL_CR3_SCHEDULE_TIME:
    {
        if(parse_array(arg, &opt.interval.array) < 0)
            goto usage;
        interval_table_alloc(opt.interval.array.count);
        opt.interval.output = INTERVAL_CR3_SCHEDULE_TIME;
        opt.interval.check = INTERVAL_CHECK_CR3;
        opt.interval.mode = INTERVAL_MODE_ARRAY;
        opt.interval_mode = 1;
        opt.summary_info = 1;
        opt.with_cr3_enumeration = 1;
        G.output_defined = 1;
        break;
    usage:
        fprintf(stderr, "Invalid input for cr3_schedule_time\n");
        argp_usage(state);
        break;
    }

    case OPT_INTERVAL_CR3_SCHEDULE_TIME_ALL:
        opt.interval.output = INTERVAL_CR3_SCHEDULE_TIME;
        opt.interval.check = INTERVAL_CHECK_CR3;
        opt.interval.mode = INTERVAL_MODE_LIST;
        opt.interval_mode = 1;
        opt.summary_info = 1;
        opt.with_cr3_enumeration = 1;
        G.output_defined = 1;
        break;

    case OPT_INTERVAL_CR3_SCHEDULE_ORDERED:
        opt.interval.output = INTERVAL_CR3_SCHEDULE_ORDERED;
        opt.interval.check = INTERVAL_CHECK_CR3;
        opt.interval_mode = 1;
        opt.summary_info = 1;
        opt.with_cr3_enumeration = 1;
        G.output_defined = 1;
        break;

    case OPT_INTERVAL_CR3_SHORT_SUMMARY:
    {
        if(parse_array(arg, &opt.interval.array) < 0
           || opt.interval.array.count != 1)
            goto usage;
        opt.interval.output = INTERVAL_CR3_SHORT_SUMMARY;
        opt.interval.check = INTERVAL_CHECK_CR3;
        opt.interval_mode = 1;
        opt.summary_info = 1;
        opt.with_cr3_enumeration = 1;
        G.output_defined = 1;
        break;
    }

    case OPT_INTERVAL_DOMAIN_TOTAL_TIME:
    {
        if(parse_array(arg, &opt.interval.array) < 0)
            goto idtt_usage;
        interval_table_alloc(opt.interval.array.count);
        opt.interval.output = INTERVAL_DOMAIN_TOTAL_TIME;
        opt.interval.check = INTERVAL_CHECK_DOMAIN;
        opt.interval.mode = INTERVAL_MODE_ARRAY;
        opt.interval_mode = 1;
        opt.summary_info = 1;
        G.output_defined = 1;
        break;
    idtt_usage:
        fprintf(stderr, "Invalid input for domain_total_time\n");
        argp_usage(state);
        break;
    }

    case OPT_INTERVAL_DOMAIN_TOTAL_TIME_ALL:
        opt.interval.output = INTERVAL_DOMAIN_TOTAL_TIME;
        opt.interval.check = INTERVAL_CHECK_DOMAIN;
        opt.interval.mode = INTERVAL_MODE_LIST;
        opt.interval_mode = 1;
        opt.summary_info = 1;
        G.output_defined = 1;
        break;

    case OPT_INTERVAL_DOMAIN_SHORT_SUMMARY:
    {
        if((parse_array(arg, &opt.interval.array) < 0)
           || opt.interval.array.count != 1)
            argp_usage(state);

        opt.interval.output = INTERVAL_DOMAIN_SHORT_SUMMARY;
        opt.interval.check = INTERVAL_CHECK_DOMAIN;
        opt.interval_mode = 1;
        opt.summary_info = 1;
        G.output_defined = 1;
        break;
    }

    case OPT_INTERVAL_DOMAIN_GUEST_INTERRUPT:
    {
        if((parse_array(arg, &opt.interval.array) < 0)
           || opt.interval.array.count != 1)
            argp_usage(state);

        opt.interval.output = INTERVAL_DOMAIN_GUEST_INTERRUPT;
        opt.interval.check = INTERVAL_CHECK_DOMAIN;
        opt.interval_mode = 1;
        opt.summary_info = 1;
        G.output_defined = 1;
        break;
    }

    case OPT_INTERVAL_DOMAIN_GRANT_MAPS:
    {
        if((parse_array(arg, &opt.interval.array) < 0)
           || opt.interval.array.count != 1)
            argp_usage(state);

        opt.interval.output = INTERVAL_DOMAIN_GRANT_MAPS;
        opt.interval.check = INTERVAL_CHECK_DOMAIN;
        opt.interval_mode = 1;
        opt.summary_info = 1;
        G.output_defined = 1;
        break;
    }

        /* Summary group */
    case OPT_SUMMARY:
        opt.summary = 1;
        opt.summary_info = 1;
        G.output_defined = 1;
        break;
    case OPT_REPORT_PCPU:
        opt.report_pcpu = 1;
        //opt.summary_info = 1;
        G.output_defined = 1;
        break;
        /* Guest info group */
    case OPT_DEFAULT_GUEST_PAGING_LEVELS:
    {
        char *inval;
        opt.default_guest_paging_levels = (int)strtol(arg, &inval, 0);
        if ( inval == arg )
            argp_usage(state);
    }
    break;
    case OPT_SYMBOL_FILE:
        /* FIXME - strcpy */
        G.symbol_file = arg;
        break;
        /* Hardware info group */
    case OPT_SVM_MODE:
        opt.svm_mode = 1;
        break;
    case OPT_CPU_HZ:
        parse_cpu_hz(arg);
        break;
        break;

    case OPT_TOLERANCE:
    {
        char * inval;

        opt.tolerance = (int)strtol(arg, &inval, 0);

        if( inval == arg )
            argp_usage(state);

        if ( opt.tolerance > ERR_MAX_TOLERABLE )
        {
            fprintf(stderr, "ERROR: Max tolerable error %d\n",
                    ERR_MAX_TOLERABLE);
            exit(1);
        }

        printf("Tolerating errors at or below %d\n",
               opt.tolerance);
    }
    break;

    case OPT_PROGRESS:
        opt.progress = 1;
        break;

    case OPT_TSC_LOOP_FATAL:
        opt.tsc_loop_fatal = 1;
        break;

    case ARGP_KEY_ARG:
    {
        /* FIXME - strcpy */
        if (state->arg_num == 0)
            G.trace_file = arg;
        else
            argp_usage(state);
    }
    break;
    case ARGP_KEY_END:
    {
        if(opt.interval_mode) {
            opt.interval.cycles = ( opt.interval.msec * opt.cpu_hz ) / 1000 ;
            interval_header();
        }

        if(!G.output_defined)
        {
            fprintf(stderr, "No output defined, using summary.\n");
            opt.summary = 1;
            opt.summary_info = 1;
        }
        fprintf(stderr, "Using %s hardware-assisted virtualization.\n",
                opt.svm_mode?"SVM":"VMX");
    }
    break;

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

const struct argp_option cmd_opts[] =  {
    /* Dump group */
    { .name = "dump-all",
      .key = OPT_DUMP_ALL,
      .group = OPT_GROUP_DUMP,
      .doc = "Dump all records as they come in.", },

    { .name = "dump-raw-reads",
      .key = OPT_DUMP_RAW_READS,
      .group = OPT_GROUP_DUMP,
      .doc = "Dump raw data as it's read from disk.  Useful mainly for debugging the analysis tool.", },

    { .name = "dump-no-processing",
      .key = OPT_DUMP_NO_PROCESSING,
      .group = OPT_GROUP_DUMP,
      .doc = "Don't do any processing on records other than cpu changes.  Implies dump-raw-reads (or you wouldn't get anything).", },

    { .name = "dump-raw-process",
      .key = OPT_DUMP_RAW_PROCESS,
      .group = OPT_GROUP_DUMP,
      .doc = "Dump raw data as it's processed.  Useful mainly for debugging the analysis tool.", },

    { .name = "dump-ipi-latency",
      .key = OPT_DUMP_IPI_LATENCY,
      .group = OPT_GROUP_DUMP,
      .doc = "Dump IPI latency info as IPIs are delivered (vector 0xd1 only).", },

    { .name = "dump-trace-volume-on-lost-record",
      .key = OPT_DUMP_TRACE_VOLUME_ON_LOST_RECORD,
      .group = OPT_GROUP_DUMP,
      .doc = "Dump the volume of trace types in the previous cpu buffer when a lost record is created.", },

    { .name = "dump-show-power-states",
      .key = OPT_DUMP_SHOW_POWER_STATES,
      .group = OPT_GROUP_DUMP,
      .doc = "Show the power-state of the physical cpu when dumping output.", },

    /* Extra processing group */
    { .name = "with-cr3-enumeration",
      .key = OPT_WITH_CR3_ENUMERATION,
      .group = OPT_GROUP_EXTRA,
      .doc = "Keep track of per-cr3 values", },

    { .name = "with-pio-enumeration",
      .key = OPT_WITH_PIO_ENUMERATION,
      .group = OPT_GROUP_EXTRA,
      .doc = "Report summary info on indiviaul IO addresses", },

    { .name = "with-mmio-enumeration",
      .key = OPT_WITH_MMIO_ENUMERATION,
      .group = OPT_GROUP_EXTRA,
      .doc = "Report summary info on indiviaul MMIO addresses.", },

    { .name = "with-interrupt-eip-enumeration",
      .key = OPT_WITH_INTERRUPT_EIP_ENUMERATION,
      .arg = "vector",
      .group = OPT_GROUP_EXTRA,
      .doc = "Report a summary on eips interrupted by specified vector.", },

    { .name = "scatterplot-interrupt-eip",
      .key = OPT_SCATTERPLOT_INTERRUPT_EIP,
      .arg = "vector",
      .group = OPT_GROUP_EXTRA,
      .doc = "Output scatterplot of eips as a function of time.", },

    { .name = "scatterplot-extint-cycles",
      .key = OPT_SCATTERPLOT_EXTINT_CYCLES,
      .arg = "vector",
      .group = OPT_GROUP_EXTRA,
      .doc = "Output a scatterplot of vmexit cycles for external interrupts of the given vector as a funciton of time.", },

    { .name = "scatterplot-cpi",
      .key = OPT_SCATTERPLOT_CPI,
      .group = OPT_GROUP_EXTRA,
      .doc = "Output scatterplot of cpi.", },

    { .name = "scatterplot-unpin-promote",
      .key = OPT_SCATTERPLOT_UNPIN_PROMOTE,
      .group = OPT_GROUP_EXTRA,
      .doc = "Output scatterplot of unpins and promotions.  If " \
      "--with-cr3-enumeration is included, promotions include current cr3.", },

    { .name = "scatterplot-cr3-switch",
      .key = OPT_SCATTERPLOT_CR3_SWITCH,
      .group = OPT_GROUP_EXTRA,
      .doc = "Output scatterplot of cr3 switches.", },

    { .name = "scatterplot-wake-to-halt",
      .key = OPT_SCATTERPLOT_WAKE_TO_HALT,
      .group = OPT_GROUP_EXTRA,
      .doc = "Output scatterplot of wake-to-halt.", },

    { .name = "scatterplot-vmexit-eip",
      .key = OPT_SCATTERPLOT_VMEXIT_EIP,
      .group = OPT_GROUP_EXTRA,
      .doc = "Output scatterplot of vmexit eips.", },

    { .name = "scatterplot-io",
      .key = OPT_SCATTERPLOT_IO,
      .arg = "port",
      .group = OPT_GROUP_EXTRA,
      .doc = "Output scatterplot of io latencies for givein address as a function of time.", },

    { .name = "scatterplot-runstate",
      .key = OPT_SCATTERPLOT_RUNSTATE,
      .group = OPT_GROUP_EXTRA,
      .doc = "Output scatterplot of runstate.", },

    { .name = "scatterplot-runstate-time",
      .key = OPT_SCATTERPLOT_RUNSTATE_TIME,
      .group = OPT_GROUP_EXTRA,
      .doc = "Output scatterplot of time in a runstate.", },

    { .name = "scatterplot-pcpu",
      .key = OPT_SCATTERPLOT_PCPU,
      .group = OPT_GROUP_EXTRA,
      .doc = "Output scatterplot of which pcpu vcpus are run on.", },

    { .name = "scatterplot-rdtsc",
      .key = OPT_SCATTERPLOT_RDTSC,
      .group = OPT_GROUP_EXTRA,
      .doc = "Output scatterplot of rdtsc values.", },

    { .name = "scatterplot-irq",
      .key = OPT_SCATTERPLOT_IRQ,
      .group = OPT_GROUP_EXTRA,
      .doc = "Output scatterplot of irqs on pcpus.", },

    { .name = "histogram-interrupt-eip",
      .key = OPT_HISTOGRAM_INTERRUPT_EIP,
      .arg = "vector[,increment]",
      .group = OPT_GROUP_EXTRA,
      .doc = "Output histograms of eips.", },

    { .name = "interval",
      .key = OPT_INTERVAL_LENGTH,
      .arg = "sec",
      .group = OPT_GROUP_INTERVAL,
      .doc = "Interval length to do time-based graphs, in seconds", },

    { .name = "interval-cr3-schedule-time",
      .key = OPT_INTERVAL_CR3_SCHEDULE_TIME,
      .arg = "gmfn[,gmfn...]",
      .group = OPT_GROUP_INTERVAL,
      .doc = "Print a csv with the listed cr3 value(s) every interval.", },

    { .name = "interval-cr3-schedule-time-all",
      .key = OPT_INTERVAL_CR3_SCHEDULE_TIME_ALL,
      .group = OPT_GROUP_INTERVAL,
      .doc = "Print a csv with all cr3 values every interval.", },

    { .name = "interval-cr3-schedule-ordered",
      .key = OPT_INTERVAL_CR3_SCHEDULE_ORDERED,
      .group = OPT_GROUP_INTERVAL,
      .doc = "Print summary with the top 10 cr3 values every interval.", },

    { .name = "interval-cr3-short-summary",
      .key = OPT_INTERVAL_CR3_SHORT_SUMMARY,
      .arg = "gmfn",
      .group = OPT_GROUP_INTERVAL,
      .doc = "Print a csv with the hvm short summary of cr3 value every interval.", },

    { .name = "interval-domain-total-time",
      .key = OPT_INTERVAL_DOMAIN_TOTAL_TIME,
      .arg = "domain[,domain...]",
      .group = OPT_GROUP_INTERVAL,
      .doc = "Print a csv with the listed domain(s) total runtime every interval.", },

    { .name = "interval-domain-total-time-all",
      .key = OPT_INTERVAL_DOMAIN_TOTAL_TIME_ALL,
      .group = OPT_GROUP_INTERVAL,
      .doc = "Print a csv with all domains every interval.", },

    { .name = "interval-domain-short-summary",
      .key = OPT_INTERVAL_DOMAIN_SHORT_SUMMARY,
      .arg = "domain-id",
      .group = OPT_GROUP_INTERVAL,
      .doc = "Print a csv with the hvm short summary of given domain every interval.", },

    { .name = "interval-domain-guest-interrupt",
      .key = OPT_INTERVAL_DOMAIN_GUEST_INTERRUPT,
      .arg = "domain-id",
      .group = OPT_GROUP_INTERVAL,
      .doc = "Print a csv with the guest interrupt count of given domain every interval.", },

    { .name = "interval-domain-grant-maps",
      .key = OPT_INTERVAL_DOMAIN_GRANT_MAPS,
      .arg = "domain-id",
      .group = OPT_GROUP_INTERVAL,
      .doc = "Print a csv with the grant maps done on behalf of a given domain every interval.", },

    /* Summary group */
    { .name = "show-default-domain-summary",
      .key = OPT_SHOW_DEFAULT_DOMAIN_SUMMARY,
      .group = OPT_GROUP_SUMMARY,
      .doc = "Show default domain information on summary", },

    { .name = "mmio-enumeration-skip-vga",
      .key = OPT_MMIO_ENUMERATION_SKIP_VGA,
      .arg = "[0|1]",
      .group = OPT_GROUP_SUMMARY,
      .doc = "Control whether we enumerate MMIO accesses to the VGA area, which can be extremly high during boot.  Default: 0", },

    { .name = "sample-size",
      .key = OPT_SAMPLE_SIZE,
      .arg = "size",
      .group = OPT_GROUP_SUMMARY,
      .doc = "Keep [size] samples for percentile purposes.  Enter 0 to " \
      "disable.  Default 10240.", },

    { .name = "summary",
      .key = OPT_SUMMARY,
      .group = OPT_GROUP_SUMMARY,
      .doc = "Output a summary", },

    { .name = "report-pcpu",
      .key = OPT_REPORT_PCPU,
      .group = OPT_GROUP_SUMMARY,
      .doc = "Report utilization for pcpus", },

    /* Guest info */
    { .name = "default-guest-paging-levels",
      .key = OPT_DEFAULT_GUEST_PAGING_LEVELS,
      .group = OPT_GROUP_GUEST,
      .arg = "L",
      .doc = "Default guest paging levels.  Mainly necessary for Rio, as Miami traces include guest paging levels where appropriate.", },

    { .name = "symbol-file",
      .key = OPT_SYMBOL_FILE,
      .group = OPT_GROUP_GUEST,
      .arg = "filename",
      .doc = "A symbol file for interpreting guest eips.", },

    /* Hardware info */
    { .name = "cpu-hz",
      .key = OPT_CPU_HZ,
      .group = OPT_GROUP_HARDWARE,
      .arg = "HZ",
      .doc = "Cpu speed of the tracing host, used to convert tsc into seconds.", },

    { .name = "svm-mode",
      .key = OPT_SVM_MODE,
      .group = OPT_GROUP_HARDWARE,
      .doc = "Assume AMD SVM-style vmexit error codes.  (Default is Intel VMX.)", },

    { .name = "progress",
      .key = OPT_PROGRESS,
      .doc = "Progress dialog.  Requires the zenity (GTK+) executable.", },

    { .name = "tsc-loop-fatal",
      .key = OPT_TSC_LOOP_FATAL,
      .doc = "Stop processing and exit if tsc skew tracking detects a dependency loop.", },

    { .name = "tolerance",
      .key = OPT_TOLERANCE,
      .arg = "errlevel",
      .doc = "Sets tolerance for errors found in the file.  Default is 3; max is 6.", },


    { 0 },
};

const struct argp parser_def = {
    .options = cmd_opts,
    .parser = cmd_parser,
    .args_doc = "[trace file]",
    .doc = "",
};

const char *argp_program_bug_address = "George Dunlap <george.dunlap@eu.citrix.com>";


int main(int argc, char *argv[]) {
    /* Start with warn at stderr. */
    warn = stderr;

    argp_parse(&parser_def, argc, argv, 0, NULL, NULL);

    if (G.trace_file == NULL)
        exit(1);

    if ( (G.fd = open(G.trace_file, O_RDONLY)) < 0) {
        perror("open");
        error(ERR_SYSTEM, NULL);
    } else {
        struct stat s;
        fstat(G.fd, &s);
        G.file_size = s.st_size;
    }

    if ( (G.mh = mread_init(G.fd)) == NULL )
        perror("mread");

    if (G.symbol_file != NULL)
        parse_symbol_file(G.symbol_file);

    if(opt.dump_all)
        warn = stdout;

    init_pcpus();

    if(opt.progress)
        progress_init();

    process_records();

    if(opt.interval_mode)
        interval_tail();

    if(opt.summary)
        summary();

    if(opt.report_pcpu)
        report_pcpu();

    if(opt.progress)
        progress_finish();

    return 0;
}
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
