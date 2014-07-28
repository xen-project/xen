/******************************************************************************
 * tools/xenbaked.c
 *
 * Tool for collecting raw trace buffer data from Xen and 
 *  performing some accumulation operations and other processing
 *  on it.
 *
 * Copyright (C) 2004 by Intel Research Cambridge
 * Copyright (C) 2005 by Hewlett Packard, Palo Alto and Fort Collins
 * Copyright (C) 2006 by Hewlett Packard Fort Collins
 *
 * Authors: Diwaker Gupta, diwaker.gupta@hp.com
 *          Rob Gardner, rob.gardner@hp.com
 *          Lucy Cherkasova, lucy.cherkasova.hp.com
 * Much code based on xentrace, authored by Mark Williamson, 
 * mark.a.williamson@intel.com
 * Date:   November, 2005
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <xenctrl.h>
#include <xen/xen.h>
#include <string.h>
#include <sys/select.h>
#include <getopt.h>

#define PERROR(_m, _a...)                                       \
do {                                                            \
    int __saved_errno = errno;                                  \
    fprintf(stderr, "ERROR: " _m " (%d = %s)\n" , ## _a ,       \
            __saved_errno, strerror(__saved_errno));            \
    errno = __saved_errno;                                      \
} while (0)

typedef struct { int counter; } atomic_t;
#define _atomic_read(v)		((v).counter)

#include <xen/trace.h>
#include "xenbaked.h"


/***** Compile time configuration of defaults ********************************/

/* when we've got more records than this waiting, we log it to the output */
#define NEW_DATA_THRESH 1

/* sleep for this long (milliseconds) between checking the trace buffers */
#define POLL_SLEEP_MILLIS 100

/* Size of time period represented by each sample */
#define MS_PER_SAMPLE 100

/* CPU Frequency */
#define MHZ
#define CPU_FREQ 2660 MHZ

/***** The code **************************************************************/

typedef struct settings_st {
    struct timespec poll_sleep;
    unsigned long new_data_thresh;
    unsigned long ms_per_sample;
    double cpu_freq;
} settings_t;

struct t_struct {
    const struct t_info *t_info; /* Structure with information about individual buffers */
    struct t_buf **meta;    /* Pointers to trace buffer metadata */
    unsigned char **data;   /* Pointers to trace buffer data areas */
};

settings_t opts;

int interrupted = 0; /* gets set if we get a SIGHUP */
int rec_count = 0;
int wakeups = 0;
time_t start_time;
int dom0_flips = 0;

_new_qos_data *new_qos;
_new_qos_data **cpu_qos_data;

int global_cpu;
uint64_t global_now;

// array of currently running domains, indexed by cpu
int *running = NULL;

// number of cpu's on this platform
int NCPU = 0;


static void advance_next_datapoint(uint64_t);
static void alloc_qos_data(int ncpu);
static int process_record(int, struct t_rec *);
static void qos_kill_thread(int domid);


static void init_current(int ncpu)
{
    running = calloc(ncpu, sizeof(int));
    NCPU = ncpu;
    printf("Initialized with %d %s\n", ncpu, (ncpu == 1) ? "cpu" : "cpu's");
}

static int is_current(int domain, int cpu)
{
    //  int i;
  
    //  for (i=0; i<NCPU; i++)
    if (running[cpu] == domain)
        return 1;
    return 0;
}


#if 0 /* unused */
// return the domain that's currently running on the given cpu
static int current(int cpu)
{
    return running[cpu];
}
#endif

static void set_current(int cpu, int domain)
{
    running[cpu] = domain;
}



static void close_handler(int signal)
{
    interrupted = 1;
}

#if 0
void dump_record(int cpu, struct t_rec *x)
{
    printf("record: cpu=%x, tsc=%lx, event=%x, d1=%lx\n", 
           cpu, x->cycles, x->event, x->data[0]);
}
#endif

/**
 * millis_to_timespec - convert a time in milliseconds to a struct timespec
 * @millis:             time interval in milliseconds
 */
static struct timespec millis_to_timespec(unsigned long millis)
{
    struct timespec spec;

    spec.tv_sec = millis / 1000;
    spec.tv_nsec = (millis % 1000) * 1000;

    return spec;
}


typedef struct 
{
    int event_count;
    int event_id;
    char *text;
} stat_map_t;

stat_map_t stat_map[] = {
    { 0,       0, 	    "Other" },
    { 0, TRC_SCHED_DOM_ADD, "Add Domain" },
    { 0, TRC_SCHED_DOM_REM, "Remove Domain" },
    { 0, TRC_SCHED_SLEEP, "Sleep" },
    { 0, TRC_SCHED_WAKE,  "Wake" },
    { 0, TRC_SCHED_BLOCK,  "Block" },
    { 0, TRC_SCHED_SWITCH,  "Switch" },
    { 0, TRC_SCHED_S_TIMER_FN, "Timer Func"},
    { 0, TRC_SCHED_SWITCH_INFPREV,  "Switch Prev" },
    { 0, TRC_SCHED_SWITCH_INFNEXT,  "Switch Next" },
    { 0, TRC_MEM_PAGE_GRANT_MAP,  "Page Map" },
    { 0, TRC_MEM_PAGE_GRANT_UNMAP,  "Page Unmap" },
    { 0, TRC_MEM_PAGE_GRANT_TRANSFER,  "Page Transfer" },
    { 0,      0, 		 0  }
};


static void check_gotten_sum(void)
{
#if 0
    uint64_t sum, ns;
    extern uint64_t total_ns_gotten(uint64_t*);
    double percent;
    int i;

    for (i=0; i<NCPU; i++) {
        new_qos = cpu_qos_data[i];
        ns = billion;
        sum = total_ns_gotten(&ns);

        printf("[cpu%d] ns_gotten over all domains = %lldns, over %lldns\n",
               i, sum, ns);
        percent = (double) sum;
        percent = (100.0*percent) / (double)ns;
        printf(" ==> ns_gotten = %7.3f%%\n", percent);
    }
#endif
}



static void dump_stats(void) 
{
    stat_map_t *smt = stat_map;
    time_t end_time, run_time;

    time(&end_time);

    run_time = end_time - start_time;

    printf("Event counts:\n");
    while (smt->text != NULL) {
        printf("%08d\t%s\n", smt->event_count, smt->text);
        smt++;
    }

    printf("processed %d total records in %d seconds (%ld per second)\n",
           rec_count, (int)run_time, (long)(rec_count/run_time));

    printf("woke up %d times in %d seconds (%ld per second)\n", wakeups,
	   (int) run_time, (long)(wakeups/run_time));

    check_gotten_sum();
}

static void log_event(int event_id) 
{
    stat_map_t *smt = stat_map;

    //  printf("event_id = 0x%x\n", event_id);

    while (smt->text != NULL) {
        if (smt->event_id == event_id) {
            smt->event_count++;
            return;
        }
        smt++;
    }
    if (smt->text == NULL)
        stat_map[0].event_count++;	// other
}

int virq_port;
xc_evtchn *xce_handle = NULL;

/* Returns the event channel handle. */
/* Stolen from xenstore code */
static int eventchn_init(void)
{
    int rc;
  
    // to revert to old way:
    if (0)
        return -1;
  
    xce_handle = xc_evtchn_open(NULL, 0);

    if (xce_handle == NULL)
        perror("Failed to open evtchn device");
  
    if ((rc = xc_evtchn_bind_virq(xce_handle, VIRQ_TBUF)) == -1)
        perror("Failed to bind to domain exception virq port");
    virq_port = rc;
  
    return xce_handle == NULL ? -1 : 0;
}

static void wait_for_event(void)
{
    int ret;
    fd_set inset;
    evtchn_port_t port;
    struct timeval tv;
    int evtchn_fd;
  
    if (xce_handle == NULL) {
        nanosleep(&opts.poll_sleep, NULL);
        return;
    }

    evtchn_fd = xc_evtchn_fd(xce_handle);

    FD_ZERO(&inset);
    FD_SET(evtchn_fd, &inset);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    // tv = millis_to_timespec(&opts.poll_sleep);
    ret = select(evtchn_fd+1, &inset, NULL, NULL, &tv);
  
    if ( (ret == 1) && FD_ISSET(evtchn_fd, &inset)) {
        if ((port = xc_evtchn_pending(xce_handle)) == -1)
            perror("Failed to read from event fd");
    
        //    if (port == virq_port)
        //      printf("got the event I was looking for\r\n");

        if (xc_evtchn_unmask(xce_handle, port) == -1)
            perror("Failed to write to event fd");
    }
}

static void get_tbufs(unsigned long *mfn, unsigned long *size)
{
    xc_interface *xc_handle = xc_interface_open(0,0,0);
    int ret;

    if ( !xc_handle ) 
    {
        exit(EXIT_FAILURE);
    }

    ret = xc_tbuf_enable(xc_handle, DEFAULT_TBUF_SIZE, mfn, size);

    if ( ret != 0 )
    {
        perror("Couldn't enable trace buffers");
        exit(1);
    }

    xc_interface_close(xc_handle);
}

static void disable_tracing(void)
{
    xc_interface *xc_handle = xc_interface_open(0,0,0);
    xc_tbuf_disable(xc_handle);  
    xc_interface_close(xc_handle);
}

/**
 * map_tbufs - memory map Xen trace buffers into user space
 * @tbufs_mfn: mfn of the trace buffers
 * @num:       number of trace buffers to map
 * @size:      size of each trace buffer
 *
 * Maps the Xen trace buffers them into process address space.
 */
static struct t_struct *map_tbufs(unsigned long tbufs_mfn, unsigned int num,
                                  unsigned long tinfo_size)
{
    xc_interface *xc_handle;
    static struct t_struct tbufs = { 0 };
    int i;

    xc_handle = xc_interface_open(0,0,0);
    if ( !xc_handle ) 
    {
        exit(EXIT_FAILURE);
    }

    /* Map t_info metadata structure */
    tbufs.t_info = xc_map_foreign_range(xc_handle, DOMID_XEN, tinfo_size,
                                        PROT_READ, tbufs_mfn);

    if ( tbufs.t_info == 0 ) 
    {
        PERROR("Failed to mmap trace buffers");
        exit(EXIT_FAILURE);
    }

    if ( tbufs.t_info->tbuf_size == 0 )
    {
        fprintf(stderr, "%s: tbuf_size 0!\n", __func__);
        exit(EXIT_FAILURE);
    }

    /* Map per-cpu buffers */
    tbufs.meta = (struct t_buf **)calloc(num, sizeof(struct t_buf *));
    tbufs.data = (unsigned char **)calloc(num, sizeof(unsigned char *));
    if ( tbufs.meta == NULL || tbufs.data == NULL )
    {
        PERROR( "Failed to allocate memory for buffer pointers\n");
        exit(EXIT_FAILURE);
    }

    for(i=0; i<num; i++)
    {
        
        const uint32_t *mfn_list = (const uint32_t *)tbufs.t_info
                                   + tbufs.t_info->mfn_offset[i];
        int j;
        xen_pfn_t pfn_list[tbufs.t_info->tbuf_size];

        for ( j=0; j<tbufs.t_info->tbuf_size; j++)
            pfn_list[j] = (xen_pfn_t)mfn_list[j];

        tbufs.meta[i] = xc_map_foreign_batch(xc_handle, DOMID_XEN,
                                             PROT_READ | PROT_WRITE,
                                             pfn_list,
                                             tbufs.t_info->tbuf_size);
        if ( tbufs.meta[i] == NULL )
        {
            PERROR("Failed to map cpu buffer!");
            exit(EXIT_FAILURE);
        }
        tbufs.data[i] = (unsigned char *)(tbufs.meta[i]+1);
    }

    xc_interface_close(xc_handle);

    return &tbufs;
}

/**
 * get_num_cpus - get the number of logical CPUs
 */
static unsigned int get_num_cpus(void)
{
    xc_physinfo_t physinfo = { 0 };
    xc_interface *xc_handle = xc_interface_open(0,0,0);
    int ret;

    ret = xc_physinfo(xc_handle, &physinfo);

    if ( ret != 0 )
    {
        PERROR("Failure to get logical CPU count from Xen");
        exit(EXIT_FAILURE);
    }

    xc_interface_close(xc_handle);
    opts.cpu_freq = (double)physinfo.cpu_khz/1000.0;

    return physinfo.nr_cpus;
}

/**
 * monitor_tbufs - monitor the contents of tbufs
 */
static int monitor_tbufs(void)
{
    int i;

    struct t_struct *tbufs;      /* Pointer to hypervisor maps */
    struct t_buf **meta;         /* pointers to the trace buffer metadata    */
    unsigned char **data;        /* pointers to the trace buffer data areas
                                  * where they are mapped into user space.   */
    unsigned long tbufs_mfn;     /* mfn of the tbufs                         */
    unsigned int  num;           /* number of trace buffers / logical CPUS   */
    unsigned long tinfo_size;    /* size of t_info metadata map              */
    unsigned long size;          /* size of a single trace buffer            */

    unsigned long data_size, rec_size;

    /* get number of logical CPUs (and therefore number of trace buffers) */
    num = get_num_cpus();

    init_current(num);
    alloc_qos_data(num);

    printf("CPU Frequency = %7.2f\n", opts.cpu_freq);
    
    /* setup access to trace buffers */
    get_tbufs(&tbufs_mfn, &tinfo_size);
    tbufs = map_tbufs(tbufs_mfn, num, tinfo_size);

    size = tbufs->t_info->tbuf_size * XC_PAGE_SIZE;

    data_size = size - sizeof(struct t_buf);

    meta = tbufs->meta;
    data = tbufs->data;

    if ( eventchn_init() < 0 )
        fprintf(stderr, "Failed to initialize event channel; "
                "Using POLL method\r\n");

    /* now, scan buffers for events */
    while ( !interrupted )
    {
        for ( i = 0; (i < num) && !interrupted; i++ )
        {
            unsigned long start_offset, end_offset, cons, prod;

            cons = meta[i]->cons;
            prod = meta[i]->prod;
            xen_rmb(); /* read prod, then read item. */

            if ( cons == prod )
                continue;

            start_offset = cons % data_size;
            end_offset = prod % data_size;

            if ( start_offset >= end_offset )
            {
                while ( start_offset != data_size )
                {
                    rec_size = process_record(
                        i, (struct t_rec *)(data[i] + start_offset));
                    start_offset += rec_size;
                }
                start_offset = 0;
            }
            while ( start_offset != end_offset )
            {
                rec_size = process_record(
                    i, (struct t_rec *)(data[i] + start_offset));
                start_offset += rec_size;
            }
            xen_mb(); /* read item, then update cons. */
            meta[i]->cons = prod;
        }

	wait_for_event();
	wakeups++;
    }

    /* cleanup */
    free(meta);
    free(data);
    /* don't need to munmap - cleanup is automatic */

    return 0;
}


/******************************************************************************
 * Command line handling
 *****************************************************************************/

const char *program_version     = "xenbaked v1.4";
const char *program_bug_address = "<rob.gardner@hp.com>";

#define xstr(x) str(x)
#define str(x) #x

static void usage(void)
{
#define USAGE_STR \
"Usage: xenbaked [OPTION...]\n" \
"Tool to capture and partially process Xen trace buffer data\n" \
"\n" \
"  -m, --ms_per_sample=MS     Specify the number of milliseconds per sample\n" \
"                             (default " xstr(MS_PER_SAMPLE) ").\n" \
"  -s, --poll-sleep=p         Set sleep time, p, in milliseconds between\n" \
"                             polling the trace buffer for new data\n" \
"                             (default " xstr(POLL_SLEEP_MILLIS) ").\n" \
"  -t, --log-thresh=l         Set number, l, of new records required to\n" \
"                             trigger a write to output (default " \
                              xstr(NEW_DATA_THRESH) ").\n" \
"  -?, --help                 Show this message\n" \
" -V, --version              Print program version\n" \
"\n" \
"This tool is used to capture trace buffer data from Xen.  The data is\n" \
"saved in a shared memory structure to be further processed by xenmon.\n"

    printf(USAGE_STR);
    printf("\nReport bugs to %s\n", program_bug_address);

    exit(EXIT_FAILURE);
}

/* convert the argument string pointed to by arg to a long int representation */
static long argtol(const char *restrict arg, int base)
{
    char *endp; 
    long val;

    errno = 0;
    val = strtol(arg, &endp, base);

    if (errno != 0) {
        fprintf(stderr, "Invalid option argument: %s\n", arg);
        fprintf(stderr, "Error: %s\n\n", strerror(errno));
        usage();
    } else if (endp == arg || *endp != '\0') {
        fprintf(stderr, "Invalid option argument: %s\n\n", arg);
        usage();
    }

    return val;
}

/* parse command line arguments */
static void parse_args(int argc, char **argv)
{
    int option;
    static struct option long_options[] = {
        { "log-thresh",    required_argument, 0, 't' },
        { "poll-sleep",    required_argument, 0, 's' },
        { "ms_per_sample", required_argument, 0, 'm' },
        { "help",          no_argument,       0, '?' },
        { "version",       no_argument,       0, 'V' },
        { 0, 0, 0, 0 }
    };

    while ( (option = getopt_long(argc, argv, "m:s:t:?V",
                    long_options, NULL)) != -1)
    {
        switch ( option )
        {
            case 't': /* set new records threshold for logging */
                opts.new_data_thresh = argtol(optarg, 0);
                break;

            case 's': /* set sleep time (given in milliseconds) */
                opts.poll_sleep = millis_to_timespec(argtol(optarg, 0));
                break;

            case 'm': /* set ms_per_sample */
                opts.ms_per_sample = argtol(optarg, 0);
                break;

            case 'V': /* print program version */
                printf("%s\n", program_version);
                exit(EXIT_SUCCESS);
                break;

            default:
               usage(); 
        }
    }

    /* all arguments should have been processed */
    if (optind != argc) {
        usage();
    }
}

#define SHARED_MEM_FILE "/var/run/xenq-shm"
static void alloc_qos_data(int ncpu)
{
    int i, n, pgsize, off=0;
    char *dummy;
    int qos_fd;

    cpu_qos_data = (_new_qos_data **) calloc(ncpu, sizeof(_new_qos_data *));


    qos_fd = open(SHARED_MEM_FILE, O_RDWR|O_CREAT|O_TRUNC, 0777);
    if (qos_fd < 0) {
        PERROR(SHARED_MEM_FILE);
        exit(2);
    }
    pgsize = getpagesize();
    dummy = malloc(pgsize);

    for (n=0; n<ncpu; n++) {

        for (i=0; i<sizeof(_new_qos_data); i=i+pgsize)
            if ((write(qos_fd, dummy, pgsize)) != pgsize) {
                PERROR(SHARED_MEM_FILE);
                exit(2);
            }

        new_qos = (_new_qos_data *) mmap(0, sizeof(_new_qos_data), PROT_READ|PROT_WRITE, 
                                         MAP_SHARED, qos_fd, off);
        off += i;
        if (new_qos == MAP_FAILED) {
            PERROR("mmap");
            exit(3);
        }
        //  printf("new_qos = %p\n", new_qos);
        memset(new_qos, 0, sizeof(_new_qos_data));
        new_qos->next_datapoint = 0;
        advance_next_datapoint(0);
        new_qos->structlen = i;
        new_qos->ncpu = ncpu;
        //      printf("structlen = 0x%x\n", i);
        cpu_qos_data[n] = new_qos;
    }
    free(dummy);
    new_qos = NULL;
}


int main(int argc, char **argv)
{
    int ret;
    struct sigaction act;

    time(&start_time);
    opts.poll_sleep = millis_to_timespec(POLL_SLEEP_MILLIS);
    opts.new_data_thresh = NEW_DATA_THRESH;
    opts.ms_per_sample = MS_PER_SAMPLE;
    opts.cpu_freq = CPU_FREQ;

    parse_args(argc, argv);
    fprintf(stderr, "ms_per_sample = %ld\n", opts.ms_per_sample);


    /* ensure that if we get a signal, we'll do cleanup, then exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);

    ret = monitor_tbufs();

    dump_stats();
    msync(new_qos, sizeof(_new_qos_data), MS_SYNC);
    disable_tracing();

    return ret;
}

static void qos_init_domain(int domid, int idx)
{
    int i;

    memset(&new_qos->domain_info[idx], 0, sizeof(_domain_info));
    new_qos->domain_info[idx].last_update_time = global_now;
    //  runnable_start_time[idx] = 0;
    new_qos->domain_info[idx].runnable_start_time = 0; // invalidate
    new_qos->domain_info[idx].in_use = 1;
    new_qos->domain_info[idx].blocked_start_time = 0;
    new_qos->domain_info[idx].id = domid;
    if (domid == IDLE_DOMAIN_ID)
        snprintf(new_qos->domain_info[idx].name,
		sizeof(new_qos->domain_info[idx].name),
		"Idle Task%d", global_cpu);
    else
        snprintf(new_qos->domain_info[idx].name,
		sizeof(new_qos->domain_info[idx].name),
		"Domain#%d", domid);
  
    for (i=0; i<NSAMPLES; i++) {
        new_qos->qdata[i].ns_gotten[idx] = 0;
        new_qos->qdata[i].ns_allocated[idx] = 0;
        new_qos->qdata[i].ns_waiting[idx] = 0;
        new_qos->qdata[i].ns_blocked[idx] = 0;
        new_qos->qdata[i].switchin_count[idx] = 0;
        new_qos->qdata[i].io_count[idx] = 0;
    }
}

static void global_init_domain(int domid, int idx) 
{
    int cpu;
    _new_qos_data *saved_qos;
  
    saved_qos = new_qos;
  
    for (cpu=0; cpu<NCPU; cpu++) {
        new_qos = cpu_qos_data[cpu];
        qos_init_domain(domid, idx);
    }
    new_qos = saved_qos;
}

// give index of this domain in the qos data array
static int indexof(int domid)
{
    int idx;
    xc_dominfo_t dominfo[NDOMAINS];
    xc_interface *xc_handle;
    int ndomains;
  
    if (domid < 0) {	// shouldn't happen
        printf("bad domain id: %d\r\n", domid);
        return 0;
    }

    for (idx=0; idx<NDOMAINS; idx++)
        if ( (new_qos->domain_info[idx].id == domid) && new_qos->domain_info[idx].in_use)
            return idx;

    // not found, make a new entry
    for (idx=0; idx<NDOMAINS; idx++)
        if (new_qos->domain_info[idx].in_use == 0) {
            global_init_domain(domid, idx);
            return idx;
        }

    // call domaininfo hypercall to try and garbage collect unused entries
    xc_handle = xc_interface_open(0,0,0);
    ndomains = xc_domain_getinfo(xc_handle, 0, NDOMAINS, dominfo);
    xc_interface_close(xc_handle);

    // for each domain in our data, look for it in the system dominfo structure
    // and purge the domain's data from our state if it does not exist in the
    // dominfo structure
    for (idx=0; idx<NDOMAINS; idx++) {
        int domid = new_qos->domain_info[idx].id;
        int jdx;
    
        for (jdx=0; jdx<ndomains; jdx++) {
            if (dominfo[jdx].domid == domid)
                break;
        }
        if (jdx == ndomains)        // we didn't find domid in the dominfo struct
            if (domid != IDLE_DOMAIN_ID) // exception for idle domain, which is not
                // contained in dominfo
                qos_kill_thread(domid);	// purge our stale data
    }
  
    // look again for a free slot
    for (idx=0; idx<NDOMAINS; idx++)
        if (new_qos->domain_info[idx].in_use == 0) {
            global_init_domain(domid, idx);
            return idx;
        }

    // still no space found, so bail
    fprintf(stderr, "out of space in domain table, increase NDOMAINS\r\n");
    exit(2);
}

static int domain_runnable(int domid)
{
    return new_qos->domain_info[indexof(domid)].runnable;
}


static void update_blocked_time(int domid, uint64_t now)
{
    uint64_t t_blocked;
    int id = indexof(domid);

    if (new_qos->domain_info[id].blocked_start_time != 0) {
        if (now >= new_qos->domain_info[id].blocked_start_time)
            t_blocked = now - new_qos->domain_info[id].blocked_start_time;
        else
            t_blocked = now + (~0ULL - new_qos->domain_info[id].blocked_start_time);
        new_qos->qdata[new_qos->next_datapoint].ns_blocked[id] += t_blocked;
    }

    if (domain_runnable(domid))
        new_qos->domain_info[id].blocked_start_time = 0;
    else
        new_qos->domain_info[id].blocked_start_time = now;
}


// advance to next datapoint for all domains
static void advance_next_datapoint(uint64_t now)
{
    int new, old, didx;

    old = new_qos->next_datapoint;
    new = QOS_INCR(old);
    new_qos->next_datapoint = new;
    //	memset(&new_qos->qdata[new], 0, sizeof(uint64_t)*(2+5*NDOMAINS));
    for (didx = 0; didx < NDOMAINS; didx++) {
        new_qos->qdata[new].ns_gotten[didx] = 0;
        new_qos->qdata[new].ns_allocated[didx] = 0;
        new_qos->qdata[new].ns_waiting[didx] = 0;
        new_qos->qdata[new].ns_blocked[didx] = 0;
        new_qos->qdata[new].switchin_count[didx] = 0;
        new_qos->qdata[new].io_count[didx] = 0;
    }
    new_qos->qdata[new].ns_passed = 0;
    new_qos->qdata[new].lost_records = 0;
    new_qos->qdata[new].flip_free_periods = 0;

    new_qos->qdata[new].timestamp = now;
}



static void qos_update_thread(int cpu, int domid, uint64_t now)
{
    int n, id;
    uint64_t last_update_time, start;
    int64_t time_since_update, run_time = 0;

    id = indexof(domid);

    n = new_qos->next_datapoint;
    last_update_time = new_qos->domain_info[id].last_update_time;

    time_since_update = now - last_update_time;

    if (time_since_update < 0) {
        // what happened here? either a timestamp wraparound, or more likely,
        // a slight inconsistency among timestamps from various cpu's
        if (-time_since_update < billion) {
            // fairly small difference, let's just adjust 'now' to be a little
            // beyond last_update_time
            time_since_update = -time_since_update;
        }
        else if ( ((~0ULL - last_update_time) < billion) && (now < billion) ) {
            // difference is huge, must be a wraparound
            // last_update time should be "near" ~0ULL,
            // and now should be "near" 0
            time_since_update = now + (~0ULL - last_update_time);
            printf("time wraparound\n");
        }
        else {
            // none of the above, may be an out of order record
            // no good solution, just ignore and update again later
            return;
        }
    }
	
    new_qos->domain_info[id].last_update_time = now;

    if (new_qos->domain_info[id].runnable_at_last_update && is_current(domid, cpu)) {
        start = new_qos->domain_info[id].start_time;
        if (start > now) {		// wrapped around
            run_time = now + (~0ULL - start);
	    // this could happen if there is nothing going on within a cpu;
	    // in this case the idle domain would run forever
	    //        printf("warning: start > now\n");
        }
        else
            run_time = now - start;
	//	if (run_time < 0)	// should not happen
	//	  printf("warning: run_time < 0; start = %lld now= %lld\n", start, now);
        new_qos->domain_info[id].ns_oncpu_since_boot += run_time;
        new_qos->domain_info[id].start_time = now;
        new_qos->domain_info[id].ns_since_boot += time_since_update;

	new_qos->qdata[n].ns_gotten[id] += run_time;
	//	if (domid == 0 && cpu == 1)
	//	  printf("adding run time for dom0 on cpu1\r\n");

    }

    new_qos->domain_info[id].runnable_at_last_update = domain_runnable(domid);

    update_blocked_time(domid, now);

    // how much time passed since this datapoint was updated?
    if (now >= new_qos->qdata[n].timestamp) {
        // all is right with the world, time is increasing
        new_qos->qdata[n].ns_passed += (now - new_qos->qdata[n].timestamp);
    }
    else {
        // time wrapped around
        //new_qos->qdata[n].ns_passed += (now + (~0LL - new_qos->qdata[n].timestamp));
        //    printf("why timewrap?\r\n");
    }
    new_qos->qdata[n].timestamp = now;
}


// called by dump routines to update all structures
static void qos_update_all(uint64_t now, int cpu)
{
    int i;

    for (i=0; i<NDOMAINS; i++)
        if (new_qos->domain_info[i].in_use)
            qos_update_thread(cpu, new_qos->domain_info[i].id, now); 
}


static void qos_update_thread_stats(int cpu, int domid, uint64_t now)
{
    if (new_qos->qdata[new_qos->next_datapoint].ns_passed > (million*opts.ms_per_sample)) {
        qos_update_all(now, cpu);
        advance_next_datapoint(now);
        return;
    }
    qos_update_thread(cpu, domid, now);
}



// called when a new thread gets the cpu
static void qos_switch_in(int cpu, int domid, uint64_t now, unsigned long ns_alloc, unsigned long ns_waited)
{
    int idx = indexof(domid);

    new_qos->domain_info[idx].runnable = 1;
    update_blocked_time(domid, now);
    new_qos->domain_info[idx].blocked_start_time = 0; // invalidate
    new_qos->domain_info[idx].runnable_start_time = 0; // invalidate
    //runnable_start_time[idx] = 0;

    new_qos->domain_info[idx].start_time = now;
    new_qos->qdata[new_qos->next_datapoint].switchin_count[idx]++;
    new_qos->qdata[new_qos->next_datapoint].ns_allocated[idx] += ns_alloc;
    new_qos->qdata[new_qos->next_datapoint].ns_waiting[idx] += ns_waited;
    qos_update_thread_stats(cpu, domid, now);
    set_current(cpu, domid);

    // count up page flips for dom0 execution
    if (domid == 0)
        dom0_flips = 0;
}

// called when the current thread is taken off the cpu
static void qos_switch_out(int cpu, int domid, uint64_t now, unsigned long gotten)
{
    int idx = indexof(domid);
    int n;

    if (!is_current(domid, cpu)) {
        //    printf("switching out domain %d but it is not current. gotten=%ld\r\n", id, gotten);
    }

    if (gotten == 0) {
        printf("gotten==0 in qos_switchout(domid=%d)\n", domid);
    }

    if (gotten < 100) {
        printf("gotten<100ns in qos_switchout(domid=%d)\n", domid);
    }


    n = new_qos->next_datapoint;
#if 0
    new_qos->qdata[n].ns_gotten[idx] += gotten;
    if (gotten > new_qos->qdata[n].ns_passed)
        printf("inconsistency #257, diff = %lld\n",
               gotten - new_qos->qdata[n].ns_passed );
#endif
    new_qos->domain_info[idx].ns_oncpu_since_boot += gotten;
    new_qos->domain_info[idx].runnable_start_time = now;
    //  runnable_start_time[id] = now;
    qos_update_thread_stats(cpu, domid, now);

    // process dom0 page flips
    if (domid == 0)
        if (dom0_flips == 0)
            new_qos->qdata[n].flip_free_periods++;
}

// called when domain is put to sleep, may also be called
// when thread is already asleep
static void qos_state_sleeping(int cpu, int domid, uint64_t now) 
{
    int idx;

    if (!domain_runnable(domid))	// double call?
        return;

    idx = indexof(domid);
    new_qos->domain_info[idx].runnable = 0;
    new_qos->domain_info[idx].blocked_start_time = now;
    new_qos->domain_info[idx].runnable_start_time = 0; // invalidate
    //  runnable_start_time[idx] = 0; // invalidate
    qos_update_thread_stats(cpu, domid, now);
}



// domain died, presume it's dead on all cpu's, not just mostly dead
static void qos_kill_thread(int domid)
{
    int cpu;
  
    for (cpu=0; cpu<NCPU; cpu++) {
        cpu_qos_data[cpu]->domain_info[indexof(domid)].in_use = 0;
    }
  
}


// called when thread becomes runnable, may also be called
// when thread is already runnable
static void qos_state_runnable(int cpu, int domid, uint64_t now)
{
    int idx;
  

    qos_update_thread_stats(cpu, domid, now);

    if (domain_runnable(domid))	// double call?
        return;

    idx = indexof(domid);
    new_qos->domain_info[idx].runnable = 1;
    update_blocked_time(domid, now);

    new_qos->domain_info[idx].blocked_start_time = 0; /* invalidate */
    new_qos->domain_info[idx].runnable_start_time = now;
    //  runnable_start_time[id] = now;
}


static void qos_count_packets(domid_t domid, uint64_t now)
{
    int i, idx = indexof(domid);
    _new_qos_data *cpu_data;

    for (i=0; i<NCPU; i++) {
        cpu_data = cpu_qos_data[i];
        if (cpu_data->domain_info[idx].in_use) {
            cpu_data->qdata[cpu_data->next_datapoint].io_count[idx]++;
        }
    }

    new_qos->qdata[new_qos->next_datapoint].io_count[0]++;
    dom0_flips++;
}


static int process_record(int cpu, struct t_rec *r)
{
    uint64_t now = 0;
    uint32_t *extra_u32 = r->u.nocycles.extra_u32;

    new_qos = cpu_qos_data[cpu];

    rec_count++;

    if ( r->cycles_included )
    {
        now = ((uint64_t)r->u.cycles.cycles_hi << 32) | r->u.cycles.cycles_lo;
        now = ((double)now) / (opts.cpu_freq / 1000.0);
        extra_u32 = r->u.cycles.extra_u32;
    }

    global_now = now;
    global_cpu = cpu;

    log_event(r->event);

    switch (r->event) {

    case TRC_SCHED_SWITCH_INFPREV:
        // domain data[0] just switched out and received data[1] ns of cpu time
        qos_switch_out(cpu, extra_u32[0], now, extra_u32[1]);
        //    printf("ns_gotten %ld\n", extra_u32[1]);
        break;
    
    case TRC_SCHED_SWITCH_INFNEXT:
        // domain data[0] just switched in and
        // waited data[1] ns, and was allocated data[2] ns of cpu time
        qos_switch_in(cpu, extra_u32[0], now, extra_u32[2], extra_u32[1]);
        break;
    
    case TRC_SCHED_DOM_ADD:
        (void) indexof(extra_u32[0]);
        break;
    
    case TRC_SCHED_DOM_REM:
        qos_kill_thread(extra_u32[0]);
        break;
    
    case TRC_SCHED_SLEEP:
        qos_state_sleeping(cpu, extra_u32[0], now);
        break;
    
    case TRC_SCHED_WAKE:
        qos_state_runnable(cpu, extra_u32[0], now);
        break;
    
    case TRC_SCHED_BLOCK:
        qos_state_sleeping(cpu, extra_u32[0], now);
        break;
    
    case TRC_MEM_PAGE_GRANT_TRANSFER:
        qos_count_packets(extra_u32[0], now);
        break;
    
    default:
        break;
    }

    new_qos = NULL;

    return 4 + (r->cycles_included ? 8 : 0) + (r->extra_u32 * 4);
}
