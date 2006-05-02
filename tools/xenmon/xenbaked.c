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
 * Much code based on xentrace, authored by Mark Williamson, mark.a.williamson@intel.com
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
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <argp.h>
#include <signal.h>
#include <xenctrl.h>
#include <xen/xen.h>
#include <string.h>
#include <sys/select.h>
#include <xen/linux/evtchn.h>

#include "xc_private.h"
typedef struct { int counter; } atomic_t;
#define _atomic_read(v)		((v).counter)

#include <xen/trace.h>
#include "xenbaked.h"

extern FILE *stderr;

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
    char *outfile;
    struct timespec poll_sleep;
    unsigned long new_data_thresh;
    unsigned long ms_per_sample;
    double cpu_freq;
} settings_t;

settings_t opts;

int interrupted = 0; /* gets set if we get a SIGHUP */
int rec_count = 0;
int wakeups = 0;
time_t start_time;
int dom0_flips = 0;

_new_qos_data *new_qos;
_new_qos_data **cpu_qos_data;


// array of currently running domains, indexed by cpu
int *running = NULL;

// number of cpu's on this platform
int NCPU = 0;


void init_current(int ncpu)
{
  running = calloc(ncpu, sizeof(int));
  NCPU = ncpu;
  printf("Initialized with %d %s\n", ncpu, (ncpu == 1) ? "cpu" : "cpu's");
}

int is_current(int domain, int cpu)
{
  //  int i;
  
  //  for (i=0; i<NCPU; i++)
    if (running[cpu] == domain)
      return 1;
  return 0;
}


// return the domain that's currently running on the given cpu
int current(int cpu)
{
  return running[cpu];
}

void set_current(int cpu, int domain)
{
  running[cpu] = domain;
}



void close_handler(int signal)
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
struct timespec millis_to_timespec(unsigned long millis)
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


void check_gotten_sum(void)
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



void dump_stats(void) 
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
            rec_count, (int)run_time, rec_count/run_time);

    printf("woke up %d times in %d seconds (%ld per second)\n", wakeups,
	   (int) run_time, wakeups/run_time);

    check_gotten_sum();
}

void log_event(int event_id) 
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

#define EVTCHN_DEV_NAME  "/dev/xen/evtchn"
#define EVTCHN_DEV_MAJOR 10
#define EVTCHN_DEV_MINOR 201

int virq_port;
int eventchn_fd = -1;

/* Returns the event channel handle. */
/* Stolen from xenstore code */
int eventchn_init(void)
{
  struct stat st;
  struct ioctl_evtchn_bind_virq bind;
  int rc;
  
  // to revert to old way:
  if (0)
    return -1;
  
  /* Make sure any existing device file links to correct device. */
  if ((lstat(EVTCHN_DEV_NAME, &st) != 0) || !S_ISCHR(st.st_mode) ||
      (st.st_rdev != makedev(EVTCHN_DEV_MAJOR, EVTCHN_DEV_MINOR)))
    (void)unlink(EVTCHN_DEV_NAME);
  
 reopen:
  eventchn_fd = open(EVTCHN_DEV_NAME, O_NONBLOCK|O_RDWR);
  if (eventchn_fd == -1) {
    if ((errno == ENOENT) &&
	((mkdir("/dev/xen", 0755) == 0) || (errno == EEXIST)) &&
	(mknod(EVTCHN_DEV_NAME, S_IFCHR|0600,
	       makedev(EVTCHN_DEV_MAJOR, EVTCHN_DEV_MINOR)) == 0))
      goto reopen;
    return -errno;
  }
  
  if (eventchn_fd < 0)
    perror("Failed to open evtchn device");
  
  bind.virq = VIRQ_TBUF;
  rc = ioctl(eventchn_fd, IOCTL_EVTCHN_BIND_VIRQ, &bind);
  if (rc == -1)
    perror("Failed to bind to domain exception virq port");
  virq_port = rc;
  
  return eventchn_fd;
}

void wait_for_event(void)
{
  int ret;
  fd_set inset;
  evtchn_port_t port;
  struct timeval tv;
  
  if (eventchn_fd < 0) {
    nanosleep(&opts.poll_sleep, NULL);
    return;
  }

  FD_ZERO(&inset);
  FD_SET(eventchn_fd, &inset);
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  // tv = millis_to_timespec(&opts.poll_sleep);
  ret = select(eventchn_fd+1, &inset, NULL, NULL, &tv);
  
  if ( (ret == 1) && FD_ISSET(eventchn_fd, &inset)) {
    if (read(eventchn_fd, &port, sizeof(port)) != sizeof(port))
      perror("Failed to read from event fd");
    
    //    if (port == virq_port)
    //      printf("got the event I was looking for\r\n");
    
    if (write(eventchn_fd, &port, sizeof(port)) != sizeof(port))
      perror("Failed to write to event fd");
  }
}

void enable_tracing_or_die(int xc_handle) 
{
  int enable = 1;
  int tbsize = DEFAULT_TBUF_SIZE;
  
  if (xc_tbuf_enable(xc_handle, enable) != 0) {
    if (xc_tbuf_set_size(xc_handle, tbsize) != 0) {
      perror("set_size Hypercall failure");
      exit(1);
    }
    printf("Set default trace buffer allocation (%d pages)\n", tbsize);
    if (xc_tbuf_enable(xc_handle, enable) != 0) {
      perror("Could not enable trace buffers\n");
      exit(1);
    }
  }
  else
    printf("Tracing enabled\n");
}

void disable_tracing(void)
{
  int enable = 0;
  int xc_handle = xc_interface_open();
    
  xc_tbuf_enable(xc_handle, enable);
  xc_interface_close(xc_handle);
}


/**
 * get_tbufs - get pointer to and size of the trace buffers
 * @mfn:  location to store mfn of the trace buffers to
 * @size: location to store the size of a trace buffer to
 *
 * Gets the machine address of the trace pointer area and the size of the
 * per CPU buffers.
 */
void get_tbufs(unsigned long *mfn, unsigned long *size)
{
    int ret;
    dom0_op_t op;                        /* dom0 op we'll build             */
    int xc_handle = xc_interface_open(); /* for accessing control interface */
    unsigned int tbsize;

    enable_tracing_or_die(xc_handle);

    if (xc_tbuf_get_size(xc_handle, &tbsize) != 0) {
      perror("Failure to get tbuf info from Xen. Guess size is 0?");
      exit(1);
    }
    else
      printf("Current tbuf size: 0x%x\n", tbsize);
    

    op.cmd = DOM0_TBUFCONTROL;
    op.interface_version = DOM0_INTERFACE_VERSION;
    op.u.tbufcontrol.op  = DOM0_TBUF_GET_INFO;

    ret = do_dom0_op(xc_handle, &op);

    xc_interface_close(xc_handle);

    if ( ret != 0 )
    {
        PERROR("Failure to get trace buffer pointer from Xen");
        exit(EXIT_FAILURE);
    }

    *mfn  = op.u.tbufcontrol.buffer_mfn;
    *size = op.u.tbufcontrol.size;
}

/**
 * map_tbufs - memory map Xen trace buffers into user space
 * @tbufs_mfn: mfn of the trace buffers
 * @num:       number of trace buffers to map
 * @size:      size of each trace buffer
 *
 * Maps the Xen trace buffers them into process address space.
 */
struct t_buf *map_tbufs(unsigned long tbufs_mfn, unsigned int num,
                        unsigned long size)
{
    int xc_handle;
    struct t_buf *tbufs_mapped;

    xc_handle = xc_interface_open();

    if ( xc_handle < 0 ) 
    {
        exit(EXIT_FAILURE);
    }

    tbufs_mapped = xc_map_foreign_range(xc_handle, DOMID_XEN,
                                        size * num, PROT_READ | PROT_WRITE,
                                        tbufs_mfn);

    xc_interface_close(xc_handle);

    if ( tbufs_mapped == 0 ) 
    {
        PERROR("Failed to mmap trace buffers");
        exit(EXIT_FAILURE);
    }

    return tbufs_mapped;
}

/**
 * init_bufs_ptrs - initialises an array of pointers to the trace buffers
 * @bufs_mapped:    the userspace address where the trace buffers are mapped
 * @num:            number of trace buffers
 * @size:           trace buffer size
 *
 * Initialises an array of pointers to individual trace buffers within the
 * mapped region containing all trace buffers.
 */
struct t_buf **init_bufs_ptrs(void *bufs_mapped, unsigned int num,
        unsigned long size)
{
    int i;
    struct t_buf **user_ptrs;

    user_ptrs = (struct t_buf **)calloc(num, sizeof(struct t_buf *));
    if ( user_ptrs == NULL )
    {
        PERROR( "Failed to allocate memory for buffer pointers\n");
        exit(EXIT_FAILURE);
    }

    /* initialise pointers to the trace buffers - given the size of a trace
     * buffer and the value of bufs_maped, we can easily calculate these */
    for ( i = 0; i<num; i++ )
        user_ptrs[i] = (struct t_buf *)((unsigned long)bufs_mapped + size * i);

    return user_ptrs;
}


/**
 * init_rec_ptrs - initialises data area pointers to locations in user space
 * @tbufs_mfn:     base mfn of the trace buffer area
 * @tbufs_mapped:  user virtual address of base of trace buffer area
 * @meta:          array of user-space pointers to struct t_buf's of metadata
 * @num:           number of trace buffers
 *
 * Initialises data area pointers to the locations that data areas have been
 * mapped in user space.  Note that the trace buffer metadata contains machine
 * pointers - the array returned allows more convenient access to them.
 */
struct t_rec **init_rec_ptrs(struct t_buf **meta, unsigned int num)
{
    int i;
    struct t_rec **data;
    
    data = calloc(num, sizeof(struct t_rec *));
    if ( data == NULL )
    {
        PERROR("Failed to allocate memory for data pointers\n");
        exit(EXIT_FAILURE);
    }

    for ( i = 0; i < num; i++ )
        data[i] = (struct t_rec *)(meta[i] + 1);

    return data;
}



/**
 * get_num_cpus - get the number of logical CPUs
 */
unsigned int get_num_cpus(void)
{
    dom0_op_t op;
    int xc_handle = xc_interface_open();
    int ret;

    op.cmd = DOM0_PHYSINFO;
    op.interface_version = DOM0_INTERFACE_VERSION;

    ret = xc_dom0_op(xc_handle, &op);

    if ( ret != 0 )
    {
        PERROR("Failure to get logical CPU count from Xen");
        exit(EXIT_FAILURE);
    }

    xc_interface_close(xc_handle);
    opts.cpu_freq = (double)op.u.physinfo.cpu_khz/1000.0;

    return (op.u.physinfo.threads_per_core *
            op.u.physinfo.cores_per_socket *
            op.u.physinfo.sockets_per_node *
            op.u.physinfo.nr_nodes);
}


/**
 * monitor_tbufs - monitor the contents of tbufs
 */
int monitor_tbufs(void)
{
    int i;
    extern void process_record(int, struct t_rec *);
    extern void alloc_qos_data(int ncpu);

    void *tbufs_mapped;          /* pointer to where the tbufs are mapped    */
    struct t_buf **meta;         /* pointers to the trace buffer metadata    */
    struct t_rec **data;         /* pointers to the trace buffer data areas
                                  * where they are mapped into user space.   */
    unsigned long tbufs_mfn;     /* mfn of the tbufs                         */
    unsigned int  num;           /* number of trace buffers / logical CPUS   */
    unsigned long size;          /* size of a single trace buffer            */

    int size_in_recs;

    /* get number of logical CPUs (and therefore number of trace buffers) */
    num = get_num_cpus();

    init_current(num);
    alloc_qos_data(num);

    printf("CPU Frequency = %7.2f\n", opts.cpu_freq);
    
    /* setup access to trace buffers */
    get_tbufs(&tbufs_mfn, &size);

    //    printf("from dom0op: %ld, t_buf: %d, t_rec: %d\n",
    //            size, sizeof(struct t_buf), sizeof(struct t_rec));

    tbufs_mapped = map_tbufs(tbufs_mfn, num, size);

    size_in_recs = (size - sizeof(struct t_buf)) / sizeof(struct t_rec);
    //    fprintf(stderr, "size_in_recs = %d\n", size_in_recs);

    /* build arrays of convenience ptrs */
    meta  = init_bufs_ptrs (tbufs_mapped, num, size);
    data  = init_rec_ptrs(meta, num);

    // Set up event channel for select()
    if (eventchn_init() < 0) {
      fprintf(stderr, "Failed to initialize event channel; Using POLL method\r\n");
    }

    /* now, scan buffers for events */
    while ( !interrupted )
    {
        for ( i = 0; ( i < num ) && !interrupted; i++ )
            while ( meta[i]->cons != meta[i]->prod )
            {
                rmb(); /* read prod, then read item. */
                process_record(i, data[i] + meta[i]->cons % size_in_recs);
                mb(); /* read item, then update cons. */
                meta[i]->cons++;
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
 * Various declarations / definitions GNU argp needs to do its work
 *****************************************************************************/


/* command parser for GNU argp - see GNU docs for more info */
error_t cmd_parser(int key, char *arg, struct argp_state *state)
{
    settings_t *setup = (settings_t *)state->input;

    switch ( key )
    {
        case 't': /* set new records threshold for logging */
            {
                char *inval;
                setup->new_data_thresh = strtol(arg, &inval, 0);
                if ( inval == arg )
                    argp_usage(state);
            }
            break;

        case 's': /* set sleep time (given in milliseconds) */
            {
                char *inval;
                setup->poll_sleep = millis_to_timespec(strtol(arg, &inval, 0));
                if ( inval == arg )
                    argp_usage(state);
            }
            break;

        case 'm': /* set ms_per_sample */
            {
                char *inval;
                setup->ms_per_sample = strtol(arg, &inval, 0);
                if ( inval == arg )
                    argp_usage(state);
            }
            break;

        case ARGP_KEY_ARG:
            {
                if ( state->arg_num == 0 )
                    setup->outfile = arg;
                else
                    argp_usage(state);
            }
            break;

        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

#define SHARED_MEM_FILE "/tmp/xenq-shm"
void alloc_qos_data(int ncpu)
{
    int i, n, pgsize, off=0;
    char *dummy;
    int qos_fd;
    void advance_next_datapoint(uint64_t);

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
      if (new_qos == NULL) {
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


#define xstr(x) str(x)
#define str(x) #x

const struct argp_option cmd_opts[] =
{
    { .name = "log-thresh", .key='t', .arg="l",
        .doc =
            "Set number, l, of new records required to trigger a write to output "
            "(default " xstr(NEW_DATA_THRESH) ")." },

    { .name = "poll-sleep", .key='s', .arg="p",
        .doc = 
            "Set sleep time, p, in milliseconds between polling the trace buffer "
            "for new data (default " xstr(POLL_SLEEP_MILLIS) ")." },

    { .name = "ms_per_sample", .key='m', .arg="MS",
        .doc = 
            "Specify the number of milliseconds per sample "
            " (default " xstr(MS_PER_SAMPLE) ")." },

    {0}
};

const struct argp parser_def =
{
    .options = cmd_opts,
    .parser = cmd_parser,
    //    .args_doc = "[output file]",
    .doc =
        "Tool to capture and partially process Xen trace buffer data"
        "\v"
        "This tool is used to capture trace buffer data from Xen.  The data is "
        "saved in a shared memory structure to be further processed by xenmon."
};


const char *argp_program_version     = "xenbaked v1.3";
const char *argp_program_bug_address = "<rob.gardner@hp.com>";


int main(int argc, char **argv)
{
    int ret;
    struct sigaction act;

    time(&start_time);
    opts.outfile = 0;
    opts.poll_sleep = millis_to_timespec(POLL_SLEEP_MILLIS);
    opts.new_data_thresh = NEW_DATA_THRESH;
    opts.ms_per_sample = MS_PER_SAMPLE;
    opts.cpu_freq = CPU_FREQ;

    argp_parse(&parser_def, argc, argv, 0, 0, &opts);
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

int domain_runnable(int domid)
{
    return new_qos->domain_info[ID(domid)].runnable;
}


void update_blocked_time(int domid, uint64_t now)
{
    uint64_t t_blocked;
    int id = ID(domid);

    if (new_qos->domain_info[id].blocked_start_time != 0) {
        if (now >= new_qos->domain_info[id].blocked_start_time)
            t_blocked = now - new_qos->domain_info[id].blocked_start_time;
        else
            t_blocked = now + (~0ULL - new_qos->domain_info[id].blocked_start_time);
        new_qos->qdata[new_qos->next_datapoint].ns_blocked[id] += t_blocked;
    }

    if (domain_runnable(id))
        new_qos->domain_info[id].blocked_start_time = 0;
    else
        new_qos->domain_info[id].blocked_start_time = now;
}


// advance to next datapoint for all domains
void advance_next_datapoint(uint64_t now)
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



void qos_update_thread(int cpu, int domid, uint64_t now)
{
    int n, id;
    uint64_t last_update_time, start;
    int64_t time_since_update, run_time = 0;

    id = ID(domid);

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
void qos_update_all(uint64_t now, int cpu)
{
    int i;

    for (i=0; i<NDOMAINS; i++)
        if (new_qos->domain_info[i].in_use)
            qos_update_thread(cpu, i, now);
}


void qos_update_thread_stats(int cpu, int domid, uint64_t now)
{
    if (new_qos->qdata[new_qos->next_datapoint].ns_passed > (million*opts.ms_per_sample)) {
        qos_update_all(now, cpu);
        advance_next_datapoint(now);
        return;
    }
    qos_update_thread(cpu, domid, now);
}


void qos_init_domain(int cpu, int domid, uint64_t now)
{
    int i, id;

    id = ID(domid);

    if (new_qos->domain_info[id].in_use)
        return;


    memset(&new_qos->domain_info[id], 0, sizeof(_domain_info));
    new_qos->domain_info[id].last_update_time = now;
    //  runnable_start_time[id] = 0;
    new_qos->domain_info[id].runnable_start_time = 0; // invalidate
    new_qos->domain_info[id].in_use = 1;
    new_qos->domain_info[id].blocked_start_time = 0;
    new_qos->domain_info[id].id = id;
    if (domid == IDLE_DOMAIN_ID)
        sprintf(new_qos->domain_info[id].name, "Idle Task%d", cpu);
    else
        sprintf(new_qos->domain_info[id].name, "Domain#%d", domid);

    for (i=0; i<NSAMPLES; i++) {
        new_qos->qdata[i].ns_gotten[id] = 0;
        new_qos->qdata[i].ns_allocated[id] = 0;
        new_qos->qdata[i].ns_waiting[id] = 0;
        new_qos->qdata[i].ns_blocked[id] = 0;
        new_qos->qdata[i].switchin_count[id] = 0;
        new_qos->qdata[i].io_count[id] = 0;
    }
}


// called when a new thread gets the cpu
void qos_switch_in(int cpu, int domid, uint64_t now, unsigned long ns_alloc, unsigned long ns_waited)
{
    int id = ID(domid);

    new_qos->domain_info[id].runnable = 1;
    update_blocked_time(domid, now);
    new_qos->domain_info[id].blocked_start_time = 0; // invalidate
    new_qos->domain_info[id].runnable_start_time = 0; // invalidate
    //runnable_start_time[id] = 0;

    new_qos->domain_info[id].start_time = now;
    new_qos->qdata[new_qos->next_datapoint].switchin_count[id]++;
    new_qos->qdata[new_qos->next_datapoint].ns_allocated[id] += ns_alloc;
    new_qos->qdata[new_qos->next_datapoint].ns_waiting[id] += ns_waited;
    qos_update_thread_stats(cpu, domid, now);
    set_current(cpu, id);

    // count up page flips for dom0 execution
    if (id == 0)
      dom0_flips = 0;
}

// called when the current thread is taken off the cpu
void qos_switch_out(int cpu, int domid, uint64_t now, unsigned long gotten)
{
    int id = ID(domid);
    int n;

    if (!is_current(id, cpu)) {
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
    new_qos->qdata[n].ns_gotten[id] += gotten;
    if (gotten > new_qos->qdata[n].ns_passed)
      printf("inconsistency #257, diff = %lld\n",
	    gotten - new_qos->qdata[n].ns_passed );
#endif
    new_qos->domain_info[id].ns_oncpu_since_boot += gotten;
    new_qos->domain_info[id].runnable_start_time = now;
    //  runnable_start_time[id] = now;
    qos_update_thread_stats(cpu, id, now);

    // process dom0 page flips
    if (id == 0)
      if (dom0_flips == 0)
	new_qos->qdata[n].flip_free_periods++;
}

// called when domain is put to sleep, may also be called
// when thread is already asleep
void qos_state_sleeping(int cpu, int domid, uint64_t now) 
{
    int id = ID(domid);

    if (!domain_runnable(id))	// double call?
        return;

    new_qos->domain_info[id].runnable = 0;
    new_qos->domain_info[id].blocked_start_time = now;
    new_qos->domain_info[id].runnable_start_time = 0; // invalidate
    //  runnable_start_time[id] = 0; // invalidate
    qos_update_thread_stats(cpu, domid, now);
}



void qos_kill_thread(int domid)
{
    new_qos->domain_info[ID(domid)].in_use = 0;
}


// called when thread becomes runnable, may also be called
// when thread is already runnable
void qos_state_runnable(int cpu, int domid, uint64_t now)
{
    int id = ID(domid);

    qos_update_thread_stats(cpu, domid, now);

    if (domain_runnable(id))	// double call?
        return;
    new_qos->domain_info[id].runnable = 1;
    update_blocked_time(domid, now);

    new_qos->domain_info[id].blocked_start_time = 0; /* invalidate */
    new_qos->domain_info[id].runnable_start_time = now;
    //  runnable_start_time[id] = now;
}


void qos_count_packets(domid_t domid, uint64_t now)
{
  int i, id = ID(domid);
  _new_qos_data *cpu_data;

  for (i=0; i<NCPU; i++) {
    cpu_data = cpu_qos_data[i];
    if (cpu_data->domain_info[id].in_use) {
      cpu_data->qdata[cpu_data->next_datapoint].io_count[id]++;
    }
  }

  new_qos->qdata[new_qos->next_datapoint].io_count[0]++;
  dom0_flips++;
}


int domain_ok(int cpu, int domid, uint64_t now)
{
    if (domid == IDLE_DOMAIN_ID)
        domid = NDOMAINS-1;
    if (domid < 0 || domid >= NDOMAINS) {
        printf("bad domain id: %d\r\n", domid);
        return 0;
    }
    if (new_qos->domain_info[domid].in_use == 0)
        qos_init_domain(cpu, domid, now);
    return 1;
}


void process_record(int cpu, struct t_rec *r)
{
  uint64_t now;


  new_qos = cpu_qos_data[cpu];

  rec_count++;

  now = ((double)r->cycles) / (opts.cpu_freq / 1000.0);

  log_event(r->event);

  switch (r->event) {

  case TRC_SCHED_SWITCH_INFPREV:
    // domain data[0] just switched out and received data[1] ns of cpu time
    if (domain_ok(cpu, r->data[0], now))
      qos_switch_out(cpu, r->data[0], now, r->data[1]);
    //    printf("ns_gotten %ld\n", r->data[1]);
    break;
    
  case TRC_SCHED_SWITCH_INFNEXT:
    // domain data[0] just switched in and
    // waited data[1] ns, and was allocated data[2] ns of cpu time
    if (domain_ok(cpu, r->data[0], now))
      qos_switch_in(cpu, r->data[0], now, r->data[2], r->data[1]);
    break;
    
  case TRC_SCHED_DOM_ADD:
    if (domain_ok(cpu, r->data[0], now))
      qos_init_domain(cpu, r->data[0],  now);
    break;
    
  case TRC_SCHED_DOM_REM:
    if (domain_ok(cpu, r->data[0], now))
      qos_kill_thread(r->data[0]);
    break;
    
  case TRC_SCHED_SLEEP:
    if (domain_ok(cpu, r->data[0], now))
      qos_state_sleeping(cpu, r->data[0], now);
    break;
    
  case TRC_SCHED_WAKE:
    if (domain_ok(cpu, r->data[0], now))
      qos_state_runnable(cpu, r->data[0], now);
    break;
    
  case TRC_SCHED_BLOCK:
    if (domain_ok(cpu, r->data[0], now))
      qos_state_sleeping(cpu, r->data[0], now);
    break;
    
  case TRC_MEM_PAGE_GRANT_TRANSFER:
    if (domain_ok(cpu, r->data[0], now))
      qos_count_packets(r->data[0], now);
    break;
    
  default:
    break;
  }
  new_qos = NULL;
}



