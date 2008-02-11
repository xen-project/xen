/******************************************************************************
 * tools/xentrace/xentrace.c
 *
 * Tool for collecting trace buffer data from Xen.
 *
 * Copyright (C) 2004 by Intel Research Cambridge
 *
 * Author: Mark Williamson, mark.a.williamson@intel.com
 * Date:   February 2004
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
#include <signal.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <sys/poll.h>

#include <xen/xen.h>
#include <xen/trace.h>

#include <xenctrl.h>

#define PERROR(_m, _a...)                                       \
do {                                                            \
    int __saved_errno = errno;                                  \
    fprintf(stderr, "ERROR: " _m " (%d = %s)\n" , ## _a ,       \
            __saved_errno, strerror(__saved_errno));            \
    errno = __saved_errno;                                      \
} while (0)


/***** Compile time configuration of defaults ********************************/

/* sleep for this long (milliseconds) between checking the trace buffers */
#define POLL_SLEEP_MILLIS 100

#define DEFAULT_TBUF_SIZE 20
/***** The code **************************************************************/

typedef struct settings_st {
    char *outfile;
    unsigned long poll_sleep; /* milliseconds to sleep between polls */
    uint32_t evt_mask;
    uint32_t cpu_mask;
    unsigned long tbuf_size;
    uint8_t discard:1;
} settings_t;

settings_t opts;

int interrupted = 0; /* gets set if we get a SIGHUP */

static int xc_handle = -1;
static int event_fd = -1;
static int virq_port = -1;

void close_handler(int signal)
{
    interrupted = 1;
}

/**
 * write_buffer - write a section of the trace buffer
 * @cpu      - source buffer CPU ID
 * @start
 * @size     - size of write (may be less than total window size)
 * @total_size - total size of the window (0 on 2nd write of wrapped windows)
 * @out      - output stream
 *
 * Outputs the trace buffer to a filestream, prepending the CPU and size
 * of the buffer write.
 */
void write_buffer(unsigned int cpu, unsigned char *start, int size,
               int total_size, int outfd)
{
    size_t written = 0;
    
    /* Write a CPU_BUF record on each buffer "window" written.  Wrapped
     * windows may involve two writes, so only write the record on the
     * first write. */
    if ( total_size != 0 )
    {
        struct {
            uint32_t header;
            struct {
                unsigned cpu;
                unsigned byte_count;
            } extra;
        } rec;

        rec.header = TRC_TRACE_CPU_CHANGE
            | ((sizeof(rec.extra)/sizeof(uint32_t)) << TRACE_EXTRA_SHIFT);
        rec.extra.cpu = cpu;
        rec.extra.byte_count = total_size;

        written = write(outfd, &rec, sizeof(rec));

        if ( written != sizeof(rec) )
        {
            fprintf(stderr, "Cannot write cpu change (write returned %zd)\n",
                    written);
            goto fail;
        }
    }

    written = write(outfd, start, size);
    if ( written != size )
    {
        fprintf(stderr, "Write failed! (size %d, returned %zd)\n",
                size, written);
        goto fail;
    }

    return;

 fail:
    PERROR("Failed to write trace data");
    exit(EXIT_FAILURE);
}

static void get_tbufs(unsigned long *mfn, unsigned long *size)
{
    int ret;

    if(!opts.tbuf_size)
      opts.tbuf_size = DEFAULT_TBUF_SIZE;

    ret = xc_tbuf_enable(xc_handle, opts.tbuf_size, mfn, size);

    if ( ret != 0 )
    {
        perror("Couldn't enable trace buffers");
        exit(1);
    }
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
    struct t_buf *tbufs_mapped;

    tbufs_mapped = xc_map_foreign_range(xc_handle, DOMID_XEN,
                                        size * num, PROT_READ | PROT_WRITE,
                                        tbufs_mfn);

    if ( tbufs_mapped == 0 ) 
    {
        PERROR("Failed to mmap trace buffers");
        exit(EXIT_FAILURE);
    }

    return tbufs_mapped;
}

/**
 * set_mask - set the cpu/event mask in HV
 * @mask:           the new mask 
 * @type:           the new mask type,0-event mask, 1-cpu mask
 *
 */
void set_mask(uint32_t mask, int type)
{
    int ret = 0;

    if (type == 1) {
        ret = xc_tbuf_set_cpu_mask(xc_handle, mask);
        fprintf(stderr, "change cpumask to 0x%x\n", mask);
    } else if (type == 0) {
        ret = xc_tbuf_set_evt_mask(xc_handle, mask);
        fprintf(stderr, "change evtmask to 0x%x\n", mask);
    }

    if ( ret != 0 )
    {
        PERROR("Failure to get trace buffer pointer from Xen and set the new mask");
        exit(EXIT_FAILURE);
    }
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
unsigned char **init_rec_ptrs(struct t_buf **meta, unsigned int num)
{
    int i;
    unsigned char **data;
    
    data = calloc(num, sizeof(unsigned char *));
    if ( data == NULL )
    {
        PERROR("Failed to allocate memory for data pointers\n");
        exit(EXIT_FAILURE);
    }

    for ( i = 0; i < num; i++ )
        data[i] = (unsigned char *)(meta[i] + 1);

    return data;
}

/**
 * get_num_cpus - get the number of logical CPUs
 */
unsigned int get_num_cpus(void)
{
    xc_physinfo_t physinfo = { 0 };
    int ret;
    
    ret = xc_physinfo(xc_handle, &physinfo);
    
    if ( ret != 0 )
    {
        PERROR("Failure to get logical CPU count from Xen");
        exit(EXIT_FAILURE);
    }

    return physinfo.nr_cpus;
}

/**
 * event_init - setup to receive the VIRQ_TBUF event
 */
void event_init(void)
{
    int rc;

    rc = xc_evtchn_open();
    if (rc < 0) {
        perror(xc_get_last_error()->message);
        exit(EXIT_FAILURE);
    }
    event_fd = rc;

    rc = xc_evtchn_bind_virq(event_fd, VIRQ_TBUF);
    if (rc == -1) {
        PERROR("failed to bind to VIRQ port");
        exit(EXIT_FAILURE);
    }
    virq_port = rc;
}

/**
 * wait_for_event_or_timeout - sleep for the specified number of milliseconds,
 *                             or until an VIRQ_TBUF event occurs
 */
void wait_for_event_or_timeout(unsigned long milliseconds)
{
    int rc;
    struct pollfd fd = { .fd = event_fd,
                         .events = POLLIN | POLLERR };
    int port;

    rc = poll(&fd, 1, milliseconds);
    if (rc == -1) {
        if (errno == EINTR)
            return;
        PERROR("poll exitted with an error");
        exit(EXIT_FAILURE);
    }

    if (rc == 1) {
        port = xc_evtchn_pending(event_fd);
        if (port == -1) {
            PERROR("failed to read port from evtchn");
            exit(EXIT_FAILURE);
        }
        if (port != virq_port) {
            fprintf(stderr,
                    "unexpected port returned from evtchn (got %d vs expected %d)\n",
                    port, virq_port);
            exit(EXIT_FAILURE);
        }
        rc = xc_evtchn_unmask(event_fd, port);
        if (rc == -1) {
            PERROR("failed to write port to evtchn");
            exit(EXIT_FAILURE);
        }
    }
}


/**
 * monitor_tbufs - monitor the contents of tbufs and output to a file
 * @logfile:       the FILE * representing the file to log to
 */
int monitor_tbufs(int outfd)
{
    int i;

    void *tbufs_mapped;          /* pointer to where the tbufs are mapped    */
    struct t_buf **meta;         /* pointers to the trace buffer metadata    */
    unsigned char **data;        /* pointers to the trace buffer data areas
                                  * where they are mapped into user space.   */
    unsigned long tbufs_mfn;     /* mfn of the tbufs                         */
    unsigned int  num;           /* number of trace buffers / logical CPUS   */
    unsigned long size;          /* size of a single trace buffer            */

    unsigned long data_size;

    /* prepare to listen for VIRQ_TBUF */
    event_init();

    /* get number of logical CPUs (and therefore number of trace buffers) */
    num = get_num_cpus();

    /* setup access to trace buffers */
    get_tbufs(&tbufs_mfn, &size);
    tbufs_mapped = map_tbufs(tbufs_mfn, num, size);

    data_size = size - sizeof(struct t_buf);

    /* build arrays of convenience ptrs */
    meta  = init_bufs_ptrs(tbufs_mapped, num, size);
    data  = init_rec_ptrs(meta, num);

    if ( opts.discard )
        for ( i = 0; i < num; i++ )
            meta[i]->cons = meta[i]->prod;

    /* now, scan buffers for events */
    while ( !interrupted )
    {
        for ( i = 0; (i < num) && !interrupted; i++ )
        {
            unsigned long start_offset, end_offset, window_size, cons, prod;
                
            /* Read window information only once. */
            cons = meta[i]->cons;
            prod = meta[i]->prod;
            rmb(); /* read prod, then read item. */
            
            if ( cons == prod )
                continue;
           
            assert(cons < 2*data_size);
            assert(prod < 2*data_size);

            // NB: if (prod<cons), then (prod-cons)%data_size will not yield
            // the correct answer because data_size is not a power of 2.
            if ( prod < cons )
                window_size = (prod + 2*data_size) - cons;
            else
                window_size = prod - cons;
            assert(window_size > 0);
            assert(window_size <= data_size);

            start_offset = cons % data_size;
            end_offset = prod % data_size;

            if ( end_offset > start_offset )
            {
                /* If window does not wrap, write in one big chunk */
                write_buffer(i, data[i]+start_offset,
                             window_size,
                             window_size,
                             outfd);
            }
            else
            {
                /* If wrapped, write in two chunks:
                 * - first, start to the end of the buffer
                 * - second, start of buffer to end of window
                 */
                write_buffer(i, data[i] + start_offset,
                             data_size - start_offset,
                             window_size,
                             outfd);
                write_buffer(i, data[i],
                             end_offset,
                             0,
                             outfd);
            }

            mb(); /* read buffer, then update cons. */
            meta[i]->cons = prod;
        }

        wait_for_event_or_timeout(opts.poll_sleep);
    }

    /* cleanup */
    free(meta);
    free(data);
    /* don't need to munmap - cleanup is automatic */
    close(outfd);

    return 0;
}


/******************************************************************************
 * Command line handling
 *****************************************************************************/

#define xstr(x) str(x)
#define str(x) #x

const char *program_version     = "xentrace v1.2";
const char *program_bug_address = "<mark.a.williamson@intel.com>";

void usage(void)
{
#define USAGE_STR \
"Usage: xentrace [OPTION...] [output file]\n" \
"Tool to capture Xen trace buffer data\n" \
"\n" \
"  -c, --cpu-mask=c        Set cpu-mask\n" \
"  -e, --evt-mask=e        Set evt-mask\n" \
"  -s, --poll-sleep=p      Set sleep time, p, in milliseconds between\n" \
"                          polling the trace buffer for new data\n" \
"                          (default " xstr(POLL_SLEEP_MILLIS) ").\n" \
"  -S, --trace-buf-size=N  Set trace buffer size in pages (default " \
                           xstr(DEFAULT_TBUF_SIZE) ").\n" \
"                          N.B. that the trace buffer cannot be resized.\n" \
"                          if it has already been set this boot cycle,\n" \
"                          this argument will be ignored.\n" \
"  -?, --help              Show this message\n" \
"  -V, --version           Print program version\n" \
"\n" \
"This tool is used to capture trace buffer data from Xen. The\n" \
"data is output in a binary format, in the following order:\n" \
"\n" \
"  CPU(uint) TSC(uint64_t) EVENT(uint32_t) D1 D2 D3 D4 D5 (all uint32_t)\n" \
"\n" \
"The output should be parsed using the tool xentrace_format,\n" \
"which can produce human-readable output in ASCII format.\n" 

    printf(USAGE_STR);
    printf("\nReport bugs to %s\n", program_bug_address);

    exit(EXIT_FAILURE);
}

/* convert the argument string pointed to by arg to a long int representation */
long argtol(const char *restrict arg, int base)
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

int parse_evtmask(char *arg)
{
    /* search filtering class */
    if (strcmp(arg, "gen") == 0){ 
        opts.evt_mask |= TRC_GEN;
    } else if(strcmp(arg, "sched") == 0){ 
        opts.evt_mask |= TRC_SCHED;
    } else if(strcmp(arg, "dom0op") == 0){ 
        opts.evt_mask |= TRC_DOM0OP;
    } else if(strcmp(arg, "hvm") == 0){ 
        opts.evt_mask |= TRC_HVM;
    } else if(strcmp(arg, "all") == 0){ 
        opts.evt_mask |= TRC_ALL;
    } else {
        opts.evt_mask = argtol(arg, 0);
    }

    return 0;
}

/* parse command line arguments */
void parse_args(int argc, char **argv)
{
    int option;
    static struct option long_options[] = {
        { "log-thresh",     required_argument, 0, 't' },
        { "poll-sleep",     required_argument, 0, 's' },
        { "cpu-mask",       required_argument, 0, 'c' },
        { "evt-mask",       required_argument, 0, 'e' },
        { "trace-buf-size", required_argument, 0, 'S' },
        { "help",           no_argument,       0, '?' },
        { "version",        no_argument,       0, 'V' },
        { 0, 0, 0, 0 }
    };

    while ( (option = getopt_long(argc, argv, "c:e:s:S:t:?V",
                    long_options, NULL)) != -1) 
    {
        switch ( option )
        {
        case 's': /* set sleep time (given in milliseconds) */
            opts.poll_sleep = argtol(optarg, 0);
            break;

        case 'c': /* set new cpu mask for filtering*/
            opts.cpu_mask = argtol(optarg, 0);
            break;
        
        case 'e': /* set new event mask for filtering*/
            parse_evtmask(optarg);
            break;
        
        case 'S': /* set tbuf size (given in pages) */
            opts.tbuf_size = argtol(optarg, 0);
            break;

        case 'V': /* print program version */
            printf("%s\n", program_version);
            exit(EXIT_SUCCESS);
            break;
            
        default:
            usage();
        }
    }

    /* get outfile (required last argument) */
    if (optind != (argc-1))
        usage();

    opts.outfile = argv[optind];
}


/* *BSD has no O_LARGEFILE */
#ifndef O_LARGEFILE
#define O_LARGEFILE	0
#endif

int main(int argc, char **argv)
{
    int outfd = 1, ret;
    struct sigaction act;

    opts.outfile = 0;
    opts.poll_sleep = POLL_SLEEP_MILLIS;
    opts.evt_mask = 0;
    opts.cpu_mask = 0;

    parse_args(argc, argv);

    xc_handle = xc_interface_open();
    if ( xc_handle < 0 ) 
    {
        perror(xc_get_last_error()->message);
        exit(EXIT_FAILURE);
    }

    if ( opts.evt_mask != 0 )
        set_mask(opts.evt_mask, 0);

    if ( opts.cpu_mask != 0 )
        set_mask(opts.cpu_mask, 1);

    if ( opts.outfile )
        outfd = open(opts.outfile,
                     O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE,
                     0644);

    if ( outfd < 0 )
    {
        perror("Could not open output file");
        exit(EXIT_FAILURE);
    }        

    if ( isatty(outfd) )
    {
        fprintf(stderr, "Cannot output to a TTY, specify a log file.\n");
        exit(EXIT_FAILURE);
    }

    /* ensure that if we get a signal, we'll do cleanup, then exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);

    ret = monitor_tbufs(outfd);

    return ret;
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
