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
#include <sys/statvfs.h>

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

#define DEFAULT_TBUF_SIZE 32
/***** The code **************************************************************/

typedef struct settings_st {
    char *outfile;
    unsigned long poll_sleep; /* milliseconds to sleep between polls */
    uint32_t evt_mask;
    uint32_t cpu_mask;
    unsigned long tbuf_size;
    unsigned long disk_rsvd;
    unsigned long timeout;
    unsigned long memory_buffer;
    uint8_t discard:1,
        disable_tracing:1,
        start_disabled:1;
} settings_t;

struct t_struct {
    const struct t_info *t_info; /* Structure with information about individual buffers */
    struct t_buf **meta;    /* Pointers to trace buffer metadata */
    unsigned char **data;   /* Pointers to trace buffer data areas */
};

settings_t opts;

int interrupted = 0; /* gets set if we get a SIGHUP */

static xc_interface *xc_handle;
static xc_evtchn *xce_handle = NULL;
static int virq_port = -1;
static int outfd = 1;

static void close_handler(int signal)
{
    interrupted = 1;
}

static struct {
    char * buf;
    unsigned long prod, cons, size;
    unsigned long pending_size, pending_prod;
} membuf = { 0 };

#define MEMBUF_INDEX_RESET_THRESHOLD (1<<29)

/* FIXME -- make a power of 2 so we can mask instead. */
#define MEMBUF_POINTER(_i) (membuf.buf + ((_i) % membuf.size))
#define MEMBUF_CONS_INCREMENT(_n)               \
    do {                                        \
        membuf.cons += (_n);                    \
    } while(0)
#define MEMBUF_PROD_SET(_x)                                             \
    do {                                                                \
        if ( (_x) < membuf.prod ) {                                     \
            fprintf(stderr, "%s: INTERNAL_ERROR: prod %lu, trying to set to %lu!\n", \
                    __func__, membuf.prod, (unsigned long)(_x));        \
            exit(1);                                                    \
        }                                                               \
        membuf.prod = (_x);                                             \
        if ( (_x) > MEMBUF_INDEX_RESET_THRESHOLD )                      \
        {                                                               \
            membuf.prod %= membuf.size;                                 \
            membuf.cons %= membuf.size;                                 \
            if( membuf.prod < membuf.cons )                             \
                membuf.prod += membuf.size;                             \
        }                                                               \
    } while(0) 

struct cpu_change_record {
    uint32_t header;
    struct {
        int cpu;
        unsigned window_size;
    } data;
};

#define CPU_CHANGE_HEADER                                           \
    (TRC_TRACE_CPU_CHANGE                                           \
     | (((sizeof(struct cpu_change_record)/sizeof(uint32_t)) - 1)   \
        << TRACE_EXTRA_SHIFT) )

void membuf_alloc(unsigned long size)
{
    membuf.buf = malloc(size);

    if(!membuf.buf)
    {
        fprintf(stderr, "%s: Couldn't malloc %lu bytes!\n",
                __func__, size);
        exit(1);
    }

    membuf.prod = membuf.cons = 0;
    membuf.size = size;
}

/*
 * Reserve a new window in the buffer.  Move the 'consumer' forward size
 * bytes, re-adjusting the cpu window sizes as necessary, and insert a
 * cpu_change record.
 */
void membuf_reserve_window(unsigned cpu, unsigned long window_size)
{
    struct cpu_change_record *rec;
    long need_to_consume, free, freed;
    int last_cpu = -1;

    if ( membuf.pending_size > 0 )
    {
        fprintf(stderr, "%s: INTERNAL_ERROR: pending_size %lu\n",
                __func__, membuf.pending_size);
        exit(1);
    }

    need_to_consume = window_size + sizeof(*rec);

    if ( window_size > membuf.size )
    {
        fprintf(stderr, "%s: reserve size %lu larger than buffer size %lu!\n",
                __func__, window_size, membuf.size);
        exit(1);
    }

    /* Subtract free space already in buffer. */
    free = membuf.size - (membuf.prod - membuf.cons);
    if( need_to_consume < free)
        goto start_window;

    need_to_consume -= free;

    /*
     * "Free" up full windows until we have enough for this window.
     * It's a bit wasteful to throw away partial buffers, but the only
     * other option is to scan throught he buffer headers.  Since the
     * common case is that it's going to be thrown away next anyway, I
     * think minimizing the overall impact is more important.
     */
    do {
        rec = (struct cpu_change_record *)MEMBUF_POINTER(membuf.cons);
        if( rec->header != CPU_CHANGE_HEADER )
        {
            fprintf(stderr, "%s: INTERNAL ERROR: no cpu_change record at consumer!\n",
                    __func__);
            exit(EXIT_FAILURE);
        }

        freed = sizeof(*rec) + rec->data.window_size;

        if ( need_to_consume > 0 )
        {
            last_cpu = rec->data.cpu;
            MEMBUF_CONS_INCREMENT(freed);
            need_to_consume -= freed;
        }
    } while( need_to_consume > 0 );

    /* For good tsc consistency, we need to start at a low-cpu buffer.  Keep
     * skipping until the cpu goes down or stays the same. */
    rec = (struct cpu_change_record *)MEMBUF_POINTER(membuf.cons);
    while ( rec->data.cpu > last_cpu )
    {
        last_cpu = rec->data.cpu; 

        freed = sizeof(*rec) + rec->data.window_size;
        
        MEMBUF_CONS_INCREMENT(freed);
        rec = (struct cpu_change_record *)MEMBUF_POINTER(membuf.cons);
    }

start_window:
    /*
     * Start writing "pending" data.  Update prod once all this data is
     * written.
     */
    membuf.pending_prod = membuf.prod;
    membuf.pending_size = window_size;

    rec = (struct cpu_change_record *)MEMBUF_POINTER(membuf.pending_prod);

    rec->header = CPU_CHANGE_HEADER;
    rec->data.cpu = cpu;
    rec->data.window_size = window_size;

    membuf.pending_prod += sizeof(*rec);
}

void membuf_write(void *start, unsigned long size) {
    char * p;
    unsigned long wsize;

    if( (membuf.size - (membuf.prod - membuf.cons)) < size )
    {
        fprintf(stderr, "%s: INTERNAL ERROR: need %lu bytes, only have %lu!\n",
                __func__, size, membuf.prod - membuf.cons);
        exit(1);
    }

    if( size > membuf.pending_size )
    {
        fprintf(stderr, "%s: INTERNAL ERROR: size %lu, pending %lu!\n",
                __func__, size, membuf.pending_size);
        exit(1);
    }

    wsize = size;
    p = MEMBUF_POINTER(membuf.pending_prod);

    /* If the buffer overlaps the "wrap", do an extra write */
    if ( p + size > membuf.buf + membuf.size )
    {
        int usize = ( membuf.buf + membuf.size ) - p;

        memcpy(p, start, usize);

        start += usize;
        wsize -= usize;
        p = membuf.buf;
    }

    memcpy(p, start, wsize);

    membuf.pending_prod += size;
    membuf.pending_size -= size;

    if ( membuf.pending_size == 0 )
    {
        MEMBUF_PROD_SET(membuf.pending_prod);
    }
}

void membuf_dump(void) {
    /* Dump circular memory buffer */
    int cons, prod, wsize, written;
    char * wstart;

    fprintf(stderr, "Dumping memory buffer.\n");

    cons = membuf.cons % membuf.size; 
    prod = membuf.prod % membuf.size;
   
    if(prod > cons)
    {
        /* Write in one go */
        wstart = membuf.buf + cons;
        wsize = prod - cons;

        written = write(outfd, wstart, wsize);
        if ( written != wsize )
            goto fail;
    }
    else
    {
        /* Write in two pieces: cons->end, beginning->prod. */
        wstart = membuf.buf + cons;
        wsize = membuf.size - cons;

        written = write(outfd, wstart, wsize);
        if ( written != wsize )
        {
            fprintf(stderr, "Write failed! (size %d, returned %d)\n",
                    wsize, written);
            goto fail;
        }

        wstart = membuf.buf;
        wsize = prod;

        written = write(outfd, wstart, wsize);
        if ( written != wsize )
        {
            fprintf(stderr, "Write failed! (size %d, returned %d)\n",
                    wsize, written);
            goto fail;
        }
    }

    membuf.cons = membuf.prod = 0;
    
    return;
fail:
    exit(1);
    return;
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
static void write_buffer(unsigned int cpu, unsigned char *start, int size,
                         int total_size)
{
    struct statvfs stat;
    size_t written = 0;
    
    if ( opts.memory_buffer == 0 && opts.disk_rsvd != 0 )
    {
        unsigned long long freespace;

        /* Check that filesystem has enough space. */
        if ( fstatvfs (outfd, &stat) )
        {
            fprintf(stderr, "Statfs failed!\n");
            goto fail;
        }

        freespace = stat.f_frsize * (unsigned long long)stat.f_bfree;

        if ( total_size )
            freespace -= total_size;
        else
            freespace -= size;

        freespace >>= 20; /* Convert to MB */

        if ( freespace <= opts.disk_rsvd )
        {
            fprintf(stderr, "Disk space limit reached (free space: %lluMB, limit: %luMB).\n", freespace, opts.disk_rsvd);
            exit (EXIT_FAILURE);
        }
    }

    /* Write a CPU_BUF record on each buffer "window" written.  Wrapped
     * windows may involve two writes, so only write the record on the
     * first write. */
    if ( total_size != 0 )
    {
        if ( opts.memory_buffer )
        {
            membuf_reserve_window(cpu, total_size);
        }
        else
        {
            struct cpu_change_record rec;

            rec.header = CPU_CHANGE_HEADER;
            rec.data.cpu = cpu;
            rec.data.window_size = total_size;

            written = write(outfd, &rec, sizeof(rec));
            if ( written != sizeof(rec) )
            {
                fprintf(stderr, "Cannot write cpu change (write returned %zd)\n",
                        written);
                goto fail;
            }
        }
    }

    if ( opts.memory_buffer )
    {
        membuf_write(start, size);
    }
    else
    {
        written = write(outfd, start, size);
        if ( written != size )
        {
            fprintf(stderr, "Write failed! (size %d, returned %zd)\n",
                    size, written);
            goto fail;
        }
    }

    return;

fail:
    PERROR("Failed to write trace data");
    exit(EXIT_FAILURE);
}

static void disable_tbufs(void)
{
    xc_interface *xc_handle = xc_interface_open(0,0,0);

    if ( !xc_handle ) 
    {
        perror("Couldn't open xc handle to disable tbufs.");
        return;
    }

    if ( xc_tbuf_disable(xc_handle) != 0 )
    {
        perror("Couldn't disable trace buffers");
    }

    xc_interface_close(xc_handle);
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
static struct t_struct *map_tbufs(unsigned long tbufs_mfn, unsigned int num,
                                  unsigned long tinfo_size)
{
    static struct t_struct tbufs = { 0 };
    int i;

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

    return &tbufs;
}

/**
 * set_mask - set the cpu/event mask in HV
 * @mask:           the new mask 
 * @type:           the new mask type,0-event mask, 1-cpu mask
 *
 */
static void set_mask(uint32_t mask, int type)
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
 * get_num_cpus - get the number of logical CPUs
 */
static unsigned int get_num_cpus(void)
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
static void event_init(void)
{
    int rc;

    xce_handle = xc_evtchn_open(NULL, 0);
    if (xce_handle == NULL) {
        perror("event channel open");
        exit(EXIT_FAILURE);
    }

    rc = xc_evtchn_bind_virq(xce_handle, VIRQ_TBUF);
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
static void wait_for_event_or_timeout(unsigned long milliseconds)
{
    int rc;
    struct pollfd fd = { .fd = xc_evtchn_fd(xce_handle),
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
        port = xc_evtchn_pending(xce_handle);
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
        rc = xc_evtchn_unmask(xce_handle, port);
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
static int monitor_tbufs(void)
{
    int i;

    struct t_struct *tbufs;      /* Pointer to hypervisor maps */
    struct t_buf **meta;         /* pointers to the trace buffer metadata    */
    unsigned char **data;        /* pointers to the trace buffer data areas
                                  * where they are mapped into user space.   */
    unsigned long tbufs_mfn;     /* mfn of the tbufs                         */
    unsigned int  num;           /* number of trace buffers / logical CPUS   */
    unsigned long tinfo_size;    /* size of t_info metadata map */
    unsigned long size;          /* size of a single trace buffer            */

    unsigned long data_size;

    int last_read = 1;

    /* prepare to listen for VIRQ_TBUF */
    event_init();

    /* get number of logical CPUs (and therefore number of trace buffers) */
    num = get_num_cpus();

    /* setup access to trace buffers */
    get_tbufs(&tbufs_mfn, &tinfo_size);

    if ( opts.start_disabled )
        disable_tbufs();
    
    tbufs = map_tbufs(tbufs_mfn, num, tinfo_size);

    size = tbufs->t_info->tbuf_size * XC_PAGE_SIZE;

    data_size = size - sizeof(struct t_buf);

    meta = tbufs->meta;
    data = tbufs->data;

    if ( opts.discard )
        for ( i = 0; i < num; i++ )
            meta[i]->cons = meta[i]->prod;

    /* now, scan buffers for events */
    while ( 1 )
    {
        for ( i = 0; i < num; i++ )
        {
            unsigned long start_offset, end_offset, window_size, cons, prod;
                
            /* Read window information only once. */
            cons = meta[i]->cons;
            prod = meta[i]->prod;
            xen_rmb(); /* read prod, then read item. */

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
                             window_size);
            }
            else
            {
                /* If wrapped, write in two chunks:
                 * - first, start to the end of the buffer
                 * - second, start of buffer to end of window
                 */
                write_buffer(i, data[i] + start_offset,
                             data_size - start_offset,
                             window_size);
                write_buffer(i, data[i],
                             end_offset,
                             0);
            }

            xen_mb(); /* read buffer, then update cons. */
            meta[i]->cons = prod;

        }

        if ( interrupted )
        {
            if ( last_read )
            {
                /* Disable tracing, then read through all the buffers one last time */
                if ( opts.disable_tracing )
                    disable_tbufs();
                last_read = 0;
                continue;
            }
            else
                break;
        }

        wait_for_event_or_timeout(opts.poll_sleep);
    }

    if ( opts.memory_buffer )
        membuf_dump();

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

static void usage(void)
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
"  -D  --discard-buffers   Discard all records currently in the trace\n" \
"                          buffers before beginning.\n" \
"  -x  --dont-disable-tracing\n" \
"                          By default, xentrace will disable tracing when\n" \
"                          it exits. Selecting this option will tell it to\n" \
"                          keep tracing on.  Traces will be collected in\n" \
"                          Xen's trace buffers until they become full.\n" \
"  -X  --start-disabled    Setup trace buffers and listen, but don't enable\n" \
"                          tracing. (Useful if tracing will be enabled by\n" \
"                          else.)\n" \
"  -T  --time-interval=s   Run xentrace for s seconds and quit.\n" \
"  -?, --help              Show this message\n" \
"  -V, --version           Print program version\n" \
"  -M, --memory-buffer=b   Copy trace records to a circular memory buffer.\n" \
"                          Dump to file on exit.\n" \
"  -r  --reserve-disk-space=n Before writing trace records to disk, check to see\n" \
"                          that after the write there will be at least n space\n" \
"                          left on the disk.\n" \
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

/* convert the argument string pointed to by arg to a long int representation,
 * including suffixes such as 'M' and 'k'. */
#define MB (1024*1024)
#define KB (1024)
long sargtol(const char *restrict arg, int base)
{
    char *endp;
    long val;

    errno = 0;
    val = strtol(arg, &endp, base);
    
    if ( errno != 0 )
    {
        fprintf(stderr, "Invalid option argument: %s\n", arg);
        fprintf(stderr, "Error: %s\n\n", strerror(errno));
        usage();
    }
    else if (endp == arg)
    {
        goto invalid;
    }

    switch(*endp)
    {
    case '\0':
        break;
    case 'M':
        val *= MB;
        break;
    case 'K':
    case 'k':
        val *= KB;
        break;
    default:
        fprintf(stderr, "Unknown suffix %c\n", *endp);
        exit(1);
    }


    return val;

invalid:
    fprintf(stderr, "Invalid option argument: %s\n\n", arg);
    usage();
    return 0; /* not actually reached */
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

static int parse_evtmask(char *arg)
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
static void parse_args(int argc, char **argv)
{
    int option;
    static struct option long_options[] = {
        { "log-thresh",     required_argument, 0, 't' },
        { "poll-sleep",     required_argument, 0, 's' },
        { "cpu-mask",       required_argument, 0, 'c' },
        { "evt-mask",       required_argument, 0, 'e' },
        { "trace-buf-size", required_argument, 0, 'S' },
        { "reserve-disk-space", required_argument, 0, 'r' },
        { "time-interval",  required_argument, 0, 'T' },
        { "memory-buffer",  required_argument, 0, 'M' },
        { "discard-buffers", no_argument,      0, 'D' },
        { "dont-disable-tracing", no_argument, 0, 'x' },
        { "start-disabled", no_argument,       0, 'X' },
        { "help",           no_argument,       0, '?' },
        { "version",        no_argument,       0, 'V' },
        { 0, 0, 0, 0 }
    };

    while ( (option = getopt_long(argc, argv, "t:s:c:e:S:r:T:M:DxX?V",
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

        case 'D': /* Discard traces currently in buffer */
            opts.discard = 1;
            break;

        case 'r': /* Disk-space reservation */
            opts.disk_rsvd = argtol(optarg, 0);
            break;

        case 'x': /* Don't disable tracing */
            opts.disable_tracing = 0;
            break;

        case 'X': /* Start disabled */
            opts.start_disabled = 1;
            break;

        case 'T':
            opts.timeout = argtol(optarg, 0);
            break;

        case 'M':
            opts.memory_buffer = sargtol(optarg, 0);
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
    int ret;
    struct sigaction act;

    opts.outfile = 0;
    opts.poll_sleep = POLL_SLEEP_MILLIS;
    opts.evt_mask = 0;
    opts.cpu_mask = 0;
    opts.disk_rsvd = 0;
    opts.disable_tracing = 1;
    opts.start_disabled = 0;
    opts.timeout = 0;

    parse_args(argc, argv);

    xc_handle = xc_interface_open(0,0,0);
    if ( !xc_handle ) 
    {
        perror("xenctrl interface open");
        exit(EXIT_FAILURE);
    }

    if ( opts.evt_mask != 0 )
        set_mask(opts.evt_mask, 0);

    if ( opts.cpu_mask != 0 )
        set_mask(opts.cpu_mask, 1);

    if ( opts.timeout != 0 ) 
        alarm(opts.timeout);

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

    if ( opts.memory_buffer > 0 )
        membuf_alloc(opts.memory_buffer);

    /* ensure that if we get a signal, we'll do cleanup, then exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    ret = monitor_tbufs();

    return ret;
}
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
