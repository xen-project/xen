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
#include <argp.h>
#include <signal.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>

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

extern FILE *stderr;

/***** Compile time configuration of defaults ********************************/

/* when we've got more records than this waiting, we log it to the output */
#define NEW_DATA_THRESH 1

/* sleep for this long (milliseconds) between checking the trace buffers */
#define POLL_SLEEP_MILLIS 100

#define DEFAULT_TBUF_SIZE 20
/***** The code **************************************************************/

typedef struct settings_st {
    char *outfile;
    struct timespec poll_sleep;
    unsigned long new_data_thresh;
    uint32_t evt_mask;
    uint32_t cpu_mask;
    unsigned long tbuf_size;
    uint8_t discard:1;
} settings_t;

settings_t opts;

int interrupted = 0; /* gets set if we get a SIGHUP */

void close_handler(int signal)
{
    interrupted = 1;
}

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
            fprintf(stderr, "Cannot write cpu change (write returned %d)\n",
                    written);
            goto fail;
        }
    }

    written = write(outfd, start, size);
    if ( written != size )
    {
        fprintf(stderr, "Write failed! (size %d, returned %d)\n",
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
    int xc_handle = xc_interface_open();
    int ret;

    if ( xc_handle < 0 ) 
    {
        exit(EXIT_FAILURE);
    }

    if(!opts.tbuf_size)
      opts.tbuf_size = DEFAULT_TBUF_SIZE;

    ret = xc_tbuf_enable(xc_handle, opts.tbuf_size, mfn, size);

    if ( ret != 0 )
    {
        perror("Couldn't enable trace buffers");
        exit(1);
    }

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
 * set_mask - set the cpu/event mask in HV
 * @mask:           the new mask 
 * @type:           the new mask type,0-event mask, 1-cpu mask
 *
 */
void set_mask(uint32_t mask, int type)
{
    int ret = 0;
    int xc_handle = xc_interface_open(); /* for accessing control interface */

    if (type == 1) {
        ret = xc_tbuf_set_cpu_mask(xc_handle, mask);
        fprintf(stderr, "change cpumask to 0x%x\n", mask);
    } else if (type == 0) {
        ret = xc_tbuf_set_evt_mask(xc_handle, mask);
        fprintf(stderr, "change evtmask to 0x%x\n", mask);
    }

    xc_interface_close(xc_handle);

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
    int xc_handle = xc_interface_open();
    int ret;
    
    ret = xc_physinfo(xc_handle, &physinfo);
    
    if ( ret != 0 )
    {
        PERROR("Failure to get logical CPU count from Xen");
        exit(EXIT_FAILURE);
    }

    xc_interface_close(xc_handle);

    return (physinfo.threads_per_core *
            physinfo.cores_per_socket *
            physinfo.sockets_per_node *
            physinfo.nr_nodes);
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
           
            assert(prod > cons);

            window_size = prod - cons;
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
            meta[i]->cons = meta[i]->prod;
        }

        nanosleep(&opts.poll_sleep, NULL);
    }

    /* cleanup */
    free(meta);
    free(data);
    /* don't need to munmap - cleanup is automatic */
    close(outfd);

    return 0;
}


/******************************************************************************
 * Various declarations / definitions GNU argp needs to do its work
 *****************************************************************************/

int parse_evtmask(char *arg, struct argp_state *state)
{
    settings_t *setup = (settings_t *)state->input;
    char *inval;

    /* search filtering class */
    if (strcmp(arg, "gen") == 0){ 
        setup->evt_mask |= TRC_GEN;
    } else if(strcmp(arg, "sched") == 0){ 
        setup->evt_mask |= TRC_SCHED;
    } else if(strcmp(arg, "dom0op") == 0){ 
        setup->evt_mask |= TRC_DOM0OP;
    } else if(strcmp(arg, "hvm") == 0){ 
        setup->evt_mask |= TRC_HVM;
    } else if(strcmp(arg, "all") == 0){ 
        setup->evt_mask |= TRC_ALL;
    } else {
        setup->evt_mask = strtol(arg, &inval, 0);
        if ( inval == arg )
            argp_usage(state);
    }

    return 0;

}

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

    case 'c': /* set new cpu mask for filtering*/
    {
        char *inval;
        setup->cpu_mask = strtol(arg, &inval, 0);
        if ( inval == arg )
            argp_usage(state);
    }
    break;
    
    case 'e': /* set new event mask for filtering*/
    {
        parse_evtmask(arg, state);
    }
    break;
    
    case 'S': /* set tbuf size (given in pages) */
    {
        char *inval;
        setup->tbuf_size = strtol(arg, &inval, 0);
        if ( inval == arg )
            argp_usage(state);
    }
    break;

    case 'D': /* Discard traces currently in the buffer before beginning */
    {
        opts.discard = 1;
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

    { .name = "cpu-mask", .key='c', .arg="c",
      .doc = 
      "Set cpu-mask." },

    { .name = "evt-mask", .key='e', .arg="e",
      .doc = 
      "Set trace event mask.  This can accept a numerical (including hex) "
      " argument or a symbolic name.  Symbolic names include: gen, sched, "
      "dom0op, hvm, and all." },

    { .name = "trace-buf-size", .key='S', .arg="N",
      .doc =
      "Set trace buffer size in pages (default " xstr(DEFAULT_TBUF_SIZE) "). "
      "N.B. that the trace buffer cannot be resized.  If it has "
      "already been set this boot cycle, this argument will be ignored." },

    { .name = "discard-buffers", .key='D', .arg=NULL,
      .flags=OPTION_ARG_OPTIONAL,
      .doc = "Discard all records currently in the trace buffers before "
      " beginning." },

    {0}
};

const struct argp parser_def =
{
    .options = cmd_opts,
    .parser = cmd_parser,
    .args_doc = "[output file]",
    .doc =
    "Tool to capure Xen trace buffer data"
    "\v"
    "This tool is used to capture trace buffer data from Xen.  The data is "
    "output in a binary format, in the following order:\n\n"
    "  CPU(uint) TSC(uint64_t) EVENT(uint32_t) D1 D2 D3 D4 D5 "
    "(all uint32_t)\n\n"
    "The output should be parsed using the tool xentrace_format, which can "
    "produce human-readable output in ASCII format."
};


const char *argp_program_version     = "xentrace v1.1";
const char *argp_program_bug_address = "<mark.a.williamson@intel.com>";
        
    
int main(int argc, char **argv)
{
    int outfd = 1, ret;
    struct sigaction act;

    opts.outfile = 0;
    opts.poll_sleep = millis_to_timespec(POLL_SLEEP_MILLIS);
    opts.new_data_thresh = NEW_DATA_THRESH;
    opts.evt_mask = 0;
    opts.cpu_mask = 0;

    argp_parse(&parser_def, argc, argv, 0, 0, &opts);

    if (opts.evt_mask != 0) { 
        set_mask(opts.evt_mask, 0);
    }

    if (opts.cpu_mask != 0) {
        set_mask(opts.cpu_mask, 1);
    }

    if ( opts.outfile )
        outfd = open(opts.outfile, O_WRONLY | O_CREAT | O_LARGEFILE, 0644);

    if(outfd < 0)
    {
        perror("Could not open output file");
        exit(EXIT_FAILURE);
    }        

    if(isatty(outfd))
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
