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

#include "xc_private.h"

typedef struct { int counter; } atomic_t;
#define _atomic_read(v)		((v).counter)

#include <xen/trace.h>

extern FILE *stderr;

/***** Compile time configuration of defaults ********************************/

/* when we've got more records than this waiting, we log it to the output */
#define NEW_DATA_THRESH 1

/* sleep for this long (milliseconds) between checking the trace buffers */
#define POLL_SLEEP_MILLIS 100


/***** The code **************************************************************/

typedef struct settings_st {
    char *outfile;
    struct timespec poll_sleep;
    unsigned long new_data_thresh;
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
 * write_rec - output a trace record in binary format
 * @cpu      - source buffer CPU ID
 * @rec      - trace record to output
 * @out      - output stream
 *
 * Outputs the trace record to a filestream, prepending the CPU ID of the
 * source trace buffer.
 */
void write_rec(unsigned int cpu, struct t_rec *rec, FILE *out)
{
    size_t written = 0;
    written += fwrite(&cpu, sizeof(cpu), 1, out);
    written += fwrite(rec, sizeof(*rec), 1, out);
    if ( written != 2 )
    {
        PERROR("Failed to write trace record");
        exit(EXIT_FAILURE);
    }
}

/**
 * get_tbufs - get pointer to and size of the trace buffers
 * @mach_addr: location to store machine address if the trace buffers to
 * @size:      location to store the size of a trace buffer to
 *
 * Gets the machine address of the trace pointer area and the size of the
 * per CPU buffers.
 */
void get_tbufs(unsigned long *mach_addr, unsigned long *size)
{
    int ret;
    dom0_op_t op;                        /* dom0 op we'll build             */
    int xc_handle = xc_interface_open(); /* for accessing control interface */

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

    *mach_addr = op.u.tbufcontrol.mach_addr;
    *size      = op.u.tbufcontrol.size;
}

/**
 * map_tbufs - memory map Xen trace buffers into user space
 * @tbufs:     machine address of the trace buffers
 * @num:       number of trace buffers to map
 * @size:      size of each trace buffer
 *
 * Maps the Xen trace buffers them into process address space.
 */
struct t_buf *map_tbufs(unsigned long tbufs_mach, unsigned int num,
                        unsigned long size)
{
    int xc_handle;                  /* file descriptor for /proc/xen/privcmd */
    struct t_buf *tbufs_mapped;

    xc_handle = xc_interface_open();

    if ( xc_handle < 0 ) 
    {
        PERROR("Open /proc/xen/privcmd when mapping trace buffers\n");
        exit(EXIT_FAILURE);
    }

    tbufs_mapped = xc_map_foreign_range(xc_handle, 0 /* Dom 0 ID */,
                                        size * num, PROT_READ,
                                        tbufs_mach >> PAGE_SHIFT);

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
 * @tbufs_mach:    machine base address of the trace buffer area
 * @tbufs_mapped:  user virtual address of base of trace buffer area
 * @meta:          array of user-space pointers to struct t_buf's of metadata
 * @num:           number of trace buffers
 *
 * Initialises data area pointers to the locations that data areas have been
 * mapped in user space.  Note that the trace buffer metadata contains machine
 * pointers - the array returned allows more convenient access to them.
 */
struct t_rec **init_rec_ptrs(unsigned long tbufs_mach,
                             struct t_buf *tbufs_mapped,
                             struct t_buf **meta,
                             unsigned int num)
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
        data[i] = (struct t_rec *)(meta[i]->rec_addr - tbufs_mach
                                   + (unsigned long)tbufs_mapped);

    return data;
}

/**
 * init_tail_idxs - initialise an array of tail indexes
 * @bufs:           array of pointers to trace buffer metadata
 * @num:            number of trace buffers
 *
 * The tail indexes indicate where we're read to so far in the data array of a
 * trace buffer.  Each entry in this table corresponds to the tail index for a
 * particular trace buffer.
 */
unsigned long *init_tail_idxs(struct t_buf **bufs, unsigned int num)
{
    int i;
    unsigned long *tails = calloc(num, sizeof(unsigned int));
 
    if ( tails == NULL )
    {
        PERROR("Failed to allocate memory for tail pointers\n");
        exit(EXIT_FAILURE);
    }
    
    for ( i = 0; i<num; i++ )
        tails[i] = _atomic_read(bufs[i]->rec_idx);

    return tails;
}

/**
 * get_num_cpus - get the number of logical CPUs
 */
unsigned int get_num_cpus()
{
    dom0_op_t op;
    int xc_handle = xc_interface_open();
    int ret;
    
    op.cmd = DOM0_PHYSINFO;
    op.interface_version = DOM0_INTERFACE_VERSION;

    ret = do_dom0_op(xc_handle, &op);
    
    if ( ret != 0 )
    {
        PERROR("Failure to get logical CPU count from Xen");
        exit(EXIT_FAILURE);
    }

    xc_interface_close(xc_handle);

    return op.u.physinfo.ht_per_core * op.u.physinfo.cores;
}


/**
 * monitor_tbufs - monitor the contents of tbufs and output to a file
 * @logfile:       the FILE * representing the file to log to
 */
int monitor_tbufs(FILE *logfile)
{
    int i;

    void *tbufs_mapped;          /* pointer to where the tbufs are mapped    */
    struct t_buf **meta;         /* pointers to the trace buffer metadata    */
    struct t_rec **data;         /* pointers to the trace buffer data areas
                                  * where they are mapped into user space.   */
    unsigned long *cons;         /* store tail indexes for the trace buffers */
    unsigned long tbufs_mach;    /* machine address of the tbufs             */
    unsigned int  num;           /* number of trace buffers / logical CPUS   */
    unsigned long size;          /* size of a single trace buffer            */

    int size_in_recs;

    /* get number of logical CPUs (and therefore number of trace buffers) */
    num = get_num_cpus();

    /* setup access to trace buffers */
    get_tbufs(&tbufs_mach, &size);
    tbufs_mapped = map_tbufs(tbufs_mach, num, size);

    size_in_recs = (size - sizeof(struct t_buf)) / sizeof(struct t_rec);

    /* build arrays of convenience ptrs */
    meta  = init_bufs_ptrs (tbufs_mapped, num, size);
    data  = init_rec_ptrs  (tbufs_mach, tbufs_mapped, meta, num);
    cons  = init_tail_idxs (meta, num);

    /* now, scan buffers for events */
    while ( !interrupted )
    {
        for ( i = 0; ( i < num ) && !interrupted; i++ )
            while( cons[i] != _atomic_read(meta[i]->rec_idx) )
            {
                write_rec(i, data[i] + cons[i], logfile);
                cons[i] = (cons[i] + 1) % size_in_recs;
            }

        nanosleep(&opts.poll_sleep, NULL);
    }

    /* cleanup */
    free(meta);
    free(data);
    free(cons);
    /* don't need to munmap - cleanup is automatic */
    fclose(logfile);

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
    "  CPU(uint) TSC(u64) EVENT(u32) D1 D2 D3 D4 D5 (all u32)\n\n"
    "The output should be parsed using the tool xentrace_format, which can "
    "produce human-readable output in ASCII format."
};


const char *argp_program_version     = "xentrace v1.1";
const char *argp_program_bug_address = "<mark.a.williamson@intel.com>";
        
    
int main(int argc, char **argv)
{
    int outfd = 1, ret;
    FILE *logfile;
    struct sigaction act;

    opts.outfile = 0;
    opts.poll_sleep = millis_to_timespec(POLL_SLEEP_MILLIS);
    opts.new_data_thresh = NEW_DATA_THRESH;

    argp_parse(&parser_def, argc, argv, 0, 0, &opts);

    if ( opts.outfile )
        outfd = open(opts.outfile, O_WRONLY | O_CREAT);

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

    logfile = fdopen(outfd, "w");
    
    /* ensure that if we get a signal, we'll do cleanup, then exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);

    ret = monitor_tbufs(logfile);

    return ret;
}
