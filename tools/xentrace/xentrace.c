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
#include <sys/mman.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <argp.h>
#include <signal.h>

#include "../xc/lib/xc_private.h"

#include <xeno/trace.h>

extern FILE *stdout;

/***** Compile time configuration of defaults ********************************/

#define NUM_CPUS 1 /* XXX this ought to be removed and replaced with something
                    * cleverer to dynamically query the machine - I'll use a
                    * dom0 op once I've implemented it! :-) */

/* when we've got more records than this waiting, we log it to the output */
#define NEW_DATA_THRESH 1

/* sleep for this long (milliseconds) between checking the trace buffers */
#define POLL_SLEEP_MILLIS 100

/***** The code **************************************************************/

typedef struct settings_st {
    char *outfile;
    unsigned int num_cpus;
    struct timespec poll_sleep;
    unsigned long new_data_thresh;
} settings_t;

settings_t opts;

int interrupted = 0; /* gets set if we get a SIGHUP */

void close_handler(int signal)
{
    interrupted = 1;
    fprintf(stderr,"Received signal %d, now exiting\n", signal);
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
 * print_rec - plain print an event given a pointer to its start
 * @cpu:       CPU the data came from
 * @data:      pointer to the start of the event data
 * @out:       file stream to print out to
 *
 * Takes a pointer to a record and prints out the data.
 */
void print_rec(unsigned int cpu, struct t_rec *rec, FILE *out)
{    
    fprintf(out, "%u %llu %lu %lu %lu %lu %lu %lu\n",
	    cpu, rec->cycles, rec->event, rec->d1, rec->d2,
	    rec->d3, rec->d4, rec->d5);
}


/**
 * get_tbuf_ptrs - get pointer to trace buffers
 *
 * Does a dom0 op to fetch a "pointer" to the trace buffers.  The pointer can't
 * be dereferenced immediately, since it is a physical address of memory in Xen
 * space - they are used in this program to mmap the right area from /dev/mem.
 */
unsigned long get_tbuf_ptrs(void)
{
    int ret;
    dom0_op_t op;                        /* dom0 op we'll build             */
    int xc_handle = xc_interface_open(); /* for accessing control interface */

    op.cmd = DOM0_GETTBUFS;
    op.interface_version = DOM0_INTERFACE_VERSION;

    ret = do_dom0_op(xc_handle, &op);

    xc_interface_close(xc_handle);

    if ( ret != 0 )
    {
        PERROR("Failure to get trace buffer pointer from Xen");
        exit(EXIT_FAILURE);
    }
    
    return op.u.gettbufs.phys_addr;
}

/**
 * map_tbufs - memory map Xen trace buffers into user space
 * @tbufs:     physical address of the trace buffers
 *
 * Given the physical address of the Xen trace buffers, maps them into process
 * address space by memory mapping /dev/mem.  Returns a pointer to the location
 * the buffers have been mapped to.
 */
struct t_buf *map_tbufs(unsigned long tbufs_phys)
{
    int dm_fd;                    /* file descriptor for /dev/mem */
    struct t_buf *tbufs_mapped;

    dm_fd = open("/dev/mem", O_RDONLY);
    if ( dm_fd < 0 ) 
    {
        PERROR("Open /dev/mem when mapping trace buffers\n");
        exit(EXIT_FAILURE);
    }
    
    tbufs_mapped = (struct t_buf *)mmap(NULL, opts.num_cpus * TB_SIZE,
                                        PROT_READ, MAP_SHARED,
                                        dm_fd, (off_t)tbufs_phys);

    close(dm_fd);

    if ( tbufs_mapped == MAP_FAILED ) 
    {
        PERROR("Failed to mmap trace buffers");
        exit(EXIT_FAILURE);
    }
    
    return tbufs_mapped;
}


/**
 * init_bufs_ptrs - initialises an array of pointers to the trace buffers
 * @bufs_mapped:    the userspace address where the trace buffers are mapped
 *
 * Initialises an array of pointers to individual trace buffers within the
 * mapped region containing all trace buffers.
 */
struct t_buf **init_bufs_ptrs(void *bufs_mapped)
{
    int i;
    struct t_buf **user_ptrs;

    user_ptrs = (struct t_buf **)calloc(opts.num_cpus, sizeof(struct t_buf *));
    if ( user_ptrs == NULL )
    {
        PERROR( "Failed to allocate memory for buffer pointers\n");
        exit(EXIT_FAILURE);
    }
    
    /* initialise pointers to the trace buffers - given the size of a trace
     * buffer and the value of bufs_maped, we can easily calculate these */
    for ( i = 0; i<opts.num_cpus; i++ )
        user_ptrs[i] = (struct t_buf *)(
            (unsigned long)bufs_mapped + TB_SIZE * i);

    return user_ptrs;
}


/**
 * init_rec_ptrs - initialises data area pointers to locations in user space
 * @tbufs_phys:    physical base address of the trace buffer area
 * @tbufs_mapped:  user virtual address of base of trace buffer area
 * @meta:          array of user-space pointers to struct t_buf's of metadata
 *
 * Initialises data area pointers to the locations that data areas have been
 * mapped in user space.  Note that the trace buffer metadata contains physical
 * pointers - the array returned allows more convenient access to them.
 */
struct t_rec **init_rec_ptrs(unsigned long tbufs_phys,
                             struct t_buf *tbufs_mapped,
                             struct t_buf **meta)
{
    int i;
    struct t_rec **data;
    
    data = calloc(opts.num_cpus, sizeof(struct t_rec *));
    if ( data == NULL )
    {
        PERROR("Failed to allocate memory for data pointers\n");
        exit(EXIT_FAILURE);
    }

    for ( i = 0; i<opts.num_cpus; i++ )
        data[i] = (struct t_rec *)((unsigned long)meta[i]->data -
                                   tbufs_phys + (unsigned long)tbufs_mapped);

    return data;
}

/**
 * init_tail_idxs - initialise an array of tail indexes
 * @bufs:           array of pointers to trace buffer metadata in struct t_buf's
 *
 * The tail indexes indicate where we're read to so far in the data array of a
 * trace buffer.  Each entry in this table corresponds to the tail index for a
 * particular trace buffer.
 */
int *init_tail_idxs(struct t_buf **bufs)
{
    int i;
    int *tails = calloc(opts.num_cpus, sizeof(unsigned int));
 
    if ( tails == NULL )
    {
        PERROR("Failed to allocate memory for tail pointers\n");
        exit(EXIT_FAILURE);
    }
    
    for ( i = 0; i<opts.num_cpus; i++ )
        tails[i] = bufs[i]->head;

    return tails;
}


/**
 * monitor_tbufs - monitor the contents of tbufs and output to a file
 * @logfile:       the FILE * representing the file to log to
 */
int monitor_tbufs(FILE *logfile)
{
    int i, j;
    void *tbufs_mapped;          /* pointer to where the tbufs are mapped    */
    struct t_buf **meta;         /* pointers to the trace buffer metadata    */
    struct t_rec **data;         /* pointers to the trace buffer data areas
                                  * where they are mapped into user space.   */
    int *tails;                  /* store tail indexes for the trace buffers */
    unsigned long tbufs_phys;    /* physical address of the tbufs            */
    
    /* setup access to trace buffers */
    tbufs_phys   = get_tbuf_ptrs();
    tbufs_mapped = map_tbufs(tbufs_phys);

    /* build arrays of convenience ptrs */
    meta  = init_bufs_ptrs (tbufs_mapped);
    data  = init_rec_ptrs  (tbufs_phys, tbufs_mapped, meta);
    tails = init_tail_idxs (meta);

    /* now, scan buffers for events */
    while ( !interrupted )
    {
        for ( i = 0; i < opts.num_cpus; i++ )
        {
            signed long newdata = meta[i]->head - tails[i];
            signed long prewrap = newdata;

	    /* correct newdata and prewrap in case of a pointer wrap */
            if ( newdata < 0 )
            {
                newdata += meta[i]->size;
                prewrap  = meta[i]->size - tails[i];
            }

            if ( newdata >= opts.new_data_thresh )
            {
                /* output pre-wrap data */
                for(j = 0; j < prewrap; j++)
                    print_rec(i, data[i] + tails[i] + j, logfile);
                
                /* output post-wrap data, if any */                    
                for(j = 0; j < (newdata - prewrap); j++)
                    print_rec(i, data[i] + j, logfile);  
                
                tails[i] += newdata;
                if(tails[i] >= meta[i]->size) tails[i] = 0;
            }
        }
        nanosleep(&opts.poll_sleep, NULL);
    }

    /* cleanup */
    free(meta);
    free(data);
    free(tails);
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

    case 'n': /* set number of CPU trace buffers to map */
    {
        char *inval;
        setup->num_cpus = strtol(arg, &inval, 0);
        if (inval == arg )
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

    { .name = "num-cpus", .key = 'n', .arg="i",
      .doc = 
      "Set number, i, of CPU trace buffers to map.  This should not exceed "
      "the number of CPUs in the system (default " xstr(NUM_CPUS) ")." },

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
    "output as space-separated decimal numbers, represented in ASCII, in "
    "the following order:\n\n"
    "  CPU TSC EVENT DATA1 DATA2 DATA3 DATA4 DATA5\n"
};


const char *argp_program_version     = "xentrace v1.0";
const char *argp_program_bug_address = "<mark.a.williamson@intel.com>";
        
    
int main(int argc, char **argv)
{
    int ret;
    FILE *logfile = stdout;

    const struct sigaction act = { .sa_handler = close_handler };

    opts.outfile = 0;
    opts.num_cpus = 1;
    opts.poll_sleep = millis_to_timespec(POLL_SLEEP_MILLIS);
    opts.new_data_thresh = NEW_DATA_THRESH;

    argp_parse(&parser_def, argc, argv, 0, 0, &opts);

    if ( opts.outfile )
        logfile = fopen(opts.outfile, "w");
    
    /* ensure that if we get a signal, we'll do cleanup, then exit */
    sigaction(SIGHUP,  &act, 0);
    sigaction(SIGTERM, &act, 0);
    sigaction(SIGINT,  &act, 0);

    ret = monitor_tbufs(logfile);

    return ret;
}
