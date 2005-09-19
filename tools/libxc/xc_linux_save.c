/******************************************************************************
 * xc_linux_save.c
 * 
 * Save the state of a running Linux session.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include <inttypes.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include "xg_private.h"

#define BATCH_SIZE 1024   /* 1024 pages (4MB) at a time */

#define MAX_MBIT_RATE 500

/*
** Default values for important tuning parameters. Can override by passing
** non-zero replacement values to xc_linux_save().  
**
** XXX SMH: should consider if want to be able to override MAX_MBIT_RATE too. 
** 
*/
#define DEF_MAX_ITERS   29   /* limit us to 30 times round loop */ 
#define DEF_MAX_FACTOR   3   /* never send more than 3x nr_pfns */

/* Flags to control behaviour of xc_linux_save */
#define XCFLAGS_LIVE      1
#define XCFLAGS_DEBUG     2

#define DEBUG 0

#if 1
#define ERR(_f, _a...) do { fprintf(stderr, _f , ## _a); fflush(stderr); } while (0)
#else
#define ERR(_f, _a...) ((void)0)
#endif

#if DEBUG
#define DPRINTF(_f, _a...) fprintf ( stderr, _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

#define PROGRESS 0
#if PROGRESS
#define PPRINTF(_f, _a...) fprintf ( stderr, _f , ## _a )
#else
#define PPRINTF(_f, _a...)
#endif

/*
 * Returns TRUE if the given machine frame number has a unique mapping
 * in the guest's pseudophysical map.
 */

#define MFN_IS_IN_PSEUDOPHYS_MAP(_mfn)                                    \
    (((_mfn) < (1024*1024)) &&                                            \
     ((live_mfn_to_pfn_table[_mfn] < nr_pfns) &&                         \
       (live_pfn_to_mfn_table[live_mfn_to_pfn_table[_mfn]] == (_mfn))))

 
/* Returns TRUE if MFN is successfully converted to a PFN. */
#define translate_mfn_to_pfn(_pmfn)            \
({                                             \
    unsigned long mfn = *(_pmfn);              \
    int _res = 1;                              \
    if ( !MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )      \
        _res = 0;                              \
    else                                       \
        *(_pmfn) = live_mfn_to_pfn_table[mfn]; \
    _res;                                      \
})

#define is_mapped(pfn) (!((pfn) & 0x80000000UL))

static inline int test_bit ( int nr, volatile void * addr)
{
    return (((unsigned long*)addr)[nr/(sizeof(unsigned long)*8)] >> 
            (nr % (sizeof(unsigned long)*8))) & 1;
}

static inline void clear_bit ( int nr, volatile void * addr)
{
    ((unsigned long*)addr)[nr/(sizeof(unsigned long)*8)] &= 
        ~(1 << (nr % (sizeof(unsigned long)*8) ) );
}

static inline void set_bit ( int nr, volatile void * addr)
{
    ((unsigned long*)addr)[nr/(sizeof(unsigned long)*8)] |= 
        (1 << (nr % (sizeof(unsigned long)*8) ) );
}

/* Returns the hamming weight (i.e. the number of bits set) in a N-bit word */
static inline unsigned int hweight32(unsigned int w)
{
    unsigned int res = (w & 0x55555555) + ((w >> 1) & 0x55555555);
    res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
    res = (res & 0x0F0F0F0F) + ((res >> 4) & 0x0F0F0F0F);
    res = (res & 0x00FF00FF) + ((res >> 8) & 0x00FF00FF);
    return (res & 0x0000FFFF) + ((res >> 16) & 0x0000FFFF);
}

static inline int count_bits ( int nr, volatile void *addr)
{
    int i, count = 0;
    unsigned long *p = (unsigned long *)addr;
    /* We know that the array is padded to unsigned long. */
    for( i = 0; i < (nr / (sizeof(unsigned long)*8)); i++, p++ )
        count += hweight32(*p);
    return count;
}

static inline int permute( int i, int nr, int order_nr  )
{
    /* Need a simple permutation function so that we scan pages in a
       pseudo random order, enabling us to get a better estimate of
       the domain's page dirtying rate as we go (there are often 
       contiguous ranges of pfns that have similar behaviour, and we
       want to mix them up. */

    /* e.g. nr->oder 15->4 16->4 17->5 */
    /* 512MB domain, 128k pages, order 17 */

    /*
      QPONMLKJIHGFEDCBA  
             QPONMLKJIH  
      GFEDCBA  
     */
    
    /*
      QPONMLKJIHGFEDCBA  
                  EDCBA  
             QPONM
      LKJIHGF
      */

    do { i = ((i>>(order_nr-10)) | ( i<<10 ) ) & ((1<<order_nr)-1); }
    while ( i >= nr ); /* this won't ever loop if nr is a power of 2 */

    return i;
}

static long long tv_to_us( struct timeval *new )
{
    return (new->tv_sec * 1000000) + new->tv_usec;
}

static long long llgettimeofday( void )
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return tv_to_us(&now);
}

static long long tv_delta( struct timeval *new, struct timeval *old )
{
    return ((new->tv_sec - old->tv_sec)*1000000 ) + 
        (new->tv_usec - old->tv_usec);
}


#define START_MBIT_RATE 0 //ioctxt->resource

static int mbit_rate, ombit_rate = 0;
static int burst_time_us = -1;

#define MBIT_RATE mbit_rate
#define BURST_BUDGET (100*1024)

/* 
   1000000/((100)*1024*1024/8/(100*1024))
   7812
   1000000/((100)*1024/8/(100))
   7812
   1000000/((100)*128/(100))
   7812
   100000000/((100)*128)
   7812
   100000000/128
   781250
 */
#define RATE_TO_BTU 781250
#define BURST_TIME_US burst_time_us

static int
ratewrite(int io_fd, void *buf, int n)
{
    static int budget = 0;
    static struct timeval last_put = { 0 };
    struct timeval now;
    struct timespec delay;
    long long delta;

    if ( START_MBIT_RATE == 0 )
        return write(io_fd, buf, n);
    
    budget -= n;
    if ( budget < 0 )
    {
        if ( MBIT_RATE != ombit_rate )
        {
            BURST_TIME_US = RATE_TO_BTU / MBIT_RATE;
            ombit_rate = MBIT_RATE;
            DPRINTF("rate limit: %d mbit/s burst budget %d slot time %d\n",
                    MBIT_RATE, BURST_BUDGET, BURST_TIME_US);
        }
        if ( last_put.tv_sec == 0 )
        {
            budget += BURST_BUDGET;
            gettimeofday(&last_put, NULL);
        }
        else
        {
            while ( budget < 0 )
            {
                gettimeofday(&now, NULL);
                delta = tv_delta(&now, &last_put);
                while ( delta > BURST_TIME_US )
                {
                    budget += BURST_BUDGET;
                    last_put.tv_usec += BURST_TIME_US;
                    if ( last_put.tv_usec > 1000000 )
                    {
                        last_put.tv_usec -= 1000000;
                        last_put.tv_sec++;
                    }
                    delta -= BURST_TIME_US;
                }
                if ( budget > 0 )
                    break;
                delay.tv_sec = 0;
                delay.tv_nsec = 1000 * (BURST_TIME_US - delta);
                while ( delay.tv_nsec > 0 )
                    if ( nanosleep(&delay, &delay) == 0 )
                        break;
            }
        }
    }
    return write(io_fd, buf, n);
}

static int print_stats( int xc_handle, u32 domid, 
                        int pages_sent, xc_shadow_control_stats_t *stats,
                        int print )
{
    static struct timeval wall_last;
    static long long      d0_cpu_last;
    static long long      d1_cpu_last;

    struct timeval        wall_now;
    long long             wall_delta;
    long long             d0_cpu_now, d0_cpu_delta;
    long long             d1_cpu_now, d1_cpu_delta;

    gettimeofday(&wall_now, NULL);

    d0_cpu_now = xc_domain_get_cpu_usage(xc_handle, 0, /* FIXME */ 0)/1000;
    d1_cpu_now = xc_domain_get_cpu_usage(xc_handle, domid, /* FIXME */ 0)/1000;

    if ( (d0_cpu_now == -1) || (d1_cpu_now == -1) ) 
        fprintf(stderr, "ARRHHH!!\n");

    wall_delta = tv_delta(&wall_now,&wall_last)/1000;

    if ( wall_delta == 0 ) wall_delta = 1;

    d0_cpu_delta  = (d0_cpu_now - d0_cpu_last)/1000;
    d1_cpu_delta  = (d1_cpu_now - d1_cpu_last)/1000;

    if ( print )
        fprintf(stderr,
                "delta %lldms, dom0 %d%%, target %d%%, sent %dMb/s, "
                "dirtied %dMb/s %" PRId32 " pages\n",
                wall_delta, 
                (int)((d0_cpu_delta*100)/wall_delta),
                (int)((d1_cpu_delta*100)/wall_delta),
                (int)((pages_sent*PAGE_SIZE)/(wall_delta*(1000/8))),
                (int)((stats->dirty_count*PAGE_SIZE)/(wall_delta*(1000/8))),
                stats->dirty_count);

    if ( ((stats->dirty_count*PAGE_SIZE)/(wall_delta*(1000/8))) > mbit_rate )
    {
        mbit_rate = (int)((stats->dirty_count*PAGE_SIZE)/(wall_delta*(1000/8)))
            + 50;
        if (mbit_rate > MAX_MBIT_RATE)
            mbit_rate = MAX_MBIT_RATE;
    }

    d0_cpu_last  = d0_cpu_now;
    d1_cpu_last  = d1_cpu_now;
    wall_last = wall_now; 

    return 0;
}

static int analysis_phase( int xc_handle, u32 domid, 
                           int nr_pfns, unsigned long *arr, int runs )
{
    long long start, now;
    xc_shadow_control_stats_t stats;
    int j;

    start = llgettimeofday();

    for ( j = 0; j < runs; j++ )
    {
        int i;

        xc_shadow_control( xc_handle, domid, 
                           DOM0_SHADOW_CONTROL_OP_CLEAN,
                           arr, nr_pfns, NULL);
        fprintf(stderr, "#Flush\n");
        for ( i = 0; i < 40; i++ )
        {     
            usleep(50000);     
            now = llgettimeofday();
            xc_shadow_control( xc_handle, domid, 
                               DOM0_SHADOW_CONTROL_OP_PEEK,
                               NULL, 0, &stats);

            fprintf(stderr, "now= %lld faults= %" PRId32 " dirty= %" PRId32
                    " dirty_net= %" PRId32 " dirty_block= %" PRId32"\n", 
                    ((now-start)+500)/1000, 
                    stats.fault_count, stats.dirty_count,
                    stats.dirty_net_count, stats.dirty_block_count);
        }
    }

    return -1;
}


static int suspend_and_state(int xc_handle, int io_fd, int dom,       
                             xc_dominfo_t *info,
                             vcpu_guest_context_t *ctxt)
{
    int i = 0;
    char ans[30];

    printf("suspend\n");
    fflush(stdout);
    if ( fgets(ans, sizeof(ans), stdin) == NULL )
    {
        ERR("failed reading suspend reply");
        return -1;
    }
    if ( strncmp(ans, "done\n", 5) )
    {
        ERR("suspend reply incorrect: %s", ans);
        return -1;
    }

 retry:

    if ( xc_domain_getinfo(xc_handle, dom, 1, info) != 1)
    {
        ERR("Could not get domain info");
        return -1;
    }

    if ( xc_domain_get_vcpu_context(xc_handle, dom, 0 /* XXX */, 
                                    ctxt) )
    {
        ERR("Could not get vcpu context");
    }

    if ( info->shutdown && info->shutdown_reason == SHUTDOWN_suspend )
    {
        return 0; // success
    }

    if ( info->paused )
    {
        // try unpausing domain, wait, and retest 
        xc_domain_unpause( xc_handle, dom );

        ERR("Domain was paused. Wait and re-test.");
        usleep(10000);  // 10ms

        goto retry;
    }


    if( ++i < 100 )
    {
        ERR("Retry suspend domain.");
        usleep(10000);  // 10ms 
        goto retry;
    }

    ERR("Unable to suspend domain.");

    return -1;
}

int xc_linux_save(int xc_handle, int io_fd, u32 dom, u32 max_iters, 
                  u32 max_factor, u32 flags)
{
    xc_dominfo_t info;

    int rc = 1, i, j, k, last_iter, iter = 0;
    unsigned long mfn;
    int live  = (flags & XCFLAGS_LIVE); 
    int debug = (flags & XCFLAGS_DEBUG); 
    int sent_last_iter, skip_this_iter;

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;
    
    /* A copy of the CPU context of the guest. */
    vcpu_guest_context_t ctxt;

    /* A table containg the type of each PFN (/not/ MFN!). */
    unsigned long *pfn_type = NULL;
    unsigned long *pfn_batch = NULL;

    /* A temporary mapping, and a copy, of one frame of guest memory. */
    unsigned long page[1024];

    /* A copy of the pfn-to-mfn table frame list. */
    unsigned long *live_pfn_to_mfn_frame_list_list = NULL;
    unsigned long *live_pfn_to_mfn_frame_list = NULL;
    unsigned long pfn_to_mfn_frame_list[1024];

    /* Live mapping of the table mapping each PFN to its current MFN. */
    unsigned long *live_pfn_to_mfn_table = NULL;
    /* Live mapping of system MFN to PFN table. */
    unsigned long *live_mfn_to_pfn_table = NULL;
    unsigned long mfn_to_pfn_table_start_mfn;
    
    /* Live mapping of shared info structure */
    shared_info_t *live_shinfo = NULL;

    /* base of the region in which domain memory is mapped */
    unsigned char *region_base = NULL;

    /* number of pages we're dealing with */
    unsigned long nr_pfns;

    /* power of 2 order of nr_pfns */
    int order_nr; 

    /* bitmap of pages:
       - that should be sent this iteration (unless later marked as skip); 
       - to skip this iteration because already dirty;
       - to fixup by sending at the end if not already resent; */
    unsigned long *to_send = NULL, *to_skip = NULL, *to_fix = NULL;
    
    xc_shadow_control_stats_t stats;

    int needed_to_fix = 0;
    int total_sent    = 0;

    MBIT_RATE = START_MBIT_RATE;


    /* If no explicit control parameters given, use defaults */
    if( !max_iters ) 
        max_iters = DEF_MAX_ITERS; 
    if( !max_factor ) 
        max_factor = DEF_MAX_FACTOR; 


    DPRINTF("xc_linux_save start DOM%u live=%s\n", dom, live?"true":"false"); 

    if ( mlock(&ctxt, sizeof(ctxt)) ) 
    {
        ERR("Unable to mlock ctxt");
        return 1;
    }
    
    if ( xc_domain_getinfo(xc_handle, dom, 1, &info) != 1 )
    {
        ERR("Could not get domain info");
        goto out;
    }
    if ( xc_domain_get_vcpu_context(xc_handle, dom, /* FIXME */ 0, &ctxt) )
    {
        ERR("Could not get vcpu context");
        goto out;
    }
    shared_info_frame = info.shared_info_frame;

    /* A cheesy test to see whether the domain contains valid state. */
    if ( ctxt.ctrlreg[3] == 0 )
    {
        ERR("Domain is not in a valid Linux guest OS state");
        goto out;
    }
    
    nr_pfns = info.max_memkb >> (PAGE_SHIFT - 10);

    /* cheesy sanity check */
    if ( nr_pfns > 1024*1024 )
    {
        ERR("Invalid state record -- pfn count out of range: %lu", nr_pfns);
        goto out;
    }

    /* Map the shared info frame */
    live_shinfo = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_READ, shared_info_frame);
    if ( !live_shinfo )
    {
        ERR("Couldn't map live_shinfo");
        goto out;
    }

    live_pfn_to_mfn_frame_list_list = xc_map_foreign_range(
        xc_handle, dom,
        PAGE_SIZE, PROT_READ, live_shinfo->arch.pfn_to_mfn_frame_list_list);

    if (!live_pfn_to_mfn_frame_list_list){
        ERR("Couldn't map pfn_to_mfn_frame_list_list");
        goto out;
    }

    live_pfn_to_mfn_frame_list = 
        xc_map_foreign_batch(xc_handle, dom, 
                             PROT_READ,
                             live_pfn_to_mfn_frame_list_list,
                             (nr_pfns+(1024*1024)-1)/(1024*1024) );

    if ( !live_pfn_to_mfn_frame_list)
    {
        ERR("Couldn't map pfn_to_mfn_frame_list");
        goto out;
    }


    /* Map all the frames of the pfn->mfn table. For migrate to succeed, 
       the guest must not change which frames are used for this purpose. 
       (its not clear why it would want to change them, and we'll be OK
       from a safety POV anyhow. */

    live_pfn_to_mfn_table = xc_map_foreign_batch(xc_handle, dom, 
                                                 PROT_READ,
                                                 live_pfn_to_mfn_frame_list,
                                                 (nr_pfns+1023)/1024 );  
    if ( !live_pfn_to_mfn_table )
    {
        ERR("Couldn't map pfn_to_mfn table");
        goto out;
    }

    /* Setup the mfn_to_pfn table mapping */
    mfn_to_pfn_table_start_mfn = xc_get_m2p_start_mfn( xc_handle );

    live_mfn_to_pfn_table = 
        xc_map_foreign_range(xc_handle, DOMID_XEN, 
                             PAGE_SIZE*1024, PROT_READ, 
                             mfn_to_pfn_table_start_mfn );

    /* Canonicalise the pfn-to-mfn table frame-number list. */
    memcpy( pfn_to_mfn_frame_list, live_pfn_to_mfn_frame_list, PAGE_SIZE );

    for ( i = 0; i < nr_pfns; i += 1024 )
    {
        if ( !translate_mfn_to_pfn(&pfn_to_mfn_frame_list[i/1024]) )
        {
            ERR("Frame# in pfn-to-mfn frame list is not in pseudophys");
            goto out;
        }
    }


    /* Domain is still running at this point */

    if ( live )
    {
        if ( xc_shadow_control( xc_handle, dom, 
                                DOM0_SHADOW_CONTROL_OP_ENABLE_LOGDIRTY,
                                NULL, 0, NULL ) < 0 )
        {
            ERR("Couldn't enable shadow mode");
            goto out;
        }

        last_iter = 0;
    } 
    else
    {
        /* This is a non-live suspend. Issue the call back to get the
           domain suspended */

        last_iter = 1;

        if ( suspend_and_state( xc_handle, io_fd, dom, &info, &ctxt) )
        {
            ERR("Domain appears not to have suspended");
            goto out;
        }

    }
    sent_last_iter = 1<<20; /* 4GB of pages */

    /* calculate the power of 2 order of nr_pfns, e.g.
       15->4 16->4 17->5 */
    for ( i = nr_pfns-1, order_nr = 0; i ; i >>= 1, order_nr++ )
        continue;

    /* Setup to_send bitmap */
    {
        /* size these for a maximal 4GB domain, to make interaction
           with balloon driver easier. It's only user space memory,
           ater all... (3x 128KB) */

        int sz = ( 1<<20 ) / 8;
 
        to_send = malloc( sz );
        to_fix  = calloc( 1, sz );
        to_skip = malloc( sz );

        if ( !to_send || !to_fix || !to_skip )
        {
            ERR("Couldn't allocate to_send array");
            goto out;
        }

        memset(to_send, 0xff, sz);

        if ( mlock(to_send, sz) )
        {
            ERR("Unable to mlock to_send");
            return 1;
        }

        /* (to fix is local only) */

        if ( mlock(to_skip, sz) )
        {
            ERR("Unable to mlock to_skip");
            return 1;
        }

    }

    analysis_phase( xc_handle, dom, nr_pfns, to_skip, 0 );

    /* We want zeroed memory so use calloc rather than malloc. */
    pfn_type = calloc(BATCH_SIZE, sizeof(unsigned long));
    pfn_batch = calloc(BATCH_SIZE, sizeof(unsigned long));

    if ( (pfn_type == NULL) || (pfn_batch == NULL) )
    {
        errno = ENOMEM;
        goto out;
    }

    if ( mlock(pfn_type, BATCH_SIZE * sizeof(unsigned long)) )
    {
        ERR("Unable to mlock");
        goto out;
    }


    /*
     * Quick belt and braces sanity check.
     */
#if DEBUG
    {
        int err=0;
        for ( i = 0; i < nr_pfns; i++ )
        {
            mfn = live_pfn_to_mfn_table[i];
     
            if( (live_mfn_to_pfn_table[mfn] != i) && (mfn != 0xffffffffUL) )
            {
                fprintf(stderr, "i=0x%x mfn=%lx live_mfn_to_pfn_table=%lx\n",
                        i,mfn,live_mfn_to_pfn_table[mfn]);
                err++;
            }
        }
        fprintf(stderr, "Had %d unexplained entries in p2m table\n",err);
    }
#endif


    /* Start writing out the saved-domain record. */

    if ( write(io_fd, &nr_pfns, sizeof(unsigned long)) !=
         sizeof(unsigned long) )
    {
        ERR("write: nr_pfns");
        goto out;
    }

    if ( write(io_fd, pfn_to_mfn_frame_list, PAGE_SIZE) != PAGE_SIZE )
    {
        ERR("write: pfn_to_mfn_frame_list");
        goto out;
    }

    print_stats( xc_handle, dom, 0, &stats, 0 );

    /* Now write out each data page, canonicalising page tables as we go... */
    
    for ( ; ; )
    {
        unsigned int prev_pc, sent_this_iter, N, batch;

        iter++;
        sent_this_iter = 0;
        skip_this_iter = 0;
        prev_pc = 0;
        N=0;

        DPRINTF("Saving memory pages: iter %d   0%%", iter);

        while ( N < nr_pfns )
        {
            unsigned int this_pc = (N * 100) / nr_pfns;

            if ( (this_pc - prev_pc) >= 5 )
            {
                DPRINTF("\b\b\b\b%3d%%", this_pc);
                prev_pc = this_pc;
            }

            /* slightly wasteful to peek the whole array evey time, 
               but this is fast enough for the moment. */

            if ( !last_iter && 
                 xc_shadow_control(xc_handle, dom, 
                                   DOM0_SHADOW_CONTROL_OP_PEEK,
                                   to_skip, nr_pfns, NULL) != nr_pfns )
            {
                ERR("Error peeking shadow bitmap");
                goto out;
            }
     

            /* load pfn_type[] with the mfn of all the pages we're doing in
               this batch. */

            for ( batch = 0; batch < BATCH_SIZE && N < nr_pfns ; N++ )
            {
                int n = permute(N, nr_pfns, order_nr );

                if ( 0 && debug ) {
                    fprintf(stderr,"%d pfn= %08lx mfn= %08lx %d  "
                            " [mfn]= %08lx\n",
                            iter, (unsigned long)n, live_pfn_to_mfn_table[n],
                            test_bit(n,to_send),
                            live_mfn_to_pfn_table[live_pfn_to_mfn_table[n]&
                                                 0xFFFFF]);
                }

                if ( !last_iter && 
                     test_bit(n, to_send) && 
                     test_bit(n, to_skip) ) {
                    skip_this_iter++; /* stats keeping */
                }

                if ( !((test_bit(n, to_send) && !test_bit(n, to_skip)) ||
                       (test_bit(n, to_send) && last_iter) ||
                       (test_bit(n, to_fix)  && last_iter)) ) {
                    continue;
                }

                /* we get here if:
                   1. page is marked to_send & hasn't already been re-dirtied
                   2. (ignore to_skip in last iteration)
                   3. add in pages that still need fixup (net bufs)
                */
  
                pfn_batch[batch] = n;
                pfn_type[batch] = live_pfn_to_mfn_table[n];

                if( ! is_mapped(pfn_type[batch]) )
                {
                    /* not currently in pusedo-physical map -- set bit
                       in to_fix that we must send this page in last_iter
                       unless its sent sooner anyhow */

                    set_bit( n, to_fix );
                    if( iter>1 )
                        DPRINTF("netbuf race: iter %d, pfn %x. mfn %lx\n",
                                iter,n,pfn_type[batch]);
                    continue;
                }

                if ( last_iter && 
                     test_bit(n, to_fix) && 
                     !test_bit(n, to_send) )
                {
                    needed_to_fix++;
                    DPRINTF("Fix! iter %d, pfn %x. mfn %lx\n",
                            iter,n,pfn_type[batch]);
                }

                clear_bit(n, to_fix); 

                batch++;
            }
     
            if ( batch == 0 )
                goto skip; /* vanishingly unlikely... */
      
            if ( (region_base = xc_map_foreign_batch(xc_handle, dom, 
                                                     PROT_READ,
                                                     pfn_type,
                                                     batch)) == 0 ){
                ERR("map batch failed");
                goto out;
            }
     
            if ( xc_get_pfn_type_batch(xc_handle, dom, batch, pfn_type) ){
                ERR("get_pfn_type_batch failed");
                goto out;
            }
     
            for ( j = 0; j < batch; j++ )
            {
                if ( (pfn_type[j] & LTAB_MASK) == XTAB )
                {
                    DPRINTF("type fail: page %i mfn %08lx\n",j,pfn_type[j]);
                    continue;
                }
  
                if ( 0 && debug )
                    fprintf(stderr, "%d pfn= %08lx mfn= %08lx [mfn]= %08lx"
                            " sum= %08lx\n",
                            iter, 
                            (pfn_type[j] & LTAB_MASK) | pfn_batch[j],
                            pfn_type[j],
                            live_mfn_to_pfn_table[pfn_type[j]&(~LTAB_MASK)],
                            csum_page(region_base + (PAGE_SIZE*j)));

                /* canonicalise mfn->pfn */
                pfn_type[j] = (pfn_type[j] & LTAB_MASK) | pfn_batch[j];
            }

            if ( write(io_fd, &batch, sizeof(int)) != sizeof(int) )
            {
                ERR("Error when writing to state file (2)");
                goto out;
            }

            if ( write(io_fd, pfn_type, sizeof(unsigned long)*j) !=
                 (sizeof(unsigned long) * j) )
            {
                ERR("Error when writing to state file (3)");
                goto out;
            }
     
            /* entering this loop, pfn_type is now in pfns (Not mfns) */
            for ( j = 0; j < batch; j++ )
            {
                /* write out pages in batch */
                if ( (pfn_type[j] & LTAB_MASK) == XTAB )
                {
                    DPRINTF("SKIP BOGUS page %i mfn %08lx\n",j,pfn_type[j]);
                    continue;
                }
  
                if ( ((pfn_type[j] & LTABTYPE_MASK) == L1TAB) || 
                     ((pfn_type[j] & LTABTYPE_MASK) == L2TAB) ){
                    memcpy(page, region_base + (PAGE_SIZE*j), PAGE_SIZE);
      
                    for ( k = 0; 
                          k < (((pfn_type[j] & LTABTYPE_MASK) == L2TAB) ? 
                               (HYPERVISOR_VIRT_START >> L2_PAGETABLE_SHIFT) :
                               1024); 
                          k++ )
                    {
                        unsigned long pfn;

                        if ( !(page[k] & _PAGE_PRESENT) )
                            continue;
                        
                        mfn = page[k] >> PAGE_SHIFT;      
                        pfn = live_mfn_to_pfn_table[mfn];

                        if ( !MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )
                        {
                            /* I don't think this should ever happen */
                            fprintf(stderr, "FNI %d : [%08lx,%d] pte=%08lx, "
                                    "mfn=%08lx, pfn=%08lx [mfn]=%08lx\n",
                                    j, pfn_type[j], k,
                                    page[k], mfn, live_mfn_to_pfn_table[mfn],
                                    (live_mfn_to_pfn_table[mfn]<nr_pfns)? 
                                    live_pfn_to_mfn_table[
                                        live_mfn_to_pfn_table[mfn]] : 
                                    0xdeadbeef);

                            pfn = 0; /* be suspicious */
                        }

                        page[k] &= PAGE_SIZE - 1;
                        page[k] |= pfn << PAGE_SHIFT;
   
#if 0
                        fprintf(stderr,
                                "L%d i=%d pfn=%d mfn=%d k=%d pte=%08lx "
                                "xpfn=%d\n",
                                pfn_type[j]>>28,
                                j,i,mfn,k,page[k],page[k]>>PAGE_SHIFT);
#endif     
   
                    } /* end of page table rewrite for loop */
      
                    if (ratewrite(io_fd, page, PAGE_SIZE) != PAGE_SIZE) {
                        ERR("Error when writing to state file (4)");
                        goto out;
                    }
      
                }  /* end of it's a PT page */ else {  /* normal page */

                    if ( ratewrite(io_fd, region_base + (PAGE_SIZE*j), 
                                   PAGE_SIZE) != PAGE_SIZE )
                    {
                        ERR("Error when writing to state file (5)");
                        goto out;
                    }
                }
            } /* end of the write out for this batch */
     
            sent_this_iter += batch;

        } /* end of this while loop for this iteration */

        munmap(region_base, batch*PAGE_SIZE);

    skip: 

        total_sent += sent_this_iter;

        DPRINTF("\r %d: sent %d, skipped %d, ", 
                iter, sent_this_iter, skip_this_iter );

        if ( last_iter ) {
            print_stats( xc_handle, dom, sent_this_iter, &stats, 1);

            DPRINTF("Total pages sent= %d (%.2fx)\n", 
                    total_sent, ((float)total_sent)/nr_pfns );
            DPRINTF("(of which %d were fixups)\n", needed_to_fix  );
        }       

        if (last_iter && debug){
            int minusone = -1;
            memset( to_send, 0xff, (nr_pfns+8)/8 );
            debug = 0;
            fprintf(stderr, "Entering debug resend-all mode\n");
    
            /* send "-1" to put receiver into debug mode */
            if (write(io_fd, &minusone, sizeof(int)) != sizeof(int)) {
                ERR("Error when writing to state file (6)");
                goto out;
            }

            continue;
        }

        if ( last_iter ) break; 

        if ( live )
        {
            if ( 
                ( ( sent_this_iter > sent_last_iter ) &&
                  (mbit_rate == MAX_MBIT_RATE ) ) ||
                (iter >= max_iters) || 
                (sent_this_iter+skip_this_iter < 50) || 
                (total_sent > nr_pfns*max_factor) )
            {
                DPRINTF("Start last iteration\n");
                last_iter = 1;

                if ( suspend_and_state( xc_handle, io_fd, dom, &info, &ctxt) )
                {
                    ERR("Domain appears not to have suspended");
                    goto out;
                }

                DPRINTF("SUSPEND shinfo %08lx eip %08u esi %08u\n",
                        info.shared_info_frame,
                        ctxt.user_regs.eip, ctxt.user_regs.esi);
            } 

            if ( xc_shadow_control( xc_handle, dom, 
                                    DOM0_SHADOW_CONTROL_OP_CLEAN,
                                    to_send, nr_pfns, &stats ) != nr_pfns ) 
            {
                ERR("Error flushing shadow PT");
                goto out;
            }

            sent_last_iter = sent_this_iter;

            print_stats( xc_handle, dom, sent_this_iter, &stats, 1);
     
        }


    } /* end of while 1 */

    DPRINTF("All memory is saved\n");

    /* Success! */
    rc = 0;
    
    /* Zero terminate */
    if ( write(io_fd, &rc, sizeof(int)) != sizeof(int) )
    {
        ERR("Error when writing to state file (6)");
        goto out;
    }

    /* Send through a list of all the PFNs that were not in map at the close */
    {
        unsigned int i,j;
        unsigned int pfntab[1024];

        for ( i = 0, j = 0; i < nr_pfns; i++ )
            if ( !is_mapped(live_pfn_to_mfn_table[i]) )
                j++;

        if ( write(io_fd, &j, sizeof(unsigned int)) != sizeof(unsigned int) )
        {
            ERR("Error when writing to state file (6a)");
            goto out;
        } 

        for ( i = 0, j = 0; i < nr_pfns; )
        {
            if ( !is_mapped(live_pfn_to_mfn_table[i]) )
            {
                pfntab[j++] = i;
            }
            i++;
            if ( j == 1024 || i == nr_pfns )
            {
                if ( write(io_fd, &pfntab, sizeof(unsigned long)*j) !=
                     (sizeof(unsigned long) * j) )
                {
                    ERR("Error when writing to state file (6b)");
                    goto out;
                } 
                j = 0;
            }
        }
    }

    /* Canonicalise the suspend-record frame number. */
    if ( !translate_mfn_to_pfn(&ctxt.user_regs.esi) )
    {
        ERR("Suspend record is not in range of pseudophys map");
        goto out;
    }

    /* Canonicalise each GDT frame number. */
    for ( i = 0; i < ctxt.gdt_ents; i += 512 )
    {
        if ( !translate_mfn_to_pfn(&ctxt.gdt_frames[i]) ) 
        {
            ERR("GDT frame is not in range of pseudophys map");
            goto out;
        }
    }

    /* Canonicalise the page table base pointer. */
    if ( !MFN_IS_IN_PSEUDOPHYS_MAP(ctxt.ctrlreg[3] >> PAGE_SHIFT) )
    {
        ERR("PT base is not in range of pseudophys map");
        goto out;
    }
    ctxt.ctrlreg[3] = live_mfn_to_pfn_table[ctxt.ctrlreg[3] >> PAGE_SHIFT] <<
        PAGE_SHIFT;

    if ( write(io_fd, &ctxt, sizeof(ctxt)) != sizeof(ctxt) ||
         write(io_fd, live_shinfo, PAGE_SIZE) != PAGE_SIZE)
    {
        ERR("Error when writing to state file (1)");
        goto out;
    }

 out:

    if ( live_shinfo )
        munmap(live_shinfo, PAGE_SIZE);

    if ( live_pfn_to_mfn_frame_list ) 
        munmap(live_pfn_to_mfn_frame_list, PAGE_SIZE);

    if ( live_pfn_to_mfn_table ) 
        munmap(live_pfn_to_mfn_table, nr_pfns*4);

    if ( live_mfn_to_pfn_table ) 
        munmap(live_mfn_to_pfn_table, PAGE_SIZE*1024);

    free(pfn_type);
    free(pfn_batch);
    free(to_send);
    free(to_fix);
    free(to_skip);

    DPRINTF("Save exit rc=%d\n",rc);
    return !!rc;
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
