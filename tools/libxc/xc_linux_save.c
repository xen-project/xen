/******************************************************************************
 * xc_linux_save.c
 * 
 * Save the state of a running Linux session.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include <inttypes.h>
#include <sys/time.h>
#include "xc_private.h"
#include <xen/linux/suspend.h>
#include <xen/io/domain_controller.h>
#include <time.h>

#define BATCH_SIZE 1024   /* 1024 pages (4MB) at a time */

#define MAX_MBIT_RATE 500

#define DEBUG  0
#define DDEBUG 0

#if DEBUG
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

#if DDEBUG
#define DDPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DDPRINTF(_f, _a...) ((void)0)
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
    for(i=0;i<nr/(sizeof(unsigned long)*8);i++,p++)
        count += hweight32( *p );
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

static long long llgettimeofday()
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


#define START_MBIT_RATE ioctxt->resource

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

static int xcio_ratewrite(XcIOContext *ioctxt, void *buf, int n)
{
    static int budget = 0;
    static struct timeval last_put = { 0 };
    struct timeval now;
    struct timespec delay;
    long long delta;

    if (START_MBIT_RATE == 0)
	return xcio_write(ioctxt, buf, n);
    
    budget -= n;
    if (budget < 0) {
	if (MBIT_RATE != ombit_rate) {
	    BURST_TIME_US = RATE_TO_BTU / MBIT_RATE;
	    ombit_rate = MBIT_RATE;
	    xcio_info(ioctxt,
		      "rate limit: %d mbit/s burst budget %d slot time %d\n",
		      MBIT_RATE, BURST_BUDGET, BURST_TIME_US);
	}
	if (last_put.tv_sec == 0) {
	    budget += BURST_BUDGET;
	    gettimeofday(&last_put, NULL);
	} else {
	    while (budget < 0) {
		gettimeofday(&now, NULL);
		delta = tv_delta(&now, &last_put);
		while (delta > BURST_TIME_US) {
		    budget += BURST_BUDGET;
		    last_put.tv_usec += BURST_TIME_US;
		    if (last_put.tv_usec > 1000000) {
			last_put.tv_usec -= 1000000;
			last_put.tv_sec++;
		    }
		    delta -= BURST_TIME_US;
		}
		if (budget > 0)
		    break;
		delay.tv_sec = 0;
		delay.tv_nsec = 1000 * (BURST_TIME_US - delta);
		while (delay.tv_nsec > 0)
		    if (nanosleep(&delay, &delay) == 0)
			break;
	    }
	}
    }
    return xcio_write(ioctxt, buf, n);
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
        printf("ARRHHH!!\n");

    wall_delta = tv_delta(&wall_now,&wall_last)/1000;

    if ( wall_delta == 0 ) wall_delta = 1;

    d0_cpu_delta  = (d0_cpu_now - d0_cpu_last)/1000;
    d1_cpu_delta  = (d1_cpu_now - d1_cpu_last)/1000;

    if ( print )
        printf("delta %lldms, dom0 %d%%, target %d%%, sent %dMb/s, "
               "dirtied %dMb/s %" PRId32 " pages\n",
               wall_delta, 
               (int)((d0_cpu_delta*100)/wall_delta),
               (int)((d1_cpu_delta*100)/wall_delta),
               (int)((pages_sent*PAGE_SIZE)/(wall_delta*(1000/8))),
               (int)((stats->dirty_count*PAGE_SIZE)/(wall_delta*(1000/8))),
               stats->dirty_count);

    if (((stats->dirty_count*PAGE_SIZE)/(wall_delta*(1000/8))) > mbit_rate) {
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

/** Write the vmconfig string.
 * It is stored as a 4-byte count 'n' followed by n bytes.
 *
 * @param ioctxt i/o context
 * @return 0 on success, non-zero on error.
 */
static int write_vmconfig(XcIOContext *ioctxt)
{
    int err = -1;
    if(xcio_write(ioctxt, &ioctxt->vmconfig_n, sizeof(ioctxt->vmconfig_n))) 
        goto exit;
    if(xcio_write(ioctxt, ioctxt->vmconfig, ioctxt->vmconfig_n)) 
        goto exit;
    err = 0;
  exit:
    return err;
}

static int analysis_phase( int xc_handle, u32 domid, 
                           int nr_pfns, unsigned long *arr, int runs )
{
    long long start, now;
    xc_shadow_control_stats_t stats;
    int j;

    start = llgettimeofday();

    for (j = 0; j < runs; j++)
    {
        int i;

        xc_shadow_control( xc_handle, domid, 
                           DOM0_SHADOW_CONTROL_OP_CLEAN,
                           arr, nr_pfns, NULL);
        printf("#Flush\n");
        for ( i = 0; i < 40; i++ )
        {     
            usleep(50000);     
            now = llgettimeofday();
            xc_shadow_control( xc_handle, domid, 
                               DOM0_SHADOW_CONTROL_OP_PEEK,
                               NULL, 0, &stats);

            printf("now= %lld faults= %" PRId32 " dirty= %" PRId32
                   " dirty_net= %" PRId32 " dirty_block= %" PRId32"\n", 
                   ((now-start)+500)/1000, 
                   stats.fault_count, stats.dirty_count,
                   stats.dirty_net_count, stats.dirty_block_count);
        }
    }

    return -1;
}


int suspend_and_state(int xc_handle, XcIOContext *ioctxt,		      
                      xc_dominfo_t *info,
                      vcpu_guest_context_t *ctxt)
{
    int i=0;
    
    xcio_suspend_domain(ioctxt);

retry:

    if ( xc_domain_getinfo(xc_handle, ioctxt->domain, 1, info) )
    {
	xcio_error(ioctxt, "Could not get full domain info");
	return -1;
    }

    if ( xc_domain_get_vcpu_context(xc_handle, ioctxt->domain, 0 /* XXX */, 
				    ctxt) )
    {
        xcio_error(ioctxt, "Could not get vcpu context");
    }

    if ( (info->flags & 
          (DOMFLAGS_SHUTDOWN | (SHUTDOWN_suspend<<DOMFLAGS_SHUTDOWNSHIFT))) ==
         (DOMFLAGS_SHUTDOWN | (SHUTDOWN_suspend<<DOMFLAGS_SHUTDOWNSHIFT)) )
    {
	return 0; // success
    }

    if ( info->flags & DOMFLAGS_PAUSED )
    {
	// try unpausing domain, wait, and retest	
	xc_domain_unpause( xc_handle, ioctxt->domain );

	xcio_error(ioctxt, "Domain was paused. Wait and re-test. (%u)",
		   info->flags);
	usleep(10000);  // 10ms

	goto retry;
    }


    if( ++i < 100 )
    {
	xcio_error(ioctxt, "Retry suspend domain (%u)", info->flags);
	usleep(10000);  // 10ms	
	goto retry;
    }

    xcio_error(ioctxt, "Unable to suspend domain. (%u)", info->flags);

    return -1;
}

int xc_linux_save(int xc_handle, XcIOContext *ioctxt)
{
    xc_dominfo_t info;

    int rc = 1, i, j, k, last_iter, iter = 0;
    unsigned long mfn;
    u32 domid = ioctxt->domain;
    int live =  (ioctxt->flags & XCFLAGS_LIVE);
    int debug = (ioctxt->flags & XCFLAGS_DEBUG);
    int sent_last_iter, skip_this_iter;

    /* Important tuning parameters */
    int max_iters  = 29; /* limit us to 30 times round loop */
    int max_factor = 3;  /* never send more than 3x nr_pfns */

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

    /* A temporary mapping, and a copy, of the guest's suspend record. */
    suspend_record_t *p_srec = NULL;

    /* number of pages we're dealing with */
    unsigned long nr_pfns;

    /* power of 2 order of nr_pfns */
    int order_nr; 

    /* bitmap of pages:
       - that should be sent this iteration (unless later marked as skip); 
       - to skip this iteration because already dirty;
       - to fixup by sending at the end if not already resent; */
    unsigned long *to_send, *to_skip, *to_fix;
    
    xc_shadow_control_stats_t stats;

    int needed_to_fix = 0;
    int total_sent    = 0;

    MBIT_RATE = START_MBIT_RATE;

    xcio_info(ioctxt, "xc_linux_save start %d\n", domid);
    
    if (mlock(&ctxt, sizeof(ctxt))) {
        xcio_perror(ioctxt, "Unable to mlock ctxt");
        return 1;
    }
    
    if ( xc_domain_getinfo(xc_handle, domid, 1, &info) )
    {
        xcio_error(ioctxt, "Could not get full domain info");
        goto out;
    }
    if ( xc_domain_get_vcpu_context( xc_handle, domid, /* FIXME */ 0, 
                                &ctxt) )
    {
        xcio_error(ioctxt, "Could not get vcpu context");
        goto out;
    }
    shared_info_frame = info.shared_info_frame;

    /* A cheesy test to see whether the domain contains valid state. */
    if ( ctxt.pt_base == 0 ){
        xcio_error(ioctxt, "Domain is not in a valid Linux guest OS state");
        goto out;
    }
    
    nr_pfns = info.nr_pages; 

    /* cheesy sanity check */
    if ( nr_pfns > 1024*1024 ){
        xcio_error(ioctxt, 
                   "Invalid state record -- pfn count out of range: %lu", 
                   nr_pfns);
        goto out;
    }


    /* Map the shared info frame */
    live_shinfo = xc_map_foreign_range(xc_handle, domid,
                                        PAGE_SIZE, PROT_READ,
                                        shared_info_frame);

    if (!live_shinfo){
        xcio_error(ioctxt, "Couldn't map live_shinfo");
        goto out;
    }

    /* the pfn_to_mfn_frame_list fits in a single page */
    live_pfn_to_mfn_frame_list = 
        xc_map_foreign_range(xc_handle, domid, 
                              PAGE_SIZE, PROT_READ, 
                              live_shinfo->arch.pfn_to_mfn_frame_list );

    if (!live_pfn_to_mfn_frame_list){
        xcio_error(ioctxt, "Couldn't map pfn_to_mfn_frame_list");
        goto out;
    }


    /* Map all the frames of the pfn->mfn table. For migrate to succeed, 
       the guest must not change which frames are used for this purpose. 
       (its not clear why it would want to change them, and we'll be OK
       from a safety POV anyhow. */

    live_pfn_to_mfn_table = xc_map_foreign_batch(xc_handle, domid, 
                                                 PROT_READ,
                                                 live_pfn_to_mfn_frame_list,
                                                 (nr_pfns+1023)/1024 );  
    if( !live_pfn_to_mfn_table ){
        xcio_perror(ioctxt, "Couldn't map pfn_to_mfn table");
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

    for ( i = 0; i < nr_pfns; i += 1024 ){
        if ( !translate_mfn_to_pfn(&pfn_to_mfn_frame_list[i/1024]) ){
            xcio_error(ioctxt, 
                       "Frame# in pfn-to-mfn frame list is not in pseudophys");
            goto out;
        }
    }


    /* Domain is still running at this point */

    if( live )
    {
        if ( xc_shadow_control( xc_handle, domid, 
                                DOM0_SHADOW_CONTROL_OP_ENABLE_LOGDIRTY,
                                NULL, 0, NULL ) < 0 ) {
            xcio_error(ioctxt, "Couldn't enable shadow mode");
            goto out;
        }

        last_iter = 0;
    } else{
	/* This is a non-live suspend. Issue the call back to get the
	 domain suspended */

        last_iter = 1;

	if ( suspend_and_state( xc_handle, ioctxt, &info, &ctxt) )
	{
	    xcio_error(ioctxt, "Domain appears not to have suspended: %u",
		       info.flags);
	    goto out;
	}

    }
    sent_last_iter = 1<<20; /* 4GB of pages */

    /* calculate the power of 2 order of nr_pfns, e.g.
       15->4 16->4 17->5 */
    for( i=nr_pfns-1, order_nr=0; i ; i>>=1, order_nr++ );

    /* Setup to_send bitmap */
    {
	/* size these for a maximal 4GB domain, to make interaction
	   with balloon driver easier. It's only user space memory,
	   ater all... (3x 128KB) */

        int sz = ( 1<<20 ) / 8;
 
        to_send = malloc( sz );
        to_fix  = calloc( 1, sz );
        to_skip = malloc( sz );

        if (!to_send || !to_fix || !to_skip){
            xcio_error(ioctxt, "Couldn't allocate to_send array");
            goto out;
        }

        memset( to_send, 0xff, sz );

        if ( mlock( to_send, sz ) ){
            xcio_perror(ioctxt, "Unable to mlock to_send");
            return 1;
        }

        /* (to fix is local only) */

        if ( mlock( to_skip, sz ) ){
            xcio_perror(ioctxt, "Unable to mlock to_skip");
            return 1;
        }

    }

    analysis_phase( xc_handle, domid, nr_pfns, to_skip, 0 );

    /* We want zeroed memory so use calloc rather than malloc. */
    pfn_type = calloc(BATCH_SIZE, sizeof(unsigned long));
    pfn_batch = calloc(BATCH_SIZE, sizeof(unsigned long));

    if ( (pfn_type == NULL) || (pfn_batch == NULL) ){
        errno = ENOMEM;
        goto out;
    }

    if ( mlock( pfn_type, BATCH_SIZE * sizeof(unsigned long) ) ){
        xcio_error(ioctxt, "Unable to mlock");
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
		printf("i=0x%x mfn=%lx live_mfn_to_pfn_table=%lx\n",
		       i,mfn,live_mfn_to_pfn_table[mfn]);
		err++;
	    }
	}
	printf("Had %d unexplained entries in p2m table\n",err);
    }
#endif


    /* Start writing out the saved-domain record. */

    if ( xcio_write(ioctxt, "LinuxGuestRecord",    16) ||
         xcio_write(ioctxt, &nr_pfns,              sizeof(unsigned long)) ||
         xcio_write(ioctxt, pfn_to_mfn_frame_list, PAGE_SIZE) ){
        xcio_error(ioctxt, "Error writing header");
        goto out;
    }
    if(write_vmconfig(ioctxt)){
        xcio_error(ioctxt, "Error writing vmconfig");
        goto out;
    }

    print_stats( xc_handle, domid, 0, &stats, 0 );

    /* Now write out each data page, canonicalising page tables as we go... */
    
    while(1){
        unsigned int prev_pc, sent_this_iter, N, batch;

        iter++;
        sent_this_iter = 0;
        skip_this_iter = 0;
        prev_pc = 0;
        N=0;

        xcio_info(ioctxt, "Saving memory pages: iter %d   0%%", iter);

        while( N < nr_pfns ){
            unsigned int this_pc = (N * 100) / nr_pfns;

            if ( (this_pc - prev_pc) >= 5 ){
                xcio_info(ioctxt, "\b\b\b\b%3d%%", this_pc);
                prev_pc = this_pc;
            }

            /* slightly wasteful to peek the whole array evey time, 
               but this is fast enough for the moment. */

            if ( !last_iter && 
		 xc_shadow_control(xc_handle, domid, 
                                   DOM0_SHADOW_CONTROL_OP_PEEK,
                                   to_skip, nr_pfns, NULL) != nr_pfns )
	    {
                xcio_error(ioctxt, "Error peeking shadow bitmap");
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
                        DDPRINTF("netbuf race: iter %d, pfn %x. mfn %lx\n",
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
     
//            DDPRINTF("batch %d:%d (n=%d)\n", iter, batch, n);

            if ( batch == 0 )
                goto skip; /* vanishingly unlikely... */
      
            if ( (region_base = xc_map_foreign_batch(xc_handle, domid, 
                                                     PROT_READ,
                                                     pfn_type,
                                                     batch)) == 0 ){
                xcio_perror(ioctxt, "map batch failed");
                goto out;
            }
     
            if ( get_pfn_type_batch(xc_handle, domid, batch, pfn_type) ){
                xcio_error(ioctxt, "get_pfn_type_batch failed");
                goto out;
            }
     
            for ( j = 0; j < batch; j++ ){
                if ( (pfn_type[j] & LTAB_MASK) == XTAB ){
                    DDPRINTF("type fail: page %i mfn %08lx\n",j,pfn_type[j]);
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

            if ( xcio_write(ioctxt, &batch, sizeof(int) ) ){
                xcio_error(ioctxt, "Error when writing to state file (2)");
                goto out;
            }

            if ( xcio_write(ioctxt, pfn_type, sizeof(unsigned long)*j ) ){
                xcio_error(ioctxt, "Error when writing to state file (3)");
                goto out;
            }
     
            /* entering this loop, pfn_type is now in pfns (Not mfns) */
            for( j = 0; j < batch; j++ ){
                /* write out pages in batch */
                if( (pfn_type[j] & LTAB_MASK) == XTAB){
                    DDPRINTF("SKIP BOGUS page %i mfn %08lx\n",j,pfn_type[j]);
                    continue;
                }
  
                if ( ((pfn_type[j] & LTABTYPE_MASK) == L1TAB) || 
                     ((pfn_type[j] & LTABTYPE_MASK) == L2TAB) ){
                    memcpy(page, region_base + (PAGE_SIZE*j), PAGE_SIZE);
      
                    for ( k = 0; 
                          k < (((pfn_type[j] & LTABTYPE_MASK) == L2TAB) ? 
                               (HYPERVISOR_VIRT_START >> L2_PAGETABLE_SHIFT) :
                               1024); 
                          k++ ){
                        unsigned long pfn;

                        if ( !(page[k] & _PAGE_PRESENT) )
                            continue;
                        
                        mfn = page[k] >> PAGE_SHIFT;      
                        pfn = live_mfn_to_pfn_table[mfn];

                        if ( !MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )
                        {
                            /* I don't think this should ever happen */
                            printf("FNI %d : [%08lx,%d] pte=%08lx, "
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
                        printf("L%d i=%d pfn=%d mfn=%d k=%d pte=%08lx "
                               "xpfn=%d\n",
                               pfn_type[j]>>28,
                               j,i,mfn,k,page[k],page[k]>>PAGE_SHIFT);
#endif     
   
                    } /* end of page table rewrite for loop */
      
                    if ( xcio_ratewrite(ioctxt, page, PAGE_SIZE) ){
                        xcio_error(ioctxt, 
                                   "Error when writing to state file (4)");
                        goto out;
                    }
      
                }  /* end of it's a PT page */ else {  /* normal page */

                    if ( xcio_ratewrite(ioctxt, region_base + (PAGE_SIZE*j), 
                                     PAGE_SIZE) ){
                        xcio_error(ioctxt, 
                                   "Error when writing to state file (5)");
                        goto out;
                    }
                }
            } /* end of the write out for this batch */
     
            sent_this_iter += batch;

        } /* end of this while loop for this iteration */

        munmap(region_base, batch*PAGE_SIZE);

    skip: 

        total_sent += sent_this_iter;

        xcio_info(ioctxt, "\r %d: sent %d, skipped %d, ", 
                       iter, sent_this_iter, skip_this_iter );

        if ( last_iter ) {
            print_stats( xc_handle, domid, sent_this_iter, &stats, 1);

            xcio_info(ioctxt, "Total pages sent= %d (%.2fx)\n", 
                           total_sent, ((float)total_sent)/nr_pfns );
            xcio_info(ioctxt, "(of which %d were fixups)\n", needed_to_fix  );
        }       

        if (last_iter && debug){
            int minusone = -1;
            memset( to_send, 0xff, (nr_pfns+8)/8 );
            debug = 0;
            printf("Entering debug resend-all mode\n");
    
            /* send "-1" to put receiver into debug mode */
            if ( xcio_write(ioctxt, &minusone, sizeof(int)) )
            {
                xcio_error(ioctxt, "Error when writing to state file (6)");
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

		if ( suspend_and_state( xc_handle, ioctxt, &info, &ctxt) )
		{
		    xcio_error(ioctxt, 
                               "Domain appears not to have suspended: %u",
			       info.flags);
		    goto out;
		}

		xcio_info(ioctxt,
                          "SUSPEND flags %08u shinfo %08lx eip %08u "
                          "esi %08u\n",info.flags,
                          info.shared_info_frame,
                          ctxt.user_regs.eip, ctxt.user_regs.esi );
            } 

            if ( xc_shadow_control( xc_handle, domid, 
                                    DOM0_SHADOW_CONTROL_OP_CLEAN,
                                    to_send, nr_pfns, &stats ) != nr_pfns ) 
            {
                xcio_error(ioctxt, "Error flushing shadow PT");
                goto out;
            }

            sent_last_iter = sent_this_iter;

            print_stats( xc_handle, domid, sent_this_iter, &stats, 1);
     
        }


    } /* end of while 1 */

    DPRINTF("All memory is saved\n");

    /* Success! */
    rc = 0;
    
    /* Zero terminate */
    if ( xcio_write(ioctxt, &rc, sizeof(int)) )
    {
        xcio_error(ioctxt, "Error when writing to state file (6)");
        goto out;
    }

    /* Send through a list of all the PFNs that were not in map at the close */
    {
	unsigned int i,j;
	unsigned int pfntab[1024];

	for ( i = 0, j = 0; i < nr_pfns; i++ )
	{
	    if ( ! is_mapped(live_pfn_to_mfn_table[i]) )
		j++;
	}

	if ( xcio_write(ioctxt, &j, sizeof(unsigned int)) )
	{
	    xcio_error(ioctxt, "Error when writing to state file (6a)");
	    goto out;
	}	

	for ( i = 0, j = 0; i < nr_pfns; )
	{
	    if ( ! is_mapped(live_pfn_to_mfn_table[i]) )
	    {
		pfntab[j++] = i;
	    }
	    i++;
	    if ( j == 1024 || i == nr_pfns )
	    {
		if ( xcio_write(ioctxt, &pfntab, sizeof(unsigned long)*j) )
		{
		    xcio_error(ioctxt, 
                               "Error when writing to state file (6b)");
		    goto out;
		}	
		j = 0;
	    }
	}
    }

    /* Map the suspend-record MFN to pin it. The page must be owned by 
       domid for this to succeed. */
    p_srec = xc_map_foreign_range(xc_handle, domid,
                                   sizeof(*p_srec), PROT_READ, 
                                   ctxt.user_regs.esi);
    if (!p_srec){
        xcio_error(ioctxt, "Couldn't map suspend record");
        goto out;
    }

    if (nr_pfns != p_srec->nr_pfns )
    {
	xcio_error(ioctxt, "Suspend record nr_pfns unexpected (%ld != %ld)",
		   p_srec->nr_pfns, nr_pfns);
        goto out;
    }

    /* Canonicalise the suspend-record frame number. */
    if ( !translate_mfn_to_pfn(&ctxt.user_regs.esi) ){
        xcio_error(ioctxt, "Suspend record is not in range of pseudophys map");
        goto out;
    }

    /* Canonicalise each GDT frame number. */
    for ( i = 0; i < ctxt.gdt_ents; i += 512 ) {
        if ( !translate_mfn_to_pfn(&ctxt.gdt_frames[i]) ) {
            xcio_error(ioctxt, "GDT frame is not in range of pseudophys map");
            goto out;
        }
    }

    /* Canonicalise the page table base pointer. */
    if ( !MFN_IS_IN_PSEUDOPHYS_MAP(ctxt.pt_base >> PAGE_SHIFT) ) {
        xcio_error(ioctxt, "PT base is not in range of pseudophys map");
        goto out;
    }
    ctxt.pt_base = live_mfn_to_pfn_table[ctxt.pt_base >> PAGE_SHIFT] <<
        PAGE_SHIFT;

    if ( xcio_write(ioctxt, &ctxt,       sizeof(ctxt)) ||
         xcio_write(ioctxt, live_shinfo, PAGE_SIZE) ) {
        xcio_error(ioctxt, "Error when writing to state file (1)");
        goto out;
    }

 out:

    if(live_shinfo)
        munmap(live_shinfo, PAGE_SIZE);

    if(p_srec) 
        munmap(p_srec, sizeof(*p_srec));

    if(live_pfn_to_mfn_frame_list) 
        munmap(live_pfn_to_mfn_frame_list, PAGE_SIZE);

    if(live_pfn_to_mfn_table) 
        munmap(live_pfn_to_mfn_table, nr_pfns*4);

    if(live_mfn_to_pfn_table) 
        munmap(live_mfn_to_pfn_table, PAGE_SIZE*1024);

    if (pfn_type != NULL) 
        free(pfn_type);

    DPRINTF("Save exit rc=%d\n",rc);
    return !!rc;
}
