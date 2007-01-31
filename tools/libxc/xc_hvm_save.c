/******************************************************************************
 * xc_hvm_save.c
 *
 * Save the state of a running HVM guest.
 *
 * Copyright (c) 2003, K A Fraser.
 * Copyright (c) 2006 Intel Corperation
 * rewriten for hvm guest by Zhai Edwin <edwin.zhai@intel.com>
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

#include <inttypes.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include "xc_private.h"
#include "xg_private.h"
#include "xg_save_restore.h"

/*
 * Size of a buffer big enough to take the HVM state of a domain.
 * Ought to calculate this a bit more carefully, or maybe ask Xen.
 */
#define HVM_CTXT_SIZE 8192

/*
** Default values for important tuning parameters. Can override by passing
** non-zero replacement values to xc_hvm_save().
**
** XXX SMH: should consider if want to be able to override MAX_MBIT_RATE too.
**
*/
#define DEF_MAX_ITERS   29   /* limit us to 30 times round loop   */
#define DEF_MAX_FACTOR   3   /* never send more than 3x nr_pfns   */

/* max mfn of the whole machine */
static unsigned long max_mfn;

/* virtual starting address of the hypervisor */
static unsigned long hvirt_start;

/* #levels of page tables used by the currrent guest */
static unsigned int pt_levels;

/* total number of pages used by the current guest */
static unsigned long max_pfn;

/*
** During (live) save/migrate, we maintain a number of bitmaps to track
** which pages we have to send, to fixup, and to skip.
*/

#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define BITMAP_SIZE   ((max_pfn + BITS_PER_LONG - 1) / 8)

#define BITMAP_ENTRY(_nr,_bmap) \
   ((unsigned long *)(_bmap))[(_nr)/BITS_PER_LONG]

#define BITMAP_SHIFT(_nr) ((_nr) % BITS_PER_LONG)

static inline int test_bit (int nr, volatile void * addr)
{
    return (BITMAP_ENTRY(nr, addr) >> BITMAP_SHIFT(nr)) & 1;
}

static inline void clear_bit (int nr, volatile void * addr)
{
    BITMAP_ENTRY(nr, addr) &= ~(1UL << BITMAP_SHIFT(nr));
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

static uint64_t tv_to_us(struct timeval *new)
{
    return (new->tv_sec * 1000000) + new->tv_usec;
}

static uint64_t llgettimeofday(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return tv_to_us(&now);
}

static uint64_t tv_delta(struct timeval *new, struct timeval *old)
{
    return ((new->tv_sec - old->tv_sec)*1000000 ) +
        (new->tv_usec - old->tv_usec);
}


#define RATE_IS_MAX() (0)
#define ratewrite(_io_fd, _buf, _n) write((_io_fd), (_buf), (_n))
#define initialize_mbit_rate()

static inline ssize_t write_exact(int fd, void *buf, size_t count)
{
    if(write(fd, buf, count) != count)
        return 0;
    return 1;
}

static int print_stats(int xc_handle, uint32_t domid, int pages_sent,
                       xc_shadow_op_stats_t *stats, int print)
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
        DPRINTF("ARRHHH!!\n");

    wall_delta = tv_delta(&wall_now,&wall_last)/1000;

    if (wall_delta == 0) wall_delta = 1;

    d0_cpu_delta = (d0_cpu_now - d0_cpu_last)/1000;
    d1_cpu_delta = (d1_cpu_now - d1_cpu_last)/1000;

    if (print)
        DPRINTF(
                "delta %lldms, dom0 %d%%, target %d%%, sent %dMb/s, "
                "dirtied %dMb/s %" PRId32 " pages\n",
                wall_delta,
                (int)((d0_cpu_delta*100)/wall_delta),
                (int)((d1_cpu_delta*100)/wall_delta),
                (int)((pages_sent*PAGE_SIZE)/(wall_delta*(1000/8))),
                (int)((stats->dirty_count*PAGE_SIZE)/(wall_delta*(1000/8))),
                stats->dirty_count);

    d0_cpu_last = d0_cpu_now;
    d1_cpu_last = d1_cpu_now;
    wall_last   = wall_now;

    return 0;
}

static int analysis_phase(int xc_handle, uint32_t domid, int max_pfn,
                          unsigned long *arr, int runs)
{
    long long start, now;
    xc_shadow_op_stats_t stats;
    int j;

    start = llgettimeofday();

    for (j = 0; j < runs; j++) {
        int i;

        xc_shadow_control(xc_handle, domid, XEN_DOMCTL_SHADOW_OP_CLEAN,
                          arr, max_pfn, NULL, 0, NULL);
        DPRINTF("#Flush\n");
        for ( i = 0; i < 40; i++ ) {
            usleep(50000);
            now = llgettimeofday();
            xc_shadow_control(xc_handle, domid, XEN_DOMCTL_SHADOW_OP_PEEK,
                              NULL, 0, NULL, 0, &stats);

            DPRINTF("now= %lld faults= %"PRId32" dirty= %"PRId32"\n",
                    ((now-start)+500)/1000,
                    stats.fault_count, stats.dirty_count);
        }
    }

    return -1;
}

static int suspend_and_state(int (*suspend)(int), int xc_handle, int io_fd,
                             int dom, xc_dominfo_t *info,
                             vcpu_guest_context_t *ctxt)
{
    int i = 0;

    if (!(*suspend)(dom)) {
        ERROR("Suspend request failed");
        return -1;
    }

 retry:

    if (xc_domain_getinfo(xc_handle, dom, 1, info) != 1) {
        ERROR("Could not get domain info");
        return -1;
    }

    if ( xc_vcpu_getcontext(xc_handle, dom, 0 /* XXX */, ctxt))
        ERROR("Could not get vcpu context");


    if (info->shutdown && info->shutdown_reason == SHUTDOWN_suspend)
        return 0; // success

    if (info->paused) {
        // try unpausing domain, wait, and retest
        xc_domain_unpause( xc_handle, dom );

        ERROR("Domain was paused. Wait and re-test.");
        usleep(10000);  // 10ms

        goto retry;
    }


    if( ++i < 100 ) {
        ERROR("Retry suspend domain.");
        usleep(10000);  // 10ms
        goto retry;
    }

    ERROR("Unable to suspend domain.");

    return -1;
}

int xc_hvm_save(int xc_handle, int io_fd, uint32_t dom, uint32_t max_iters,
                  uint32_t max_factor, uint32_t flags, int (*suspend)(int))
{
    xc_dominfo_t info;

    int rc = 1, i, last_iter, iter = 0;
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

    /* A copy of hvm domain context buffer*/
    uint8_t *hvm_buf = NULL;

    /* Live mapping of shared info structure */
    shared_info_t *live_shinfo = NULL;

    /* base of the region in which domain memory is mapped */
    unsigned char *region_base = NULL;

    uint32_t nr_pfns, rec_size, nr_vcpus;
    unsigned long *page_array = NULL;

    /* power of 2 order of max_pfn */
    int order_nr;

    /* bitmap of pages:
       - that should be sent this iteration (unless later marked as skip);
       - to skip this iteration because already dirty; */
    unsigned long *to_send = NULL, *to_skip = NULL;

    xc_shadow_op_stats_t stats;

    unsigned long total_sent    = 0;

    DPRINTF("xc_hvm_save:dom=%d, max_iters=%d, max_factor=%d, flags=0x%x, live=%d, debug=%d.\n",
            dom, max_iters, max_factor, flags,
            live, debug);

    /* If no explicit control parameters given, use defaults */
    if(!max_iters)
        max_iters = DEF_MAX_ITERS;
    if(!max_factor)
        max_factor = DEF_MAX_FACTOR;

    initialize_mbit_rate();

    if(!get_platform_info(xc_handle, dom,
                          &max_mfn, &hvirt_start, &pt_levels)) {
        ERROR("HVM:Unable to get platform info.");
        return 1;
    }

    if (xc_domain_getinfo(xc_handle, dom, 1, &info) != 1) {
        ERROR("HVM:Could not get domain info");
        return 1;
    }
    nr_vcpus = info.nr_online_vcpus;

    if (mlock(&ctxt, sizeof(ctxt))) {
        ERROR("HVM:Unable to mlock ctxt");
        return 1;
    }

    /* Only have to worry about vcpu 0 even for SMP */
    if (xc_vcpu_getcontext(xc_handle, dom, 0, &ctxt)) {
        ERROR("HVM:Could not get vcpu context");
        goto out;
    }
    shared_info_frame = info.shared_info_frame;

    /* A cheesy test to see whether the domain contains valid state. */
    if (ctxt.ctrlreg[3] == 0)
    {
        ERROR("Domain is not in a valid HVM guest state");
        goto out;
    }

   /* cheesy sanity check */
    if ((info.max_memkb >> (PAGE_SHIFT - 10)) > max_mfn) {
        ERROR("Invalid HVM state record -- pfn count out of range: %lu",
            (info.max_memkb >> (PAGE_SHIFT - 10)));
        goto out;
    }

    /* Map the shared info frame */
    if(!(live_shinfo = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                            PROT_READ, shared_info_frame))) {
        ERROR("HVM:Couldn't map live_shinfo");
        goto out;
    }

    max_pfn = live_shinfo->arch.max_pfn;

    DPRINTF("saved hvm domain info:max_memkb=0x%lx, max_mfn=0x%lx, nr_pages=0x%lx\n", info.max_memkb, max_mfn, info.nr_pages); 

    /* nr_pfns: total pages excluding vga acc mem
     * max_pfn: nr_pfns + 0x20 vga hole(0xa0~0xc0)
     * getdomaininfo.tot_pages: all the allocated pages for this domain
     */
    if (live) {
        ERROR("hvm domain doesn't support live migration now.\n");
        goto out;

        if (xc_shadow_control(xc_handle, dom,
                              XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY,
                              NULL, 0, NULL, 0, NULL) < 0) {
            ERROR("Couldn't enable shadow mode");
            goto out;
        }

        /* excludes vga acc mem */
        nr_pfns = info.nr_pages - 0x800;

        last_iter = 0;
        DPRINTF("hvm domain live migration debug start: logdirty enable.\n");
    } else {
        /* This is a non-live suspend. Issue the call back to get the
           domain suspended */

        last_iter = 1;

        /* suspend hvm domain */
        if (suspend_and_state(suspend, xc_handle, io_fd, dom, &info, &ctxt)) {
            ERROR("HVM Domain appears not to have suspended");
            goto out;
        }
        nr_pfns = info.nr_pages;
        DPRINTF("after suspend hvm domain nr_pages=0x%x.\n", nr_pfns);
    }

    DPRINTF("after 1st handle hvm domain nr_pfns=0x%x, nr_pages=0x%lx, max_memkb=0x%lx, live=%d.\n",
            nr_pfns,
            info.nr_pages,
            info.max_memkb,
            live);

    nr_pfns = info.nr_pages;

    /*XXX: caculate the VGA hole*/
    max_pfn = nr_pfns + 0x20;

    skip_this_iter = 0;/*XXX*/
    /* pretend we sent all the pages last iteration */
    sent_last_iter = max_pfn;

    /* calculate the power of 2 order of max_pfn, e.g.
       15->4 16->4 17->5 */
    for (i = max_pfn-1, order_nr = 0; i ; i >>= 1, order_nr++)
        continue;

    /* Setup to_send / to_fix and to_skip bitmaps */
    to_send = malloc(BITMAP_SIZE);
    to_skip = malloc(BITMAP_SIZE);

    page_array = (unsigned long *) malloc( sizeof(unsigned long) * max_pfn);

    hvm_buf = malloc(HVM_CTXT_SIZE);

    if (!to_send ||!to_skip ||!page_array ||!hvm_buf ) {
        ERROR("Couldn't allocate memory");
        goto out;
    }

    memset(to_send, 0xff, BITMAP_SIZE);

    if (lock_pages(to_send, BITMAP_SIZE)) {
        ERROR("Unable to lock to_send");
        return 1;
    }

    /* (to fix is local only) */
    if (lock_pages(to_skip, BITMAP_SIZE)) {
        ERROR("Unable to lock to_skip");
        return 1;
    }

    analysis_phase(xc_handle, dom, max_pfn, to_skip, 0);

    /* get all the HVM domain pfns */
    for ( i = 0; i < max_pfn; i++)
        page_array[i] = i;


    /* We want zeroed memory so use calloc rather than malloc. */
    pfn_type  = calloc(MAX_BATCH_SIZE, sizeof(*pfn_type));
    pfn_batch = calloc(MAX_BATCH_SIZE, sizeof(*pfn_batch));

    if ((pfn_type == NULL) || (pfn_batch == NULL)) {
        ERROR("failed to alloc memory for pfn_type and/or pfn_batch arrays");
        errno = ENOMEM;
        goto out;
    }

    if (lock_pages(pfn_type, MAX_BATCH_SIZE * sizeof(*pfn_type))) {
        ERROR("Unable to lock");
        goto out;
    }

    /* Start writing out the saved-domain record. */
    if (!write_exact(io_fd, &max_pfn, sizeof(unsigned long))) {
        ERROR("write: max_pfn");
        goto out;
    }

    while(1) {

        unsigned int prev_pc, sent_this_iter, N, batch;

        iter++;
        sent_this_iter = 0;
        skip_this_iter = 0;
        prev_pc = 0;
        N=0;

        DPRINTF("Saving HVM domain memory pages: iter %d   0%%", iter);

        while( N < max_pfn ){

            unsigned int this_pc = (N * 100) / max_pfn;

            if ((this_pc - prev_pc) >= 5) {
                DPRINTF("\b\b\b\b%3d%%", this_pc);
                prev_pc = this_pc;
            }

            /* slightly wasteful to peek the whole array evey time,
               but this is fast enough for the moment. */
            if (!last_iter && xc_shadow_control(
                    xc_handle, dom, XEN_DOMCTL_SHADOW_OP_PEEK,
                    to_skip, max_pfn, NULL, 0, NULL) != max_pfn) {
                ERROR("Error peeking HVM shadow bitmap");
                goto out;
            }


            /* load pfn_type[] with the mfn of all the pages we're doing in
               this batch. */
            for (batch = 0; batch < MAX_BATCH_SIZE && N < max_pfn ; N++) {

                int n = permute(N, max_pfn, order_nr);

                if (debug) {
                    DPRINTF("%d pfn= %08lx mfn= %08lx %d \n",
                            iter, (unsigned long)n, page_array[n],
                            test_bit(n, to_send));
                }

                if (!last_iter && test_bit(n, to_send)&& test_bit(n, to_skip))
                    skip_this_iter++; /* stats keeping */

                if (!((test_bit(n, to_send) && !test_bit(n, to_skip)) ||
                      (test_bit(n, to_send) && last_iter)))
                    continue;

                if (n >= 0xa0 && n < 0xc0) {
/*                    DPRINTF("get a vga hole pfn= %x.\n", n);*/
                    continue;
                }
                /*
                ** we get here if:
                **  1. page is marked to_send & hasn't already been re-dirtied
                **  2. (ignore to_skip in last iteration)
                */

                pfn_batch[batch] = n;
                pfn_type[batch]  = page_array[n];

                batch++;
            }

            if (batch == 0)
                goto skip; /* vanishingly unlikely... */

            /* map_foreign use pfns now !*/
            if ((region_base = xc_map_foreign_batch(
                     xc_handle, dom, PROT_READ, pfn_batch, batch)) == 0) {
                ERROR("map batch failed");
                goto out;
            }

            /* write num of pfns */
            if(!write_exact(io_fd, &batch, sizeof(unsigned int))) {
                ERROR("Error when writing to state file (2)");
                goto out;
            }

            /* write all the pfns */
            if(!write_exact(io_fd, pfn_batch, sizeof(unsigned long)*batch)) {
                ERROR("Error when writing to state file (3)");
                goto out;
            }

            if (ratewrite(io_fd, region_base, PAGE_SIZE * batch) != PAGE_SIZE * batch) {
                ERROR("ERROR when writting to state file (4)");
                goto out;
            }


            sent_this_iter += batch;

            munmap(region_base, batch*PAGE_SIZE);

        } /* end of this while loop for this iteration */

      skip:

        total_sent += sent_this_iter;

        DPRINTF("\r %d: sent %d, skipped %d, ",
                iter, sent_this_iter, skip_this_iter );

        if (last_iter) {
            print_stats( xc_handle, dom, sent_this_iter, &stats, 1);

            DPRINTF("Total pages sent= %ld (%.2fx)\n",
                    total_sent, ((float)total_sent)/max_pfn );
        }

        if (last_iter && debug){
            int minusone = -1;
            memset(to_send, 0xff, BITMAP_SIZE);
            debug = 0;
            DPRINTF("Entering debug resend-all mode\n");

            /* send "-1" to put receiver into debug mode */
            if(!write_exact(io_fd, &minusone, sizeof(int))) {
                ERROR("Error when writing to state file (6)");
                goto out;
            }

            continue;
        }

        if (last_iter) break;

        if (live) {


            if(
                ((sent_this_iter > sent_last_iter) && RATE_IS_MAX()) ||
                (iter >= max_iters) ||
                (sent_this_iter+skip_this_iter < 50) ||
                (total_sent > max_pfn*max_factor) ) {

                DPRINTF("Start last iteration for HVM domain\n");
                last_iter = 1;

                if (suspend_and_state(suspend, xc_handle, io_fd, dom, &info,
                                      &ctxt)) {
                    ERROR("Domain appears not to have suspended");
                    goto out;
                }

                DPRINTF("SUSPEND shinfo %08lx eip %08lx edx %08lx\n",
                        info.shared_info_frame,
                        (unsigned long)ctxt.user_regs.eip,
                        (unsigned long)ctxt.user_regs.edx);
            }

            if (xc_shadow_control(xc_handle, dom, 
                                  XEN_DOMCTL_SHADOW_OP_CLEAN, to_send, 
                                  max_pfn, NULL, 0, &stats) != max_pfn) {
                ERROR("Error flushing shadow PT");
                goto out;
            }

            sent_last_iter = sent_this_iter;

            print_stats(xc_handle, dom, sent_this_iter, &stats, 1);

        }


    } /* end of while 1 */


    DPRINTF("All HVM memory is saved\n");

    /* Zero terminate */
    i = 0;
    if (!write_exact(io_fd, &i, sizeof(int))) {
        ERROR("Error when writing to state file (6)");
        goto out;
    }

    if ( (rec_size = xc_domain_hvm_getcontext(xc_handle, dom, hvm_buf, 
                                              HVM_CTXT_SIZE)) == -1) {
        ERROR("HVM:Could not get hvm buffer");
        goto out;
    }

    if (!write_exact(io_fd, &rec_size, sizeof(uint32_t))) {
        ERROR("error write hvm buffer size");
        goto out;
    }

    if ( !write_exact(io_fd, hvm_buf, rec_size) ) {
        ERROR("write HVM info failed!\n");
    }

    /* save vcpu/vmcs context */
    if (!write_exact(io_fd, &nr_vcpus, sizeof(uint32_t))) {
        ERROR("error write nr vcpus");
        goto out;
    }

    /*XXX: need a online map to exclude down cpu */
    for (i = 0; i < nr_vcpus; i++) {

        if (xc_vcpu_getcontext(xc_handle, dom, i, &ctxt)) {
            ERROR("HVM:Could not get vcpu context");
            goto out;
        }

        rec_size = sizeof(ctxt);
        DPRINTF("write %d vcpucontext of total %d.\n", i, nr_vcpus); 
        if (!write_exact(io_fd, &rec_size, sizeof(uint32_t))) {
            ERROR("error write vcpu ctxt size");
            goto out;
        }

        if (!write_exact(io_fd, &(ctxt), sizeof(ctxt)) ) {
            ERROR("write vmcs failed!\n");
            goto out;
        }
    }

    /* Shared-info pfn */
    if (!write_exact(io_fd, &(shared_info_frame), sizeof(uint32_t)) ) {
        ERROR("write shared-info pfn failed!\n");
        goto out;
    }
 
    /* Success! */
    rc = 0;

 out:

    if (live) {
        if(xc_shadow_control(xc_handle, dom, 
                             XEN_DOMCTL_SHADOW_OP_OFF,
                             NULL, 0, NULL, 0, NULL) < 0) {
            DPRINTF("Warning - couldn't disable shadow mode");
        }
    }

    free(hvm_buf);
    free(page_array);

    free(pfn_type);
    free(pfn_batch);
    free(to_send);
    free(to_skip);

    return !!rc;
}
