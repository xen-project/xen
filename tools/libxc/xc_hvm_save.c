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

#include <xen/hvm/e820.h>
#include <xen/hvm/params.h>

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

/* #levels of page tables used by the current guest */
static unsigned int pt_levels;

/* Shared-memory bitmaps for getting log-dirty bits from qemu */
static unsigned long *qemu_bitmaps[2];
static int qemu_active;
static int qemu_non_active;

/*
** During (live) save/migrate, we maintain a number of bitmaps to track
** which pages we have to send, to fixup, and to skip.
*/

#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define BITS_TO_LONGS(bits) (((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#define BITMAP_SIZE   (BITS_TO_LONGS(pfn_array_size) * sizeof(unsigned long))

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

static int analysis_phase(int xc_handle, uint32_t domid, int pfn_array_size,
                          unsigned long *arr, int runs)
{
    long long start, now;
    xc_shadow_op_stats_t stats;
    int j;

    start = llgettimeofday();

    for (j = 0; j < runs; j++) {
        int i;

        xc_shadow_control(xc_handle, domid, XEN_DOMCTL_SHADOW_OP_CLEAN,
                          arr, pfn_array_size, NULL, 0, NULL);
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
                uint32_t max_factor, uint32_t flags, int (*suspend)(int),
                void *(*init_qemu_maps)(int, unsigned), 
                void (*qemu_flip_buffer)(int, int))
{
    xc_dominfo_t info;

    int rc = 1, i, j, last_iter, iter = 0;
    int live  = (flags & XCFLAGS_LIVE);
    int debug = (flags & XCFLAGS_DEBUG);
    int stdvga = (flags & XCFLAGS_STDVGA);
    int sent_last_iter, skip_this_iter;

    /* The highest guest-physical frame number used by the current guest */
    unsigned long max_pfn;

    /* The size of an array big enough to contain all guest pfns */
    unsigned long pfn_array_size;

    /* Other magic frames: ioreqs and xenstore comms */
    unsigned long ioreq_pfn, bufioreq_pfn, store_pfn;

    /* A copy of the CPU context of the guest. */
    vcpu_guest_context_t ctxt;

    /* A table containg the PFNs (/not/ MFN!) to map. */
    xen_pfn_t *pfn_batch = NULL;

    /* A copy of hvm domain context buffer*/
    uint32_t hvm_buf_size;
    uint8_t *hvm_buf = NULL;

    /* base of the region in which domain memory is mapped */
    unsigned char *region_base = NULL;

    uint32_t rec_size, nr_vcpus;

    /* power of 2 order of pfn_array_size */
    int order_nr;

    /* bitmap of pages:
       - that should be sent this iteration (unless later marked as skip);
       - to skip this iteration because already dirty; */
    unsigned long *to_send = NULL, *to_skip = NULL;

    xc_shadow_op_stats_t stats;

    unsigned long total_sent    = 0;

    DPRINTF("xc_hvm_save: dom=%d, max_iters=%d, max_factor=%d, flags=0x%x, "
            "live=%d, debug=%d.\n", dom, max_iters, max_factor, flags,
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

    /* cheesy sanity check */
    if ((info.max_memkb >> (PAGE_SHIFT - 10)) > max_mfn) {
        ERROR("Invalid HVM state record -- pfn count out of range: %lu",
            (info.max_memkb >> (PAGE_SHIFT - 10)));
        goto out;
    }

    if ( xc_get_hvm_param(xc_handle, dom, HVM_PARAM_STORE_PFN, &store_pfn)
         || xc_get_hvm_param(xc_handle, dom, HVM_PARAM_IOREQ_PFN, &ioreq_pfn)
         || xc_get_hvm_param(xc_handle, dom, 
                             HVM_PARAM_BUFIOREQ_PFN, &bufioreq_pfn) )
    {
        ERROR("HVM: Could not read magic PFN parameters");
        goto out;
    }
    DPRINTF("saved hvm domain info:max_memkb=0x%lx, max_mfn=0x%lx, "
            "nr_pages=0x%lx\n", info.max_memkb, max_mfn, info.nr_pages); 

    if (live) {
        
        if (xc_shadow_control(xc_handle, dom,
                              XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY,
                              NULL, 0, NULL, 0, NULL) < 0) {
            ERROR("Couldn't enable shadow mode");
            goto out;
        }

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
    }

    DPRINTF("after 1st handle hvm domain nr_pages=0x%lx, "
            "max_memkb=0x%lx, live=%d.\n",
            info.nr_pages, info.max_memkb, live);

    /* Calculate the highest PFN of "normal" memory:
     * HVM memory is sequential except for the VGA and MMIO holes. */
    max_pfn = info.nr_pages - 1;
    /* If the domain has a Cirrus framebuffer and we haven't already 
     * suspended qemu-dm, it will have 8MB of framebuffer memory 
     * still allocated, which we don't want to copy: qemu will save it 
     * for us later */
    if ( live && !stdvga )
        max_pfn -= 0x800;
    /* Skip the VGA hole from 0xa0000 to 0xc0000 */
    max_pfn += 0x20;
    /* Skip the MMIO hole: 256MB just below 4GB */
    if ( max_pfn >= (HVM_BELOW_4G_MMIO_START >> PAGE_SHIFT) )
        max_pfn += (HVM_BELOW_4G_MMIO_LENGTH >> PAGE_SHIFT); 

    /* Size of any array that covers 0 ... max_pfn */
    pfn_array_size = max_pfn + 1;

    /* pretend we sent all the pages last iteration */
    sent_last_iter = pfn_array_size;

    /* calculate the power of 2 order of pfn_array_size, e.g.
       15->4 16->4 17->5 */
    for (i = pfn_array_size-1, order_nr = 0; i ; i >>= 1, order_nr++)
        continue;

    /* Setup to_send / to_fix and to_skip bitmaps */
    to_send = malloc(BITMAP_SIZE);
    to_skip = malloc(BITMAP_SIZE);


    if (live) {
        /* Get qemu-dm logging dirty pages too */
        void *seg = init_qemu_maps(dom, BITMAP_SIZE);
        qemu_bitmaps[0] = seg;
        qemu_bitmaps[1] = seg + BITMAP_SIZE;
        qemu_active = 0;
        qemu_non_active = 1;
    }

    hvm_buf_size = xc_domain_hvm_getcontext(xc_handle, dom, 0, 0);
    if ( hvm_buf_size == -1 )
    {
        ERROR("Couldn't get HVM context size from Xen");
        goto out;
    }
    hvm_buf = malloc(hvm_buf_size);

    if (!to_send ||!to_skip ||!hvm_buf) {
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

    analysis_phase(xc_handle, dom, pfn_array_size, to_skip, 0);


    /* We want zeroed memory so use calloc rather than malloc. */
    pfn_batch = calloc(MAX_BATCH_SIZE, sizeof(*pfn_batch));

    if (pfn_batch == NULL) {
        ERROR("failed to alloc memory for pfn_batch array");
        errno = ENOMEM;
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

        while( N < pfn_array_size ){

            unsigned int this_pc = (N * 100) / pfn_array_size;
            int rc;

            if ((this_pc - prev_pc) >= 5) {
                DPRINTF("\b\b\b\b%3d%%", this_pc);
                prev_pc = this_pc;
            }

            /* slightly wasteful to peek the whole array evey time,
               but this is fast enough for the moment. */
            if (!last_iter && (rc = xc_shadow_control(
                    xc_handle, dom, XEN_DOMCTL_SHADOW_OP_PEEK, to_skip, 
                    pfn_array_size, NULL, 0, NULL)) != pfn_array_size) {
                ERROR("Error peeking HVM shadow bitmap");
                goto out;
            }


            /* load pfn_batch[] with the mfn of all the pages we're doing in
               this batch. */
            for (batch = 0; batch < MAX_BATCH_SIZE && N < pfn_array_size; N++){

                int n = permute(N, pfn_array_size, order_nr);

                if (0&&debug) {
                    DPRINTF("%d pfn= %08lx %d \n",
                            iter, (unsigned long)n, test_bit(n, to_send));
                }

                if (!last_iter && test_bit(n, to_send)&& test_bit(n, to_skip))
                    skip_this_iter++; /* stats keeping */

                if (!((test_bit(n, to_send) && !test_bit(n, to_skip)) ||
                      (test_bit(n, to_send) && last_iter)))
                    continue;

                /* Skip PFNs that aren't really there */
                if ((n >= 0xa0 && n < 0xc0) /* VGA hole */
                    || (n >= (HVM_BELOW_4G_MMIO_START >> PAGE_SHIFT)
                        && n < (1ULL << 32) >> PAGE_SHIFT) /* 4G MMIO hole */
                    || n == store_pfn
                    || n == ioreq_pfn
                    || n == bufioreq_pfn)
                    continue;

                /*
                ** we get here if:
                **  1. page is marked to_send & hasn't already been re-dirtied
                **  2. (ignore to_skip in last iteration)
                */

                pfn_batch[batch] = n;

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

            for ( j = 0; j < batch; j++ )
            {
                if ( pfn_batch[j] & XEN_DOMCTL_PFINFO_LTAB_MASK )
                    continue;
                if ( ratewrite(io_fd, region_base + j*PAGE_SIZE,
                               PAGE_SIZE) != PAGE_SIZE )
                {
                    ERROR("ERROR when writing to state file (4)");
                    goto out;
                }
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
                    total_sent, ((float)total_sent)/pfn_array_size );
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
                (total_sent > pfn_array_size*max_factor) ) {

                DPRINTF("Start last iteration for HVM domain\n");
                last_iter = 1;

                if (suspend_and_state(suspend, xc_handle, io_fd, dom, &info,
                                      &ctxt)) {
                    ERROR("Domain appears not to have suspended");
                    goto out;
                }

                DPRINTF("SUSPEND eip %08lx edx %08lx\n",
                        (unsigned long)ctxt.user_regs.eip,
                        (unsigned long)ctxt.user_regs.edx);
            }

            if (xc_shadow_control(xc_handle, dom, 
                                  XEN_DOMCTL_SHADOW_OP_CLEAN, to_send, 
                                  pfn_array_size, NULL, 
                                  0, &stats) != pfn_array_size) {
                ERROR("Error flushing shadow PT");
                goto out;
            }

            /* Pull in the dirty bits from qemu too */
            if (!last_iter) {
                qemu_active = qemu_non_active;
                qemu_non_active = qemu_active ? 0 : 1;
                qemu_flip_buffer(dom, qemu_active);
                for (j = 0; j < BITMAP_SIZE / sizeof(unsigned long); j++) {
                    to_send[j] |= qemu_bitmaps[qemu_non_active][j];
                    qemu_bitmaps[qemu_non_active][j] = 0;
                }
            } else {
                for (j = 0; j < BITMAP_SIZE / sizeof(unsigned long); j++) 
                    to_send[j] |= qemu_bitmaps[qemu_active][j];
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

    if ( (rec_size = xc_domain_hvm_getcontext(xc_handle, dom, hvm_buf, 
                                              hvm_buf_size)) == -1) {
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
    free(pfn_batch);
    free(to_send);
    free(to_skip);

    return !!rc;
}
