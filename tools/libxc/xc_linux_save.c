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

#include "xc_private.h"
#include "xc_dom.h"
#include "xg_private.h"
#include "xg_save_restore.h"

/*
** Default values for important tuning parameters. Can override by passing
** non-zero replacement values to xc_linux_save().
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

/* Live mapping of the table mapping each PFN to its current MFN. */
static xen_pfn_t *live_p2m = NULL;

/* Live mapping of system MFN to PFN table. */
static xen_pfn_t *live_m2p = NULL;
static unsigned long m2p_mfn0;

/* grep fodder: machine_to_phys */

#define mfn_to_pfn(_mfn) live_m2p[(_mfn)]

/*
 * Returns TRUE if the given machine frame number has a unique mapping
 * in the guest's pseudophysical map.
 */
#define MFN_IS_IN_PSEUDOPHYS_MAP(_mfn)          \
(((_mfn) < (max_mfn)) &&                        \
 ((mfn_to_pfn(_mfn) < (max_pfn)) &&               \
  (live_p2m[mfn_to_pfn(_mfn)] == (_mfn))))


/* Returns TRUE if MFN is successfully converted to a PFN. */
#define translate_mfn_to_pfn(_pmfn)                             \
({                                                              \
    unsigned long mfn = *(_pmfn);                               \
    int _res = 1;                                               \
    if ( !MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )                       \
        _res = 0;                                               \
    else                                                        \
        *(_pmfn) = mfn_to_pfn(mfn);                             \
    _res;                                                       \
})

/*
** During (live) save/migrate, we maintain a number of bitmaps to track
** which pages we have to send, to fixup, and to skip.
*/

#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define BITMAP_SIZE   ((max_pfn + BITS_PER_LONG - 1) / 8)

#define BITMAP_ENTRY(_nr,_bmap) \
   ((volatile unsigned long *)(_bmap))[(_nr)/BITS_PER_LONG]

#define BITMAP_SHIFT(_nr) ((_nr) % BITS_PER_LONG)

static inline int test_bit (int nr, volatile void * addr)
{
    return (BITMAP_ENTRY(nr, addr) >> BITMAP_SHIFT(nr)) & 1;
}

static inline void clear_bit (int nr, volatile void * addr)
{
    BITMAP_ENTRY(nr, addr) &= ~(1UL << BITMAP_SHIFT(nr));
}

static inline void set_bit ( int nr, volatile void * addr)
{
    BITMAP_ENTRY(nr, addr) |= (1UL << BITMAP_SHIFT(nr));
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
    volatile unsigned long *p = (volatile unsigned long *)addr;
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

static int noncached_write(int fd, int live, void *buffer, int len) 
{
    static int write_count = 0;

    int rc = write(fd,buffer,len);

    if (!live) {
        write_count += len;

        if (write_count >= MAX_PAGECACHE_USAGE*PAGE_SIZE) {
            int serrno = errno;

            /* Time to discard cache - dont care if this fails */
            discard_file_cache(fd, 0 /* no flush */);

            write_count = 0;

            errno = serrno;
        }
    }
    return rc;
}

#ifdef ADAPTIVE_SAVE


/*
** We control the rate at which we transmit (or save) to minimize impact
** on running domains (including the target if we're doing live migrate).
*/

#define MAX_MBIT_RATE    500      /* maximum transmit rate for migrate */
#define START_MBIT_RATE  100      /* initial transmit rate for migrate */


/* Scaling factor to convert between a rate (in Mb/s) and time (in usecs) */
#define RATE_TO_BTU      781250

/* Amount in bytes we allow ourselves to send in a burst */
#define BURST_BUDGET (100*1024)


/* We keep track of the current and previous transmission rate */
static int mbit_rate, ombit_rate = 0;

/* Have we reached the maximum transmission rate? */
#define RATE_IS_MAX() (mbit_rate == MAX_MBIT_RATE)


static inline void initialize_mbit_rate()
{
    mbit_rate = START_MBIT_RATE;
}


static int ratewrite(int io_fd, int live, void *buf, int n)
{
    static int budget = 0;
    static int burst_time_us = -1;
    static struct timeval last_put = { 0 };
    struct timeval now;
    struct timespec delay;
    long long delta;

    if (START_MBIT_RATE == 0)
        return noncached_write(io_fd, live, buf, n);

    budget -= n;
    if (budget < 0) {
        if (mbit_rate != ombit_rate) {
            burst_time_us = RATE_TO_BTU / mbit_rate;
            ombit_rate = mbit_rate;
            DPRINTF("rate limit: %d mbit/s burst budget %d slot time %d\n",
                    mbit_rate, BURST_BUDGET, burst_time_us);
        }
        if (last_put.tv_sec == 0) {
            budget += BURST_BUDGET;
            gettimeofday(&last_put, NULL);
        } else {
            while (budget < 0) {
                gettimeofday(&now, NULL);
                delta = tv_delta(&now, &last_put);
                while (delta > burst_time_us) {
                    budget += BURST_BUDGET;
                    last_put.tv_usec += burst_time_us;
                    if (last_put.tv_usec > 1000000) {
                        last_put.tv_usec -= 1000000;
                        last_put.tv_sec++;
                    }
                    delta -= burst_time_us;
                }
                if (budget > 0)
                    break;
                delay.tv_sec = 0;
                delay.tv_nsec = 1000 * (burst_time_us - delta);
                while (delay.tv_nsec > 0)
                    if (nanosleep(&delay, &delay) == 0)
                        break;
            }
        }
    }
    return noncached_write(io_fd, live, buf, n);
}

#else /* ! ADAPTIVE SAVE */

#define RATE_IS_MAX() (0)
#define ratewrite(_io_fd, _live, _buf, _n) noncached_write((_io_fd), (_live), (_buf), (_n))
#define initialize_mbit_rate()

#endif


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

#ifdef ADAPTIVE_SAVE
    if (((stats->dirty_count*PAGE_SIZE)/(wall_delta*(1000/8))) > mbit_rate) {
        mbit_rate = (int)((stats->dirty_count*PAGE_SIZE)/(wall_delta*(1000/8)))
            + 50;
        if (mbit_rate > MAX_MBIT_RATE)
            mbit_rate = MAX_MBIT_RATE;
    }
#endif

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


    if (info->dying) {
        ERROR("domain is dying");
        return -1;
    }

    if (info->crashed) {
        ERROR("domain has crashed");
        return -1;
    }

    if (info->shutdown) {
        switch (info->shutdown_reason) {
        case SHUTDOWN_poweroff:
        case SHUTDOWN_reboot:
            ERROR("domain has shut down");
            return -1;
        case SHUTDOWN_suspend:
            return 0;
        case SHUTDOWN_crash:
            ERROR("domain has crashed");
            return -1;
        }
    }

    if (info->paused) {
        // try unpausing domain, wait, and retest
        xc_domain_unpause( xc_handle, dom );

        ERROR("Domain was paused. Wait and re-test.");
        usleep(10000);  // 10ms

        goto retry;
    }


    if( ++i < 100 ) {
        ERROR("Retry suspend domain");
        usleep(10000);  // 10ms
        goto retry;
    }

    ERROR("Unable to suspend domain.");

    return -1;
}

/*
** Map the top-level page of MFNs from the guest. The guest might not have
** finished resuming from a previous restore operation, so we wait a while for
** it to update the MFN to a reasonable value.
*/
static void *map_frame_list_list(int xc_handle, uint32_t dom,
                                 shared_info_t *shinfo)
{
    int count = 100;
    void *p;

    while (count-- && shinfo->arch.pfn_to_mfn_frame_list_list == 0)
        usleep(10000);

    if (shinfo->arch.pfn_to_mfn_frame_list_list == 0) {
        ERROR("Timed out waiting for frame list updated.");
        return NULL;
    }

    p = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE, PROT_READ,
                             shinfo->arch.pfn_to_mfn_frame_list_list);

    if (p == NULL)
        ERROR("Couldn't map p2m_frame_list_list (errno %d)", errno);

    return p;
}

/*
** During transfer (or in the state file), all page-table pages must be
** converted into a 'canonical' form where references to actual mfns
** are replaced with references to the corresponding pfns.
**
** This function performs the appropriate conversion, taking into account
** which entries do not require canonicalization (in particular, those
** entries which map the virtual address reserved for the hypervisor).
*/
static int canonicalize_pagetable(unsigned long type, unsigned long pfn,
                           const void *spage, void *dpage)
{

    int i, pte_last, xen_start, xen_end, race = 0; 
    uint64_t pte;

    /*
    ** We need to determine which entries in this page table hold
    ** reserved hypervisor mappings. This depends on the current
    ** page table type as well as the number of paging levels.
    */
    xen_start = xen_end = pte_last = PAGE_SIZE / ((pt_levels == 2)? 4 : 8);

    if (pt_levels == 2 && type == XEN_DOMCTL_PFINFO_L2TAB)
        xen_start = (hvirt_start >> L2_PAGETABLE_SHIFT);

    if (pt_levels == 3 && type == XEN_DOMCTL_PFINFO_L3TAB)
        xen_start = L3_PAGETABLE_ENTRIES_PAE;

    /*
    ** in PAE only the L2 mapping the top 1GB contains Xen mappings.
    ** We can spot this by looking for the guest linear mapping which
    ** Xen always ensures is present in that L2. Guests must ensure
    ** that this check will fail for other L2s.
    */
    if (pt_levels == 3 && type == XEN_DOMCTL_PFINFO_L2TAB) {
        int hstart;
        uint64_t he;

        hstart = (hvirt_start >> L2_PAGETABLE_SHIFT_PAE) & 0x1ff;
        he = ((const uint64_t *) spage)[hstart];

        if ( ((he >> PAGE_SHIFT) & MFN_MASK_X86) == m2p_mfn0 ) {
            /* hvirt starts with xen stuff... */
            xen_start = hstart;
        } else if ( hvirt_start != 0xf5800000 ) {
            /* old L2s from before hole was shrunk... */
            hstart = (0xf5800000 >> L2_PAGETABLE_SHIFT_PAE) & 0x1ff;
            he = ((const uint64_t *) spage)[hstart];

            if( ((he >> PAGE_SHIFT) & MFN_MASK_X86) == m2p_mfn0 )
                xen_start = hstart;
        }
    }

    if (pt_levels == 4 && type == XEN_DOMCTL_PFINFO_L4TAB) {
        /*
        ** XXX SMH: should compute these from hvirt_start (which we have)
        ** and hvirt_end (which we don't)
        */
        xen_start = 256;
        xen_end   = 272;
    }

    /* Now iterate through the page table, canonicalizing each PTE */
    for (i = 0; i < pte_last; i++ ) {

        unsigned long pfn, mfn;

        if (pt_levels == 2)
            pte = ((const uint32_t*)spage)[i];
        else
            pte = ((const uint64_t*)spage)[i];

        if (i >= xen_start && i < xen_end)
            pte = 0;

        if (pte & _PAGE_PRESENT) {

            mfn = (pte >> PAGE_SHIFT) & MFN_MASK_X86;
            if (!MFN_IS_IN_PSEUDOPHYS_MAP(mfn)) {
                /* This will happen if the type info is stale which
                   is quite feasible under live migration */
                pfn  = 0;  /* zap it - we'll retransmit this page later */
                race = 1;  /* inform the caller of race; fatal if !live */ 
            } else
                pfn = mfn_to_pfn(mfn);

            pte &= ~MADDR_MASK_X86;
            pte |= (uint64_t)pfn << PAGE_SHIFT;

            /*
             * PAE guest L3Es can contain these flags when running on
             * a 64bit hypervisor. We zap these here to avoid any
             * surprise at restore time...
             */
            if ( pt_levels == 3 &&
                 type == XEN_DOMCTL_PFINFO_L3TAB &&
                 pte & (_PAGE_USER|_PAGE_RW|_PAGE_ACCESSED) )
            {
                pte &= ~(_PAGE_USER|_PAGE_RW|_PAGE_ACCESSED);
            }
        }

        if (pt_levels == 2)
            ((uint32_t*)dpage)[i] = pte;
        else
            ((uint64_t*)dpage)[i] = pte;

    }

    return race; 
}



static xen_pfn_t *xc_map_m2p(int xc_handle,
                                 unsigned long max_mfn,
                                 int prot)
{
    struct xen_machphys_mfn_list xmml;
    privcmd_mmap_entry_t *entries;
    unsigned long m2p_chunks, m2p_size;
    xen_pfn_t *m2p;
    xen_pfn_t *extent_start;
    int i, rc;

    m2p_size   = M2P_SIZE(max_mfn);
    m2p_chunks = M2P_CHUNKS(max_mfn);

    xmml.max_extents = m2p_chunks;
    if (!(extent_start = malloc(m2p_chunks * sizeof(xen_pfn_t)))) {
        ERROR("failed to allocate space for m2p mfns");
        return NULL;
    }
    set_xen_guest_handle(xmml.extent_start, extent_start);

    if (xc_memory_op(xc_handle, XENMEM_machphys_mfn_list, &xmml) ||
        (xmml.nr_extents != m2p_chunks)) {
        ERROR("xc_get_m2p_mfns");
        return NULL;
    }

    if ((m2p = mmap(NULL, m2p_size, prot,
                    MAP_SHARED, xc_handle, 0)) == MAP_FAILED) {
        ERROR("failed to mmap m2p");
        return NULL;
    }

    if (!(entries = malloc(m2p_chunks * sizeof(privcmd_mmap_entry_t)))) {
        ERROR("failed to allocate space for mmap entries");
        return NULL;
    }

    for (i=0; i < m2p_chunks; i++) {
        entries[i].va = (unsigned long)(((void *)m2p) + (i * M2P_CHUNK_SIZE));
        entries[i].mfn = extent_start[i];
        entries[i].npages = M2P_CHUNK_SIZE >> PAGE_SHIFT;
    }

    if ((rc = xc_map_foreign_ranges(xc_handle, DOMID_XEN,
        entries, m2p_chunks)) < 0) {
        ERROR("xc_mmap_foreign_ranges failed (rc = %d)", rc);
        return NULL;
    }

    m2p_mfn0 = entries[0].mfn;

    free(extent_start);
    free(entries);

    return m2p;
}



int xc_linux_save(int xc_handle, int io_fd, uint32_t dom, uint32_t max_iters,
                  uint32_t max_factor, uint32_t flags, int (*suspend)(int))
{
    xc_dominfo_t info;

    int rc = 1, i, j, last_iter, iter = 0;
    int live  = (flags & XCFLAGS_LIVE);
    int debug = (flags & XCFLAGS_DEBUG);
    int race = 0, sent_last_iter, skip_this_iter;

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;

    /* A copy of the CPU context of the guest. */
    vcpu_guest_context_t ctxt;

    /* A table containg the type of each PFN (/not/ MFN!). */
    unsigned long *pfn_type = NULL;
    unsigned long *pfn_batch = NULL;

    /* A temporary mapping, and a copy, of one frame of guest memory. */
    char page[PAGE_SIZE];

    /* Double and single indirect references to the live P2M table */
    xen_pfn_t *live_p2m_frame_list_list = NULL;
    xen_pfn_t *live_p2m_frame_list = NULL;

    /* A copy of the pfn-to-mfn table frame list. */
    xen_pfn_t *p2m_frame_list = NULL;

    /* Live mapping of shared info structure */
    shared_info_t *live_shinfo = NULL;

    /* base of the region in which domain memory is mapped */
    unsigned char *region_base = NULL;

    /* power of 2 order of max_pfn */
    int order_nr;

    /* bitmap of pages:
       - that should be sent this iteration (unless later marked as skip);
       - to skip this iteration because already dirty;
       - to fixup by sending at the end if not already resent; */
    unsigned long *to_send = NULL, *to_skip = NULL, *to_fix = NULL;

    xc_shadow_op_stats_t stats;

    unsigned long needed_to_fix = 0;
    unsigned long total_sent    = 0;


    /* If no explicit control parameters given, use defaults */
    if(!max_iters)
        max_iters = DEF_MAX_ITERS;
    if(!max_factor)
        max_factor = DEF_MAX_FACTOR;

    initialize_mbit_rate();

    if(!get_platform_info(xc_handle, dom,
                          &max_mfn, &hvirt_start, &pt_levels)) {
        ERROR("Unable to get platform info.");
        return 1;
    }

    if (xc_domain_getinfo(xc_handle, dom, 1, &info) != 1) {
        ERROR("Could not get domain info");
        return 1;
    }

    if (lock_pages(&ctxt, sizeof(ctxt))) {
        ERROR("Unable to lock ctxt");
        return 1;
    }

    /* Only have to worry about vcpu 0 even for SMP */
    if (xc_vcpu_getcontext(xc_handle, dom, 0, &ctxt)) {
        ERROR("Could not get vcpu context");
        goto out;
    }
    shared_info_frame = info.shared_info_frame;

    /* A cheesy test to see whether the domain contains valid state. */
    if (ctxt.ctrlreg[3] == 0)
    {
        ERROR("Domain is not in a valid Linux guest OS state");
        goto out;
    }

    /* Map the shared info frame */
    if(!(live_shinfo = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                            PROT_READ, shared_info_frame))) {
        ERROR("Couldn't map live_shinfo");
        goto out;
    }

    max_pfn = live_shinfo->arch.max_pfn;

    live_p2m_frame_list_list = map_frame_list_list(xc_handle, dom,
                                                   live_shinfo);

    if (!live_p2m_frame_list_list)
        goto out;

    live_p2m_frame_list =
        xc_map_foreign_batch(xc_handle, dom, PROT_READ,
                             live_p2m_frame_list_list,
                             P2M_FLL_ENTRIES);

    if (!live_p2m_frame_list) {
        ERROR("Couldn't map p2m_frame_list");
        goto out;
    }

    /* Map all the frames of the pfn->mfn table. For migrate to succeed,
       the guest must not change which frames are used for this purpose.
       (its not clear why it would want to change them, and we'll be OK
       from a safety POV anyhow. */

    live_p2m = xc_map_foreign_batch(xc_handle, dom, PROT_READ,
                                    live_p2m_frame_list,
                                    P2M_FL_ENTRIES);

    if (!live_p2m) {
        ERROR("Couldn't map p2m table");
        goto out;
    }

    /* Setup the mfn_to_pfn table mapping */
    if(!(live_m2p = xc_map_m2p(xc_handle, max_mfn, PROT_READ))) {
        ERROR("Failed to map live M2P table");
        goto out;
    }


    /* Get a local copy of the live_P2M_frame_list */
    if(!(p2m_frame_list = malloc(P2M_FL_SIZE))) {
        ERROR("Couldn't allocate p2m_frame_list array");
        goto out;
    }
    memcpy(p2m_frame_list, live_p2m_frame_list, P2M_FL_SIZE);

    /* Canonicalise the pfn-to-mfn table frame-number list. */
    for (i = 0; i < max_pfn; i += fpp) {
        if (!translate_mfn_to_pfn(&p2m_frame_list[i/fpp])) {
            ERROR("Frame# in pfn-to-mfn frame list is not in pseudophys");
            ERROR("entry %d: p2m_frame_list[%ld] is 0x%"PRIx64, i, i/fpp,
                (uint64_t)p2m_frame_list[i/fpp]);
            goto out;
        }
    }

    /* Domain is still running at this point */
    if (live) {

        if (xc_shadow_control(xc_handle, dom,
                              XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY,
                              NULL, 0, NULL, 0, NULL) < 0) {
            ERROR("Couldn't enable shadow mode");
            goto out;
        }

        last_iter = 0;

    } else {

        /* This is a non-live suspend. Issue the call back to get the
           domain suspended */

        last_iter = 1;

        if (suspend_and_state(suspend, xc_handle, io_fd, dom, &info, &ctxt)) {
            ERROR("Domain appears not to have suspended");
            goto out;
        }

    }

    /* pretend we sent all the pages last iteration */
    sent_last_iter = max_pfn;


    /* calculate the power of 2 order of max_pfn, e.g.
       15->4 16->4 17->5 */
    for (i = max_pfn-1, order_nr = 0; i ; i >>= 1, order_nr++)
        continue;

    /* Setup to_send / to_fix and to_skip bitmaps */
    to_send = malloc(BITMAP_SIZE);
    to_fix  = calloc(1, BITMAP_SIZE);
    to_skip = malloc(BITMAP_SIZE);

    if (!to_send || !to_fix || !to_skip) {
        ERROR("Couldn't allocate to_send array");
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

    /* We want zeroed memory so use calloc rather than malloc. */
    pfn_type   = calloc(MAX_BATCH_SIZE, sizeof(*pfn_type));
    pfn_batch  = calloc(MAX_BATCH_SIZE, sizeof(*pfn_batch));

    if ((pfn_type == NULL) || (pfn_batch == NULL)) {
        ERROR("failed to alloc memory for pfn_type and/or pfn_batch arrays");
        errno = ENOMEM;
        goto out;
    }

    if (lock_pages(pfn_type, MAX_BATCH_SIZE * sizeof(*pfn_type))) {
        ERROR("Unable to lock");
        goto out;
    }

    /*
     * Quick belt and braces sanity check.
     */
    {
        int err=0;
        unsigned long mfn;
        for (i = 0; i < max_pfn; i++) {

            mfn = live_p2m[i];
            if((mfn != INVALID_P2M_ENTRY) && (mfn_to_pfn(mfn) != i)) {
                DPRINTF("i=0x%x mfn=%lx live_m2p=%lx\n", i,
                        mfn, mfn_to_pfn(mfn));
                err++;
            }
        }
        DPRINTF("Had %d unexplained entries in p2m table\n", err);
    }


    /* Start writing out the saved-domain record. */

    if (!write_exact(io_fd, &max_pfn, sizeof(unsigned long))) {
        ERROR("write: max_pfn");
        goto out;
    }

    /*
     * Write an extended-info structure to inform the restore code that
     * a PAE guest understands extended CR3 (PDPTs above 4GB). Turns off
     * slow paths in the restore code.
     */
    if ((pt_levels == 3) &&
        (ctxt.vm_assist & (1UL << VMASST_TYPE_pae_extended_cr3))) {
        unsigned long signature = ~0UL;
        uint32_t tot_sz   = sizeof(struct vcpu_guest_context) + 8;
        uint32_t chunk_sz = sizeof(struct vcpu_guest_context);
        char chunk_sig[]  = "vcpu";
        if (!write_exact(io_fd, &signature, sizeof(signature)) ||
            !write_exact(io_fd, &tot_sz,    sizeof(tot_sz)) ||
            !write_exact(io_fd, &chunk_sig, 4) ||
            !write_exact(io_fd, &chunk_sz,  sizeof(chunk_sz)) ||
            !write_exact(io_fd, &ctxt,      sizeof(ctxt))) {
            ERROR("write: extended info");
            goto out;
        }
    }

    if (!write_exact(io_fd, p2m_frame_list, P2M_FL_SIZE)) {
        ERROR("write: p2m_frame_list");
        goto out;
    }

    print_stats(xc_handle, dom, 0, &stats, 0);

    /* Now write out each data page, canonicalising page tables as we go... */

    while(1) {

        unsigned int prev_pc, sent_this_iter, N, batch;

        iter++;
        sent_this_iter = 0;
        skip_this_iter = 0;
        prev_pc = 0;
        N=0;

        DPRINTF("Saving memory pages: iter %d   0%%", iter);

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
                ERROR("Error peeking shadow bitmap");
                goto out;
            }


            /* load pfn_type[] with the mfn of all the pages we're doing in
               this batch. */
            for (batch = 0; batch < MAX_BATCH_SIZE && N < max_pfn ; N++) {

                int n = permute(N, max_pfn, order_nr);

                if (debug) {
                    DPRINTF("%d pfn= %08lx mfn= %08lx %d  [mfn]= %08lx\n",
                            iter, (unsigned long)n, live_p2m[n],
                            test_bit(n, to_send),
                            mfn_to_pfn(live_p2m[n]&0xFFFFF));
                }

                if (!last_iter && test_bit(n, to_send)&& test_bit(n, to_skip))
                    skip_this_iter++; /* stats keeping */

                if (!((test_bit(n, to_send) && !test_bit(n, to_skip)) ||
                      (test_bit(n, to_send) && last_iter) ||
                      (test_bit(n, to_fix)  && last_iter)))
                    continue;

                /*
                ** we get here if:
                **  1. page is marked to_send & hasn't already been re-dirtied
                **  2. (ignore to_skip in last iteration)
                **  3. add in pages that still need fixup (net bufs)
                */

                pfn_batch[batch] = n;
                pfn_type[batch]  = live_p2m[n];

                if(!is_mapped(pfn_type[batch])) {

                    /*
                    ** not currently in psuedo-physical map -- set bit
                    ** in to_fix since we must send this page in last_iter
                    ** unless its sent sooner anyhow, or it never enters
                    ** pseudo-physical map (e.g. for ballooned down domains)
                    */

                    set_bit(n, to_fix);
                    continue;
                }

                if(last_iter && test_bit(n, to_fix) && !test_bit(n, to_send)) {
                    needed_to_fix++;
                    DPRINTF("Fix! iter %d, pfn %x. mfn %lx\n",
                            iter, n, pfn_type[batch]);
                }

                clear_bit(n, to_fix);

                batch++;
            }

            if (batch == 0)
                goto skip; /* vanishingly unlikely... */

            if ((region_base = xc_map_foreign_batch(
                     xc_handle, dom, PROT_READ, pfn_type, batch)) == 0) {
                ERROR("map batch failed");
                goto out;
            }

            for ( j = 0; j < batch; j++ )
                ((uint32_t *)pfn_type)[j] = pfn_type[j];
            if ( xc_get_pfn_type_batch(xc_handle, dom, batch,
                                       (uint32_t *)pfn_type) )
            {
                ERROR("get_pfn_type_batch failed");
                goto out;
            }
            for ( j = batch-1; j >= 0; j-- )
                pfn_type[j] = ((uint32_t *)pfn_type)[j];

            for ( j = 0; j < batch; j++ )
            {

                if ( (pfn_type[j] & XEN_DOMCTL_PFINFO_LTAB_MASK) ==
                     XEN_DOMCTL_PFINFO_XTAB )
                {
                    DPRINTF("type fail: page %i mfn %08lx\n", j, pfn_type[j]);
                    continue;
                }

                if (debug)
                    DPRINTF("%d pfn= %08lx mfn= %08lx [mfn]= %08lx"
                            " sum= %08lx\n",
                            iter,
                            (pfn_type[j] & XEN_DOMCTL_PFINFO_LTAB_MASK) |
                            pfn_batch[j],
                            pfn_type[j],
                            mfn_to_pfn(pfn_type[j] &
                                       ~XEN_DOMCTL_PFINFO_LTAB_MASK),
                            csum_page(region_base + (PAGE_SIZE*j)));

                /* canonicalise mfn->pfn */
                pfn_type[j] = (pfn_type[j] & XEN_DOMCTL_PFINFO_LTAB_MASK) |
                    pfn_batch[j];
            }

            if(!write_exact(io_fd, &batch, sizeof(unsigned int))) {
                ERROR("Error when writing to state file (2) (errno %d)",
                      errno);
                goto out;
            }

            if(!write_exact(io_fd, pfn_type, sizeof(unsigned long)*j)) {
                ERROR("Error when writing to state file (3) (errno %d)",
                      errno);
                goto out;
            }

            /* entering this loop, pfn_type is now in pfns (Not mfns) */
            for ( j = 0; j < batch; j++ )
            {
                unsigned long pfn, pagetype;
                void *spage = (char *)region_base + (PAGE_SIZE*j);

                pfn      = pfn_type[j] & ~XEN_DOMCTL_PFINFO_LTAB_MASK;
                pagetype = pfn_type[j] &  XEN_DOMCTL_PFINFO_LTAB_MASK;

                /* write out pages in batch */
                if ( pagetype == XEN_DOMCTL_PFINFO_XTAB )
                    continue;

                pagetype &= XEN_DOMCTL_PFINFO_LTABTYPE_MASK;

                if ( (pagetype >= XEN_DOMCTL_PFINFO_L1TAB) &&
                     (pagetype <= XEN_DOMCTL_PFINFO_L4TAB) )
                {
                    /* We have a pagetable page: need to rewrite it. */
                    race = 
                        canonicalize_pagetable(pagetype, pfn, spage, page); 

                    if(race && !live) {
                        ERROR("Fatal PT race (pfn %lx, type %08lx)", pfn,
                              pagetype);
                        goto out;
                    }

                    if (ratewrite(io_fd, live, page, PAGE_SIZE) != PAGE_SIZE) {
                        ERROR("Error when writing to state file (4)"
                              " (errno %d)", errno);
                        goto out;
                    }

                }  else {

                    /* We have a normal page: just write it directly. */
                    if (ratewrite(io_fd, live, spage, PAGE_SIZE) != PAGE_SIZE) {
                        ERROR("Error when writing to state file (5)"
                              " (errno %d)", errno);
                        goto out;
                    }
                }
            } /* end of the write out for this batch */

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
            DPRINTF("(of which %ld were fixups)\n", needed_to_fix  );
        }

        if (last_iter && debug) {
            int minusone = -1;
            memset(to_send, 0xff, BITMAP_SIZE);
            debug = 0;
            DPRINTF("Entering debug resend-all mode\n");

            /* send "-1" to put receiver into debug mode */
            if(!write_exact(io_fd, &minusone, sizeof(int))) {
                ERROR("Error when writing to state file (6) (errno %d)",
                      errno);
                goto out;
            }

            continue;
        }

        if (last_iter)
            break;

        if (live) {
            if (((sent_this_iter > sent_last_iter) && RATE_IS_MAX()) ||
                (iter >= max_iters) ||
                (sent_this_iter+skip_this_iter < 50) ||
                (total_sent > max_pfn*max_factor)) {
                DPRINTF("Start last iteration\n");
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

    DPRINTF("All memory is saved\n");

    /* Zero terminate */
    i = 0;
    if (!write_exact(io_fd, &i, sizeof(int))) {
        ERROR("Error when writing to state file (6') (errno %d)", errno);
        goto out;
    }

    /* Send through a list of all the PFNs that were not in map at the close */
    {
        unsigned int i,j;
        unsigned long pfntab[1024];

        for (i = 0, j = 0; i < max_pfn; i++) {
            if (!is_mapped(live_p2m[i]))
                j++;
        }

        if(!write_exact(io_fd, &j, sizeof(unsigned int))) {
            ERROR("Error when writing to state file (6a) (errno %d)", errno);
            goto out;
        }

        for (i = 0, j = 0; i < max_pfn; ) {

            if (!is_mapped(live_p2m[i]))
                pfntab[j++] = i;

            i++;
            if (j == 1024 || i == max_pfn) {
                if(!write_exact(io_fd, &pfntab, sizeof(unsigned long)*j)) {
                    ERROR("Error when writing to state file (6b) (errno %d)",
                          errno);
                    goto out;
                }
                j = 0;
            }
        }

    }

    /* Canonicalise the suspend-record frame number. */
    if ( !translate_mfn_to_pfn(&ctxt.user_regs.edx) ){
        ERROR("Suspend record is not in range of pseudophys map");
        goto out;
    }

    /* Canonicalise each GDT frame number. */
    for ( i = 0; (512*i) < ctxt.gdt_ents; i++ ) {
        if ( !translate_mfn_to_pfn(&ctxt.gdt_frames[i]) ) {
            ERROR("GDT frame is not in range of pseudophys map");
            goto out;
        }
    }

    /* Canonicalise the page table base pointer. */
    if ( !MFN_IS_IN_PSEUDOPHYS_MAP(xen_cr3_to_pfn(ctxt.ctrlreg[3])) ) {
        ERROR("PT base is not in range of pseudophys map");
        goto out;
    }
    ctxt.ctrlreg[3] = 
        xen_pfn_to_cr3(mfn_to_pfn(xen_cr3_to_pfn(ctxt.ctrlreg[3])));

    /*
     * Reset the MFN to be a known-invalid value. See map_frame_list_list().
     */
    memcpy(page, live_shinfo, PAGE_SIZE);
    ((shared_info_t *)page)->arch.pfn_to_mfn_frame_list_list = 0;

    if (!write_exact(io_fd, &ctxt, sizeof(ctxt)) ||
        !write_exact(io_fd, page, PAGE_SIZE)) {
        ERROR("Error when writing to state file (1) (errno %d)", errno);
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
    else {
        // flush last write and discard cache for file
        discard_file_cache(io_fd, 1 /* flush */);
    }            

    if (live_shinfo)
        munmap(live_shinfo, PAGE_SIZE);

    if (live_p2m_frame_list_list)
        munmap(live_p2m_frame_list_list, PAGE_SIZE);

    if (live_p2m_frame_list)
        munmap(live_p2m_frame_list, P2M_FLL_ENTRIES * PAGE_SIZE);

    if(live_p2m)
        munmap(live_p2m, P2M_SIZE);

    if(live_m2p)
        munmap(live_m2p, M2P_SIZE(max_mfn));

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
