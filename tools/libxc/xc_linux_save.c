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
static unsigned long *live_p2m = NULL;

/* Live mapping of system MFN to PFN table. */
static unsigned long *live_m2p = NULL;

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
   ((unsigned long *)(_bmap))[(_nr)/BITS_PER_LONG]

#define BITMAP_SHIFT(_nr) ((_nr) % BITS_PER_LONG)

static inline int test_bit (int nr, volatile void * addr)
{
    return (BITMAP_ENTRY(nr, addr) >> BITMAP_SHIFT(nr)) & 1;
}

static inline void clear_bit (int nr, volatile void * addr)
{
    BITMAP_ENTRY(nr, addr) &= ~(1 << BITMAP_SHIFT(nr));
}

static inline void set_bit ( int nr, volatile void * addr)
{
    BITMAP_ENTRY(nr, addr) |= (1 << BITMAP_SHIFT(nr));
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


static int ratewrite(int io_fd, void *buf, int n)
{
    static int budget = 0;
    static int burst_time_us = -1;
    static struct timeval last_put = { 0 };
    struct timeval now;
    struct timespec delay;
    long long delta;

    if (START_MBIT_RATE == 0)
        return write(io_fd, buf, n);

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
    return write(io_fd, buf, n);
}

#else /* ! ADAPTIVE SAVE */

#define RATE_IS_MAX() (0)
#define ratewrite(_io_fd, _buf, _n) write((_io_fd), (_buf), (_n))
#define initialize_mbit_rate()

#endif


static inline ssize_t write_exact(int fd, void *buf, size_t count)
{
    if(write(fd, buf, count) != count)
        return 0;
    return 1;
}



static int print_stats(int xc_handle, uint32_t domid, int pages_sent,
                       xc_shadow_control_stats_t *stats, int print)
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

    if (wall_delta == 0) wall_delta = 1;

    d0_cpu_delta = (d0_cpu_now - d0_cpu_last)/1000;
    d1_cpu_delta = (d1_cpu_now - d1_cpu_last)/1000;

    if (print)
        fprintf(stderr,
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
    xc_shadow_control_stats_t stats;
    int j;

    start = llgettimeofday();

    for (j = 0; j < runs; j++) {
        int i;

        xc_shadow_control(xc_handle, domid, DOM0_SHADOW_CONTROL_OP_CLEAN,
                          arr, max_pfn, NULL);
        fprintf(stderr, "#Flush\n");
        for ( i = 0; i < 40; i++ ) {
            usleep(50000);
            now = llgettimeofday();
            xc_shadow_control(xc_handle, domid, DOM0_SHADOW_CONTROL_OP_PEEK,
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


static int suspend_and_state(int (*suspend)(int), int xc_handle, int io_fd,
                             int dom, xc_dominfo_t *info,
                             vcpu_guest_context_t *ctxt)
{
    int i = 0;

    if (!(*suspend)(dom)) {
        ERR("Suspend request failed");
        return -1;
    }

 retry:

    if (xc_domain_getinfo(xc_handle, dom, 1, info) != 1) {
        ERR("Could not get domain info");
        return -1;
    }

    if ( xc_vcpu_getcontext(xc_handle, dom, 0 /* XXX */, ctxt))
        ERR("Could not get vcpu context");


    if (info->shutdown && info->shutdown_reason == SHUTDOWN_suspend)
        return 0; // success

    if (info->paused) {
        // try unpausing domain, wait, and retest
        xc_domain_unpause( xc_handle, dom );

        ERR("Domain was paused. Wait and re-test.");
        usleep(10000);  // 10ms

        goto retry;
    }


    if( ++i < 100 ) {
        ERR("Retry suspend domain.");
        usleep(10000);  // 10ms
        goto retry;
    }

    ERR("Unable to suspend domain.");

    return -1;
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
void canonicalize_pagetable(unsigned long type, unsigned long pfn,
                             const void *spage, void *dpage)
{

    int i, pte_last, xen_start, xen_end;
    uint64_t pte;

    /*
    ** We need to determine which entries in this page table hold
    ** reserved hypervisor mappings. This depends on the current
    ** page table type as well as the number of paging levels.
    */
    xen_start = xen_end = pte_last = PAGE_SIZE / ((pt_levels == 2)? 4 : 8);

    if (pt_levels == 2 && type == L2TAB)
        xen_start = (hvirt_start >> L2_PAGETABLE_SHIFT);

    if (pt_levels == 3 && type == L3TAB)
        xen_start = L3_PAGETABLE_ENTRIES_PAE;

    /*
    ** in PAE only the L2 mapping the top 1GB contains Xen mappings.
    ** We can spot this by looking for the guest linear mapping which
    ** Xen always ensures is present in that L2. Guests must ensure
    ** that this check will fail for other L2s.
    */
    if (pt_levels == 3 && type == L2TAB) {

/* XXX index of the L2 entry in PAE mode which holds the guest LPT */
#define PAE_GLPT_L2ENTRY (495)
        pte = ((uint64_t*)spage)[PAE_GLPT_L2ENTRY];

        if(((pte >> PAGE_SHIFT) & 0x0fffffff) == live_p2m[pfn])
            xen_start = (hvirt_start >> L2_PAGETABLE_SHIFT_PAE) & 0x1ff;
    }

    if (pt_levels == 4 && type == L4TAB) {
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
            pte = ((uint32_t*)spage)[i];
        else
            pte = ((uint64_t*)spage)[i];

        if (i >= xen_start && i < xen_end)
            pte = 0;

        if (pte & _PAGE_PRESENT) {

            mfn = (pte >> PAGE_SHIFT) & 0xfffffff;
            if (!MFN_IS_IN_PSEUDOPHYS_MAP(mfn)) {
                /* This will happen if the type info is stale which
                   is quite feasible under live migration */
                DPRINTF("PT Race: [%08lx,%d] pte=%llx, mfn=%08lx\n",
                        type, i, (unsigned long long)pte, mfn);
                pfn = 0; /* zap it - we'll retransmit this page later */
            } else
                pfn = mfn_to_pfn(mfn);

            pte &= 0xffffff0000000fffULL;
            pte |= (uint64_t)pfn << PAGE_SHIFT;
        }

        if (pt_levels == 2)
            ((uint32_t*)dpage)[i] = pte;
        else
            ((uint64_t*)dpage)[i] = pte;

    }

    return;
}



static unsigned long *xc_map_m2p(int xc_handle,
                                 unsigned long max_mfn,
                                 int prot)
{
    struct xen_machphys_mfn_list xmml;
    privcmd_mmap_entry_t *entries;
    unsigned long m2p_chunks, m2p_size;
    unsigned long *m2p;
    unsigned long *extent_start;
    int i, rc;

    m2p_size   = M2P_SIZE(max_mfn);
    m2p_chunks = M2P_CHUNKS(max_mfn);

    xmml.max_extents = m2p_chunks;
    if (!(extent_start = malloc(m2p_chunks * sizeof(unsigned long)))) {
        ERR("failed to allocate space for m2p mfns");
        return NULL;
    }
    set_xen_guest_handle(xmml.extent_start, extent_start);

    if (xc_memory_op(xc_handle, XENMEM_machphys_mfn_list, &xmml) ||
        (xmml.nr_extents != m2p_chunks)) {
        ERR("xc_get_m2p_mfns");
        return NULL;
    }

    if ((m2p = mmap(NULL, m2p_size, prot,
                    MAP_SHARED, xc_handle, 0)) == MAP_FAILED) {
        ERR("failed to mmap m2p");
        return NULL;
    }

    if (!(entries = malloc(m2p_chunks * sizeof(privcmd_mmap_entry_t)))) {
        ERR("failed to allocate space for mmap entries");
        return NULL;
    }

    for (i=0; i < m2p_chunks; i++) {
        entries[i].va = (unsigned long)(((void *)m2p) + (i * M2P_CHUNK_SIZE));
        entries[i].mfn = extent_start[i];
        entries[i].npages = M2P_CHUNK_SIZE >> PAGE_SHIFT;
    }

    if ((rc = xc_map_foreign_ranges(xc_handle, DOMID_XEN,
        entries, m2p_chunks)) < 0) {
        ERR("xc_mmap_foreign_ranges failed (rc = %d)", rc);
        return NULL;
    }

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
    int sent_last_iter, skip_this_iter;

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
    unsigned long *live_p2m_frame_list_list = NULL;
    unsigned long *live_p2m_frame_list = NULL;

    /* A copy of the pfn-to-mfn table frame list. */
    unsigned long *p2m_frame_list = NULL;

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

    xc_shadow_control_stats_t stats;

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
        ERR("Unable to get platform info.");
        return 1;
    }

    if (xc_domain_getinfo(xc_handle, dom, 1, &info) != 1) {
        ERR("Could not get domain info");
        return 1;
    }

    if (mlock(&ctxt, sizeof(ctxt))) {
        ERR("Unable to mlock ctxt");
        return 1;
    }

    /* Only have to worry about vcpu 0 even for SMP */
    if (xc_vcpu_getcontext(xc_handle, dom, 0, &ctxt)) {
        ERR("Could not get vcpu context");
        goto out;
    }
    shared_info_frame = info.shared_info_frame;

    /* A cheesy test to see whether the domain contains valid state. */
    if (ctxt.ctrlreg[3] == 0)
    {
        ERR("Domain is not in a valid Linux guest OS state");
        goto out;
    }

   /* cheesy sanity check */
    if ((info.max_memkb >> (PAGE_SHIFT - 10)) > max_mfn) {
        ERR("Invalid state record -- pfn count out of range: %lu",
            (info.max_memkb >> (PAGE_SHIFT - 10)));
        goto out;
     }

    /* Map the shared info frame */
    if(!(live_shinfo = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                            PROT_READ, shared_info_frame))) {
        ERR("Couldn't map live_shinfo");
        goto out;
    }

    max_pfn = live_shinfo->arch.max_pfn;

    live_p2m_frame_list_list =
        xc_map_foreign_range(xc_handle, dom, PAGE_SIZE, PROT_READ,
                             live_shinfo->arch.pfn_to_mfn_frame_list_list);

    if (!live_p2m_frame_list_list) {
        ERR("Couldn't map p2m_frame_list_list (errno %d)", errno);
        goto out;
    }

    live_p2m_frame_list =
        xc_map_foreign_batch(xc_handle, dom, PROT_READ,
                             live_p2m_frame_list_list,
                             P2M_FLL_ENTRIES);

    if (!live_p2m_frame_list) {
        ERR("Couldn't map p2m_frame_list");
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
        ERR("Couldn't map p2m table");
        goto out;
    }

    /* Setup the mfn_to_pfn table mapping */
    if(!(live_m2p = xc_map_m2p(xc_handle, max_mfn, PROT_READ))) {
        ERR("Failed to map live M2P table");
        goto out;
    }


    /* Get a local copy of the live_P2M_frame_list */
    if(!(p2m_frame_list = malloc(P2M_FL_SIZE))) {
        ERR("Couldn't allocate p2m_frame_list array");
        goto out;
    }
    memcpy(p2m_frame_list, live_p2m_frame_list, P2M_FL_SIZE);

    /* Canonicalise the pfn-to-mfn table frame-number list. */
    for (i = 0; i < max_pfn; i += ulpp) {
        if (!translate_mfn_to_pfn(&p2m_frame_list[i/ulpp])) {
            ERR("Frame# in pfn-to-mfn frame list is not in pseudophys");
            ERR("entry %d: p2m_frame_list[%ld] is 0x%lx", i, i/ulpp,
                p2m_frame_list[i/ulpp]);
            goto out;
        }
    }

    /* Domain is still running at this point */
    if (live) {

        if (xc_shadow_control(xc_handle, dom,
                              DOM0_SHADOW_CONTROL_OP_ENABLE_LOGDIRTY,
                              NULL, 0, NULL ) < 0) {
            ERR("Couldn't enable shadow mode");
            goto out;
        }

        last_iter = 0;

    } else {

        /* This is a non-live suspend. Issue the call back to get the
           domain suspended */

        last_iter = 1;

        if (suspend_and_state(suspend, xc_handle, io_fd, dom, &info, &ctxt)) {
            ERR("Domain appears not to have suspended");
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
        ERR("Couldn't allocate to_send array");
        goto out;
    }

    memset(to_send, 0xff, BITMAP_SIZE);

    if (mlock(to_send, BITMAP_SIZE)) {
        ERR("Unable to mlock to_send");
        return 1;
    }

    /* (to fix is local only) */
    if (mlock(to_skip, BITMAP_SIZE)) {
        ERR("Unable to mlock to_skip");
        return 1;
    }

    analysis_phase(xc_handle, dom, max_pfn, to_skip, 0);

    /* We want zeroed memory so use calloc rather than malloc. */
    pfn_type  = calloc(MAX_BATCH_SIZE, sizeof(unsigned long));
    pfn_batch = calloc(MAX_BATCH_SIZE, sizeof(unsigned long));

    if ((pfn_type == NULL) || (pfn_batch == NULL)) {
        ERR("failed to alloc memory for pfn_type and/or pfn_batch arrays");
        errno = ENOMEM;
        goto out;
    }

    if (mlock(pfn_type, MAX_BATCH_SIZE * sizeof(unsigned long))) {
        ERR("Unable to mlock");
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

    if(!write_exact(io_fd, &max_pfn, sizeof(unsigned long))) {
        ERR("write: max_pfn");
        goto out;
    }

    if(!write_exact(io_fd, p2m_frame_list, P2M_FL_SIZE)) {
        ERR("write: p2m_frame_list");
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
                    xc_handle, dom, DOM0_SHADOW_CONTROL_OP_PEEK,
                    to_skip, max_pfn, NULL) != max_pfn) {
                ERR("Error peeking shadow bitmap");
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

                    /* not currently in pusedo-physical map -- set bit
                       in to_fix that we must send this page in last_iter
                       unless its sent sooner anyhow */

                    set_bit(n, to_fix);
                    if( (iter > 1) && IS_REAL_PFN(n) )
                        DPRINTF("netbuf race: iter %d, pfn %x. mfn %lx\n",
                                iter, n, pfn_type[batch]);
                    continue;
                }

                if(last_iter && test_bit(n, to_fix) && !test_bit(n, to_send)) {
                    needed_to_fix++;
                    DPRINTF("Fix! iter %d, pfn %x. mfn %lx\n",
                            iter,n,pfn_type[batch]);
                }

                clear_bit(n, to_fix);

                batch++;
            }

            if (batch == 0)
                goto skip; /* vanishingly unlikely... */

            if ((region_base = xc_map_foreign_batch(
                     xc_handle, dom, PROT_READ, pfn_type, batch)) == 0) {
                ERR("map batch failed");
                goto out;
            }

            if (xc_get_pfn_type_batch(xc_handle, dom, batch, pfn_type)) {
                ERR("get_pfn_type_batch failed");
                goto out;
            }

            for (j = 0; j < batch; j++) {

                if ((pfn_type[j] & LTAB_MASK) == XTAB) {
                    DPRINTF("type fail: page %i mfn %08lx\n", j, pfn_type[j]);
                    continue;
                }

                if (debug)
                    fprintf(stderr, "%d pfn= %08lx mfn= %08lx [mfn]= %08lx"
                            " sum= %08lx\n",
                            iter,
                            (pfn_type[j] & LTAB_MASK) | pfn_batch[j],
                            pfn_type[j],
                            mfn_to_pfn(pfn_type[j]&(~LTAB_MASK)),
                            csum_page(region_base + (PAGE_SIZE*j)));

                /* canonicalise mfn->pfn */
                pfn_type[j] = (pfn_type[j] & LTAB_MASK) | pfn_batch[j];
            }

            if(!write_exact(io_fd, &batch, sizeof(unsigned int))) {
                ERR("Error when writing to state file (2)");
                goto out;
            }

            if(!write_exact(io_fd, pfn_type, sizeof(unsigned long)*j)) {
                ERR("Error when writing to state file (3)");
                goto out;
            }

            /* entering this loop, pfn_type is now in pfns (Not mfns) */
            for (j = 0; j < batch; j++) {

                unsigned long pfn      = pfn_type[j] & ~LTAB_MASK;
                unsigned long pagetype = pfn_type[j] & LTAB_MASK;
                void *spage            = (void *) region_base + (PAGE_SIZE*j);


                /* write out pages in batch */
                if (pagetype == XTAB)
                    continue;

                pagetype &= LTABTYPE_MASK;

                if (pagetype >= L1TAB && pagetype <= L4TAB) {

                    /* We have a pagetable page: need to rewrite it. */
                    canonicalize_pagetable(pagetype, pfn, spage, page);

                    if (ratewrite(io_fd, page, PAGE_SIZE) != PAGE_SIZE) {
                        ERR("Error when writing to state file (4)");
                        goto out;
                    }

                }  else {

                    /* We have a normal page: just write it directly. */
                    if (ratewrite(io_fd, spage, PAGE_SIZE) != PAGE_SIZE) {
                        ERR("Error when writing to state file (5)");
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

        if (last_iter && debug){
            int minusone = -1;
            memset(to_send, 0xff, BITMAP_SIZE);
            debug = 0;
            fprintf(stderr, "Entering debug resend-all mode\n");

            /* send "-1" to put receiver into debug mode */
            if(!write_exact(io_fd, &minusone, sizeof(int))) {
                ERR("Error when writing to state file (6)");
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

                DPRINTF("Start last iteration\n");
                last_iter = 1;

                if (suspend_and_state(suspend, xc_handle, io_fd, dom, &info,
                                      &ctxt)) {
                    ERR("Domain appears not to have suspended");
                    goto out;
                }

                DPRINTF("SUSPEND shinfo %08lx eip %08lx edx %08lx\n",
                        info.shared_info_frame,
                        (unsigned long)ctxt.user_regs.eip,
                        (unsigned long)ctxt.user_regs.edx);
            }

            if (xc_shadow_control(xc_handle, dom, DOM0_SHADOW_CONTROL_OP_CLEAN,
                                  to_send, max_pfn, &stats ) != max_pfn) {
                ERR("Error flushing shadow PT");
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
        ERR("Error when writing to state file (6)");
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
            ERR("Error when writing to state file (6a)");
            goto out;
        }

        for (i = 0, j = 0; i < max_pfn; ) {

            if (!is_mapped(live_p2m[i]))
                pfntab[j++] = i;

            i++;
            if (j == 1024 || i == max_pfn) {
                if(!write_exact(io_fd, &pfntab, sizeof(unsigned long)*j)) {
                    ERR("Error when writing to state file (6b)");
                    goto out;
                }
                j = 0;
            }
        }

    }

    /* Canonicalise the suspend-record frame number. */
    if ( !translate_mfn_to_pfn(&ctxt.user_regs.edx) ){
        ERR("Suspend record is not in range of pseudophys map");
        goto out;
    }

    /* Canonicalise each GDT frame number. */
    for ( i = 0; i < ctxt.gdt_ents; i += 512 ) {
        if ( !translate_mfn_to_pfn(&ctxt.gdt_frames[i]) ) {
            ERR("GDT frame is not in range of pseudophys map");
            goto out;
        }
    }

    /* Canonicalise the page table base pointer. */
    if ( !MFN_IS_IN_PSEUDOPHYS_MAP(ctxt.ctrlreg[3] >> PAGE_SHIFT) ) {
        ERR("PT base is not in range of pseudophys map");
        goto out;
    }
    ctxt.ctrlreg[3] = mfn_to_pfn(ctxt.ctrlreg[3] >> PAGE_SHIFT) <<
        PAGE_SHIFT;

    if (!write_exact(io_fd, &ctxt, sizeof(ctxt)) ||
        !write_exact(io_fd, live_shinfo, PAGE_SIZE)) {
        ERR("Error when writing to state file (1)");
        goto out;
    }

    /* Success! */
    rc = 0;

 out:

    if (live) {
        if(xc_shadow_control(xc_handle, dom, DOM0_SHADOW_CONTROL_OP_OFF,
                             NULL, 0, NULL ) < 0) {
            DPRINTF("Warning - couldn't disable shadow mode");
        }
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
