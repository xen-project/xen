/******************************************************************************
 * xc_ia64_linux_save.c
 *
 * Save the state of a running Linux session.
 *
 * Copyright (c) 2003, K A Fraser.
 *  Rewritten for ia64 by Tristan Gingold <tristan.gingold@bull.net>
 */

#include <inttypes.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include "xg_private.h"

/*
** Default values for important tuning parameters. Can override by passing
** non-zero replacement values to xc_linux_save().
**
** XXX SMH: should consider if want to be able to override MAX_MBIT_RATE too.
**
*/
#define DEF_MAX_ITERS    (4 - 1)	/* limit us to 4 times round loop  */
#define DEF_MAX_FACTOR   3		/* never send more than 3x nr_pfns */

/*
** During (live) save/migrate, we maintain a number of bitmaps to track
** which pages we have to send, and to skip.
*/

#define BITS_PER_LONG (sizeof(unsigned long) * 8)

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

static inline void set_bit ( int nr, volatile void * addr)
{
    BITMAP_ENTRY(nr, addr) |= (1UL << BITMAP_SHIFT(nr));
}

/* total number of pages used by the current guest */
static unsigned long max_pfn;

static int xc_ia64_shadow_control(int xc_handle,
                                  uint32_t domid,
                                  unsigned int sop,
                                  unsigned long *dirty_bitmap,
                                  unsigned long pages,
                                  xc_shadow_op_stats_t *stats)
{
    if (dirty_bitmap != NULL && pages > 0) {
        int i;
        unsigned char *bmap = (unsigned char *)dirty_bitmap;
        unsigned long bmap_bytes =
            ((pages + BITS_PER_LONG - 1) & ~(BITS_PER_LONG - 1)) / 8;
        unsigned int bmap_pages = (bmap_bytes + PAGE_SIZE - 1) / PAGE_SIZE; 

        /* Touch the page so that it is in the TC.
           FIXME: use a more reliable method.  */
        for (i = 0 ; i < bmap_pages ; i++)
            bmap[i * PAGE_SIZE] = 0;
        /* Because bmap is not page aligned (allocated by malloc), be sure the
           last page is touched.  */
        bmap[bmap_bytes - 1] = 0;
    }

    return xc_shadow_control(xc_handle, domid, sop,
                             dirty_bitmap, pages, NULL, 0, stats);
}

static inline ssize_t
write_exact(int fd, void *buf, size_t count)
{
    if (write(fd, buf, count) != count)
        return 0;
    return 1;
}

static int
suspend_and_state(int (*suspend)(int), int xc_handle, int io_fd,
                  int dom, xc_dominfo_t *info)
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

    if (info->shutdown && info->shutdown_reason == SHUTDOWN_suspend)
        return 0; // success

    if (info->paused) {
        // try unpausing domain, wait, and retest
        xc_domain_unpause(xc_handle, dom);

        ERROR("Domain was paused. Wait and re-test.");
        usleep(10000);  // 10ms

        goto retry;
    }


    if(++i < 100) {
        ERROR("Retry suspend domain.");
        usleep(10000);  // 10ms
        goto retry;
    }

    ERROR("Unable to suspend domain.");

    return -1;
}

int
xc_domain_save(int xc_handle, int io_fd, uint32_t dom, uint32_t max_iters,
               uint32_t max_factor, uint32_t flags, int (*suspend)(int),
               int hvm, void *(*init_qemu_maps)(int, unsigned),
               void (*qemu_flip_buffer)(int, int))
{
    DECLARE_DOMCTL;
    xc_dominfo_t info;

    int rc = 1;

    //int live  = (flags & XCFLAGS_LIVE);
    int debug = (flags & XCFLAGS_DEBUG);
    int live  = (flags & XCFLAGS_LIVE);

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;

    /* A copy of the CPU context of the guest. */
    vcpu_guest_context_t ctxt;

    unsigned long *page_array = NULL;

    /* Live mapping of shared info structure */
    shared_info_t *live_shinfo = NULL;

    /* Iteration number.  */
    int iter;

    /* Number of pages sent in the last iteration (live only).  */
    unsigned int sent_last_iter;

    /* Number of pages sent (live only).  */
    unsigned int total_sent;

    /* Size of the shadow bitmap (live only).  */
    unsigned int bitmap_size = 0;

    /* True if last iteration.  */
    int last_iter;

    /* Bitmap of pages to be sent.  */
    unsigned long *to_send = NULL;
    /* Bitmap of pages not to be sent (because dirtied).  */
    unsigned long *to_skip = NULL;

    char *mem;

    if (debug)
        fprintf (stderr, "xc_linux_save (ia64): started dom=%d\n", dom);

    /* If no explicit control parameters given, use defaults */
    if (!max_iters)
        max_iters = DEF_MAX_ITERS;
    if (!max_factor)
        max_factor = DEF_MAX_FACTOR;

    //initialize_mbit_rate();

    if (xc_domain_getinfo(xc_handle, dom, 1, &info) != 1) {
        ERROR("Could not get domain info");
        return 1;
    }

    shared_info_frame = info.shared_info_frame;

#if 0
    /* cheesy sanity check */
    if ((info.max_memkb >> (PAGE_SHIFT - 10)) > max_mfn) {
        ERROR("Invalid state record -- pfn count out of range: %lu",
            (info.max_memkb >> (PAGE_SHIFT - 10)));
        goto out;
     }
#endif

    /* Map the shared info frame */
    live_shinfo = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                       PROT_READ, shared_info_frame);
    if (!live_shinfo) {
        ERROR("Couldn't map live_shinfo");
        goto out;
    }

    max_pfn = info.max_memkb >> (PAGE_SHIFT - 10);

    page_array = malloc(max_pfn * sizeof(unsigned long));
    if (page_array == NULL) {
        ERROR("Could not allocate memory");
        goto out;
    }

    /* This is expected by xm restore.  */
    if (!write_exact(io_fd, &max_pfn, sizeof(unsigned long))) {
        ERROR("write: max_pfn");
        goto out;
    }

    /* xc_linux_restore starts to read here.  */
    /* Write a version number.  This can avoid searching for a stupid bug
       if the format change.
       The version is hard-coded, don't forget to change the restore code
       too!  */
    {
        unsigned long version = 1;

        if (!write_exact(io_fd, &version, sizeof(unsigned long))) {
            ERROR("write: version");
            goto out;
        }
    }

    domctl.cmd = XEN_DOMCTL_arch_setup;
    domctl.domain = (domid_t)dom;
    domctl.u.arch_setup.flags = XEN_DOMAINSETUP_query;
    if (xc_domctl(xc_handle, &domctl) < 0) {
        ERROR("Could not get domain setup");
        goto out;
    }
    if (!write_exact(io_fd, &domctl.u.arch_setup,
                     sizeof(domctl.u.arch_setup))) {
        ERROR("write: domain setup");
        goto out;
    }

    /* Domain is still running at this point */
    if (live) {

        if (xc_ia64_shadow_control(xc_handle, dom,
                                   XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY,
                                   NULL, 0, NULL ) < 0) {
            ERROR("Couldn't enable shadow mode");
            goto out;
        }

        last_iter = 0;

        bitmap_size = ((max_pfn + BITS_PER_LONG-1) & ~(BITS_PER_LONG-1)) / 8;
        to_send = malloc(bitmap_size);
        to_skip = malloc(bitmap_size);

        if (!to_send || !to_skip) {
            ERROR("Couldn't allocate bitmap array");
            goto out;
        }

        /* Initially all the pages must be sent.  */
        memset(to_send, 0xff, bitmap_size);

        if (mlock(to_send, bitmap_size)) {
            ERROR("Unable to mlock to_send");
            goto out;
        }
        if (mlock(to_skip, bitmap_size)) {
            ERROR("Unable to mlock to_skip");
            goto out;
        }
        
    } else {

        /* This is a non-live suspend. Issue the call back to get the
           domain suspended */

        last_iter = 1;

        if (suspend_and_state(suspend, xc_handle, io_fd, dom, &info)) {
            ERROR("Domain appears not to have suspended");
            goto out;
        }

    }

    sent_last_iter = max_pfn;
    total_sent = 0;

    for (iter = 1; ; iter++) {
        unsigned int sent_this_iter, skip_this_iter;
        unsigned long N;

        sent_this_iter = 0;
        skip_this_iter = 0;

        /* Get the pfn list, as it may change.  */
        if (xc_ia64_get_pfn_list(xc_handle, dom, page_array,
                                 0, max_pfn) != max_pfn) {
            ERROR("Could not get the page frame list");
            goto out;
        }

        /* Dirtied pages won't be saved.
           slightly wasteful to peek the whole array evey time,
           but this is fast enough for the moment. */
        if (!last_iter) {
            if (xc_ia64_shadow_control(xc_handle, dom,
                                       XEN_DOMCTL_SHADOW_OP_PEEK,
                                       to_skip, max_pfn, NULL) != max_pfn) {
                ERROR("Error peeking shadow bitmap");
                goto out;
            }
        }

        /* Start writing out the saved-domain record. */
        for (N = 0; N < max_pfn; N++) {
            if (page_array[N] == INVALID_MFN)
                continue;
            if (!last_iter) {
                if (test_bit(N, to_skip) && test_bit(N, to_send))
                    skip_this_iter++;
                if (test_bit(N, to_skip) || !test_bit(N, to_send))
                    continue;
            }

            if (debug)
                fprintf(stderr, "xc_linux_save: page %lx (%lu/%lu)\n",
                        page_array[N], N, max_pfn);

            mem = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                       PROT_READ|PROT_WRITE, N);
            if (mem == NULL) {
                /* The page may have move.
                   It will be remarked dirty.
                   FIXME: to be tracked.  */
                fprintf(stderr, "cannot map mfn page %lx gpfn %lx: %s\n",
                        page_array[N], N, safe_strerror(errno));
                continue;
            }

            if (!write_exact(io_fd, &N, sizeof(N))) {
                ERROR("write: max_pfn");
                goto out;
            }

            if (write(io_fd, mem, PAGE_SIZE) != PAGE_SIZE) {
                ERROR("Error when writing to state file (5)");
                goto out;
            }
            munmap(mem, PAGE_SIZE);
            sent_this_iter++;
            total_sent++;
        }

        if (last_iter)
            break;

        DPRINTF(" %d: sent %d, skipped %d\n",
                iter, sent_this_iter, skip_this_iter );

        if (live) {
            if ( /* ((sent_this_iter > sent_last_iter) && RATE_IS_MAX()) || */
                (iter >= max_iters) || (sent_this_iter+skip_this_iter < 50) ||
                (total_sent > max_pfn*max_factor)) {
                DPRINTF("Start last iteration\n");
                last_iter = 1;

                if (suspend_and_state(suspend, xc_handle, io_fd, dom, &info)) {
                    ERROR("Domain appears not to have suspended");
                    goto out;
                }
            }

            /* Pages to be sent are pages which were dirty.  */
            if (xc_ia64_shadow_control(xc_handle, dom,
                                       XEN_DOMCTL_SHADOW_OP_CLEAN,
                                       to_send, max_pfn, NULL ) != max_pfn) {
                ERROR("Error flushing shadow PT");
                goto out;
            }

            sent_last_iter = sent_this_iter;

            //print_stats(xc_handle, dom, sent_this_iter, &stats, 1);
        }

    }

    fprintf (stderr, "All memory is saved\n");

    /* terminate */
    {
        unsigned long pfn = INVALID_MFN;
        if (!write_exact(io_fd, &pfn, sizeof(pfn))) {
            ERROR("Error when writing to state file (6)");
            goto out;
        }
    }

    /* Send through a list of all the PFNs that were not in map at the close */
    {
        unsigned int i,j;
        unsigned long pfntab[1024];

        for (i = 0, j = 0; i < max_pfn; i++) {
            if (page_array[i] == INVALID_MFN)
                j++;
        }

        if (!write_exact(io_fd, &j, sizeof(unsigned int))) {
            ERROR("Error when writing to state file (6a)");
            goto out;
        }

        for (i = 0, j = 0; i < max_pfn; ) {

            if (page_array[i] == INVALID_MFN)
                pfntab[j++] = i;

            i++;
            if (j == 1024 || i == max_pfn) {
                if (!write_exact(io_fd, &pfntab, sizeof(unsigned long)*j)) {
                    ERROR("Error when writing to state file (6b)");
                    goto out;
                }
                j = 0;
            }
        }

    }

    if (xc_vcpu_getcontext(xc_handle, dom, 0, &ctxt)) {
        ERROR("Could not get vcpu context");
        goto out;
    }

    if (!write_exact(io_fd, &ctxt, sizeof(ctxt))) {
        ERROR("Error when writing to state file (1)");
        goto out;
    }

    fprintf(stderr, "ip=%016lx, b0=%016lx\n", ctxt.user_regs.cr_iip,
            ctxt.user_regs.b0);

    mem = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                               PROT_READ|PROT_WRITE, ctxt.privregs_pfn);
    if (mem == NULL) {
        ERROR("cannot map privreg page");
        goto out;
    }
    if (write(io_fd, mem, PAGE_SIZE) != PAGE_SIZE) {
        ERROR("Error when writing privreg to state file (5)");
        goto out;
    }
    munmap(mem, PAGE_SIZE);    

    if (!write_exact(io_fd, live_shinfo, PAGE_SIZE)) {
        ERROR("Error when writing to state file (1)");
        goto out;
    }

    /* Success! */
    rc = 0;

 out:

    if (live) {
        if (xc_ia64_shadow_control(xc_handle, dom, XEN_DOMCTL_SHADOW_OP_OFF,
                                   NULL, 0, NULL ) < 0) {
            DPRINTF("Warning - couldn't disable shadow mode");
        }
    }

    free(page_array);
    free(to_send);
    free(to_skip);
    if (live_shinfo)
        munmap(live_shinfo, PAGE_SIZE);

    fprintf(stderr,"Save exit rc=%d\n",rc);

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
