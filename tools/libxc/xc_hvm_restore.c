/******************************************************************************
 * xc_hvm_restore.c
 *
 * Restore the state of a HVM guest.
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

#include <stdlib.h>
#include <unistd.h>

#include "xg_private.h"
#include "xg_save_restore.h"

#include <xen/hvm/ioreq.h>
#include <xen/hvm/params.h>
#include <xen/hvm/e820.h>

static ssize_t
read_exact(int fd, void *buf, size_t count)
{
    int r = 0, s;
    unsigned char *b = buf;

    while ( r < count )
    {
        s = read(fd, &b[r], count - r);
        if ( (s == -1) && (errno == EINTR) )
            continue;
        if ( s <= 0 )
            break;
        r += s;
    }

    return (r == count) ? 1 : 0;
}

#define BPL (sizeof(long)*8)
#define test_bit(bit, map) !!((map)[(bit)/BPL] & (1UL << ((bit) % BPL)))
#define set_bit(bit, map)  ((map)[(bit)/BPL] |= (1UL << ((bit) % BPL)))
static int test_and_set_bit(unsigned long nr, unsigned long *map)
{
    int rc = test_bit(nr, map);
    if ( !rc )
        set_bit(nr, map);
    return rc;
}

int xc_hvm_restore(int xc_handle, int io_fd, uint32_t dom,
                   unsigned int store_evtchn, unsigned long *store_mfn,
                   unsigned int pae, unsigned int apic)
{
    DECLARE_DOMCTL;

    /* A copy of the CPU context of the guest. */
    vcpu_guest_context_t ctxt;

    char *region_base;

    unsigned long buf[PAGE_SIZE/sizeof(unsigned long)];

    xc_dominfo_t info;
    unsigned int rc = 1, n, i;
    uint32_t rec_len, nr_vcpus;
    uint8_t *hvm_buf = NULL;

    /* Magic frames: ioreqs and xenstore comms. */
    uint64_t magic_pfns[3]; /* ioreq_pfn, bufioreq_pfn, store_pfn */

    unsigned long pfn;
    int verify = 0;

    /* Types of the pfns in the current region */
    unsigned long region_pfn_type[MAX_BATCH_SIZE];
    xen_pfn_t pfn_alloc_batch[MAX_BATCH_SIZE];
    unsigned int pfn_alloc_batch_size;

    /* The size of an array big enough to contain all guest pfns */
    unsigned long max_pfn = 0xfffffUL; /* initial memory map guess: 4GB */
    unsigned long *pfn_bitmap = NULL, *new_pfn_bitmap;

    DPRINTF("xc_hvm_restore:dom=%d, store_evtchn=%d, "
            "pae=%u, apic=%u.\n", dom, store_evtchn, pae, apic);

    DPRINTF("xc_hvm_restore start: max_pfn = %lx\n", max_pfn);

    if ( mlock(&ctxt, sizeof(ctxt)) )
    {
        /* needed for build dom0 op, but might as well do early */
        ERROR("Unable to mlock ctxt");
        return 1;
    }

    if ( xc_domain_getinfo(xc_handle, dom, 1, &info) != 1 )
    {
        ERROR("Could not get domain info");
        return 1;
    }

    domctl.cmd = XEN_DOMCTL_getdomaininfo;
    domctl.domain = (domid_t)dom;
    if ( xc_domctl(xc_handle, &domctl) < 0 )
    {
        ERROR("Could not get information on new domain");
        goto out;
    }

    pfn_bitmap = calloc((max_pfn+1)/8, 1);
    if ( pfn_bitmap == NULL )
    {
        ERROR("Could not allocate pfn bitmap");
        goto out;
    }

    n = 0;
    for ( ; ; )
    {
        int j;

        if ( !read_exact(io_fd, &j, sizeof(int)) )
        {
            ERROR("HVM restore Error when reading batch size");
            goto out;
        }

        PPRINTF("batch %d\n",j);

        if ( j == -1 )
        {
            verify = 1;
            DPRINTF("Entering page verify mode\n");
            continue;
        }

        if ( j == 0 )
            break;  /* our work here is done */

        if ( j > MAX_BATCH_SIZE )
        {
            ERROR("Max batch size exceeded. Giving up.");
            goto out;
        }

        if ( !read_exact(io_fd, region_pfn_type, j*sizeof(unsigned long)) )
        {
            ERROR("Error when reading region pfn types");
            goto out;
        }

        pfn_alloc_batch_size = 0;
        for ( i = 0; i < j; i++ )
        {
            pfn = region_pfn_type[i];
            if ( pfn & XEN_DOMCTL_PFINFO_LTAB_MASK )
                continue;

            while ( pfn > max_pfn )
            {
                if ( max_pfn >= 0xfffffff )
                {
                    ERROR("Maximum PFN beyond reason (1TB) %lx\n", pfn);
                    goto out;
                }
                max_pfn = 2*max_pfn + 1;
                new_pfn_bitmap = realloc(pfn_bitmap, (max_pfn+1)/8);
                if ( new_pfn_bitmap == NULL )
                {
                    ERROR("Could not realloc pfn bitmap for max_pfn=%lx\n",
                          max_pfn);
                    goto out;
                }
                pfn_bitmap = new_pfn_bitmap;
                memset(&pfn_bitmap[(max_pfn+1)/(2*BPL)], 0, (max_pfn+1)/(2*8));
            }

            if ( !test_and_set_bit(pfn, pfn_bitmap) )
                pfn_alloc_batch[pfn_alloc_batch_size++] = pfn;
        }

        if ( pfn_alloc_batch_size != 0 )
        {
             rc = xc_domain_memory_populate_physmap(
                 xc_handle, dom, pfn_alloc_batch_size, 0, 0, pfn_alloc_batch);
             if ( rc != 0 )
             {
                 PERROR("Could not allocate %u pages for HVM guest.\n",
                        pfn_alloc_batch_size);
                 goto out;
             }
        }

        region_base = xc_map_foreign_batch(
            xc_handle, dom, PROT_WRITE, region_pfn_type, j);

        for ( i = 0; i < j; i++ )
        {
            void *page;

            pfn = region_pfn_type[i];
            if ( pfn & XEN_DOMCTL_PFINFO_LTAB_MASK )
                continue;

            /* In verify mode, we use a copy; otherwise we work in place */
            page = verify ? (void *)buf : (region_base + i*PAGE_SIZE);

            if ( !read_exact(io_fd, page, PAGE_SIZE) )
            {
                ERROR("Error when reading page (%x)", i);
                goto out;
            }

            if ( verify )
            {
                int res = memcmp(buf, (region_base + i*PAGE_SIZE), PAGE_SIZE);
                if ( res )
                {
                    int v;

                    DPRINTF("************** pfn=%lx gotcs=%08lx "
                            "actualcs=%08lx\n", pfn, 
                            csum_page(region_base + i*PAGE_SIZE),
                            csum_page(buf));

                    for ( v = 0; v < 4; v++ )
                    {
                        unsigned long *p = (unsigned long *)
                            (region_base + i*PAGE_SIZE);
                        if (buf[v] != p[v])
                            DPRINTF("    %d: %08lx %08lx\n", v, buf[v], p[v]);
                    }
                }
            }

        } /* end of 'batch' for loop */

        munmap(region_base, j*PAGE_SIZE);
        n += j; /* crude stats */
    }
    
    xc_set_hvm_param(xc_handle, dom, HVM_PARAM_PAE_ENABLED, pae);
    xc_set_hvm_param(xc_handle, dom, HVM_PARAM_STORE_EVTCHN, store_evtchn);

    if ( !read_exact(io_fd, magic_pfns, sizeof(magic_pfns)) )
    {
        ERROR("error reading magic page addresses\n");
        goto out;
    }

    if ( xc_clear_domain_page(xc_handle, dom, magic_pfns[0]) ||
         xc_clear_domain_page(xc_handle, dom, magic_pfns[1]) ||
         xc_clear_domain_page(xc_handle, dom, magic_pfns[2]) )
    {
        rc = -1;
        goto out;
    }

    xc_set_hvm_param(xc_handle, dom, HVM_PARAM_IOREQ_PFN, magic_pfns[0]);
    xc_set_hvm_param(xc_handle, dom, HVM_PARAM_BUFIOREQ_PFN, magic_pfns[1]);
    xc_set_hvm_param(xc_handle, dom, HVM_PARAM_STORE_PFN, magic_pfns[2]);
    *store_mfn = magic_pfns[2];
    DPRINTF("hvm restore: calculate new store_mfn=0x%lx.\n", *store_mfn);

    if ( !read_exact(io_fd, &nr_vcpus, sizeof(uint32_t)) )
    {
        ERROR("error read nr vcpu !\n");
        goto out;
    }
    DPRINTF("hvm restore:get nr_vcpus=%d.\n", nr_vcpus);

    for ( i = 0; i < nr_vcpus; i++ )
    {
        if ( !read_exact(io_fd, &rec_len, sizeof(uint32_t)) )
        {
            ERROR("error read vcpu context size!\n");
            goto out;
        }
        if ( rec_len != sizeof(ctxt) )
        {
            ERROR("vcpu context size dismatch!\n");
            goto out;
        }

        if ( !read_exact(io_fd, &(ctxt), sizeof(ctxt)) )
        {
            ERROR("error read vcpu context.\n");
            goto out;
        }

        if ( (rc = xc_vcpu_setcontext(xc_handle, dom, i, &ctxt)) )
        {
            ERROR("Could not set vcpu context, rc=%d", rc);
            goto out;
        }
    }

    /* restore hvm context including pic/pit/shpage */
    if ( !read_exact(io_fd, &rec_len, sizeof(uint32_t)) )
    {
        ERROR("error read hvm context size!\n");
        goto out;
    }

    hvm_buf = malloc(rec_len);
    if ( hvm_buf == NULL )
    {
        ERROR("memory alloc for hvm context buffer failed");
        errno = ENOMEM;
        goto out;
    }

    if ( !read_exact(io_fd, hvm_buf, rec_len) )
    {
        ERROR("error read hvm buffer!\n");
        goto out;
    }

    if ( (rc = xc_domain_hvm_setcontext(xc_handle, dom, hvm_buf, rec_len)) )
    {
        ERROR("error set hvm buffer!\n");
        goto out;
    }

    rc = 0;
    goto out;

 out:
    if ( (rc != 0) && (dom != 0) )
        xc_domain_destroy(xc_handle, dom);
    free(hvm_buf);
    free(pfn_bitmap);

    DPRINTF("Restore exit with rc=%d\n", rc);

    return rc;
}
