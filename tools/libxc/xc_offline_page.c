/******************************************************************************
 * xc_offline_page.c
 *
 * Helper functions to offline/online one page
 *
 * Copyright (c) 2003, K A Fraser.
 * Copyright (c) 2009, Intel Corporation.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include <inttypes.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <xc_core.h>

#include "xc_private.h"
#include "xc_dom.h"
#include "xg_private.h"
#include "xg_save_restore.h"

struct pte_backup_entry
{
    xen_pfn_t table_mfn;
    int offset;
};

#define DEFAULT_BACKUP_COUNT 1024
struct pte_backup
{
    struct pte_backup_entry *entries;
    int max;
    int cur;
};

static struct domain_info_context _dinfo;
static struct domain_info_context *dinfo = &_dinfo;

int xc_mark_page_online(xc_interface *xch, unsigned long start,
                        unsigned long end, uint32_t *status)
{
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(status, sizeof(uint32_t)*(end - start + 1), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    int ret = -1;

    if ( !status || (end < start) )
    {
        errno = EINVAL;
        return -1;
    }
    if ( xc_hypercall_bounce_pre(xch, status) )
    {
        ERROR("Could not bounce memory for xc_mark_page_online\n");
        return -1;
    }

    sysctl.cmd = XEN_SYSCTL_page_offline_op;
    sysctl.u.page_offline.start = start;
    sysctl.u.page_offline.cmd = sysctl_page_online;
    sysctl.u.page_offline.end = end;
    set_xen_guest_handle(sysctl.u.page_offline.status, status);
    ret = xc_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, status);

    return ret;
}

int xc_mark_page_offline(xc_interface *xch, unsigned long start,
                          unsigned long end, uint32_t *status)
{
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(status, sizeof(uint32_t)*(end - start + 1), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    int ret = -1;

    if ( !status || (end < start) )
    {
        errno = EINVAL;
        return -1;
    }
    if ( xc_hypercall_bounce_pre(xch, status) )
    {
        ERROR("Could not bounce memory for xc_mark_page_offline");
        return -1;
    }

    sysctl.cmd = XEN_SYSCTL_page_offline_op;
    sysctl.u.page_offline.start = start;
    sysctl.u.page_offline.cmd = sysctl_page_offline;
    sysctl.u.page_offline.end = end;
    set_xen_guest_handle(sysctl.u.page_offline.status, status);
    ret = xc_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, status);

    return ret;
}

int xc_query_page_offline_status(xc_interface *xch, unsigned long start,
                                 unsigned long end, uint32_t *status)
{
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(status, sizeof(uint32_t)*(end - start + 1), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    int ret = -1;

    if ( !status || (end < start) )
    {
        errno = EINVAL;
        return -1;
    }
    if ( xc_hypercall_bounce_pre(xch, status) )
    {
        ERROR("Could not bounce memory for xc_query_page_offline_status\n");
        return -1;
    }

    sysctl.cmd = XEN_SYSCTL_page_offline_op;
    sysctl.u.page_offline.start = start;
    sysctl.u.page_offline.cmd = sysctl_query_page_offline;
    sysctl.u.page_offline.end = end;
    set_xen_guest_handle(sysctl.u.page_offline.status, status);
    ret = xc_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, status);

    return ret;
}

 /*
  * There should no update to the grant when domain paused
  */
static int xc_is_page_granted_v1(xc_interface *xch, xen_pfn_t gpfn,
                                 grant_entry_v1_t *gnttab, int gnt_num)
{
    int i = 0;

    if (!gnttab)
        return 0;

    for (i = 0; i < gnt_num; i++)
        if ( ((gnttab[i].flags & GTF_type_mask) !=  GTF_invalid) &&
             (gnttab[i].frame == gpfn) )
             break;

   return (i != gnt_num);
}

static int xc_is_page_granted_v2(xc_interface *xch, xen_pfn_t gpfn,
                                 grant_entry_v2_t *gnttab, int gnt_num)
{
    int i = 0;

    if (!gnttab)
        return 0;

    for (i = 0; i < gnt_num; i++)
        if ( ((gnttab[i].hdr.flags & GTF_type_mask) !=  GTF_invalid) &&
             (gnttab[i].full_page.frame == gpfn) )
             break;

   return (i != gnt_num);
}

static int backup_ptes(xen_pfn_t table_mfn, int offset,
                       struct pte_backup *backup)
{
    if (!backup)
        return -EINVAL;

    if (backup->max == backup->cur)
    {
        backup->entries = realloc(backup->entries,
                            backup->max * 2 * sizeof(struct pte_backup_entry));
        if (backup->entries == NULL)
            return -1;
        else
            backup->max *= 2;
    }

    backup->entries[backup->cur].table_mfn = table_mfn;
    backup->entries[backup->cur++].offset = offset;

    return 0;
}

/*
 * return:
 * 1 when MMU update is required
 * 0 when no changes
 * <0 when error happen
 */
typedef int (*pte_func)(xc_interface *xch,
                       uint64_t pte, uint64_t *new_pte,
                       unsigned long table_mfn, int table_offset,
                       struct pte_backup *backup,
                       unsigned long no_use);

static int __clear_pte(xc_interface *xch,
                       uint64_t pte, uint64_t *new_pte,
                       unsigned long table_mfn, int table_offset,
                       struct pte_backup *backup,
                       unsigned long mfn)
{
    /* If no new_pte pointer, same as no changes needed */
    if (!new_pte || !backup)
        return -EINVAL;

    if ( !(pte & _PAGE_PRESENT))
        return 0;

    /* XXX Check for PSE bit here */
    /* Hit one entry */
    if ( ((pte >> PAGE_SHIFT_X86) & MFN_MASK_X86) == mfn)
    {
        *new_pte = pte & ~_PAGE_PRESENT;
        if (!backup_ptes(table_mfn, table_offset, backup))
            return 1;
    }

    return 0;
}

static int __update_pte(xc_interface *xch,
                      uint64_t pte, uint64_t *new_pte,
                      unsigned long table_mfn, int table_offset,
                      struct pte_backup *backup,
                      unsigned long new_mfn)
{
    int index;

    if (!new_pte)
        return 0;

    for (index = 0; index < backup->cur; index ++)
        if ( (backup->entries[index].table_mfn == table_mfn) &&
             (backup->entries[index].offset == table_offset) )
            break;

    if (index != backup->cur)
    {
        if (pte & _PAGE_PRESENT)
            ERROR("Page present while in backup ptes\n");
        pte &= ~MFN_MASK_X86;
        pte |= (new_mfn << PAGE_SHIFT_X86) | _PAGE_PRESENT;
        *new_pte = pte;
        return 1;
    }

    return 0;
}

static int change_pte(xc_interface *xch, uint32_t domid,
                     struct xc_domain_meminfo *minfo,
                     struct pte_backup *backup,
                     struct xc_mmu *mmu,
                     pte_func func,
                     unsigned long data)
{
    int pte_num, rc;
    uint64_t i;
    void *content = NULL;

    pte_num = PAGE_SIZE / ((minfo->pt_levels == 2) ? 4 : 8);

    for (i = 0; i < minfo->p2m_size; i++)
    {
        xen_pfn_t table_mfn = xc_pfn_to_mfn(i, minfo->p2m_table,
                                            minfo->guest_width);
        uint64_t pte, new_pte;
        int j;

        if ( (table_mfn == INVALID_PFN) ||
             ((minfo->pfn_type[i] & XEN_DOMCTL_PFINFO_LTAB_MASK) ==
              XEN_DOMCTL_PFINFO_XTAB) )
            continue;

        if ( minfo->pfn_type[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK )
        {
            content = xc_map_foreign_range(xch, domid, PAGE_SIZE,
                                            PROT_READ, table_mfn);
            if (!content)
                goto failed;

            for (j = 0; j < pte_num; j++)
            {
                if ( minfo->pt_levels == 2 )
                    pte = ((const uint32_t*)content)[j];
                else
                    pte = ((const uint64_t*)content)[j];

                rc = func(xch, pte, &new_pte, table_mfn, j, backup, data);

                switch (rc)
                {
                    case 1:
                    if ( xc_add_mmu_update(xch, mmu,
                          table_mfn << PAGE_SHIFT |
                          j * ( (minfo->pt_levels == 2) ?
                              sizeof(uint32_t): sizeof(uint64_t)) |
                          MMU_PT_UPDATE_PRESERVE_AD,
                          new_pte) )
                        goto failed;
                    break;

                    case 0:
                    break;

                    default:
                    goto failed;
                }
            }

            munmap(content, PAGE_SIZE);
            content = NULL;
        }
    }

    if ( xc_flush_mmu_updates(xch, mmu) )
        goto failed;

    return 0;
failed:
    /* XXX Shall we take action if we have fail to swap? */
    if (content)
        munmap(content, PAGE_SIZE);

    return -1;
}

static int update_pte(xc_interface *xch, uint32_t domid,
                     struct xc_domain_meminfo *minfo,
                     struct pte_backup *backup,
                     struct xc_mmu *mmu,
                     unsigned long new_mfn)
{
    return change_pte(xch, domid,  minfo, backup, mmu,
                      __update_pte, new_mfn);
}

static int clear_pte(xc_interface *xch, uint32_t domid,
                     struct xc_domain_meminfo *minfo,
                     struct pte_backup *backup,
                     struct xc_mmu *mmu,
                     xen_pfn_t mfn)
{
    return change_pte(xch, domid, minfo, backup, mmu,
                      __clear_pte, mfn);
}

/*
 * Check if a page can be exchanged successfully
 */

static int is_page_exchangable(xc_interface *xch, uint32_t domid, xen_pfn_t mfn,
                               xc_dominfo_t *info)
{
    uint32_t status;
    int rc;

    /* domain checking */
    if ( !domid || (domid > DOMID_FIRST_RESERVED) )
    {
        DPRINTF("Dom0's page can't be LM");
        return 0;
    }
    if (info->hvm)
    {
        DPRINTF("Currently we can only live change PV guest's page\n");
        return 0;
    }

    /* Check if pages are offline pending or not */
    rc = xc_query_page_offline_status(xch, mfn, mfn, &status);

    if ( rc || !(status & PG_OFFLINE_STATUS_OFFLINE_PENDING) )
    {
        ERROR("Page %lx is not offline pending %x\n",
          mfn, status);
        return 0;
    }

    return 1;
}

xen_pfn_t *xc_map_m2p(xc_interface *xch,
                      unsigned long max_mfn,
                      int prot,
                      unsigned long *mfn0)
{
    privcmd_mmap_entry_t *entries;
    unsigned long m2p_chunks, m2p_size;
    xen_pfn_t *m2p;
    xen_pfn_t *extent_start;
    int i;

    m2p = NULL;
    m2p_size   = M2P_SIZE(max_mfn);
    m2p_chunks = M2P_CHUNKS(max_mfn);

    extent_start = calloc(m2p_chunks, sizeof(xen_pfn_t));
    if ( !extent_start )
    {
        ERROR("failed to allocate space for m2p mfns");
        goto err0;
    }

    if ( xc_machphys_mfn_list(xch, m2p_chunks, extent_start) )
    {
        PERROR("xc_get_m2p_mfns");
        goto err1;
    }

    entries = calloc(m2p_chunks, sizeof(privcmd_mmap_entry_t));
    if (entries == NULL)
    {
        ERROR("failed to allocate space for mmap entries");
        goto err1;
    }

    for ( i = 0; i < m2p_chunks; i++ )
        entries[i].mfn = extent_start[i];

    m2p = xc_map_foreign_ranges(xch, DOMID_XEN,
			m2p_size, prot, M2P_CHUNK_SIZE,
			entries, m2p_chunks);
    if (m2p == NULL)
    {
        PERROR("xc_mmap_foreign_ranges failed");
        goto err2;
    }

    if (mfn0)
        *mfn0 = entries[0].mfn;

err2:
    free(entries);
err1:
    free(extent_start);

err0:
    return m2p;
}

/* The domain should be suspended when called here */
int xc_exchange_page(xc_interface *xch, uint32_t domid, xen_pfn_t mfn)
{
    xc_dominfo_t info;
    struct xc_domain_meminfo minfo;
    struct xc_mmu *mmu = NULL;
    struct pte_backup old_ptes = {NULL, 0, 0};
    grant_entry_v1_t *gnttab_v1 = NULL;
    grant_entry_v2_t *gnttab_v2 = NULL;
    struct mmuext_op mops;
    int gnt_num, unpined = 0;
    void *old_p, *backup = NULL;
    int rc, result = -1;
    uint32_t status;
    xen_pfn_t new_mfn, gpfn;
    xen_pfn_t *m2p_table;
    unsigned long max_mfn;

    if ( xc_domain_getinfo(xch, domid, 1, &info) != 1 )
    {
        ERROR("Could not get domain info");
        return -1;
    }

    if (!info.shutdown || info.shutdown_reason != SHUTDOWN_suspend)
    {
        errno = EINVAL;
        ERROR("Can't exchange page unless domain is suspended\n");
        return -1;
    }
    if (!is_page_exchangable(xch, domid, mfn, &info))
    {
        ERROR("Could not exchange page\n");
        return -1;
    }

    /* Map M2P and obtain gpfn */
    rc = xc_maximum_ram_page(xch, &max_mfn);
    if ( rc || !(m2p_table = xc_map_m2p(xch, max_mfn, PROT_READ, NULL)) )
    {
        PERROR("Failed to map live M2P table");
        return -1;
    }
    gpfn = m2p_table[mfn];

    /* Map domain's memory information */
    memset(&minfo, 0, sizeof(minfo));
    if ( xc_map_domain_meminfo(xch, domid, &minfo) )
    {
        PERROR("Could not map domain's memory information\n");
        goto failed;
    }

    /* For translation macros */
    dinfo->guest_width = minfo.guest_width;
    dinfo->p2m_size = minfo.p2m_size;

    /* Don't exchange CR3 for PAE guest in PAE host environment */
    if (minfo.guest_width > sizeof(long))
    {
        if ( (minfo.pfn_type[gpfn] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK) ==
                    XEN_DOMCTL_PFINFO_L3TAB )
            goto failed;
    }

    gnttab_v2 = xc_gnttab_map_table_v2(xch, domid, &gnt_num);
    if (!gnttab_v2)
    {
        gnttab_v1 = xc_gnttab_map_table_v1(xch, domid, &gnt_num);
        if (!gnttab_v1)
        {
            ERROR("Failed to map grant table\n");
            goto failed;
        }
    }

    if (gnttab_v1
        ? xc_is_page_granted_v1(xch, mfn, gnttab_v1, gnt_num)
        : xc_is_page_granted_v2(xch, mfn, gnttab_v2, gnt_num))
    {
        ERROR("Page %lx is granted now\n", mfn);
        goto failed;
    }

    /* allocate required data structure */
    backup = malloc(PAGE_SIZE);
    if (!backup)
    {
        ERROR("Failed to allocate backup pages pointer\n");
        goto failed;
    }

    old_ptes.max = DEFAULT_BACKUP_COUNT;
    old_ptes.entries = malloc(sizeof(struct pte_backup_entry) *
                              DEFAULT_BACKUP_COUNT);

    if (!old_ptes.entries)
    {
        ERROR("Faield to allocate backup\n");
        goto failed;
    }
    old_ptes.cur = 0;

    /* Unpin the page if it is pined */
    if (minfo.pfn_type[gpfn] & XEN_DOMCTL_PFINFO_LPINTAB)
    {
        mops.cmd = MMUEXT_UNPIN_TABLE;
        mops.arg1.mfn = mfn;

        if ( xc_mmuext_op(xch, &mops, 1, domid) < 0 )
        {
            ERROR("Failed to unpin page %lx", mfn);
            goto failed;
        }
        mops.arg1.mfn = mfn;
        unpined = 1;
    }

    /* backup the content */
    old_p = xc_map_foreign_range(xch, domid, PAGE_SIZE,
      PROT_READ, mfn);
    if (!old_p)
    {
        ERROR("Failed to map foreign page %lx\n", mfn);
        goto failed;
    }

    memcpy(backup, old_p, PAGE_SIZE);
    munmap(old_p, PAGE_SIZE);

    mmu = xc_alloc_mmu_updates(xch, domid);
    if ( mmu == NULL )
    {
        ERROR("%s: failed at %d\n", __FUNCTION__, __LINE__);
        goto failed;
    }

    /* Firstly update all pte to be invalid to remove the reference */
    rc = clear_pte(xch, domid,  &minfo, &old_ptes, mmu, mfn);

    if (rc)
    {
        ERROR("clear pte failed\n");
        goto failed;
    }

    rc = xc_domain_memory_exchange_pages(xch, domid,
					 1, 0, &mfn,
					 1, 0, &new_mfn);

    if (rc)
    {
        ERROR("Exchange the page failed\n");
        /* Exchange fail means there are refere to the page still */
        rc = update_pte(xch, domid, &minfo, &old_ptes, mmu, mfn);
        if (rc)
            result = -2;
        goto failed;
    }

    rc = update_pte(xch, domid, &minfo, &old_ptes, mmu, new_mfn);

    if (rc)
    {
        ERROR("update pte failed guest may be broken now\n");
        /* No recover action now for swap fail */
        result = -2;
        goto failed;
    }

    /* Check if pages are offlined already */
    rc = xc_query_page_offline_status(xch, mfn, mfn,
                            &status);

    if (rc)
    {
        ERROR("Fail to query offline status\n");
    }else if ( !(status & PG_OFFLINE_STATUS_OFFLINED) )
    {
        ERROR("page is still online or pending\n");
        goto failed;
    }
    else
    {
        void *new_p;
        IPRINTF("Now page is offlined %lx\n", mfn);
        /* Update the p2m table */
        minfo.p2m_table[gpfn] = new_mfn;

        new_p = xc_map_foreign_range(xch, domid, PAGE_SIZE,
                                     PROT_READ|PROT_WRITE, new_mfn);
        if ( new_p == NULL )
        {
            ERROR("failed to map new_p for copy, guest may be broken?");
            goto failed;
        }
        memcpy(new_p, backup, PAGE_SIZE);
        munmap(new_p, PAGE_SIZE);
        mops.arg1.mfn = new_mfn;
        result = 0;
    }

failed:

    if (unpined && (minfo.pfn_type[mfn] & XEN_DOMCTL_PFINFO_LPINTAB))
    {
        switch ( minfo.pfn_type[mfn] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK )
        {
            case XEN_DOMCTL_PFINFO_L1TAB:
                mops.cmd = MMUEXT_PIN_L1_TABLE;
                break;

            case XEN_DOMCTL_PFINFO_L2TAB:
                mops.cmd = MMUEXT_PIN_L2_TABLE;
                break;

            case XEN_DOMCTL_PFINFO_L3TAB:
                mops.cmd = MMUEXT_PIN_L3_TABLE;
                break;

            case XEN_DOMCTL_PFINFO_L4TAB:
                mops.cmd = MMUEXT_PIN_L4_TABLE;
                break;

            default:
                ERROR("Unpined for non pate table page\n");
                break;
        }

        if ( xc_mmuext_op(xch, &mops, 1, domid) < 0 )
        {
            ERROR("failed to pin the mfn again\n");
            result = -2;
        }
    }

    free(mmu);

    free(old_ptes.entries);

    free(backup);

    if (gnttab_v1)
        munmap(gnttab_v1, gnt_num / (PAGE_SIZE/sizeof(grant_entry_v1_t)));
    if (gnttab_v2)
        munmap(gnttab_v2, gnt_num / (PAGE_SIZE/sizeof(grant_entry_v2_t)));

    xc_unmap_domain_meminfo(xch, &minfo);
    munmap(m2p_table, M2P_SIZE(max_mfn));

    return result;
}
