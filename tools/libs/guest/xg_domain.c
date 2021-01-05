/******************************************************************************
 * xg_domain.c
 *
 * API for manipulating and obtaining information on domains.
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
 *
 * Copyright (c) 2003, K A Fraser.
 */

#include "xg_private.h"
#include "xc_core.h"

int xc_unmap_domain_meminfo(xc_interface *xch, struct xc_domain_meminfo *minfo)
{
    struct domain_info_context _di = { .guest_width = minfo->guest_width,
                                       .p2m_size = minfo->p2m_size};
    struct domain_info_context *dinfo = &_di;

    free(minfo->pfn_type);
    if ( minfo->p2m_table )
        munmap(minfo->p2m_table, P2M_FL_ENTRIES * PAGE_SIZE);
    minfo->p2m_table = NULL;

    return 0;
}

int xc_map_domain_meminfo(xc_interface *xch, uint32_t domid,
                          struct xc_domain_meminfo *minfo)
{
    struct domain_info_context _di;
    struct domain_info_context *dinfo = &_di;

    xc_dominfo_t info;
    shared_info_any_t *live_shinfo;
    xen_capabilities_info_t xen_caps = "";
    int i;

    /* Only be initialized once */
    if ( minfo->pfn_type || minfo->p2m_table )
    {
        errno = EINVAL;
        return -1;
    }

    if ( xc_domain_getinfo(xch, domid, 1, &info) != 1 )
    {
        PERROR("Could not get domain info");
        return -1;
    }

    if ( xc_domain_get_guest_width(xch, domid, &minfo->guest_width) )
    {
        PERROR("Could not get domain address size");
        return -1;
    }
    _di.guest_width = minfo->guest_width;

    /* Get page table levels */
    if ( xc_version(xch, XENVER_capabilities, &xen_caps) )
    {
        PERROR("Could not get Xen capabilities (for page table levels)");
        return -1;
    }
    if ( strstr(xen_caps, "xen-3.0-x86_64") )
        /* Depends on whether it's a compat 32-on-64 guest */
        minfo->pt_levels = ( (minfo->guest_width == 8) ? 4 : 3 );
    else if ( strstr(xen_caps, "xen-3.0-x86_32p") )
        minfo->pt_levels = 3;
    else if ( strstr(xen_caps, "xen-3.0-x86_32") )
        minfo->pt_levels = 2;
    else
    {
        errno = EFAULT;
        return -1;
    }

    /* We need the shared info page for mapping the P2M */
    live_shinfo = xc_map_foreign_range(xch, domid, PAGE_SIZE, PROT_READ,
                                       info.shared_info_frame);
    if ( !live_shinfo )
    {
        PERROR("Could not map the shared info frame (MFN 0x%lx)",
               info.shared_info_frame);
        return -1;
    }

    if ( xc_core_arch_map_p2m_writable(xch, minfo->guest_width, &info,
                                       live_shinfo, &minfo->p2m_table,
                                       &minfo->p2m_size) )
    {
        PERROR("Could not map the P2M table");
        munmap(live_shinfo, PAGE_SIZE);
        return -1;
    }
    munmap(live_shinfo, PAGE_SIZE);
    _di.p2m_size = minfo->p2m_size;

    /* Make space and prepare for getting the PFN types */
    minfo->pfn_type = calloc(sizeof(*minfo->pfn_type), minfo->p2m_size);
    if ( !minfo->pfn_type )
    {
        PERROR("Could not allocate memory for the PFN types");
        goto failed;
    }
    for ( i = 0; i < minfo->p2m_size; i++ )
        minfo->pfn_type[i] = xc_pfn_to_mfn(i, minfo->p2m_table,
                                           minfo->guest_width);

    /* Retrieve PFN types in batches */
    for ( i = 0; i < minfo->p2m_size ; i+=1024 )
    {
        int count = ((minfo->p2m_size - i ) > 1024 ) ?
                        1024: (minfo->p2m_size - i);

        if ( xc_get_pfn_type_batch(xch, domid, count, minfo->pfn_type + i) )
        {
            PERROR("Could not get %d-eth batch of PFN types", (i+1)/1024);
            goto failed;
        }
    }

    return 0;

failed:
    if ( minfo->pfn_type )
    {
        free(minfo->pfn_type);
        minfo->pfn_type = NULL;
    }
    if ( minfo->p2m_table )
    {
        munmap(minfo->p2m_table, P2M_FL_ENTRIES * PAGE_SIZE);
        minfo->p2m_table = NULL;
    }

    return -1;
}
