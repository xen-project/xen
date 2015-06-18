/******************************************************************************
 * xc_foreign_memory.c
 *
 * Functions for mapping foreign domain's memory.
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

#include "xc_private.h"

void *xc_map_foreign_pages(xc_interface *xch, uint32_t dom, int prot,
                           const xen_pfn_t *arr, int num)
{
    void *res;
    int i, *err;

    if (num < 0) {
        errno = EINVAL;
        return NULL;
    }

    err = malloc(num * sizeof(*err));
    if (!err)
        return NULL;

    res = xc_map_foreign_bulk(xch, dom, prot, arr, err, num);
    if (res) {
        for (i = 0; i < num; i++) {
            if (err[i]) {
                errno = -err[i];
                munmap(res, num * PAGE_SIZE);
                res = NULL;
                break;
            }
        }
    }

    free(err);
    return res;
}

void *xc_map_foreign_range(xc_interface *xch,
                           uint32_t dom, int size, int prot,
                           unsigned long mfn)
{
    xen_pfn_t *arr;
    int num;
    int i;
    void *ret;

    num = (size + XC_PAGE_SIZE - 1) >> XC_PAGE_SHIFT;
    arr = calloc(num, sizeof(xen_pfn_t));
    if ( arr == NULL )
        return NULL;

    for ( i = 0; i < num; i++ )
        arr[i] = mfn + i;

    ret = xc_map_foreign_pages(xch, dom, prot, arr, num);
    free(arr);
    return ret;
}

void *xc_map_foreign_ranges(xc_interface *xch,
                            uint32_t dom, size_t size,
                            int prot, size_t chunksize,
                            privcmd_mmap_entry_t entries[],
                            int nentries)
{
    xen_pfn_t *arr;
    int num_per_entry;
    int num;
    int i;
    int j;
    void *ret;

    num_per_entry = chunksize >> XC_PAGE_SHIFT;
    num = num_per_entry * nentries;
    arr = calloc(num, sizeof(xen_pfn_t));
    if ( arr == NULL )
        return NULL;

    for ( i = 0; i < nentries; i++ )
        for ( j = 0; j < num_per_entry; j++ )
            arr[i * num_per_entry + j] = entries[i].mfn + j;

    ret = xc_map_foreign_pages(xch, dom, prot, arr, num);
    free(arr);
    return ret;
}

/*
 * stub for all not yet converted OSes (NetBSD and Solaris). New OSes should
 * just implement xc_map_foreign_bulk.
 */
#if defined(__NetBSD__) || defined(__sun__)
void *osdep_map_foreign_batch(xc_interface *xch, uint32_t dom, int prot,
                              xen_pfn_t *arr, int num );
void *xc_map_foreign_bulk(xc_interface *xch,
                          uint32_t dom, int prot,
                          const xen_pfn_t *arr, int *err, unsigned int num)
{
    xen_pfn_t *pfn;
    unsigned int i;
    void *ret;

    if ((int)num <= 0) {
        errno = EINVAL;
        return NULL;
    }

    pfn = malloc(num * sizeof(*pfn));
    if (!pfn) {
        errno = ENOMEM;
        return NULL;
    }

    memcpy(pfn, arr, num * sizeof(*arr));
    ret = osdep_map_foreign_batch(xch, dom, prot, pfn, num);

    if (ret) {
        for (i = 0; i < num; ++i)
            switch (pfn[i] ^ arr[i]) {
            case 0:
                err[i] = 0;
                break;
            default:
                err[i] = -EINVAL;
                break;
            }
    } else
        memset(err, 0, num * sizeof(*err));

    free(pfn);

    return ret;
}
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
