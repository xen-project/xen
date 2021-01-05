/*
 * Definitions and utilities for save / restore.
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

#include <xen/foreign/x86_32.h>
#include <xen/foreign/x86_64.h>

/*
** We process save/restore/migrate in batches of pages; the below
** determines how many pages we (at maximum) deal with in each batch.
*/
#define MAX_BATCH_SIZE 1024   /* up to 1024 pages (4MB) at a time */

/* When pinning page tables at the end of restore, we also use batching. */
#define MAX_PIN_BATCH  1024


/*
** Save/restore deal with the mfn_to_pfn (M2P) and pfn_to_mfn (P2M) tables.
** The M2P simply holds the corresponding PFN, while the top bit of a P2M
** entry tell us whether or not the the PFN is currently mapped.
*/

#define PFN_TO_KB(_pfn) ((_pfn) << (PAGE_SHIFT - 10))


/*
** The M2P is made up of some number of 'chunks' of at least 2MB in size.
** The below definitions and utility function(s) deal with mapping the M2P
** regarldess of the underlying machine memory size or architecture.
*/
#define M2P_SHIFT       L2_PAGETABLE_SHIFT_PAE
#define M2P_CHUNK_SIZE  (1 << M2P_SHIFT)
#define M2P_SIZE(_m)    ROUNDUP(((_m) * sizeof(xen_pfn_t)), M2P_SHIFT)
#define M2P_CHUNKS(_m)  (M2P_SIZE((_m)) >> M2P_SHIFT)

#define UNFOLD_CR3(_c)                                                  \
  ((uint64_t)((dinfo->guest_width == 8)                                 \
              ? ((_c) >> 12)                                            \
              : (((uint32_t)(_c) >> 12) | ((uint32_t)(_c) << 20))))

#define FOLD_CR3(_c)                                                    \
  ((uint64_t)((dinfo->guest_width == 8)                                 \
              ? ((uint64_t)(_c)) << 12                                  \
              : (((uint32_t)(_c) << 12) | ((uint32_t)(_c) >> 20))))

#define MEMCPY_FIELD(_d, _s, _f, _w) do {                          \
    if ((_w) == 8)                                                 \
        memcpy(&(_d)->x64._f, &(_s)->x64._f,sizeof((_d)->x64._f)); \
    else                                                           \
        memcpy(&(_d)->x32._f, &(_s)->x32._f,sizeof((_d)->x32._f)); \
} while (0)

#define MEMSET_ARRAY_FIELD(_p, _f, _v, _w) do {                    \
    if ((_w) == 8)                                                 \
        memset(&(_p)->x64._f[0], (_v), sizeof((_p)->x64._f));      \
    else                                                           \
        memset(&(_p)->x32._f[0], (_v), sizeof((_p)->x32._f));      \
} while (0)
