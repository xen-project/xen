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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "xc_private.h"

#include <xen/foreign/x86_32.h>
#include <xen/foreign/x86_64.h>

/*
 * SAVE/RESTORE/MIGRATE PROTOCOL
 * =============================
 *
 * The general form of a stream of chunks is a header followed by a
 * body consisting of a variable number of chunks (terminated by a
 * chunk with type 0) followed by a trailer.
 *
 * For a rolling/checkpoint (e.g. remus) migration then the body and
 * trailer phases can be repeated until an external event
 * (e.g. failure) causes the process to terminate and commit to the
 * most recent complete checkpoint.
 *
 * HEADER
 * ------
 *
 * unsigned long        : p2m_size
 *
 * extended-info (PV-only, optional):
 *
 *   If first unsigned long == ~0UL then extended info is present,
 *   otherwise unsigned long is part of p2m. Note that p2m_size above
 *   does not include the length of the extended info.
 *
 *   extended-info:
 *
 *     unsigned long    : signature == ~0UL
 *     uint32_t	        : number of bytes remaining in extended-info
 *
 *     1 or more extended-info blocks of form:
 *     char[4]          : block identifier
 *     uint32_t         : block data size
 *     bytes            : block data
 *
 *     defined extended-info blocks:
 *     "vcpu"		: VCPU context info containing vcpu_guest_context_t.
 *                        The precise variant of the context structure
 *                        (e.g. 32 vs 64 bit) is distinguished by
 *                        the block size.
 *     "extv"           : Presence indicates use of extended VCPU context in
 *                        tail, data size is 0.
 *
 * p2m (PV-only):
 *
 *   consists of p2m_size bytes comprising an array of xen_pfn_t sized entries.
 *
 * BODY PHASE - Format A (for live migration or Remus without compression)
 * ----------
 *
 * A series of chunks with a common header:
 *   int              : chunk type
 *
 * If the chunk type is +ve then chunk contains guest memory data, and the
 * type contains the number of pages in the batch:
 *
 *     unsigned long[]  : PFN array, length == number of pages in batch
 *                        Each entry consists of XEN_DOMCTL_PFINFO_*
 *                        in bits 31-28 and the PFN number in bits 27-0.
 *     page data        : PAGE_SIZE bytes for each page marked present in PFN
 *                        array
 *
 * If the chunk type is -ve then chunk consists of one of a number of
 * metadata types.  See definitions of XC_SAVE_ID_* below.
 *
 * If chunk type is 0 then body phase is complete.
 *
 *
 * BODY PHASE - Format B (for Remus with compression)
 * ----------
 *
 * A series of chunks with a common header:
 *   int              : chunk type
 *
 * If the chunk type is +ve then chunk contains array of PFNs corresponding
 * to guest memory and type contains the number of PFNs in the batch:
 *
 *     unsigned long[]  : PFN array, length == number of pages in batch
 *                        Each entry consists of XEN_DOMCTL_PFINFO_*
 *                        in bits 31-28 and the PFN number in bits 27-0.
 *
 * If the chunk type is -ve then chunk consists of one of a number of
 * metadata types.  See definitions of XC_SAVE_ID_* below.
 *
 * If the chunk type is -ve and equals XC_SAVE_ID_COMPRESSED_DATA, then the
 * chunk consists of compressed page data, in the following format:
 *
 *     unsigned long        : Size of the compressed chunk to follow
 *     compressed data :      variable length data of size indicated above.
 *                            This chunk consists of compressed page data.
 *                            The number of pages in one chunk depends on
 *                            the amount of space available in the sender's
 *                            output buffer.
 *
 * Format of compressed data:
 *   compressed_data = <deltas>*
 *   delta           = <marker, run*>
 *   marker          = (RUNFLAG|SKIPFLAG) bitwise-or RUNLEN [1 byte marker]
 *   RUNFLAG         = 0
 *   SKIPFLAG        = 1 << 7
 *   RUNLEN          = 7-bit unsigned value indicating number of WORDS in the run
 *   run             = string of bytes of length sizeof(WORD) * RUNLEN
 *
 *    If marker contains RUNFLAG, then RUNLEN * sizeof(WORD) bytes of data following
 *   the marker is copied into the target page at the appropriate offset indicated by
 *   the offset_ptr
 *    If marker contains SKIPFLAG, then the offset_ptr is advanced
 *   by RUNLEN * sizeof(WORD).
 *
 * If chunk type is 0 then body phase is complete.
 *
 * There can be one or more chunks with type XC_SAVE_ID_COMPRESSED_DATA,
 * containing compressed pages. The compressed chunks are collated to form
 * one single compressed chunk for the entire iteration. The number of pages
 * present in this final compressed chunk will be equal to the total number
 * of valid PFNs specified by the +ve chunks.
 *
 * At the sender side, compressed pages are inserted into the output stream
 * in the same order as they would have been if compression logic was absent.
 *
 * Until last iteration, the BODY is sent in Format A, to maintain live
 * migration compatibility with receivers of older Xen versions.
 * At the last iteration, if Remus compression was enabled, the sender sends
 * a trigger, XC_SAVE_ID_ENABLE_COMPRESSION to tell the receiver to parse the
 * BODY in Format B from the next iteration onwards.
 *
 * An example sequence of chunks received in Format B:
 *     +16                              +ve chunk
 *     unsigned long[16]                PFN array
 *     +100                             +ve chunk
 *     unsigned long[100]               PFN array
 *     +50                              +ve chunk
 *     unsigned long[50]                PFN array
 *
 *     XC_SAVE_ID_COMPRESSED_DATA       TAG
 *       N                              Length of compressed data
 *       N bytes of DATA                Decompresses to 166 pages
 *
 *     XC_SAVE_ID_*                     other xc save chunks
 *     0                                END BODY TAG
 *
 * Corner case with checkpoint compression:
 *     At sender side, after pausing the domain, dirty pages are usually
 *   copied out to a temporary buffer. After the domain is resumed,
 *   compression is done and the compressed chunk(s) are sent, followed by
 *   other XC_SAVE_ID_* chunks.
 *     If the temporary buffer gets full while scanning for dirty pages,
 *   the sender stops buffering of dirty pages, compresses the temporary
 *   buffer and sends the compressed data with XC_SAVE_ID_COMPRESSED_DATA.
 *   The sender then resumes the buffering of dirty pages and continues
 *   scanning for the dirty pages.
 *     For e.g., assume that the temporary buffer can hold 4096 pages and
 *   there are 5000 dirty pages. The following is the sequence of chunks
 *   that the receiver will see:
 *
 *     +1024                       +ve chunk
 *     unsigned long[1024]         PFN array
 *     +1024                       +ve chunk
 *     unsigned long[1024]         PFN array
 *     +1024                       +ve chunk
 *     unsigned long[1024]         PFN array
 *     +1024                       +ve chunk
 *     unsigned long[1024]         PFN array
 *
 *     XC_SAVE_ID_COMPRESSED_DATA  TAG
 *      N                          Length of compressed data
 *      N bytes of DATA            Decompresses to 4096 pages
 *
 *     +4                          +ve chunk
 *     unsigned long[4]            PFN array
 *
 *     XC_SAVE_ID_COMPRESSED_DATA  TAG
 *      M                          Length of compressed data
 *      M bytes of DATA            Decompresses to 4 pages
 *
 *     XC_SAVE_ID_*                other xc save chunks
 *     0                           END BODY TAG
 *
 *     In other words, XC_SAVE_ID_COMPRESSED_DATA can be interleaved with
 *   +ve chunks arbitrarily. But at the receiver end, the following condition
 *   always holds true until the end of BODY PHASE:
 *    num(PFN entries +ve chunks) >= num(pages received in compressed form)
 *
 * TAIL PHASE
 * ----------
 *
 * Content differs for PV and HVM guests.
 *
 * HVM TAIL:
 *
 *  "Magic" pages:
 *     uint64_t         : I/O req PFN
 *     uint64_t         : Buffered I/O req PFN
 *     uint64_t         : Store PFN
 *  Xen HVM Context:
 *     uint32_t         : Length of context in bytes
 *     bytes            : Context data
 *  Qemu context:
 *     char[21]         : Signature:
 *       "QemuDeviceModelRecord" : Read Qemu save data until EOF
 *       "DeviceModelRecord0002" : uint32_t length field followed by that many
 *                                 bytes of Qemu save data
 *       "RemusDeviceModelState" : Currently the same as "DeviceModelRecord0002".
 *
 * PV TAIL:
 *
 *  Unmapped PFN list   : list of all the PFNs that were not in map at the close
 *     unsigned int     : Number of unmapped pages
 *     unsigned long[]  : PFNs of unmapped pages
 *
 *  VCPU context data   : A series of VCPU records, one per present VCPU
 *                        Maximum and present map supplied in XC_SAVE_ID_VCPUINFO
 *     bytes:           : VCPU context structure. Size is determined by size
 *                        provided in extended-info header
 *     bytes[128]       : Extended VCPU context (present IFF "extv" block
 *                        present in extended-info header)
 *
 *  Shared Info Page    : 4096 bytes of shared info page
 */

#define XC_SAVE_ID_ENABLE_VERIFY_MODE -1 /* Switch to validation phase. */
#define XC_SAVE_ID_VCPU_INFO          -2 /* Additional VCPU info */
#define XC_SAVE_ID_HVM_IDENT_PT       -3 /* (HVM-only) */
#define XC_SAVE_ID_HVM_VM86_TSS       -4 /* (HVM-only) */
#define XC_SAVE_ID_TMEM               -5
#define XC_SAVE_ID_TMEM_EXTRA         -6
#define XC_SAVE_ID_TSC_INFO           -7
#define XC_SAVE_ID_HVM_CONSOLE_PFN    -8 /* (HVM-only) */
#define XC_SAVE_ID_LAST_CHECKPOINT    -9 /* Commit to restoring after completion of current iteration. */
#define XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION -10
#define XC_SAVE_ID_HVM_VIRIDIAN       -11
#define XC_SAVE_ID_COMPRESSED_DATA    -12 /* Marker to indicate arrival of compressed data */
#define XC_SAVE_ID_ENABLE_COMPRESSION -13 /* Marker to enable compression logic at receiver side */
#define XC_SAVE_ID_HVM_GENERATION_ID_ADDR -14
/* Markers for the pfn's hosting these mem event rings */
#define XC_SAVE_ID_HVM_PAGING_RING_PFN  -15
#define XC_SAVE_ID_HVM_ACCESS_RING_PFN  -16
#define XC_SAVE_ID_HVM_SHARING_RING_PFN -17
#define XC_SAVE_ID_TOOLSTACK          -18 /* Optional toolstack specific info */
/* These are a pair; it is an error for one to exist without the other */
#define XC_SAVE_ID_HVM_IOREQ_SERVER_PFN -19
#define XC_SAVE_ID_HVM_NR_IOREQ_SERVER_PAGES -20

/*
** We process save/restore/migrate in batches of pages; the below
** determines how many pages we (at maximum) deal with in each batch.
*/
#define MAX_BATCH_SIZE 1024   /* up to 1024 pages (4MB) at a time */

/* When pinning page tables at the end of restore, we also use batching. */
#define MAX_PIN_BATCH  1024

/* Maximum #VCPUs currently supported for save/restore. */
#define XC_SR_MAX_VCPUS 4096
#define vcpumap_sz(max_id) (((max_id)/64+1)*sizeof(uint64_t))


/*
** Determine various platform information required for save/restore, in
** particular:
**
**    - the maximum MFN on this machine, used to compute the size of
**      the M2P table;
**
**    - the starting virtual address of the the hypervisor; we use this
**      to determine which parts of guest address space(s) do and don't
**      require canonicalization during save/restore; and
**
**    - the number of page-table levels for save/ restore. This should
**      be a property of the domain, but for the moment we just read it
**      from the hypervisor.
**
**    - The width of a guest word (unsigned long), in bytes.
**
** Returns 1 on success, 0 on failure.
*/
static inline int get_platform_info(xc_interface *xch, uint32_t dom,
                                    /* OUT */ unsigned long *max_mfn,
                                    /* OUT */ unsigned long *hvirt_start,
                                    /* OUT */ unsigned int *pt_levels,
                                    /* OUT */ unsigned int *guest_width)
{
    xen_capabilities_info_t xen_caps = "";
    xen_platform_parameters_t xen_params;

    if (xc_version(xch, XENVER_platform_parameters, &xen_params) != 0)
        return 0;

    if (xc_version(xch, XENVER_capabilities, &xen_caps) != 0)
        return 0;

    *max_mfn = xc_maximum_ram_page(xch);

    *hvirt_start = xen_params.virt_start;

    if ( xc_domain_get_guest_width(xch, dom, guest_width) != 0)
        return 0; 

    /* 64-bit tools will see the 64-bit hvirt_start, but 32-bit guests 
     * will be using the compat one. */
    if ( *guest_width < sizeof (unsigned long) )
        /* XXX need to fix up a way of extracting this value from Xen if
         * XXX it becomes variable for domU */
        *hvirt_start = 0xf5800000;

    if (strstr(xen_caps, "xen-3.0-x86_64"))
        /* Depends on whether it's a compat 32-on-64 guest */
        *pt_levels = ( (*guest_width == 8) ? 4 : 3 );
    else if (strstr(xen_caps, "xen-3.0-x86_32p"))
        *pt_levels = 3;
    else
        return 0;

    return 1;
}


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

/* Returns TRUE if the PFN is currently mapped */
#define is_mapped(pfn_type) (!((pfn_type) & 0x80000000UL))


#define GET_FIELD(_p, _f, _w) (((_w) == 8) ? ((_p)->x64._f) : ((_p)->x32._f))

#define SET_FIELD(_p, _f, _v, _w) do {          \
    if ((_w) == 8)                              \
        (_p)->x64._f = (_v);                    \
    else                                        \
        (_p)->x32._f = (_v);                    \
} while (0)

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
