/******************************************************************************
 * xc_hvm_build.c
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

#include <stddef.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <zlib.h>

#include "xg_private.h"
#include "xc_private.h"

#include <xen/foreign/x86_32.h>
#include <xen/foreign/x86_64.h>
#include <xen/hvm/hvm_info_table.h>
#include <xen/hvm/params.h>
#include <xen/hvm/e820.h>

#include <xen/libelf/libelf.h>

#define SUPERPAGE_2MB_SHIFT   9
#define SUPERPAGE_2MB_NR_PFNS (1UL << SUPERPAGE_2MB_SHIFT)
#define SUPERPAGE_1GB_SHIFT   18
#define SUPERPAGE_1GB_NR_PFNS (1UL << SUPERPAGE_1GB_SHIFT)

#define SPECIALPAGE_BUFIOREQ 0
#define SPECIALPAGE_XENSTORE 1
#define SPECIALPAGE_IOREQ    2
#define SPECIALPAGE_IDENT_PT 3
#define SPECIALPAGE_CONSOLE  4
#define NR_SPECIAL_PAGES     5
#define special_pfn(x) (0xff000u - NR_SPECIAL_PAGES + (x))

static void build_hvm_info(void *hvm_info_page, uint64_t mem_size)
{
    struct hvm_info_table *hvm_info = (struct hvm_info_table *)
        (((unsigned char *)hvm_info_page) + HVM_INFO_OFFSET);
    uint64_t lowmem_end = mem_size, highmem_end = 0;
    uint8_t sum;
    int i;

    if ( lowmem_end > HVM_BELOW_4G_RAM_END )
    {
        highmem_end = lowmem_end + (1ull<<32) - HVM_BELOW_4G_RAM_END;
        lowmem_end = HVM_BELOW_4G_RAM_END;
    }

    memset(hvm_info_page, 0, PAGE_SIZE);

    /* Fill in the header. */
    strncpy(hvm_info->signature, "HVM INFO", 8);
    hvm_info->length = sizeof(struct hvm_info_table);

    /* Sensible defaults: these can be overridden by the caller. */
    hvm_info->apic_mode = 1;
    hvm_info->nr_vcpus = 1;
    memset(hvm_info->vcpu_online, 0xff, sizeof(hvm_info->vcpu_online));

    /* Memory parameters. */
    hvm_info->low_mem_pgend = lowmem_end >> PAGE_SHIFT;
    hvm_info->high_mem_pgend = highmem_end >> PAGE_SHIFT;
    hvm_info->reserved_mem_pgstart = special_pfn(0);

    /* Finish with the checksum. */
    for ( i = 0, sum = 0; i < hvm_info->length; i++ )
        sum += ((uint8_t *)hvm_info)[i];
    hvm_info->checksum = -sum;
}

static int loadelfimage(
    xc_interface *xch,
    struct elf_binary *elf, uint32_t dom, unsigned long *parray)
{
    privcmd_mmap_entry_t *entries = NULL;
    unsigned long pfn_start = elf->pstart >> PAGE_SHIFT;
    unsigned long pfn_end = (elf->pend + PAGE_SIZE - 1) >> PAGE_SHIFT;
    size_t pages = pfn_end - pfn_start;
    int i, rc = -1;

    /* Map address space for initial elf image. */
    entries = calloc(pages, sizeof(privcmd_mmap_entry_t));
    if ( entries == NULL )
        goto err;

    for ( i = 0; i < pages; i++ )
        entries[i].mfn = parray[(elf->pstart >> PAGE_SHIFT) + i];

    elf->dest = xc_map_foreign_ranges(
        xch, dom, pages << PAGE_SHIFT, PROT_READ | PROT_WRITE, 1 << PAGE_SHIFT,
        entries, pages);
    if ( elf->dest == NULL )
        goto err;

    elf->dest += elf->pstart & (PAGE_SIZE - 1);

    /* Load the initial elf image. */
    rc = elf_load_binary(elf);
    if ( rc < 0 )
        PERROR("Failed to load elf binary\n");

    munmap(elf->dest, pages << PAGE_SHIFT);
    elf->dest = NULL;

 err:
    free(entries);

    return rc;
}

/*
 * Check whether there exists mmio hole in the specified memory range.
 * Returns 1 if exists, else returns 0.
 */
static int check_mmio_hole(uint64_t start, uint64_t memsize)
{
    if ( start + memsize <= HVM_BELOW_4G_MMIO_START ||
         start >= HVM_BELOW_4G_MMIO_START + HVM_BELOW_4G_MMIO_LENGTH )
        return 0;
    else
        return 1;
}

static int setup_guest(xc_interface *xch,
                       uint32_t dom, const struct xc_hvm_build_args *args,
                       char *image, unsigned long image_size)
{
    xen_pfn_t *page_array = NULL;
    unsigned long i, nr_pages = args->mem_size >> PAGE_SHIFT;
    unsigned long target_pages = args->mem_target >> PAGE_SHIFT;
    unsigned long entry_eip, cur_pages, cur_pfn;
    void *hvm_info_page;
    uint32_t *ident_pt;
    struct elf_binary elf;
    uint64_t v_start, v_end;
    int rc;
    xen_capabilities_info_t caps;
    unsigned long stat_normal_pages = 0, stat_2mb_pages = 0, 
        stat_1gb_pages = 0;
    int pod_mode = 0;

    if ( nr_pages > target_pages )
        pod_mode = 1;

    memset(&elf, 0, sizeof(elf));
    if ( elf_init(&elf, image, image_size) != 0 )
        goto error_out;

    xc_elf_set_logfile(xch, &elf, 1);

    elf_parse_binary(&elf);
    v_start = 0;
    v_end = args->mem_size;

    if ( xc_version(xch, XENVER_capabilities, &caps) != 0 )
    {
        PERROR("Could not get Xen capabilities");
        goto error_out;
    }

    IPRINTF("VIRTUAL MEMORY ARRANGEMENT:\n"
            "  Loader:        %016"PRIx64"->%016"PRIx64"\n"
            "  TOTAL:         %016"PRIx64"->%016"PRIx64"\n"
            "  ENTRY ADDRESS: %016"PRIx64"\n",
            elf.pstart, elf.pend,
            v_start, v_end,
            elf_uval(&elf, elf.ehdr, e_entry));

    if ( (page_array = malloc(nr_pages * sizeof(xen_pfn_t))) == NULL )
    {
        PERROR("Could not allocate memory.");
        goto error_out;
    }

    for ( i = 0; i < nr_pages; i++ )
        page_array[i] = i;
    for ( i = HVM_BELOW_4G_RAM_END >> PAGE_SHIFT; i < nr_pages; i++ )
        page_array[i] += HVM_BELOW_4G_MMIO_LENGTH >> PAGE_SHIFT;

    /*
     * Allocate memory for HVM guest, skipping VGA hole 0xA0000-0xC0000.
     *
     * We attempt to allocate 1GB pages if possible. It falls back on 2MB
     * pages if 1GB allocation fails. 4KB pages will be used eventually if
     * both fail.
     * 
     * Under 2MB mode, we allocate pages in batches of no more than 8MB to 
     * ensure that we can be preempted and hence dom0 remains responsive.
     */
    rc = xc_domain_populate_physmap_exact(
        xch, dom, 0xa0, 0, 0, &page_array[0x00]);
    cur_pages = 0xc0;
    stat_normal_pages = 0xc0;
    while ( (rc == 0) && (nr_pages > cur_pages) )
    {
        /* Clip count to maximum 1GB extent. */
        unsigned long count = nr_pages - cur_pages;
        unsigned long max_pages = SUPERPAGE_1GB_NR_PFNS;

        if ( count > max_pages )
            count = max_pages;

        cur_pfn = page_array[cur_pages];

        /* Take care the corner cases of super page tails */
        if ( ((cur_pfn & (SUPERPAGE_1GB_NR_PFNS-1)) != 0) &&
             (count > (-cur_pfn & (SUPERPAGE_1GB_NR_PFNS-1))) )
            count = -cur_pfn & (SUPERPAGE_1GB_NR_PFNS-1);
        else if ( ((count & (SUPERPAGE_1GB_NR_PFNS-1)) != 0) &&
                  (count > SUPERPAGE_1GB_NR_PFNS) )
            count &= ~(SUPERPAGE_1GB_NR_PFNS - 1);

        /* Attemp to allocate 1GB super page. Because in each pass we only
         * allocate at most 1GB, we don't have to clip super page boundaries.
         */
        if ( ((count | cur_pfn) & (SUPERPAGE_1GB_NR_PFNS - 1)) == 0 &&
             /* Check if there exists MMIO hole in the 1GB memory range */
             !check_mmio_hole(cur_pfn << PAGE_SHIFT,
                              SUPERPAGE_1GB_NR_PFNS << PAGE_SHIFT) )
        {
            long done;
            unsigned long nr_extents = count >> SUPERPAGE_1GB_SHIFT;
            xen_pfn_t sp_extents[nr_extents];

            for ( i = 0; i < nr_extents; i++ )
                sp_extents[i] = page_array[cur_pages+(i<<SUPERPAGE_1GB_SHIFT)];

            done = xc_domain_populate_physmap(xch, dom, nr_extents, SUPERPAGE_1GB_SHIFT,
                                              pod_mode ? XENMEMF_populate_on_demand : 0,
                                              sp_extents);

            if ( done > 0 )
            {
                stat_1gb_pages += done;
                done <<= SUPERPAGE_1GB_SHIFT;
                cur_pages += done;
                count -= done;
            }
        }

        if ( count != 0 )
        {
            /* Clip count to maximum 8MB extent. */
            max_pages = SUPERPAGE_2MB_NR_PFNS * 4;
            if ( count > max_pages )
                count = max_pages;
            
            /* Clip partial superpage extents to superpage boundaries. */
            if ( ((cur_pfn & (SUPERPAGE_2MB_NR_PFNS-1)) != 0) &&
                 (count > (-cur_pfn & (SUPERPAGE_2MB_NR_PFNS-1))) )
                count = -cur_pfn & (SUPERPAGE_2MB_NR_PFNS-1);
            else if ( ((count & (SUPERPAGE_2MB_NR_PFNS-1)) != 0) &&
                      (count > SUPERPAGE_2MB_NR_PFNS) )
                count &= ~(SUPERPAGE_2MB_NR_PFNS - 1); /* clip non-s.p. tail */

            /* Attempt to allocate superpage extents. */
            if ( ((count | cur_pfn) & (SUPERPAGE_2MB_NR_PFNS - 1)) == 0 )
            {
                long done;
                unsigned long nr_extents = count >> SUPERPAGE_2MB_SHIFT;
                xen_pfn_t sp_extents[nr_extents];

                for ( i = 0; i < nr_extents; i++ )
                    sp_extents[i] = page_array[cur_pages+(i<<SUPERPAGE_2MB_SHIFT)];

                done = xc_domain_populate_physmap(xch, dom, nr_extents, SUPERPAGE_2MB_SHIFT,
                                                  pod_mode ? XENMEMF_populate_on_demand : 0,
                                                  sp_extents);

                if ( done > 0 )
                {
                    stat_2mb_pages += done;
                    done <<= SUPERPAGE_2MB_SHIFT;
                    cur_pages += done;
                    count -= done;
                }
            }
        }

        /* Fall back to 4kB extents. */
        if ( count != 0 )
        {
            rc = xc_domain_populate_physmap_exact(
                xch, dom, count, 0, 0, &page_array[cur_pages]);
            cur_pages += count;
            stat_normal_pages += count;
        }
    }

    /* Subtract 0x20 from target_pages for the VGA "hole".  Xen will
     * adjust the PoD cache size so that domain tot_pages will be
     * target_pages - 0x20 after this call. */
    if ( pod_mode )
        rc = xc_domain_set_pod_target(xch, dom, target_pages - 0x20,
                                      NULL, NULL, NULL);

    if ( rc != 0 )
    {
        PERROR("Could not allocate memory for HVM guest.");
        goto error_out;
    }

    IPRINTF("PHYSICAL MEMORY ALLOCATION:\n"
            "  4KB PAGES: 0x%016lx\n"
            "  2MB PAGES: 0x%016lx\n"
            "  1GB PAGES: 0x%016lx\n",
            stat_normal_pages, stat_2mb_pages, stat_1gb_pages);
    
    if ( loadelfimage(xch, &elf, dom, page_array) != 0 )
        goto error_out;

    if ( (hvm_info_page = xc_map_foreign_range(
              xch, dom, PAGE_SIZE, PROT_READ | PROT_WRITE,
              HVM_INFO_PFN)) == NULL )
        goto error_out;
    build_hvm_info(hvm_info_page, v_end);
    munmap(hvm_info_page, PAGE_SIZE);

    /* Allocate and clear special pages. */
    for ( i = 0; i < NR_SPECIAL_PAGES; i++ )
    {
        xen_pfn_t pfn = special_pfn(i);
        rc = xc_domain_populate_physmap_exact(xch, dom, 1, 0, 0, &pfn);
        if ( rc != 0 )
        {
            PERROR("Could not allocate %d'th special page.", i);
            goto error_out;
        }
        if ( xc_clear_domain_page(xch, dom, special_pfn(i)) )
            goto error_out;
    }

    xc_set_hvm_param(xch, dom, HVM_PARAM_STORE_PFN,
                     special_pfn(SPECIALPAGE_XENSTORE));
    xc_set_hvm_param(xch, dom, HVM_PARAM_BUFIOREQ_PFN,
                     special_pfn(SPECIALPAGE_BUFIOREQ));
    xc_set_hvm_param(xch, dom, HVM_PARAM_IOREQ_PFN,
                     special_pfn(SPECIALPAGE_IOREQ));
    xc_set_hvm_param(xch, dom, HVM_PARAM_CONSOLE_PFN,
                     special_pfn(SPECIALPAGE_CONSOLE));

    /*
     * Identity-map page table is required for running with CR0.PG=0 when
     * using Intel EPT. Create a 32-bit non-PAE page directory of superpages.
     */
    if ( (ident_pt = xc_map_foreign_range(
              xch, dom, PAGE_SIZE, PROT_READ | PROT_WRITE,
              special_pfn(SPECIALPAGE_IDENT_PT))) == NULL )
        goto error_out;
    for ( i = 0; i < PAGE_SIZE / sizeof(*ident_pt); i++ )
        ident_pt[i] = ((i << 22) | _PAGE_PRESENT | _PAGE_RW | _PAGE_USER |
                       _PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_PSE);
    munmap(ident_pt, PAGE_SIZE);
    xc_set_hvm_param(xch, dom, HVM_PARAM_IDENT_PT,
                     special_pfn(SPECIALPAGE_IDENT_PT) << PAGE_SHIFT);

    /* Insert JMP <rel32> instruction at address 0x0 to reach entry point. */
    entry_eip = elf_uval(&elf, elf.ehdr, e_entry);
    if ( entry_eip != 0 )
    {
        char *page0 = xc_map_foreign_range(
            xch, dom, PAGE_SIZE, PROT_READ | PROT_WRITE, 0);
        if ( page0 == NULL )
            goto error_out;
        page0[0] = 0xe9;
        *(uint32_t *)&page0[1] = entry_eip - 5;
        munmap(page0, PAGE_SIZE);
    }

    free(page_array);
    return 0;

 error_out:
    free(page_array);
    return -1;
}

/* xc_hvm_build:
 * Create a domain for a virtualized Linux, using files/filenames.
 */
int xc_hvm_build(xc_interface *xch, uint32_t domid,
                 const struct xc_hvm_build_args *hvm_args)
{
    struct xc_hvm_build_args args = *hvm_args;
    void *image;
    unsigned long image_size;
    int sts;

    if ( domid == 0 )
        return -1;
    if ( args.image_file_name == NULL )
        return -1;

    if ( args.mem_target == 0 )
        args.mem_target = args.mem_size;

    /* An HVM guest must be initialised with at least 2MB memory. */
    if ( args.mem_size < (2ull << 20) || args.mem_target < (2ull << 20) )
        return -1;

    image = xc_read_image(xch, args.image_file_name, &image_size);
    if ( image == NULL )
        return -1;

    sts = setup_guest(xch, domid, &args, image, image_size);

    free(image);

    return sts;
}

/* xc_hvm_build_target_mem: 
 * Create a domain for a pre-ballooned virtualized Linux, using
 * files/filenames.  If target < memsize, domain is created with
 * memsize pages marked populate-on-demand, 
 * calculating pod cache size based on target.
 * If target == memsize, pages are populated normally.
 */
int xc_hvm_build_target_mem(xc_interface *xch,
                           uint32_t domid,
                           int memsize,
                           int target,
                           const char *image_name)
{
    struct xc_hvm_build_args args = {};

    args.mem_size = (uint64_t)memsize << 20;
    args.mem_target = (uint64_t)target << 20;
    args.image_file_name = image_name;

    return xc_hvm_build(xch, domid, &args);
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
