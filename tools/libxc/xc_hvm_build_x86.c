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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
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

#define SPECIALPAGE_PAGING   0
#define SPECIALPAGE_ACCESS   1
#define SPECIALPAGE_SHARING  2
#define SPECIALPAGE_BUFIOREQ 3
#define SPECIALPAGE_XENSTORE 4
#define SPECIALPAGE_IOREQ    5
#define SPECIALPAGE_IDENT_PT 6
#define SPECIALPAGE_CONSOLE  7
#define NR_SPECIAL_PAGES     8
#define special_pfn(x) (0xff000u - NR_SPECIAL_PAGES + (x))

#define NR_IOREQ_SERVER_PAGES 8
#define ioreq_server_pfn(x) (special_pfn(0) - NR_IOREQ_SERVER_PAGES + (x))

#define VGA_HOLE_SIZE (0x20)

static int modules_init(struct xc_hvm_build_args *args,
                        uint64_t vend, struct elf_binary *elf,
                        uint64_t *mstart_out, uint64_t *mend_out)
{
#define MODULE_ALIGN 1UL << 7
#define MB_ALIGN     1UL << 20
#define MKALIGN(x, a) (((uint64_t)(x) + (a) - 1) & ~(uint64_t)((a) - 1))
    uint64_t total_len = 0, offset1 = 0;

    if ( (args->acpi_module.length == 0)&&(args->smbios_module.length == 0) )
        return 0;

    /* Find the total length for the firmware modules with a reasonable large
     * alignment size to align each the modules.
     */
    total_len = MKALIGN(args->acpi_module.length, MODULE_ALIGN);
    offset1 = total_len;
    total_len += MKALIGN(args->smbios_module.length, MODULE_ALIGN);

    /* Want to place the modules 1Mb+change behind the loader image. */
    *mstart_out = MKALIGN(elf->pend, MB_ALIGN) + (MB_ALIGN);
    *mend_out = *mstart_out + total_len;

    if ( *mend_out > vend )    
        return -1;

    if ( args->acpi_module.length != 0 )
        args->acpi_module.guest_addr_out = *mstart_out;
    if ( args->smbios_module.length != 0 )
        args->smbios_module.guest_addr_out = *mstart_out + offset1;

    return 0;
}

static void build_hvm_info(void *hvm_info_page,
                           struct xc_hvm_build_args *args)
{
    struct hvm_info_table *hvm_info = (struct hvm_info_table *)
        (((unsigned char *)hvm_info_page) + HVM_INFO_OFFSET);
    uint8_t sum;
    int i;

    memset(hvm_info_page, 0, PAGE_SIZE);

    /* Fill in the header. */
    memcpy(hvm_info->signature, "HVM INFO", sizeof(hvm_info->signature));
    hvm_info->length = sizeof(struct hvm_info_table);

    /* Sensible defaults: these can be overridden by the caller. */
    hvm_info->apic_mode = 1;
    hvm_info->nr_vcpus = 1;
    memset(hvm_info->vcpu_online, 0xff, sizeof(hvm_info->vcpu_online));

    /* Memory parameters. */
    hvm_info->low_mem_pgend = args->lowmem_end >> PAGE_SHIFT;
    hvm_info->high_mem_pgend = args->highmem_end >> PAGE_SHIFT;
    hvm_info->reserved_mem_pgstart = ioreq_server_pfn(0);

    /* Finish with the checksum. */
    for ( i = 0, sum = 0; i < hvm_info->length; i++ )
        sum += ((uint8_t *)hvm_info)[i];
    hvm_info->checksum = -sum;
}

static int loadelfimage(xc_interface *xch, struct elf_binary *elf,
                        uint32_t dom, unsigned long *parray)
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

    elf->dest_base = xc_map_foreign_ranges(
        xch, dom, pages << PAGE_SHIFT, PROT_READ | PROT_WRITE, 1 << PAGE_SHIFT,
        entries, pages);
    if ( elf->dest_base == NULL )
        goto err;
    elf->dest_size = pages * PAGE_SIZE;

    ELF_ADVANCE_DEST(elf, elf->pstart & (PAGE_SIZE - 1));

    /* Load the initial elf image. */
    rc = elf_load_binary(elf);
    if ( rc < 0 )
        PERROR("Failed to load elf binary\n");

    munmap(elf->dest_base, pages << PAGE_SHIFT);
    elf->dest_base = NULL;
    elf->dest_size = 0;

 err:
    free(entries);

    return rc;
}

static int loadmodules(xc_interface *xch,
                       struct xc_hvm_build_args *args,
                       uint64_t mstart, uint64_t mend,
                       uint32_t dom, unsigned long *parray)
{
    privcmd_mmap_entry_t *entries = NULL;
    unsigned long pfn_start;
    unsigned long pfn_end;
    size_t pages;
    uint32_t i;
    uint8_t *dest;
    int rc = -1;

    if ( (mstart == 0)||(mend == 0) )
        return 0;

    pfn_start = (unsigned long)(mstart >> PAGE_SHIFT);
    pfn_end = (unsigned long)((mend + PAGE_SIZE - 1) >> PAGE_SHIFT);
    pages = pfn_end - pfn_start;

    /* Map address space for module list. */
    entries = calloc(pages, sizeof(privcmd_mmap_entry_t));
    if ( entries == NULL )
        goto error_out;

    for ( i = 0; i < pages; i++ )
        entries[i].mfn = parray[(mstart >> PAGE_SHIFT) + i];

    dest = xc_map_foreign_ranges(
        xch, dom, pages << PAGE_SHIFT, PROT_READ | PROT_WRITE, 1 << PAGE_SHIFT,
        entries, pages);
    if ( dest == NULL )
        goto error_out;

    /* Zero the range so padding is clear between modules */
    memset(dest, 0, pages << PAGE_SHIFT);

    /* Load modules into range */    
    if ( args->acpi_module.length != 0 )
    {
        memcpy(dest,
               args->acpi_module.data,
               args->acpi_module.length);
    }
    if ( args->smbios_module.length != 0 )
    {
        memcpy(dest + (args->smbios_module.guest_addr_out - mstart),
               args->smbios_module.data,
               args->smbios_module.length);
    }

    munmap(dest, pages << PAGE_SHIFT);
    rc = 0;

 error_out:
    free(entries);

    return rc;
}

/*
 * Check whether there exists mmio hole in the specified memory range.
 * Returns 1 if exists, else returns 0.
 */
static int check_mmio_hole(uint64_t start, uint64_t memsize,
                           uint64_t mmio_start, uint64_t mmio_size)
{
    if ( start + memsize <= mmio_start || start >= mmio_start + mmio_size )
        return 0;
    else
        return 1;
}

static int setup_guest(xc_interface *xch,
                       uint32_t dom, struct xc_hvm_build_args *args,
                       char *image, unsigned long image_size)
{
    xen_pfn_t *page_array = NULL;
    unsigned long i, vmemid, nr_pages = args->mem_size >> PAGE_SHIFT;
    unsigned long p2m_size;
    unsigned long target_pages = args->mem_target >> PAGE_SHIFT;
    unsigned long entry_eip, cur_pages, cur_pfn;
    void *hvm_info_page;
    uint32_t *ident_pt;
    struct elf_binary elf;
    uint64_t v_start, v_end;
    uint64_t m_start = 0, m_end = 0;
    int rc;
    xen_capabilities_info_t caps;
    unsigned long stat_normal_pages = 0, stat_2mb_pages = 0, 
        stat_1gb_pages = 0;
    unsigned int memflags = 0;
    int claim_enabled = args->claim_enabled;
    xen_pfn_t special_array[NR_SPECIAL_PAGES];
    xen_pfn_t ioreq_server_array[NR_IOREQ_SERVER_PAGES];
    uint64_t total_pages;
    xen_vmemrange_t dummy_vmemrange[2];
    unsigned int dummy_vnode_to_pnode[1];
    xen_vmemrange_t *vmemranges;
    unsigned int *vnode_to_pnode;
    unsigned int nr_vmemranges, nr_vnodes;

    memset(&elf, 0, sizeof(elf));
    if ( elf_init(&elf, image, image_size) != 0 )
    {
        PERROR("Could not initialise ELF image");
        goto error_out;
    }

    xc_elf_set_logfile(xch, &elf, 1);

    elf_parse_binary(&elf);
    v_start = 0;
    v_end = args->mem_size;

    if ( nr_pages > target_pages )
        memflags |= XENMEMF_populate_on_demand;

    if ( args->nr_vmemranges == 0 )
    {
        /* Build dummy vnode information
         *
         * Guest physical address space layout:
         * [0, hole_start) [hole_start, 4G) [4G, highmem_end)
         *
         * Of course if there is no high memory, the second vmemrange
         * has no effect on the actual result.
         */

        dummy_vmemrange[0].start = 0;
        dummy_vmemrange[0].end   = args->lowmem_end;
        dummy_vmemrange[0].flags = 0;
        dummy_vmemrange[0].nid   = 0;
        nr_vmemranges = 1;

        if ( args->highmem_end > (1ULL << 32) )
        {
            dummy_vmemrange[1].start = 1ULL << 32;
            dummy_vmemrange[1].end   = args->highmem_end;
            dummy_vmemrange[1].flags = 0;
            dummy_vmemrange[1].nid   = 0;

            nr_vmemranges++;
        }

        dummy_vnode_to_pnode[0] = XC_NUMA_NO_NODE;
        nr_vnodes = 1;
        vmemranges = dummy_vmemrange;
        vnode_to_pnode = dummy_vnode_to_pnode;
    }
    else
    {
        if ( nr_pages > target_pages )
        {
            PERROR("Cannot enable vNUMA and PoD at the same time");
            goto error_out;
        }

        nr_vmemranges = args->nr_vmemranges;
        nr_vnodes = args->nr_vnodes;
        vmemranges = args->vmemranges;
        vnode_to_pnode = args->vnode_to_pnode;
    }

    total_pages = 0;
    p2m_size = 0;
    for ( i = 0; i < nr_vmemranges; i++ )
    {
        total_pages += ((vmemranges[i].end - vmemranges[i].start)
                        >> PAGE_SHIFT);
        p2m_size = p2m_size > (vmemranges[i].end >> PAGE_SHIFT) ?
            p2m_size : (vmemranges[i].end >> PAGE_SHIFT);
    }

    if ( total_pages != (args->mem_size >> PAGE_SHIFT) )
    {
        PERROR("vNUMA memory pages mismatch (0x%"PRIx64" != 0x%"PRIx64")",
               total_pages, args->mem_size >> PAGE_SHIFT);
        goto error_out;
    }

    if ( xc_version(xch, XENVER_capabilities, &caps) != 0 )
    {
        PERROR("Could not get Xen capabilities");
        goto error_out;
    }

    if ( modules_init(args, v_end, &elf, &m_start, &m_end) != 0 )
    {
        ERROR("Insufficient space to load modules.");
        goto error_out;
    }

    DPRINTF("VIRTUAL MEMORY ARRANGEMENT:\n");
    DPRINTF("  Loader:   %016"PRIx64"->%016"PRIx64"\n", elf.pstart, elf.pend);
    DPRINTF("  Modules:  %016"PRIx64"->%016"PRIx64"\n", m_start, m_end);
    DPRINTF("  TOTAL:    %016"PRIx64"->%016"PRIx64"\n", v_start, v_end);
    DPRINTF("  ENTRY:    %016"PRIx64"\n", elf_uval(&elf, elf.ehdr, e_entry));

    if ( (page_array = malloc(p2m_size * sizeof(xen_pfn_t))) == NULL )
    {
        PERROR("Could not allocate memory.");
        goto error_out;
    }

    for ( i = 0; i < p2m_size; i++ )
        page_array[i] = ((xen_pfn_t)-1);
    for ( vmemid = 0; vmemid < nr_vmemranges; vmemid++ )
    {
        uint64_t pfn;

        for ( pfn = vmemranges[vmemid].start >> PAGE_SHIFT;
              pfn < vmemranges[vmemid].end >> PAGE_SHIFT;
              pfn++ )
            page_array[pfn] = pfn;
    }

    /*
     * Try to claim pages for early warning of insufficient memory available.
     * This should go before xc_domain_set_pod_target, becuase that function
     * actually allocates memory for the guest. Claiming after memory has been
     * allocated is pointless.
     */
    if ( claim_enabled ) {
        rc = xc_domain_claim_pages(xch, dom, target_pages - VGA_HOLE_SIZE);
        if ( rc != 0 )
        {
            PERROR("Could not allocate memory for HVM guest as we cannot claim memory!");
            goto error_out;
        }
    }

    if ( memflags & XENMEMF_populate_on_demand )
    {
        /*
         * Subtract VGA_HOLE_SIZE from target_pages for the VGA
         * "hole".  Xen will adjust the PoD cache size so that domain
         * tot_pages will be target_pages - VGA_HOLE_SIZE after
         * this call.
         */
        rc = xc_domain_set_pod_target(xch, dom,
                                      target_pages - VGA_HOLE_SIZE,
                                      NULL, NULL, NULL);
        if ( rc != 0 )
        {
            PERROR("Could not set PoD target for HVM guest.\n");
            goto error_out;
        }
    }

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
        xch, dom, 0xa0, 0, memflags, &page_array[0x00]);

    stat_normal_pages = 0;
    for ( vmemid = 0; vmemid < nr_vmemranges; vmemid++ )
    {
        unsigned int new_memflags = memflags;
        uint64_t end_pages;
        unsigned int vnode = vmemranges[vmemid].nid;
        unsigned int pnode = vnode_to_pnode[vnode];

        if ( pnode != XC_NUMA_NO_NODE )
            new_memflags |= XENMEMF_exact_node(pnode);

        end_pages = vmemranges[vmemid].end >> PAGE_SHIFT;
        /*
         * Consider vga hole belongs to the vmemrange that covers
         * 0xA0000-0xC0000. Note that 0x00000-0xA0000 is populated just
         * before this loop.
         */
        if ( vmemranges[vmemid].start == 0 )
        {
            cur_pages = 0xc0;
            stat_normal_pages += 0xc0;
        }
        else
            cur_pages = vmemranges[vmemid].start >> PAGE_SHIFT;

        while ( (rc == 0) && (end_pages > cur_pages) )
        {
            /* Clip count to maximum 1GB extent. */
            unsigned long count = end_pages - cur_pages;
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

            /* Attemp to allocate 1GB super page. Because in each pass
             * we only allocate at most 1GB, we don't have to clip
             * super page boundaries.
             */
            if ( ((count | cur_pfn) & (SUPERPAGE_1GB_NR_PFNS - 1)) == 0 &&
                 /* Check if there exists MMIO hole in the 1GB memory
                  * range */
                 !check_mmio_hole(cur_pfn << PAGE_SHIFT,
                                  SUPERPAGE_1GB_NR_PFNS << PAGE_SHIFT,
                                  args->mmio_start, args->mmio_size) )
            {
                long done;
                unsigned long nr_extents = count >> SUPERPAGE_1GB_SHIFT;
                xen_pfn_t sp_extents[nr_extents];

                for ( i = 0; i < nr_extents; i++ )
                    sp_extents[i] =
                        page_array[cur_pages+(i<<SUPERPAGE_1GB_SHIFT)];

                done = xc_domain_populate_physmap(xch, dom, nr_extents,
                                                  SUPERPAGE_1GB_SHIFT,
                                                  new_memflags,
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

                /* Clip partial superpage extents to superpage
                 * boundaries. */
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
                        sp_extents[i] =
                            page_array[cur_pages+(i<<SUPERPAGE_2MB_SHIFT)];

                    done = xc_domain_populate_physmap(xch, dom, nr_extents,
                                                      SUPERPAGE_2MB_SHIFT,
                                                      new_memflags,
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
                    xch, dom, count, 0, new_memflags, &page_array[cur_pages]);
                cur_pages += count;
                stat_normal_pages += count;
            }
        }

        if ( rc != 0 )
            break;
    }

    if ( rc != 0 )
    {
        PERROR("Could not allocate memory for HVM guest.");
        goto error_out;
    }

    DPRINTF("PHYSICAL MEMORY ALLOCATION:\n");
    DPRINTF("  4KB PAGES: 0x%016lx\n", stat_normal_pages);
    DPRINTF("  2MB PAGES: 0x%016lx\n", stat_2mb_pages);
    DPRINTF("  1GB PAGES: 0x%016lx\n", stat_1gb_pages);
    
    if ( loadelfimage(xch, &elf, dom, page_array) != 0 )
    {
        PERROR("Could not load ELF image");
        goto error_out;
    }

    if ( loadmodules(xch, args, m_start, m_end, dom, page_array) != 0 )
    {
        PERROR("Could not load ACPI modules");
        goto error_out;
    }

    if ( (hvm_info_page = xc_map_foreign_range(
              xch, dom, PAGE_SIZE, PROT_READ | PROT_WRITE,
              HVM_INFO_PFN)) == NULL )
    {
        PERROR("Could not map hvm info page");
        goto error_out;
    }
    build_hvm_info(hvm_info_page, args);
    munmap(hvm_info_page, PAGE_SIZE);

    /* Allocate and clear special pages. */
    for ( i = 0; i < NR_SPECIAL_PAGES; i++ )
        special_array[i] = special_pfn(i);

    rc = xc_domain_populate_physmap_exact(xch, dom, NR_SPECIAL_PAGES, 0, 0,
                                          special_array);
    if ( rc != 0 )
    {
        PERROR("Could not allocate special pages.");
        goto error_out;
    }

    if ( xc_clear_domain_pages(xch, dom, special_pfn(0), NR_SPECIAL_PAGES) )
    {
        PERROR("Could not clear special pages");
        goto error_out;
    }

    xc_hvm_param_set(xch, dom, HVM_PARAM_STORE_PFN,
                     special_pfn(SPECIALPAGE_XENSTORE));
    xc_hvm_param_set(xch, dom, HVM_PARAM_BUFIOREQ_PFN,
                     special_pfn(SPECIALPAGE_BUFIOREQ));
    xc_hvm_param_set(xch, dom, HVM_PARAM_IOREQ_PFN,
                     special_pfn(SPECIALPAGE_IOREQ));
    xc_hvm_param_set(xch, dom, HVM_PARAM_CONSOLE_PFN,
                     special_pfn(SPECIALPAGE_CONSOLE));
    xc_hvm_param_set(xch, dom, HVM_PARAM_PAGING_RING_PFN,
                     special_pfn(SPECIALPAGE_PAGING));
    xc_hvm_param_set(xch, dom, HVM_PARAM_MONITOR_RING_PFN,
                     special_pfn(SPECIALPAGE_ACCESS));
    xc_hvm_param_set(xch, dom, HVM_PARAM_SHARING_RING_PFN,
                     special_pfn(SPECIALPAGE_SHARING));

    /*
     * Allocate and clear additional ioreq server pages. The default
     * server will use the IOREQ and BUFIOREQ special pages above.
     */
    for ( i = 0; i < NR_IOREQ_SERVER_PAGES; i++ )
        ioreq_server_array[i] = ioreq_server_pfn(i);

    rc = xc_domain_populate_physmap_exact(xch, dom, NR_IOREQ_SERVER_PAGES, 0, 0,
                                          ioreq_server_array);
    if ( rc != 0 )
    {
        PERROR("Could not allocate ioreq server pages.");
        goto error_out;
    }

    if ( xc_clear_domain_pages(xch, dom, ioreq_server_pfn(0), NR_IOREQ_SERVER_PAGES) )
    {
        PERROR("Could not clear ioreq page");
        goto error_out;
    }

    /* Tell the domain where the pages are and how many there are */
    xc_hvm_param_set(xch, dom, HVM_PARAM_IOREQ_SERVER_PFN,
                     ioreq_server_pfn(0));
    xc_hvm_param_set(xch, dom, HVM_PARAM_NR_IOREQ_SERVER_PAGES,
                     NR_IOREQ_SERVER_PAGES);

    /*
     * Identity-map page table is required for running with CR0.PG=0 when
     * using Intel EPT. Create a 32-bit non-PAE page directory of superpages.
     */
    if ( (ident_pt = xc_map_foreign_range(
              xch, dom, PAGE_SIZE, PROT_READ | PROT_WRITE,
              special_pfn(SPECIALPAGE_IDENT_PT))) == NULL )
    {
        PERROR("Could not map special page ident_pt");
        goto error_out;
    }
    for ( i = 0; i < PAGE_SIZE / sizeof(*ident_pt); i++ )
        ident_pt[i] = ((i << 22) | _PAGE_PRESENT | _PAGE_RW | _PAGE_USER |
                       _PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_PSE);
    munmap(ident_pt, PAGE_SIZE);
    xc_hvm_param_set(xch, dom, HVM_PARAM_IDENT_PT,
                     special_pfn(SPECIALPAGE_IDENT_PT) << PAGE_SHIFT);

    /* Insert JMP <rel32> instruction at address 0x0 to reach entry point. */
    entry_eip = elf_uval(&elf, elf.ehdr, e_entry);
    if ( entry_eip != 0 )
    {
        char *page0 = xc_map_foreign_range(
            xch, dom, PAGE_SIZE, PROT_READ | PROT_WRITE, 0);
        if ( page0 == NULL )
        {
            PERROR("Could not map page0");
            goto error_out;
        }
        page0[0] = 0xe9;
        *(uint32_t *)&page0[1] = entry_eip - 5;
        munmap(page0, PAGE_SIZE);
    }

    rc = 0;
    goto out;
 error_out:
    rc = -1;
 out:
    if ( elf_check_broken(&elf) )
        ERROR("HVM ELF broken: %s", elf_check_broken(&elf));

    /* ensure no unclaimed pages are left unused */
    xc_domain_claim_pages(xch, dom, 0 /* cancels the claim */);

    free(page_array);
    return rc;
}

/* xc_hvm_build:
 * Create a domain for a virtualized Linux, using files/filenames.
 */
int xc_hvm_build(xc_interface *xch, uint32_t domid,
                 struct xc_hvm_build_args *hvm_args)
{
    struct xc_hvm_build_args args = *hvm_args;
    void *image;
    unsigned long image_size;
    int sts;

    if ( domid == 0 )
        return -1;
    if ( args.image_file_name == NULL )
        return -1;

    /* An HVM guest must be initialised with at least 2MB memory. */
    if ( args.mem_size < (2ull << 20) || args.mem_target < (2ull << 20) )
        return -1;

    image = xc_read_image(xch, args.image_file_name, &image_size);
    if ( image == NULL )
        return -1;

    sts = setup_guest(xch, domid, &args, image, image_size);

    if (!sts)
    {
        /* Return module load addresses to caller */
        hvm_args->acpi_module.guest_addr_out = 
            args.acpi_module.guest_addr_out;
        hvm_args->smbios_module.guest_addr_out = 
            args.smbios_module.guest_addr_out;
    }

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

    memset(&args, 0, sizeof(struct xc_hvm_build_args));
    args.mem_size = (uint64_t)memsize << 20;
    args.mem_target = (uint64_t)target << 20;
    args.image_file_name = image_name;
    if ( args.mmio_size == 0 )
        args.mmio_size = HVM_BELOW_4G_MMIO_LENGTH;

    return xc_hvm_build(xch, domid, &args);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
