/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/device_tree.h>
#include <xen/libfdt/libfdt.h>
#include <xen/rangeset.h>
#include <xen/sched.h>

#include <asm/domain_build.h>
#include <asm/static-memory.h>
#include <asm/static-shmem.h>

typedef struct {
    struct domain *d;
    const char *role_str;
    paddr_t gbase;
    struct shmem_membank_extra *bank_extra_info;
} alloc_heap_pages_cb_extra;

static struct {
    struct membanks_hdr common;
    struct membank bank[NR_SHMEM_BANKS];
} shm_heap_banks __initdata = {
    .common.max_banks = NR_SHMEM_BANKS,
    .common.type = STATIC_SHARED_MEMORY
};

static inline struct membanks *get_shmem_heap_banks(void)
{
    return container_of(&shm_heap_banks.common, struct membanks, common);
}

static void __init __maybe_unused build_assertions(void)
{
    /*
     * Check that no padding is between struct membanks "bank" flexible array
     * member and struct shared_meminfo "bank" member
     */
    BUILD_BUG_ON((offsetof(struct membanks, bank) !=
                 offsetof(struct shared_meminfo, bank)));
}

static const struct membank __init *
find_shm_bank_by_id(const struct membanks *shmem, const char *shm_id)
{
    unsigned int bank;

    for ( bank = 0 ; bank < shmem->nr_banks; bank++ )
    {
        if ( strcmp(shm_id, shmem->bank[bank].shmem_extra->shm_id) == 0 )
            break;
    }

    if ( bank == shmem->nr_banks )
        return NULL;

    return &shmem->bank[bank];
}

/*
 * This function checks whether the static shared memory region is
 * already allocated to dom_io.
 */
static bool __init is_shm_allocated_to_domio(paddr_t pbase)
{
    struct page_info *page;
    struct domain *d;

    page = maddr_to_page(pbase);
    d = page_get_owner_and_reference(page);
    if ( d == NULL )
        return false;
    put_page(page);

    if ( d != dom_io )
    {
        printk(XENLOG_ERR
               "shm memory node has already been allocated to a specific owner %pd, Please check your configuration\n",
               d);
        return false;
    }

    return true;
}

static mfn_t __init acquire_shared_memory_bank(struct domain *d,
                                               paddr_t pbase, paddr_t psize,
                                               bool bank_from_heap)
{
    mfn_t smfn;
    unsigned long nr_pfns;
    int res;

    /*
     * Pages of statically shared memory shall be included
     * into domain_tot_pages().
     */
    nr_pfns = PFN_DOWN(psize);
    if ( (UINT_MAX - d->max_pages) < nr_pfns )
    {
        printk(XENLOG_ERR "%pd: Over-allocation for d->max_pages: %lu.\n",
               d, nr_pfns);
        return INVALID_MFN;
    }
    d->max_pages += nr_pfns;

    smfn = maddr_to_mfn(pbase);
    if ( bank_from_heap )
        /*
         * When host address is not provided, static shared memory is
         * allocated from heap and shall be assigned to owner domain.
         */
        res = assign_pages(maddr_to_page(pbase), nr_pfns, d, 0);
    else
        res = acquire_domstatic_pages(d, smfn, nr_pfns, 0);

    if ( res )
    {
        printk(XENLOG_ERR "%pd: failed to %s static memory: %d.\n", d,
               bank_from_heap ? "assign" : "acquire", res);
        goto fail;
    }

    return smfn;

 fail:
    d->max_pages -= nr_pfns;
    return INVALID_MFN;
}

static int __init assign_shared_memory(struct domain *d, paddr_t gbase,
                                       bool bank_from_heap,
                                       const struct membank *shm_bank)
{
    mfn_t smfn;
    int ret = 0;
    unsigned long nr_pages, nr_borrowers, i;
    struct page_info *page;
    paddr_t pbase, psize;

    pbase = shm_bank->start;
    psize = shm_bank->size;
    nr_borrowers = shm_bank->shmem_extra->nr_shm_borrowers;

    smfn = acquire_shared_memory_bank(d, pbase, psize, bank_from_heap);
    if ( mfn_eq(smfn, INVALID_MFN) )
        return -EINVAL;

    /*
     * DOMID_IO is not auto-translated (i.e. it sees RAM 1:1). So we do not need
     * to create mapping in the P2M.
     */
    nr_pages = PFN_DOWN(psize);
    if ( d != dom_io )
    {
        ret = guest_physmap_add_pages(d, gaddr_to_gfn(gbase), smfn,
                                      PFN_DOWN(psize));
        if ( ret )
        {
            printk(XENLOG_ERR "Failed to map shared memory to %pd.\n", d);
            return ret;
        }
    }

    /*
     * Instead of letting borrower domain get a page ref, we add as many
     * additional reference as the number of borrowers when the owner
     * is allocated, since there is a chance that owner is created
     * after borrower.
     * So if the borrower is created first, it will cause adding pages
     * in the P2M without reference.
     */
    page = mfn_to_page(smfn);
    for ( i = 0; i < nr_pages; i++ )
    {
        if ( !get_page_nr(page + i, d, nr_borrowers) )
        {
            printk(XENLOG_ERR
                   "Failed to add %lu references to page %"PRI_mfn".\n",
                   nr_borrowers, mfn_x(smfn) + i);
            goto fail;
        }
    }

    return 0;

 fail:
    while ( --i >= 0 )
        put_page_nr(page + i, nr_borrowers);
    return ret;
}

static int __init
append_shm_bank_to_domain(struct kernel_info *kinfo, paddr_t start,
                          paddr_t size, const char *shm_id)
{
    struct membanks *shm_mem = kernel_info_get_shm_mem(kinfo);
    struct shmem_membank_extra *shm_mem_extra;

    if ( shm_mem->nr_banks >= shm_mem->max_banks )
        return -ENOMEM;

    shm_mem_extra = &kinfo->shm_mem.extra[shm_mem->nr_banks];

    shm_mem->bank[shm_mem->nr_banks].start = start;
    shm_mem->bank[shm_mem->nr_banks].size = size;
    safe_strcpy(shm_mem_extra->shm_id, shm_id);
    shm_mem->bank[shm_mem->nr_banks].shmem_extra = shm_mem_extra;
    shm_mem->nr_banks++;

    return 0;
}

static int __init handle_shared_mem_bank(struct domain *d, paddr_t gbase,
                                         const char *role_str,
                                         bool bank_from_heap,
                                         const struct membank *shm_bank)
{
    bool owner_dom_io = true;
    paddr_t pbase, psize;
    int ret;

    pbase = shm_bank->start;
    psize = shm_bank->size;

    /*
     * "role" property is optional and if it is defined explicitly,
     * then the owner domain is not the default "dom_io" domain.
     */
    if ( role_str != NULL )
        owner_dom_io = false;

    /*
     * DOMID_IO is a fake domain and is not described in the Device-Tree.
     * Therefore when the owner of the shared region is DOMID_IO, we will
     * only find the borrowers.
     */
    if ( (owner_dom_io && !is_shm_allocated_to_domio(pbase)) ||
         (!owner_dom_io && strcmp(role_str, "owner") == 0) )
    {
        /*
         * We found the first borrower of the region, the owner was not
         * specified, so they should be assigned to dom_io.
         */
        ret = assign_shared_memory(owner_dom_io ? dom_io : d, gbase,
                                   bank_from_heap, shm_bank);
        if ( ret )
            return ret;
    }

    if ( owner_dom_io || (strcmp(role_str, "borrower") == 0) )
    {
        /* Set up P2M foreign mapping for borrower domain. */
        ret = map_regions_p2mt(d, _gfn(PFN_UP(gbase)), PFN_DOWN(psize),
                               _mfn(PFN_UP(pbase)), p2m_map_foreign_rw);
        if ( ret )
            return ret;
    }

    return 0;
}

static bool __init save_map_heap_pages(struct domain *d, struct page_info *pg,
                                       unsigned int order, void *extra)
{
    alloc_heap_pages_cb_extra *b_extra = (alloc_heap_pages_cb_extra *)extra;
    int idx = shm_heap_banks.common.nr_banks;
    int ret = -ENOSPC;

    BUG_ON(!b_extra);

    if ( idx < shm_heap_banks.common.max_banks )
    {
        shm_heap_banks.bank[idx].start = page_to_maddr(pg);
        shm_heap_banks.bank[idx].size = (1ULL << (PAGE_SHIFT + order));
        shm_heap_banks.bank[idx].shmem_extra = b_extra->bank_extra_info;
        shm_heap_banks.common.nr_banks++;

        ret = handle_shared_mem_bank(b_extra->d, b_extra->gbase,
                                     b_extra->role_str, true,
                                     &shm_heap_banks.bank[idx]);
        if ( !ret )
        {
            /* Increment guest physical address for next mapping */
            b_extra->gbase += shm_heap_banks.bank[idx].size;
            return true;
        }
    }

    printk("Failed to allocate static shared memory from Xen heap: (%d)\n",
           ret);

    return false;
}

int __init process_shm(struct domain *d, struct kernel_info *kinfo,
                       const struct dt_device_node *node)
{
    struct dt_device_node *shm_node;

    dt_for_each_child_node(node, shm_node)
    {
        const struct membank *boot_shm_bank;
        const struct dt_property *prop;
        const __be32 *cells;
        uint32_t addr_cells, size_cells;
        paddr_t gbase, pbase, psize;
        int ret = 0;
        unsigned int i;
        const char *role_str;
        const char *shm_id;

        if ( !dt_device_is_compatible(shm_node, "xen,domain-shared-memory-v1") )
            continue;

        if ( dt_property_read_string(shm_node, "xen,shm-id", &shm_id) )
        {
            printk("%pd: invalid \"xen,shm-id\" property", d);
            return -EINVAL;
        }
        BUG_ON((strlen(shm_id) <= 0) || (strlen(shm_id) >= MAX_SHM_ID_LENGTH));

        boot_shm_bank = find_shm_bank_by_id(bootinfo_get_shmem(), shm_id);
        if ( !boot_shm_bank )
        {
            printk("%pd: static shared memory bank not found: '%s'", d, shm_id);
            return -ENOENT;
        }

        pbase = boot_shm_bank->start;
        psize = boot_shm_bank->size;

        /* "role" property is optional */
        if ( dt_property_read_string(shm_node, "role", &role_str) != 0 )
            role_str = NULL;

        /*
         * xen,shared-mem = <[pbase,] gbase, size>;
         * pbase is optional.
         */
        addr_cells = dt_n_addr_cells(shm_node);
        size_cells = dt_n_size_cells(shm_node);
        prop = dt_find_property(shm_node, "xen,shared-mem", NULL);
        BUG_ON(!prop);
        cells = (const __be32 *)prop->value;

        if ( pbase != INVALID_PADDR )
        {
            /* guest phys address is after host phys address */
            gbase = dt_read_paddr(cells + addr_cells, addr_cells);

            if ( is_domain_direct_mapped(d) && (pbase != gbase) )
            {
                printk("%pd: physical address 0x%"PRIpaddr" and guest address 0x%"PRIpaddr" are not direct-mapped.\n",
                       d, pbase, gbase);
                return -EINVAL;
            }

            for ( i = 0; i < PFN_DOWN(psize); i++ )
                if ( !mfn_valid(mfn_add(maddr_to_mfn(pbase), i)) )
                {
                    printk("%pd: invalid physical address 0x%"PRI_mfn"\n",
                        d, mfn_x(mfn_add(maddr_to_mfn(pbase), i)));
                    return -EINVAL;
                }

            /* The host physical address is supplied by the user */
            ret = handle_shared_mem_bank(d, gbase, role_str, false,
                                         boot_shm_bank);
            if ( ret )
                return ret;
        }
        else
        {
            /*
             * The host physical address is not supplied by the user, so it
             * means that the banks needs to be allocated from the Xen heap,
             * look into the already allocated banks from the heap.
             */
            const struct membank *alloc_bank =
                find_shm_bank_by_id(get_shmem_heap_banks(), shm_id);

            if ( is_domain_direct_mapped(d) )
            {
                printk("%pd: host and guest physical address must be supplied for direct-mapped domains\n",
                       d);
                return -EINVAL;
            }

            /* guest phys address is right at the beginning */
            gbase = dt_read_paddr(cells, addr_cells);

            if ( !alloc_bank )
            {
                alloc_heap_pages_cb_extra cb_arg = { d, role_str, gbase,
                    boot_shm_bank->shmem_extra };

                /* shm_id identified bank is not yet allocated */
                if ( !allocate_domheap_memory(NULL, psize, save_map_heap_pages,
                                              &cb_arg) )
                {
                    printk(XENLOG_ERR
                           "Failed to allocate (%"PRIpaddr"KB) pages as static shared memory from heap\n",
                           psize >> 10);
                    return -EINVAL;
                }
            }
            else
            {
                /* shm_id identified bank is already allocated */
                const struct membank *end_bank =
                        &shm_heap_banks.bank[shm_heap_banks.common.nr_banks];
                paddr_t gbase_bank = gbase;

                /*
                 * Static shared memory banks that are taken from the Xen heap
                 * are allocated sequentially in shm_heap_banks, so starting
                 * from the first bank found identified by shm_id, the code can
                 * just advance by one bank at the time until it reaches the end
                 * of the array or it finds another bank NOT identified by
                 * shm_id
                 */
                for ( ; alloc_bank < end_bank; alloc_bank++ )
                {
                    if ( strcmp(shm_id, alloc_bank->shmem_extra->shm_id) != 0 )
                        break;

                    ret = handle_shared_mem_bank(d, gbase_bank, role_str, true,
                                                 alloc_bank);
                    if ( ret )
                        return ret;

                    /* Increment guest physical address for next mapping */
                    gbase_bank += alloc_bank->size;
                }
            }
        }

        /*
         * Record static shared memory region info for later setting
         * up shm-node in guest device tree.
         */
        ret = append_shm_bank_to_domain(kinfo, gbase, psize, shm_id);
        if ( ret )
            return ret;
    }

    return 0;
}

int __init make_shm_resv_memory_node(const struct kernel_info *kinfo,
                                     int addrcells, int sizecells)
{
    const struct membanks *mem = kernel_info_get_shm_mem_const(kinfo);
    void *fdt = kinfo->fdt;
    unsigned int i = 0;
    int res = 0;

    if ( mem->nr_banks == 0 )
        return 0;

    /*
     * For each shared memory region, a range is exposed under
     * the /reserved-memory node as a child node. Each range sub-node is
     * named xen-shmem@<address>.
     */
    dt_dprintk("Create xen-shmem node\n");

    for ( ; i < mem->nr_banks; i++ )
    {
        uint64_t start = mem->bank[i].start;
        uint64_t size = mem->bank[i].size;
        const char compat[] = "xen,shared-memory-v1";
        /* Worst case addrcells + sizecells */
        __be32 reg[GUEST_ROOT_ADDRESS_CELLS + GUEST_ROOT_SIZE_CELLS];
        __be32 *cells;
        unsigned int len = (addrcells + sizecells) * sizeof(__be32);

        res = domain_fdt_begin_node(fdt, "xen-shmem", mem->bank[i].start);
        if ( res )
            return res;

        res = fdt_property(fdt, "compatible", compat, sizeof(compat));
        if ( res )
            return res;

        cells = reg;
        dt_child_set_range(&cells, addrcells, sizecells, start, size);

        res = fdt_property(fdt, "reg", reg, len);
        if ( res )
            return res;

        dt_dprintk("Shared memory bank %u: %#"PRIx64"->%#"PRIx64"\n",
                   i, start, start + size);

        res = fdt_property_string(fdt, "xen,id",
                                  mem->bank[i].shmem_extra->shm_id);
        if ( res )
            return res;

        /*
         * TODO:
         * - xen,offset: (borrower VMs only)
         *   64 bit integer offset within the owner virtual machine's shared
         *   memory region used for the mapping in the borrower VM
         */
        res = fdt_property_u64(fdt, "xen,offset", 0);
        if ( res )
            return res;

        res = fdt_end_node(fdt);
        if ( res )
            return res;
    }

    return res;
}

int __init process_shm_node(const void *fdt, int node, uint32_t address_cells,
                            uint32_t size_cells)
{
    const struct fdt_property *prop, *prop_id, *prop_role;
    const __be32 *cell;
    paddr_t paddr = INVALID_PADDR;
    paddr_t gaddr, size, end;
    struct membanks *mem = bootinfo_get_shmem();
    struct shmem_membank_extra *shmem_extra = bootinfo_get_shmem_extra();
    unsigned int i;
    int len;
    bool owner = false;
    const char *shm_id;

    if ( address_cells < 1 || size_cells < 1 )
    {
        printk("fdt: invalid #address-cells or #size-cells for static shared memory node.\n");
        return -EINVAL;
    }

    /*
     * "xen,shm-id" property holds an arbitrary string with a strict limit
     * on the number of characters, MAX_SHM_ID_LENGTH
     */
    prop_id = fdt_get_property(fdt, node, "xen,shm-id", NULL);
    if ( !prop_id )
        return -ENOENT;
    shm_id = (const char *)prop_id->data;
    if ( strnlen(shm_id, MAX_SHM_ID_LENGTH) == MAX_SHM_ID_LENGTH )
    {
        printk("fdt: invalid xen,shm-id %s, it must be limited to %u characters\n",
               shm_id, MAX_SHM_ID_LENGTH);
        return -EINVAL;
    }

    /*
     * "role" property is optional and if it is defined explicitly,
     * it must be either `owner` or `borrower`.
     */
    prop_role = fdt_get_property(fdt, node, "role", NULL);
    if ( prop_role )
    {
        if ( !strcmp(prop_role->data, "owner") )
            owner = true;
        else if ( strcmp(prop_role->data, "borrower") )
        {
            printk("fdt: invalid `role` property for static shared memory node.\n");
            return -EINVAL;
        }
    }

    /*
     * xen,shared-mem = <paddr, gaddr, size>;
     * Memory region starting from physical address #paddr of #size shall
     * be mapped to guest physical address #gaddr as static shared memory
     * region.
     */
    prop = fdt_get_property(fdt, node, "xen,shared-mem", &len);
    if ( !prop )
        return -ENOENT;

    cell = (const __be32 *)prop->data;
    if ( len != dt_cells_to_size(address_cells + size_cells + address_cells) )
    {
        if ( len == dt_cells_to_size(address_cells + size_cells) )
            device_tree_get_reg(&cell, address_cells, size_cells, &gaddr,
                                &size);
        else
        {
            printk("fdt: invalid `xen,shared-mem` property.\n");
            return -EINVAL;
        }
    }
    else
    {
        device_tree_get_reg(&cell, address_cells, address_cells, &paddr,
                            &gaddr);
        size = dt_next_cell(size_cells, &cell);

        if ( !IS_ALIGNED(paddr, PAGE_SIZE) )
        {
            printk("fdt: physical address 0x%"PRIpaddr" is not suitably aligned.\n",
                paddr);
            return -EINVAL;
        }

        end = paddr + size;
        if ( end <= paddr )
        {
            printk("fdt: static shared memory region %s overflow\n", shm_id);
            return -EINVAL;
        }
    }

    if ( !IS_ALIGNED(gaddr, PAGE_SIZE) )
    {
        printk("fdt: guest address 0x%"PRIpaddr" is not suitably aligned.\n",
               gaddr);
        return -EINVAL;
    }

    if ( !size )
    {
        printk("fdt: the size for static shared memory region can not be zero\n");
        return -EINVAL;
    }

    if ( !IS_ALIGNED(size, PAGE_SIZE) )
    {
        printk("fdt: size 0x%"PRIpaddr" is not suitably aligned\n", size);
        return -EINVAL;
    }

    for ( i = 0; i < mem->nr_banks; i++ )
    {
        /*
         * Meet the following check:
         * - when host address is provided:
         *   1) The shm ID matches and the region exactly match
         *   2) The shm ID doesn't match and the region doesn't overlap
         *      with an existing one
         * - when host address is not provided:
         *   1) The shm ID matches and the region size exactly match
         */
        bool paddr_assigned = (INVALID_PADDR != paddr);

        if ( strncmp(shm_id, shmem_extra[i].shm_id, MAX_SHM_ID_LENGTH) == 0 )
        {
            /*
             * Regions have same shm_id (cases):
             * 1) physical host address is supplied:
             *    - OK:   paddr is equal and size is equal (same region)
             *    - Fail: paddr doesn't match or size doesn't match (there
             *            cannot exists two shmem regions with same shm_id)
             * 2) physical host address is NOT supplied:
             *    - OK:   size is equal (same region)
             *    - Fail: size is not equal (same shm_id must identify only one
             *            region, there can't be two different regions with same
             *            shm_id)
             */
            bool start_match = paddr_assigned ? (paddr == mem->bank[i].start) :
                                                true;

            if ( start_match && (size == mem->bank[i].size) )
                break;
            else
            {
                printk("fdt: different shared memory region could not share the same shm ID %s\n",
                       shm_id);
                return -EINVAL;
            }
        }

        /*
         * Regions have different shm_id (cases):
         * 1) physical host address is supplied:
         *    - OK:   paddr different, or size different (case where paddr
         *            is equal but psize is different are wrong, but they
         *            are handled later when checking for overlapping)
         *    - Fail: paddr equal and size equal (the same region can't be
         *            identified with different shm_id)
         * 2) physical host address is NOT supplied:
         *    - OK:   Both have different shm_id so even with same size they
         *            can exists
         */
        if ( !paddr_assigned || (paddr != mem->bank[i].start) ||
             (size != mem->bank[i].size) )
            continue;
        else
        {
            printk("fdt: xen,shm-id %s does not match for all the nodes using the same region\n",
                   shm_id);
            return -EINVAL;
        }
    }

    if ( i == mem->nr_banks )
    {
        if (i < mem->max_banks)
        {
            if ( (paddr != INVALID_PADDR) &&
                 check_reserved_regions_overlap(paddr, size, false) )
                return -EINVAL;

            /* Static shared memory shall be reserved from any other use. */
            safe_strcpy(shmem_extra[mem->nr_banks].shm_id, shm_id);
            mem->bank[mem->nr_banks].start = paddr;
            mem->bank[mem->nr_banks].size = size;
            mem->bank[mem->nr_banks].shmem_extra = &shmem_extra[mem->nr_banks];
            mem->nr_banks++;
        }
        else
        {
            printk("Warning: Max number of supported memory regions reached.\n");
            return -ENOSPC;
        }
    }
    /*
     * keep a count of the number of borrowers, which later may be used
     * to calculate the reference count.
     */
    if ( !owner )
        shmem_extra[i].nr_shm_borrowers++;

    return 0;
}

int __init make_resv_memory_node(const struct kernel_info *kinfo, int addrcells,
                                 int sizecells)
{
    const struct membanks *mem = kernel_info_get_shm_mem_const(kinfo);
    void *fdt = kinfo->fdt;
    int res = 0;
    /* Placeholder for reserved-memory\0 */
    const char resvbuf[16] = "reserved-memory";

    if ( mem->nr_banks == 0 )
        /* No shared memory provided. */
        return 0;

    dt_dprintk("Create reserved-memory node\n");

    res = fdt_begin_node(fdt, resvbuf);
    if ( res )
        return res;

    res = fdt_property(fdt, "ranges", NULL, 0);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#address-cells", addrcells);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#size-cells", sizecells);
    if ( res )
        return res;

    res = make_shm_resv_memory_node(kinfo, addrcells, sizecells);
    if ( res )
        return res;

    res = fdt_end_node(fdt);

    return res;
}

void __init early_print_info_shmem(void)
{
    const struct membanks *shmem = bootinfo_get_shmem();
    unsigned int bank;
    unsigned int printed = 0;

    for ( bank = 0; bank < shmem->nr_banks; bank++, printed++ )
        if ( shmem->bank[bank].start != INVALID_PADDR )
            printk(" SHMEM[%u]: %"PRIpaddr" - %"PRIpaddr"\n", printed,
                shmem->bank[bank].start,
                shmem->bank[bank].start + shmem->bank[bank].size - 1);
}

void __init init_sharedmem_pages(void)
{
    const struct membanks *shmem = bootinfo_get_shmem();
    unsigned int bank;

    for ( bank = 0 ; bank < shmem->nr_banks; bank++ )
        if ( shmem->bank[bank].start != INVALID_PADDR )
            init_staticmem_bank(&shmem->bank[bank]);
}

int __init remove_shm_from_rangeset(const struct kernel_info *kinfo,
                                    struct rangeset *rangeset)
{
    const struct membanks *shm_mem = kernel_info_get_shm_mem_const(kinfo);
    unsigned int i;

    /* Remove static shared memory regions */
    for ( i = 0; i < shm_mem->nr_banks; i++ )
    {
        paddr_t start, end;
        int res;

        start = shm_mem->bank[i].start;
        end = shm_mem->bank[i].start + shm_mem->bank[i].size;
        res = rangeset_remove_range(rangeset, PFN_DOWN(start),
                                    PFN_DOWN(end - 1));
        if ( res )
        {
            printk(XENLOG_ERR
                   "Failed to remove: %#"PRIpaddr"->%#"PRIpaddr", error: %d\n",
                   start, end, res);
            return -EINVAL;
        }
    }

    return 0;
}

int __init remove_shm_holes_for_domU(const struct kernel_info *kinfo,
                                     struct membanks *ext_regions)
{
    const struct membanks *shm_mem = kernel_info_get_shm_mem_const(kinfo);
    struct rangeset *guest_holes;
    unsigned int i;
    paddr_t start;
    paddr_t end;
    int res;

    /* No static shared memory region. */
    if ( shm_mem->nr_banks == 0 )
        return 0;

    dt_dprintk("Remove static shared memory holes from extended regions of DomU\n");

    guest_holes = rangeset_new(NULL, NULL, 0);
    if ( !guest_holes )
        return -ENOMEM;

    /* Copy extended regions sets into the rangeset */
    for ( i = 0; i < ext_regions->nr_banks; i++ )
    {
        start = ext_regions->bank[i].start;
        end = start + ext_regions->bank[i].size;

        res = rangeset_add_range(guest_holes, PFN_DOWN(start),
                                 PFN_DOWN(end - 1));
        if ( res )
        {
            printk(XENLOG_ERR
                   "Failed to add: %#"PRIpaddr"->%#"PRIpaddr", error: %d\n",
                   start, end, res);
            goto out;
        }
    }

    /* Remove static shared memory regions */
    res = remove_shm_from_rangeset(kinfo, guest_holes);
    if ( res )
        goto out;

    /*
     * Take the interval of memory starting from the first extended region bank
     * start address and ending to the end of the last extended region bank.
     */
    i = ext_regions->nr_banks - 1;
    start = ext_regions->bank[0].start;
    end = ext_regions->bank[i].start + ext_regions->bank[i].size - 1;

    /* Reset original extended regions to hold new value */
    ext_regions->nr_banks = 0;
    res = rangeset_report_ranges(guest_holes, PFN_DOWN(start), PFN_DOWN(end),
                                 add_ext_regions, ext_regions);
    if ( res )
        ext_regions->nr_banks = 0;
    else if ( !ext_regions->nr_banks )
        res = -ENOENT;

 out:
    rangeset_destroy(guest_holes);

    return res;
}

void __init shm_mem_node_fill_reg_range(const struct kernel_info *kinfo,
                                        __be32 *reg, int *nr_cells,
                                        int addrcells, int sizecells)
{
    const struct membanks *mem = kernel_info_get_shm_mem_const(kinfo);
    unsigned int i;
    __be32 *cells;

    BUG_ON(!nr_cells || !reg);

    cells = &reg[*nr_cells];
    for ( i = 0; i < mem->nr_banks; i++ )
    {
        paddr_t start = mem->bank[i].start;
        paddr_t size = mem->bank[i].size;

        *nr_cells += addrcells + sizecells;
        BUG_ON(*nr_cells >= DT_MEM_NODE_REG_RANGE_SIZE);
        dt_child_set_range(&cells, addrcells, sizecells, start, size);
    }
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
