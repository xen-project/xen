/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/libfdt/libfdt.h>
#include <xen/sched.h>

#include <asm/domain_build.h>
#include <asm/static-shmem.h>

static int __init acquire_nr_borrower_domain(struct domain *d,
                                             paddr_t pbase, paddr_t psize,
                                             unsigned long *nr_borrowers)
{
    unsigned int bank;

    /* Iterate reserved memory to find requested shm bank. */
    for ( bank = 0 ; bank < bootinfo.reserved_mem.nr_banks; bank++ )
    {
        paddr_t bank_start = bootinfo.reserved_mem.bank[bank].start;
        paddr_t bank_size = bootinfo.reserved_mem.bank[bank].size;

        if ( (pbase == bank_start) && (psize == bank_size) )
            break;
    }

    if ( bank == bootinfo.reserved_mem.nr_banks )
        return -ENOENT;

    *nr_borrowers = bootinfo.reserved_mem.bank[bank].nr_shm_borrowers;

    return 0;
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
                                               paddr_t pbase, paddr_t psize)
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
    res = acquire_domstatic_pages(d, smfn, nr_pfns, 0);
    if ( res )
    {
        printk(XENLOG_ERR
               "%pd: failed to acquire static memory: %d.\n", d, res);
        d->max_pages -= nr_pfns;
        return INVALID_MFN;
    }

    return smfn;
}

static int __init assign_shared_memory(struct domain *d,
                                       uint32_t addr_cells, uint32_t size_cells,
                                       paddr_t pbase, paddr_t psize,
                                       paddr_t gbase)
{
    mfn_t smfn;
    int ret = 0;
    unsigned long nr_pages, nr_borrowers, i;
    struct page_info *page;

    printk("%pd: allocate static shared memory BANK %#"PRIpaddr"-%#"PRIpaddr".\n",
           d, pbase, pbase + psize);

    smfn = acquire_shared_memory_bank(d, pbase, psize);
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
     * Get the right amount of references per page, which is the number of
     * borrower domains.
     */
    ret = acquire_nr_borrower_domain(d, pbase, psize, &nr_borrowers);
    if ( ret )
        return ret;

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

static int __init append_shm_bank_to_domain(struct kernel_info *kinfo,
                                            paddr_t start, paddr_t size,
                                            const char *shm_id)
{
    if ( kinfo->shm_mem.nr_banks >= NR_MEM_BANKS )
        return -ENOMEM;

    kinfo->shm_mem.bank[kinfo->shm_mem.nr_banks].start = start;
    kinfo->shm_mem.bank[kinfo->shm_mem.nr_banks].size = size;
    safe_strcpy(kinfo->shm_mem.bank[kinfo->shm_mem.nr_banks].shm_id, shm_id);
    kinfo->shm_mem.nr_banks++;

    return 0;
}

int __init process_shm(struct domain *d, struct kernel_info *kinfo,
                       const struct dt_device_node *node)
{
    struct dt_device_node *shm_node;

    dt_for_each_child_node(node, shm_node)
    {
        const struct dt_property *prop;
        const __be32 *cells;
        uint32_t addr_cells, size_cells;
        paddr_t gbase, pbase, psize;
        int ret = 0;
        unsigned int i;
        const char *role_str;
        const char *shm_id;
        bool owner_dom_io = true;

        if ( !dt_device_is_compatible(shm_node, "xen,domain-shared-memory-v1") )
            continue;

        /*
         * xen,shared-mem = <pbase, gbase, size>;
         * TODO: pbase is optional.
         */
        addr_cells = dt_n_addr_cells(shm_node);
        size_cells = dt_n_size_cells(shm_node);
        prop = dt_find_property(shm_node, "xen,shared-mem", NULL);
        BUG_ON(!prop);
        cells = (const __be32 *)prop->value;
        device_tree_get_reg(&cells, addr_cells, addr_cells, &pbase, &gbase);
        psize = dt_read_paddr(cells, size_cells);
        if ( !IS_ALIGNED(pbase, PAGE_SIZE) || !IS_ALIGNED(gbase, PAGE_SIZE) )
        {
            printk("%pd: physical address 0x%"PRIpaddr", or guest address 0x%"PRIpaddr" is not suitably aligned.\n",
                   d, pbase, gbase);
            return -EINVAL;
        }
        if ( !IS_ALIGNED(psize, PAGE_SIZE) )
        {
            printk("%pd: size 0x%"PRIpaddr" is not suitably aligned\n",
                   d, psize);
            return -EINVAL;
        }

        for ( i = 0; i < PFN_DOWN(psize); i++ )
            if ( !mfn_valid(mfn_add(maddr_to_mfn(pbase), i)) )
            {
                printk("%pd: invalid physical address 0x%"PRI_mfn"\n",
                       d, mfn_x(mfn_add(maddr_to_mfn(pbase), i)));
                return -EINVAL;
            }

        /*
         * "role" property is optional and if it is defined explicitly,
         * then the owner domain is not the default "dom_io" domain.
         */
        if ( dt_property_read_string(shm_node, "role", &role_str) == 0 )
            owner_dom_io = false;

        if ( dt_property_read_string(shm_node, "xen,shm-id", &shm_id) )
        {
            printk("%pd: invalid \"xen,shm-id\" property", d);
            return -EINVAL;
        }
        BUG_ON((strlen(shm_id) <= 0) || (strlen(shm_id) >= MAX_SHM_ID_LENGTH));

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
            ret = assign_shared_memory(owner_dom_io ? dom_io : d,
                                       addr_cells, size_cells,
                                       pbase, psize, gbase);
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

static int __init make_shm_memory_node(const struct domain *d, void *fdt,
                                       int addrcells, int sizecells,
                                       const struct meminfo *mem)
{
    unsigned int i = 0;
    int res = 0;

    if ( mem->nr_banks == 0 )
        return -ENOENT;

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

        res = fdt_property_string(fdt, "xen,id", mem->bank[i].shm_id);
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
    paddr_t paddr, gaddr, size;
    struct meminfo *mem = &bootinfo.reserved_mem;
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

    if ( len != dt_cells_to_size(address_cells + size_cells + address_cells) )
    {
        if ( len == dt_cells_to_size(size_cells + address_cells) )
            printk("fdt: host physical address must be chosen by users at the moment.\n");

        printk("fdt: invalid `xen,shared-mem` property.\n");
        return -EINVAL;
    }

    cell = (const __be32 *)prop->data;
    device_tree_get_reg(&cell, address_cells, address_cells, &paddr, &gaddr);
    size = dt_next_cell(size_cells, &cell);

    if ( !size )
    {
        printk("fdt: the size for static shared memory region can not be zero\n");
        return -EINVAL;
    }

    for ( i = 0; i < mem->nr_banks; i++ )
    {
        /*
         * Meet the following check:
         * 1) The shm ID matches and the region exactly match
         * 2) The shm ID doesn't match and the region doesn't overlap
         * with an existing one
         */
        if ( paddr == mem->bank[i].start && size == mem->bank[i].size )
        {
            if ( strncmp(shm_id, mem->bank[i].shm_id, MAX_SHM_ID_LENGTH) == 0 )
                break;
            else
            {
                printk("fdt: xen,shm-id %s does not match for all the nodes using the same region.\n",
                       shm_id);
                return -EINVAL;
            }
        }
        else
        {
            paddr_t end = paddr + size;
            paddr_t bank_end = mem->bank[i].start + mem->bank[i].size;

            if ( (end <= paddr) || (bank_end <= mem->bank[i].start) )
            {
                printk("fdt: static shared memory region %s overflow\n", shm_id);
                return -EINVAL;
            }

            if ( check_reserved_regions_overlap(paddr, size) )
                return -EINVAL;
            else
            {
                if ( strcmp(shm_id, mem->bank[i].shm_id) != 0 )
                    continue;
                else
                {
                    printk("fdt: different shared memory region could not share the same shm ID %s\n",
                           shm_id);
                    return -EINVAL;
                }
            }
        }
    }

    if ( i == mem->nr_banks )
    {
        if ( i < NR_MEM_BANKS )
        {
            /* Static shared memory shall be reserved from any other use. */
            safe_strcpy(mem->bank[mem->nr_banks].shm_id, shm_id);
            mem->bank[mem->nr_banks].start = paddr;
            mem->bank[mem->nr_banks].size = size;
            mem->bank[mem->nr_banks].type = MEMBANK_STATIC_DOMAIN;
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
        mem->bank[i].nr_shm_borrowers++;

    return 0;
}

int __init make_resv_memory_node(const struct domain *d, void *fdt,
                                 int addrcells, int sizecells,
                                 const struct meminfo *mem)
{
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

    res = make_shm_memory_node(d, fdt, addrcells, sizecells, mem);
    if ( res )
        return res;

    res = fdt_end_node(fdt);

    return res;
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
