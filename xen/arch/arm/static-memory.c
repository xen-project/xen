/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/sched.h>

#include <asm/static-memory.h>

static bool __init append_static_memory_to_bank(struct domain *d,
                                                struct membank *bank,
                                                mfn_t smfn,
                                                paddr_t size)
{
    int res;
    unsigned int nr_pages = PFN_DOWN(size);
    gfn_t sgfn;

    /*
     * For direct-mapped domain, the GFN match the MFN.
     * Otherwise, this is inferred on what has already been allocated
     * in the bank.
     */
    if ( !is_domain_direct_mapped(d) )
        sgfn = gaddr_to_gfn(bank->start + bank->size);
    else
        sgfn = gaddr_to_gfn(mfn_to_maddr(smfn));

    res = guest_physmap_add_pages(d, sgfn, smfn, nr_pages);
    if ( res )
    {
        dprintk(XENLOG_ERR, "Failed to map pages to DOMU: %d", res);
        return false;
    }

    bank->size = bank->size + size;

    return true;
}

static mfn_t __init acquire_static_memory_bank(struct domain *d,
                                               const __be32 **cell,
                                               u32 addr_cells, u32 size_cells,
                                               paddr_t *pbase, paddr_t *psize)
{
    mfn_t smfn;
    int res;

    device_tree_get_reg(cell, addr_cells, size_cells, pbase, psize);
    ASSERT(IS_ALIGNED(*pbase, PAGE_SIZE) && IS_ALIGNED(*psize, PAGE_SIZE));
    if ( PFN_DOWN(*psize) > UINT_MAX )
    {
        printk(XENLOG_ERR "%pd: static memory size too large: %#"PRIpaddr,
               d, *psize);
        return INVALID_MFN;
    }

    smfn = maddr_to_mfn(*pbase);
    res = acquire_domstatic_pages(d, smfn, PFN_DOWN(*psize), 0);
    if ( res )
    {
        printk(XENLOG_ERR
               "%pd: failed to acquire static memory: %d.\n", d, res);
        return INVALID_MFN;
    }

    return smfn;
}

static int __init parse_static_mem_prop(const struct dt_device_node *node,
                                        u32 *addr_cells, u32 *size_cells,
                                        int *length, const __be32 **cell)
{
    const struct dt_property *prop;

    prop = dt_find_property(node, "xen,static-mem", NULL);

    *addr_cells = dt_n_addr_cells(node);
    *size_cells = dt_n_size_cells(node);

    *cell = (const __be32 *)prop->value;
    *length = prop->length;

    return 0;
}

/* Allocate memory from static memory as RAM for one specific domain d. */
void __init allocate_static_memory(struct domain *d, struct kernel_info *kinfo,
                                   const struct dt_device_node *node)
{
    struct membanks *mem = kernel_info_get_mem(kinfo);
    u32 addr_cells, size_cells, reg_cells;
    unsigned int nr_banks, gbank, bank = 0;
    const uint64_t rambase[] = GUEST_RAM_BANK_BASES;
    const uint64_t ramsize[] = GUEST_RAM_BANK_SIZES;
    const __be32 *cell;
    u64 tot_size = 0;
    paddr_t pbase, psize, gsize;
    mfn_t smfn;
    int length;

    if ( parse_static_mem_prop(node, &addr_cells, &size_cells, &length, &cell) )
        goto fail;
    reg_cells = addr_cells + size_cells;

    /*
     * The static memory will be mapped in the guest at the usual guest memory
     * addresses (GUEST_RAM0_BASE, GUEST_RAM1_BASE) defined by
     * xen/include/public/arch-arm.h.
     */
    gbank = 0;
    gsize = ramsize[gbank];
    mem->bank[gbank].start = rambase[gbank];
    nr_banks = length / (reg_cells * sizeof (u32));

    for ( ; bank < nr_banks; bank++ )
    {
        smfn = acquire_static_memory_bank(d, &cell, addr_cells, size_cells,
                                          &pbase, &psize);
        if ( mfn_eq(smfn, INVALID_MFN) )
            goto fail;

        printk(XENLOG_INFO "%pd: STATIC BANK[%u] %#"PRIpaddr"-%#"PRIpaddr"\n",
               d, bank, pbase, pbase + psize);

        while ( 1 )
        {
            /* Map as much as possible the static range to the guest bank */
            if ( !append_static_memory_to_bank(d, &mem->bank[gbank], smfn,
                                               min(psize, gsize)) )
                goto fail;

            /*
             * The current physical bank is fully mapped.
             * Handle the next physical bank.
             */
            if ( gsize >= psize )
            {
                gsize = gsize - psize;
                break;
            }
            /*
             * When current guest bank is not enough to map, exhaust
             * the current one and seek to the next.
             * Before seeking to the next, check if we still have available
             * guest bank.
             */
            else if ( (gbank + 1) >= GUEST_RAM_BANKS )
            {
                printk(XENLOG_ERR "Exhausted all possible guest banks.\n");
                goto fail;
            }
            else
            {
                psize = psize - gsize;
                smfn = mfn_add(smfn, gsize >> PAGE_SHIFT);
                /* Update to the next guest bank. */
                gbank++;
                gsize = ramsize[gbank];
                mem->bank[gbank].start = rambase[gbank];
            }
        }

        tot_size += psize;
    }

    mem->nr_banks = ++gbank;

    kinfo->unassigned_mem -= tot_size;
    /*
     * The property 'memory' should match the amount of memory given to the
     * guest.
     * Currently, it is only possible to either acquire static memory or let
     * Xen allocate. *Mixing* is not supported.
     */
    if ( kinfo->unassigned_mem )
    {
        printk(XENLOG_ERR
               "Size of \"memory\" property doesn't match up with the sum-up of \"xen,static-mem\". Unsupported configuration.\n");
        goto fail;
    }

    return;

 fail:
    panic("Failed to allocate requested static memory for domain %pd.\n", d);
}

/*
 * Allocate static memory as RAM for one specific domain d.
 * The static memory will be directly mapped in the guest(Guest Physical
 * Address == Physical Address).
 */
void __init assign_static_memory_11(struct domain *d, struct kernel_info *kinfo,
                                    const struct dt_device_node *node)
{
    struct membanks *mem = kernel_info_get_mem(kinfo);
    u32 addr_cells, size_cells, reg_cells;
    unsigned int nr_banks, bank = 0;
    const __be32 *cell;
    paddr_t pbase, psize;
    mfn_t smfn;
    int length;

    if ( parse_static_mem_prop(node, &addr_cells, &size_cells, &length, &cell) )
    {
        printk(XENLOG_ERR
               "%pd: failed to parse \"xen,static-mem\" property.\n", d);
        goto fail;
    }
    reg_cells = addr_cells + size_cells;
    nr_banks = length / (reg_cells * sizeof(u32));

    if ( nr_banks > mem->max_banks )
    {
        printk(XENLOG_ERR
               "%pd: exceed max number of supported guest memory banks.\n", d);
        goto fail;
    }

    for ( ; bank < nr_banks; bank++ )
    {
        smfn = acquire_static_memory_bank(d, &cell, addr_cells, size_cells,
                                          &pbase, &psize);
        if ( mfn_eq(smfn, INVALID_MFN) )
            goto fail;

        printk(XENLOG_INFO "%pd: STATIC BANK[%u] %#"PRIpaddr"-%#"PRIpaddr"\n",
               d, bank, pbase, pbase + psize);

        /* One guest memory bank is matched with one physical memory bank. */
        mem->bank[bank].start = pbase;
        if ( !append_static_memory_to_bank(d, &mem->bank[bank],
                                           smfn, psize) )
            goto fail;

        kinfo->unassigned_mem -= psize;
    }

    mem->nr_banks = nr_banks;

    /*
     * The property 'memory' should match the amount of memory given to
     * the guest.
     * Currently, it is only possible to either acquire static memory or
     * let Xen allocate. *Mixing* is not supported.
     */
    if ( kinfo->unassigned_mem != 0 )
    {
        printk(XENLOG_ERR
               "Size of \"memory\" property doesn't match up with the sum-up of \"xen,static-mem\".\n");
        goto fail;
    }

    return;

 fail:
    panic("Failed to assign requested static memory for direct-map domain %pd.\n",
          d);
}

/* Static memory initialization */
void __init init_staticmem_pages(void)
{
    const struct membanks *reserved_mem = bootinfo_get_reserved_mem();
    unsigned int bank;

    for ( bank = 0 ; bank < reserved_mem->nr_banks; bank++ )
    {
        if ( reserved_mem->bank[bank].type == MEMBANK_STATIC_DOMAIN )
            init_staticmem_bank(&reserved_mem->bank[bank]);
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
