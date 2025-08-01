/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * hvm/dom0_build.c
 *
 * Dom0 builder for PVH guest.
 *
 * Copyright (C) 2017 Citrix Systems R&D
 */

#include <xen/acpi.h>
#include <xen/init.h>
#include <xen/libelf.h>
#include <xen/multiboot.h>
#include <xen/pci.h>
#include <xen/softirq.h>

#include <acpi/actables.h>

#include <asm/bootinfo.h>
#include <asm/bzimage.h>
#include <asm/dom0_build.h>
#include <asm/hvm/support.h>
#include <asm/io_apic.h>
#include <asm/p2m.h>
#include <asm/paging.h>
#include <asm/setup.h>

#include <public/arch-x86/hvm/start_info.h>
#include <public/hvm/hvm_info_table.h>
#include <public/hvm/hvm_vcpu.h>
#include <public/hvm/params.h>

/*
 * Have the TSS cover the ISA port range, which makes it
 * - 104 bytes base structure
 * - 32 bytes interrupt redirection bitmap
 * - 128 bytes I/O bitmap
 * - one trailing byte
 * or a total of 265 bytes.
 *
 * NB: as PVHv2 Dom0 doesn't have legacy devices (ISA), it shouldn't have any
 * business in accessing the ISA port range, much less in real mode, and due to
 * the lack of firmware it shouldn't also execute any INT instruction. This is
 * done just for consistency with what hvmloader does.
 */
#define HVM_VM86_TSS_SIZE 265

static unsigned int __initdata acpi_intr_overrides;
static struct acpi_madt_interrupt_override __initdata *intsrcovr;

static unsigned int __initdata order_stats[MAX_ORDER + 1];

static void __init print_order_stats(const struct domain *d)
{
    unsigned int i;

    printk("Dom%u memory allocation stats:\n", d->domain_id);
    for ( i = 0; i < ARRAY_SIZE(order_stats); i++ )
        if ( order_stats[i] )
            printk("order %2u allocations: %u\n", i, order_stats[i]);
}

static int __init modify_identity_mmio(struct domain *d, unsigned long pfn,
                                       unsigned long nr_pages, const bool map)
{
    int rc;

    for ( ; ; )
    {
        rc = map ?   map_mmio_regions(d, _gfn(pfn), nr_pages, _mfn(pfn))
                 : unmap_mmio_regions(d, _gfn(pfn), nr_pages, _mfn(pfn));
        if ( rc == 0 )
            break;
        if ( rc < 0 )
        {
            printk(XENLOG_WARNING
                   "Failed to identity %smap [%#lx,%#lx) for d%d: %d\n",
                   map ? "" : "un", pfn, pfn + nr_pages, d->domain_id, rc);
            break;
        }
        nr_pages -= rc;
        pfn += rc;
        process_pending_softirqs();
    }

    return rc;
}

/* Populate a HVM memory range using the biggest possible order. */
static int __init pvh_populate_memory_range(struct domain *d,
                                            unsigned long start,
                                            unsigned long nr_pages)
{
    static const struct {
        unsigned long align;
        unsigned int order;
    } orders[] __initconst = {
        /* NB: must be sorted by decreasing size. */
        { .align = PFN_DOWN(GB(1)), .order = PAGE_ORDER_1G },
        { .align = PFN_DOWN(MB(2)), .order = PAGE_ORDER_2M },
        { .align = PFN_DOWN(KB(4)), .order = PAGE_ORDER_4K },
    };
    unsigned int max_order = MAX_ORDER;
    struct page_info *page;
    int rc;

    while ( nr_pages != 0 )
    {
        unsigned int order, j;
        unsigned long end;

        /* Search for the largest page size which can fulfil this request. */
        for ( j = 0; j < ARRAY_SIZE(orders); j++ )
            if ( IS_ALIGNED(start, orders[j].align) &&
                 nr_pages >= (1UL << orders[j].order) )
                break;

        switch ( j )
        {
        case ARRAY_SIZE(orders):
            printk("Unable to find allocation order for [%#lx,%#lx)\n",
                   start, start + nr_pages);
            return -EINVAL;

        case 0:
            /* Highest order, aim to allocate until the end of the region. */
            end = (start + nr_pages) & ~(orders[0].align - 1);
            break;

        default:
            /*
             * Aim to allocate until the higher next order alignment or the
             * end of the region.
             */
            end = min(ROUNDUP(start + 1, orders[j - 1].align),
                      start + nr_pages);
            break;
        }

        order = get_order_from_pages(end - start + 1);
        order = min(order ? order - 1 : 0, max_order);
        /* The order allocated and populated must be aligned to the address. */
        order = min(order, start ? ffsl(start) - 1U : MAX_ORDER + 0U);
        page = alloc_domheap_pages(d, order, dom0_memflags | MEMF_no_scrub);
        if ( page == NULL )
        {
            if ( order == 0 && dom0_memflags )
            {
                /* Try again without any dom0_memflags. */
                dom0_memflags = 0;
                max_order = MAX_ORDER;
                continue;
            }
            if ( order == 0 )
            {
                printk("Unable to allocate memory with order 0!\n");
                return -ENOMEM;
            }
            max_order = order - 1;
            continue;
        }

        rc = p2m_add_page(d, _gfn(start), page_to_mfn(page), order, p2m_ram_rw);
        if ( rc != 0 )
        {
            printk("Failed to populate memory: [%#lx,%#lx): %d\n",
                   start, start + (1UL << order), rc);
            return rc;
        }
        start += 1UL << order;
        nr_pages -= 1UL << order;
        order_stats[order]++;
        /*
         * Process pending softirqs on every successful loop: it's unknown
         * whether the p2m/IOMMU code will have split the page into multiple
         * smaller entries, and thus the time consumed would be much higher
         * than populating a single entry.
         */
        process_pending_softirqs();
    }

    return 0;
}

/* Steal RAM from the end of a memory region. */
static int __init pvh_steal_ram(struct domain *d, unsigned long size,
                                unsigned long align, paddr_t limit,
                                paddr_t *addr)
{
    unsigned int i = d->arch.nr_e820;

    /*
     * Alignment 0 should be set to 1, so it doesn't wrap around in the
     * calculations below.
     */
    align = align ? : 1;
    while ( i-- )
    {
        struct e820entry *entry = &d->arch.e820[i];

        if ( entry->type != E820_RAM || entry->addr + entry->size > limit )
            continue;

        *addr = (entry->addr + entry->size - size) & ~(align - 1);
        if ( *addr < entry->addr ||
             /* Don't steal from the low 1MB due to the copying done there. */
             *addr < MB(1) )
            continue;

        entry->size = *addr - entry->addr;
        return 0;
    }

    return -ENOMEM;
}

/* NB: memory map must be sorted at all times for this to work correctly. */
static int __init pvh_add_mem_range(struct domain *d, uint64_t s, uint64_t e,
                                    unsigned int type)
{
    struct e820entry *map;
    unsigned int i;

    for ( i = 0; i < d->arch.nr_e820; i++ )
    {
        uint64_t rs = d->arch.e820[i].addr;
        uint64_t re = rs + d->arch.e820[i].size;

        if ( rs == e && d->arch.e820[i].type == type )
        {
            d->arch.e820[i].addr = s;
            return 0;
        }

        if ( re == s && d->arch.e820[i].type == type &&
             (i + 1 == d->arch.nr_e820 || d->arch.e820[i + 1].addr >= e) )
        {
            d->arch.e820[i].size += e - s;
            return 0;
        }

        if ( rs >= e )
            break;

        if ( re > s )
            return -EEXIST;
    }

    map = xzalloc_array(struct e820entry, d->arch.nr_e820 + 1);
    if ( !map )
    {
        printk(XENLOG_WARNING "E820: out of memory to add region\n");
        return -ENOMEM;
    }

    memcpy(map, d->arch.e820, i * sizeof(*d->arch.e820));
    memcpy(map + i + 1, d->arch.e820 + i,
           (d->arch.nr_e820 - i) * sizeof(*d->arch.e820));
    map[i].addr = s;
    map[i].size = e - s;
    map[i].type = type;
    xfree(d->arch.e820);
    d->arch.e820 = map;
    d->arch.nr_e820++;

    return 0;
}

static int __init pvh_setup_vmx_realmode_helpers(struct domain *d)
{
    uint32_t rc, *ident_pt;
    mfn_t mfn;
    paddr_t gaddr;
    struct vcpu *v = d->vcpu[0];

    /*
     * Steal some space from the last RAM region below 4GB and use it to
     * store the real-mode TSS. It needs to be aligned to 128 so that the
     * TSS structure (which accounts for the first 104b) doesn't cross
     * a page boundary.
     */
    if ( !pvh_steal_ram(d, HVM_VM86_TSS_SIZE, 128, GB(4), &gaddr) )
    {
        if ( hvm_copy_to_guest_phys(gaddr, NULL, HVM_VM86_TSS_SIZE, v) !=
             HVMTRANS_okay )
            printk("Unable to zero VM86 TSS area\n");
        d->arch.hvm.params[HVM_PARAM_VM86_TSS_SIZED] =
            VM86_TSS_UPDATED | ((uint64_t)HVM_VM86_TSS_SIZE << 32) | gaddr;
        if ( pvh_add_mem_range(d, gaddr, gaddr + HVM_VM86_TSS_SIZE,
                               E820_RESERVED) )
            printk("Unable to set VM86 TSS as reserved in the memory map\n");
    }
    else
        printk("Unable to allocate VM86 TSS area\n");

    /* Steal some more RAM for the identity page tables. */
    if ( pvh_steal_ram(d, PAGE_SIZE, PAGE_SIZE, GB(4), &gaddr) )
    {
        printk("Unable to find memory to stash the identity page tables\n");
        return -ENOMEM;
    }

    /*
     * Identity-map page table is required for running with CR0.PG=0
     * when using Intel EPT. Create a 32-bit non-PAE page directory of
     * superpages.
     */
    ident_pt = map_domain_gfn(p2m_get_hostp2m(d), _gfn(PFN_DOWN(gaddr)),
                              &mfn, 0, &rc);
    if ( ident_pt == NULL )
    {
        printk("Unable to map identity page tables\n");
        return -ENOMEM;
    }
    write_32bit_pse_identmap(ident_pt);
    unmap_domain_page(ident_pt);
    put_page(mfn_to_page(mfn));
    d->arch.hvm.params[HVM_PARAM_IDENT_PT] = gaddr;
    if ( pvh_add_mem_range(d, gaddr, gaddr + PAGE_SIZE, E820_RESERVED) )
            printk("Unable to set identity page tables as reserved in the memory map\n");

    return 0;
}

static __init void pvh_setup_e820(struct domain *d, unsigned long nr_pages)
{
    struct e820entry *entry, *entry_guest;
    unsigned int i;
    unsigned long pages, cur_pages = 0;
    uint64_t start, end;

    /*
     * Craft the e820 memory map for Dom0 based on the hardware e820 map.
     * Add an extra entry in case we have to split a RAM entry into a RAM and a
     * UNUSABLE one in order to truncate it.
     */
    d->arch.e820 = xzalloc_array(struct e820entry, e820.nr_map + 1);
    if ( !d->arch.e820 )
        panic("Unable to allocate memory for Dom0 e820 map\n");
    entry_guest = d->arch.e820;

    /* Clamp e820 memory map to match the memory assigned to Dom0 */
    for ( i = 0, entry = e820.map; i < e820.nr_map; i++, entry++ )
    {
        *entry_guest = *entry;

        if ( entry->type != E820_RAM )
            goto next;

        if ( nr_pages == cur_pages )
        {
            /*
             * We already have all the requested memory, turn this RAM region
             * into a UNUSABLE region in order to prevent Dom0 from placing
             * BARs in this area.
             */
            entry_guest->type = E820_UNUSABLE;
            goto next;
        }

        /*
         * Make sure the start and length are aligned to PAGE_SIZE, because
         * that's the minimum granularity of the 2nd stage translation. Since
         * the p2m code uses PAGE_ORDER_4K internally, also use it here in
         * order to prevent this code from getting out of sync.
         */
        start = ROUNDUP(entry->addr, PAGE_SIZE << PAGE_ORDER_4K);
        end = (entry->addr + entry->size) &
              ~((PAGE_SIZE << PAGE_ORDER_4K) - 1);
        if ( start >= end )
            continue;

        entry_guest->type = E820_RAM;
        entry_guest->addr = start;
        entry_guest->size = end - start;
        pages = PFN_DOWN(entry_guest->size);
        if ( (cur_pages + pages) > nr_pages )
        {
            /* Truncate region */
            entry_guest->size = (nr_pages - cur_pages) << PAGE_SHIFT;
            /* Add the remaining of the RAM region as UNUSABLE. */
            entry_guest++;
            d->arch.nr_e820++;
            entry_guest->type = E820_UNUSABLE;
            entry_guest->addr = start + ((nr_pages - cur_pages) << PAGE_SHIFT);
            entry_guest->size = end - entry_guest->addr;
            cur_pages = nr_pages;
        }
        else
        {
            cur_pages += pages;
        }
 next:
        d->arch.nr_e820++;
        entry_guest++;
        ASSERT(d->arch.nr_e820 <= e820.nr_map + 1);
    }
    ASSERT(cur_pages == nr_pages);
}

static void __init pvh_init_p2m(struct domain *d)
{
    unsigned long nr_pages = dom0_compute_nr_pages(d, NULL, 0);
    bool preempted;

    pvh_setup_e820(d, nr_pages);
    do {
        preempted = false;
        paging_set_allocation(d, dom0_paging_pages(d, nr_pages),
                              &preempted);
        process_pending_softirqs();
    } while ( preempted );
}

static int __init pvh_populate_p2m(struct domain *d)
{
    struct vcpu *v = d->vcpu[0];
    unsigned int i;
    int rc;
#define MB1_PAGES PFN_DOWN(MB(1))

    /* Populate memory map. */
    for ( i = 0; i < d->arch.nr_e820; i++ )
    {
        unsigned long addr, size;

        if ( d->arch.e820[i].type != E820_RAM )
            continue;

        addr = PFN_DOWN(d->arch.e820[i].addr);
        size = PFN_DOWN(d->arch.e820[i].size);

        rc = pvh_populate_memory_range(d, addr, size);
        if ( rc )
            return rc;

        if ( addr < MB1_PAGES )
        {
            uint64_t end = min_t(uint64_t, MB(1),
                                 d->arch.e820[i].addr + d->arch.e820[i].size);
            enum hvm_translation_result res =
                 hvm_copy_to_guest_phys(mfn_to_maddr(_mfn(addr)),
                                        mfn_to_virt(addr),
                                        end - d->arch.e820[i].addr,
                                        v);

            if ( res != HVMTRANS_okay )
                printk("Failed to copy [%#lx, %#lx): %d\n",
                       addr, addr + size, res);
        }
    }

    /* Identity map everything below 1MB that's not already mapped. */
    for ( i = rc = 0; i < MB1_PAGES; ++i )
    {
        p2m_type_t p2mt;
        mfn_t mfn = get_gfn_query(d, i, &p2mt);

        if ( mfn_eq(mfn, INVALID_MFN) )
            rc = set_mmio_p2m_entry(d, _gfn(i), _mfn(i), PAGE_ORDER_4K);
        else
            /*
             * If the p2m entry is already set it must belong to a reserved
             * region (e.g. RMRR/IVMD) and be identity mapped, or else be a
             * RAM region.
             */
            ASSERT(p2mt == p2m_ram_rw || mfn_eq(mfn, _mfn(i)));
        put_gfn(d, i);
        if ( rc )
        {
            printk("Failed to identity map PFN %x: %d\n", i, rc);
            return rc;
        }
    }

    if ( cpu_has_vmx && paging_mode_hap(d) && !vmx_unrestricted_guest(v) )
    {
        /*
         * Since Dom0 cannot be migrated, we will only setup the
         * unrestricted guest helpers if they are needed by the current
         * hardware we are running on.
         */
        rc = pvh_setup_vmx_realmode_helpers(d);
        if ( rc )
            return rc;
    }

    if ( opt_dom0_verbose )
        print_order_stats(d);

    return 0;
#undef MB1_PAGES
}

static paddr_t __init find_memory(
    const struct domain *d, const struct elf_binary *elf, size_t size)
{
    paddr_t kernel_start = (paddr_t)elf->dest_base & PAGE_MASK;
    paddr_t kernel_end = ROUNDUP((paddr_t)elf->dest_base + elf->dest_size,
                                 PAGE_SIZE);
    unsigned int i;

    /*
     * The memory map is sorted and all RAM regions starts and sizes are
     * aligned to page boundaries.
     */
    for ( i = 0; i < d->arch.nr_e820; i++ )
    {
        paddr_t start, end = d->arch.e820[i].addr + d->arch.e820[i].size;

        /* Don't use memory below 1MB, as it could overwrite BDA/EBDA/IBFT. */
        if ( end <= MB(1) || d->arch.e820[i].type != E820_RAM )
            continue;

        start = MAX(ROUNDUP(d->arch.e820[i].addr, PAGE_SIZE), MB(1));

        ASSERT(IS_ALIGNED(start, PAGE_SIZE) && IS_ALIGNED(end, PAGE_SIZE));

        /*
         * NB: Even better would be to use rangesets to determine a suitable
         * range, in particular in case a kernel requests multiple heavily
         * discontiguous regions (which right now we fold all into one big
         * region).
         */
        if ( end <= kernel_start || start >= kernel_end )
        {
            /* No overlap, just check whether the region is large enough. */
            if ( end - start >= size )
                return start;
        }
        /* Deal with the kernel already being loaded in the region. */
        else if ( kernel_start > start && kernel_start - start >= size )
            return start;
        else if ( kernel_end < end && end - kernel_end >= size )
            return kernel_end;
    }

    return INVALID_PADDR;
}

static bool __init check_load_address(
    const struct domain *d, const struct elf_binary *elf)
{
    paddr_t kernel_start = (uintptr_t)elf->dest_base;
    paddr_t kernel_end = kernel_start + elf->dest_size;
    unsigned int i;

    /* Relies on a sorted memory map with adjacent entries merged. */
    for ( i = 0; i < d->arch.nr_e820; i++ )
    {
        paddr_t start = d->arch.e820[i].addr;
        paddr_t end = start + d->arch.e820[i].size;

        if ( start >= kernel_end )
            return false;

        if ( d->arch.e820[i].type == E820_RAM &&
             start <= kernel_start &&
             end >= kernel_end )
            return true;
    }

    return false;
}

/* Find an e820 RAM region that fits the kernel at a suitable alignment. */
static paddr_t __init find_kernel_memory(
    const struct domain *d, struct elf_binary *elf,
    const struct elf_dom_parms *parms)
{
    paddr_t kernel_size = elf->dest_size;
    unsigned int align;
    unsigned int i;

    if ( parms->phys_align != UNSET_ADDR32 )
        align = parms->phys_align;
    else if ( elf->palign >= PAGE_SIZE )
        align = elf->palign;
    else
        align = MB(2);

    /* Search backwards to find the highest address. */
    for ( i = d->arch.nr_e820; i--; )
    {
        paddr_t start = d->arch.e820[i].addr;
        paddr_t end = start + d->arch.e820[i].size;
        paddr_t kstart, kend;

        if ( d->arch.e820[i].type != E820_RAM ||
             d->arch.e820[i].size < kernel_size )
            continue;

        if ( start > parms->phys_max )
            continue;

        if ( end - 1 > parms->phys_max )
            end = parms->phys_max + 1;

        kstart = (end - kernel_size) & ~(align - 1);
        kend = kstart + kernel_size;

        if ( kstart < parms->phys_min )
            return 0;

        if ( kstart >= start && kend <= end )
            return kstart;
    }

    return 0;
}

/* Check the kernel load address, and adjust if necessary and possible. */
static bool __init check_and_adjust_load_address(
    const struct domain *d, struct elf_binary *elf, struct elf_dom_parms *parms)
{
    paddr_t reloc_base;

    if ( check_load_address(d, elf) )
        return true;

    if ( !parms->phys_reloc )
    {
        printk("%pd kernel: Address conflict and not relocatable\n", d);
        return false;
    }

    reloc_base = find_kernel_memory(d, elf, parms);
    if ( !reloc_base )
    {
        printk("%pd kernel: Failed find a load address\n", d);
        return false;
    }

    if ( opt_dom0_verbose )
        printk("%pd kernel: Moving [%p, %p] -> [%"PRIpaddr", %"PRIpaddr"]\n", d,
               elf->dest_base, elf->dest_base + elf->dest_size - 1,
               reloc_base, reloc_base + elf->dest_size - 1);

    parms->phys_entry =
        reloc_base + (parms->phys_entry - (uintptr_t)elf->dest_base);
    elf->dest_base = (char *)reloc_base;

    return true;
}

static int __init pvh_load_kernel(
    const struct boot_domain *bd, paddr_t *entry, paddr_t *start_info_addr)
{
    struct domain *d = bd->d;
    struct boot_module *image = bd->kernel;
    struct boot_module *initrd = bd->initrd;
    void *image_base = bootstrap_map_bm(image);
    void *image_start = image_base + image->arch.headroom;
    unsigned long image_len = image->size;
    unsigned long initrd_len = initrd ? initrd->size : 0;
    size_t cmdline_len = bd->cmdline ? strlen(bd->cmdline) + 1 : 0;
    const char *initrd_cmdline = NULL;
    struct elf_binary elf;
    struct elf_dom_parms parms;
    size_t extra_space;
    paddr_t last_addr;
    struct hvm_start_info start_info = { 0 };
    struct hvm_modlist_entry mod = { 0 };
    struct vcpu *v = d->vcpu[0];
    int rc;

    if ( (rc = bzimage_parse(image_base, &image_start, &image_len)) != 0 )
    {
        printk("Error trying to detect bz compressed kernel\n");
        return rc;
    }

    if ( (rc = elf_init(&elf, image_start, image_len)) != 0 )
    {
        printk("Unable to init ELF\n");
        return rc;
    }
    if ( opt_dom0_verbose )
        elf_set_verbose(&elf);
    elf_parse_binary(&elf);
    if ( (rc = elf_xen_parse(&elf, &parms, true)) != 0 )
    {
        printk("Unable to parse kernel for ELFNOTES\n");
        if ( elf_check_broken(&elf) )
            printk("%pd kernel: broken ELF: %s\n", d, elf_check_broken(&elf));
        return rc;
    }

    if ( parms.phys_entry == UNSET_ADDR32 )
    {
        printk("Unable to find XEN_ELFNOTE_PHYS32_ENTRY address\n");
        return -EINVAL;
    }

    /* Copy the OS image and free temporary buffer. */
    elf.dest_base = (void *)(parms.virt_kstart - parms.virt_base);
    elf.dest_size = parms.virt_kend - parms.virt_kstart;

    if ( !check_and_adjust_load_address(d, &elf, &parms) )
        return -ENOSPC;

    elf_set_vcpu(&elf, v);
    rc = elf_load_binary(&elf);
    if ( rc < 0 )
    {
        printk("Failed to load kernel: %d\n", rc);
        if ( elf_check_broken(&elf) )
            printk("%pd kernel: broken ELF: %s\n", d, elf_check_broken(&elf));
        return rc;
    }

    /*
     * Find a RAM region big enough (and that doesn't overlap with the loaded
     * kernel) in order to load the initrd and the metadata. Note it could be
     * split into smaller allocations, done as a single region in order to
     * simplify it.
     */
    extra_space = sizeof(start_info);

    if ( initrd )
    {
        size_t initrd_space = elf_round_up(&elf, initrd_len);

        if ( initrd->arch.cmdline_pa )
        {
            initrd_cmdline = __va(initrd->arch.cmdline_pa);
            if ( !*initrd_cmdline )
                initrd_cmdline = NULL;
        }
        if ( initrd_cmdline )
            initrd_space += strlen(initrd_cmdline) + 1;

        if ( initrd_space )
            extra_space += ROUNDUP(initrd_space, PAGE_SIZE) + sizeof(mod);
        else
            initrd = NULL;
    }

    extra_space += elf_round_up(&elf, cmdline_len);

    last_addr = find_memory(d, &elf, extra_space);
    if ( last_addr == INVALID_PADDR )
    {
        printk("Unable to find a memory region to load initrd and metadata\n");
        return -ENOMEM;
    }

    if ( initrd != NULL )
    {
        rc = hvm_copy_to_guest_phys(last_addr, __va(initrd->start),
                                    initrd_len, v);
        if ( rc )
        {
            printk("Unable to copy initrd to guest\n");
            return rc;
        }

        mod.paddr = last_addr;
        mod.size = initrd_len;
        last_addr += elf_round_up(&elf, initrd_len);
        if ( initrd_cmdline )
        {
            size_t len = strlen(initrd_cmdline) + 1;

            rc = hvm_copy_to_guest_phys(last_addr, initrd_cmdline, len, v);
            if ( rc )
            {
                printk("Unable to copy module command line\n");
                return rc;
            }
            mod.cmdline_paddr = last_addr;
            last_addr += len;
        }
        last_addr = ROUNDUP(last_addr, PAGE_SIZE);
    }

    /* Free temporary buffers. */
    free_boot_modules();

    rc = hvm_copy_to_guest_phys(last_addr, bd->cmdline, cmdline_len, v);
    if ( rc )
    {
        printk("Unable to copy guest command line\n");
        return rc;
    }

    start_info.cmdline_paddr = cmdline_len ? last_addr : 0;

    /*
     * Round up to 32/64 bits (depending on the guest kernel bitness) so
     * the modlist/start_info is aligned.
     */
    last_addr += elf_round_up(&elf, cmdline_len);

    if ( initrd != NULL )
    {
        rc = hvm_copy_to_guest_phys(last_addr, &mod, sizeof(mod), v);
        if ( rc )
        {
            printk("Unable to copy guest modules\n");
            return rc;
        }
        start_info.modlist_paddr = last_addr;
        start_info.nr_modules = 1;
        last_addr += sizeof(mod);
    }

    start_info.magic = XEN_HVM_START_MAGIC_VALUE;
    start_info.flags = SIF_PRIVILEGED | SIF_INITDOMAIN;
    rc = hvm_copy_to_guest_phys(last_addr, &start_info, sizeof(start_info), v);
    if ( rc )
    {
        printk("Unable to copy start info to guest\n");
        return rc;
    }

    *entry = parms.phys_entry;
    *start_info_addr = last_addr;

    return 0;
}

static int __init pvh_setup_cpus(struct domain *d, paddr_t entry,
                                 paddr_t start_info)
{
    struct vcpu *v = d->vcpu[0];
    int rc;
    /*
     * This sets the vCPU state according to the state described in
     * docs/misc/pvh.pandoc.
     */
    vcpu_hvm_context_t cpu_ctx = {
        .mode = VCPU_HVM_MODE_32B,
        .cpu_regs.x86_32.ebx = start_info,
        .cpu_regs.x86_32.eip = entry,
        .cpu_regs.x86_32.cr0 = X86_CR0_PE | X86_CR0_ET,
        .cpu_regs.x86_32.cs_limit = ~0u,
        .cpu_regs.x86_32.ds_limit = ~0u,
        .cpu_regs.x86_32.es_limit = ~0u,
        .cpu_regs.x86_32.ss_limit = ~0u,
        .cpu_regs.x86_32.tr_limit = 0x67,
        .cpu_regs.x86_32.cs_ar = 0xc9b,
        .cpu_regs.x86_32.ds_ar = 0xc93,
        .cpu_regs.x86_32.es_ar = 0xc93,
        .cpu_regs.x86_32.ss_ar = 0xc93,
        .cpu_regs.x86_32.tr_ar = 0x8b,
    };

    sched_setup_dom0_vcpus(d);

    rc = arch_set_info_hvm_guest(v, &cpu_ctx);
    if ( rc )
    {
        printk("Unable to setup Dom0 BSP context: %d\n", rc);
        return rc;
    }

    update_domain_wallclock_time(d);

    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);

    return 0;
}

static int __init cf_check acpi_count_intr_ovr(
    struct acpi_subtable_header *header, const unsigned long end)
{
    acpi_intr_overrides++;
    return 0;
}

static int __init cf_check acpi_set_intr_ovr(
    struct acpi_subtable_header *header, const unsigned long end)
{
    const struct acpi_madt_interrupt_override *intr =
        container_of(header, struct acpi_madt_interrupt_override, header);

    *intsrcovr = *intr;
    intsrcovr++;

    return 0;
}

static int __init pvh_setup_acpi_madt(struct domain *d, paddr_t *addr)
{
    struct acpi_table_madt *madt;
    struct acpi_table_header *table;
    struct acpi_madt_io_apic *io_apic;
    struct acpi_madt_local_x2apic *x2apic;
    acpi_status status;
    unsigned long size;
    unsigned int i;
    int rc;

    /* Count number of interrupt overrides in the MADT. */
    acpi_table_parse_madt(ACPI_MADT_TYPE_INTERRUPT_OVERRIDE,
                          acpi_count_intr_ovr, UINT_MAX);

    /* Calculate the size of the crafted MADT. */
    size = sizeof(*madt);
    size += sizeof(*io_apic) * nr_ioapics;
    size += sizeof(*intsrcovr) * acpi_intr_overrides;
    size += sizeof(*x2apic) * d->max_vcpus;

    madt = xzalloc_bytes(size);
    if ( !madt )
    {
        printk("Unable to allocate memory for MADT table\n");
        rc = -ENOMEM;
        goto out;
    }

    /* Copy the native MADT table header. */
    status = acpi_get_table(ACPI_SIG_MADT, 0, &table);
    if ( !ACPI_SUCCESS(status) )
    {
        printk("Failed to get MADT ACPI table, aborting.\n");
        rc = -EINVAL;
        goto out;
    }
    madt->header = *table;
    madt->address = APIC_DEFAULT_PHYS_BASE;
    /*
     * NB: this is currently set to 4, which is the revision in the ACPI
     * spec 6.1. Sadly ACPICA doesn't provide revision numbers for the
     * tables described in the headers.
     */
    madt->header.revision = min_t(unsigned char, table->revision, 4);

    /* Setup the IO APIC entries. */
    io_apic = (void *)(madt + 1);
    for ( i = 0; i < nr_ioapics; i++ )
    {
        io_apic->header.type = ACPI_MADT_TYPE_IO_APIC;
        io_apic->header.length = sizeof(*io_apic);
        io_apic->id = domain_vioapic(d, i)->id;
        io_apic->address = domain_vioapic(d, i)->base_address;
        io_apic->global_irq_base = domain_vioapic(d, i)->base_gsi;
        io_apic++;
    }

    x2apic = (void *)io_apic;
    for ( i = 0; i < d->max_vcpus; i++ )
    {
        x2apic->header.type = ACPI_MADT_TYPE_LOCAL_X2APIC;
        x2apic->header.length = sizeof(*x2apic);
        x2apic->uid = i;
        x2apic->local_apic_id = i * 2;
        x2apic->lapic_flags = ACPI_MADT_ENABLED;
        x2apic++;
    }

    /* Setup interrupt overrides. */
    intsrcovr = (void *)x2apic;
    acpi_table_parse_madt(ACPI_MADT_TYPE_INTERRUPT_OVERRIDE, acpi_set_intr_ovr,
                          acpi_intr_overrides);

    ASSERT(((void *)intsrcovr - (void *)madt) == size);
    madt->header.length = size;
    /*
     * Calling acpi_tb_checksum here is a layering violation, but
     * introducing a wrapper for such simple usage seems overkill.
     */
    madt->header.checksum -= acpi_tb_checksum(ACPI_CAST_PTR(u8, madt), size);

    /* Place the new MADT in guest memory space. */
    if ( pvh_steal_ram(d, size, 0, GB(4), addr) )
    {
        printk("Unable to steal guest RAM for MADT\n");
        rc = -ENOMEM;
        goto out;
    }

    /* Mark this region as E820_ACPI. */
    if ( pvh_add_mem_range(d, *addr, *addr + size, E820_ACPI) )
        printk("Unable to add MADT region to memory map\n");

    rc = hvm_copy_to_guest_phys(*addr, madt, size, d->vcpu[0]);
    if ( rc )
    {
        printk("Unable to copy MADT into guest memory\n");
        goto out;
    }

    rc = 0;

 out:
    xfree(madt);

    return rc;
}

static bool __init acpi_memory_banned(unsigned long address,
                                      unsigned long size)
{
    unsigned long mfn = PFN_DOWN(address);
    unsigned long nr_pages = PFN_UP((address & ~PAGE_MASK) + size), i;

    for ( i = 0 ; i < nr_pages; i++ )
        if ( !page_is_ram_type(mfn + i, RAM_TYPE_RESERVED) &&
             !page_is_ram_type(mfn + i, RAM_TYPE_ACPI) )
            return true;

    return false;
}

static bool __init pvh_acpi_table_allowed(const char *sig,
                                          unsigned long address,
                                          unsigned long size)
{
    static const char __initconst allowed_tables[][ACPI_NAME_SIZE] = {
        ACPI_SIG_DSDT, ACPI_SIG_FADT, ACPI_SIG_FACS, ACPI_SIG_PSDT,
        ACPI_SIG_SSDT, ACPI_SIG_SBST, ACPI_SIG_MCFG, ACPI_SIG_SLIC,
        ACPI_SIG_MSDM, ACPI_SIG_WDAT, ACPI_SIG_FPDT, ACPI_SIG_S3PT,
        ACPI_SIG_VFCT,
    };
    unsigned int i;

    for ( i = 0 ; i < ARRAY_SIZE(allowed_tables); i++ )
    {
        if ( strncmp(sig, allowed_tables[i], ACPI_NAME_SIZE) )
            continue;

        if ( !acpi_memory_banned(address, size) )
            return true;
        else
        {
    skip:
            printk("Skipping table %.4s in non-ACPI non-reserved region\n",
                   sig);
            return false;
        }
    }

    if ( !strncmp(sig, "OEM", 3) )
    {
        if ( acpi_memory_banned(address, size) )
            goto skip;
        return true;
    }

    return false;
}

static bool __init pvh_acpi_xsdt_table_allowed(const char *sig,
                                               unsigned long address,
                                               unsigned long size)
{
    /*
     * DSDT and FACS are pointed to from FADT and thus don't belong
     * in XSDT.
     */
    return (pvh_acpi_table_allowed(sig, address, size) &&
            strncmp(sig, ACPI_SIG_DSDT, ACPI_NAME_SIZE) &&
            strncmp(sig, ACPI_SIG_FACS, ACPI_NAME_SIZE));
}

static int __init pvh_setup_acpi_xsdt(struct domain *d, paddr_t madt_addr,
                                      paddr_t *addr)
{
    struct acpi_table_xsdt *xsdt;
    struct acpi_table_header *table;
    struct acpi_table_rsdp *rsdp;
    const struct acpi_table_desc *tables = acpi_gbl_root_table_list.tables;
    unsigned long size = sizeof(*xsdt);
    unsigned int i, j, num_tables = 0;
    paddr_t xsdt_paddr;
    int rc;

    /*
     * Restore original DMAR table signature, we are going to filter it from
     * the new XSDT that is presented to the guest, so it is no longer
     * necessary to have it's signature zapped.
     */
    acpi_dmar_reinstate();

    /* Count the number of tables that will be added to the XSDT. */
    for( i = 0; i < acpi_gbl_root_table_list.count; i++ )
    {
        if ( pvh_acpi_xsdt_table_allowed(tables[i].signature.ascii,
                                         tables[i].address, tables[i].length) )
            num_tables++;
    }

    /*
     * No need to add or subtract anything because struct acpi_table_xsdt
     * includes one array slot already, and we have filtered out the original
     * MADT and we are going to add a custom built MADT.
     */
    size += num_tables * sizeof(xsdt->table_offset_entry[0]);

    xsdt = xzalloc_bytes(size);
    if ( !xsdt )
    {
        printk("Unable to allocate memory for XSDT table\n");
        rc = -ENOMEM;
        goto out;
    }

    /* Copy the native XSDT table header. */
    rsdp = acpi_os_map_memory(acpi_os_get_root_pointer(), sizeof(*rsdp));
    if ( !rsdp )
    {
        printk("Unable to map RSDP\n");
        rc = -EINVAL;
        goto out;
    }
    /*
     * Note the header is the same for both RSDT and XSDT, so it's fine to
     * copy the native RSDT header to the Xen crafted XSDT if no native
     * XSDT is available.
     */
    if ( rsdp->revision > 1 && rsdp->xsdt_physical_address )
        xsdt_paddr = rsdp->xsdt_physical_address;
    else
        xsdt_paddr = rsdp->rsdt_physical_address;

    acpi_os_unmap_memory(rsdp, sizeof(*rsdp));
    table = acpi_os_map_memory(xsdt_paddr, sizeof(*table));
    if ( !table )
    {
        printk("Unable to map XSDT\n");
        rc = -EINVAL;
        goto out;
    }
    xsdt->header = *table;
    acpi_os_unmap_memory(table, sizeof(*table));

    /*
     * In case the header is an RSDT copy, unconditionally ensure it has
     * an XSDT sig.
     */
    xsdt->header.signature[0] = 'X';

    /* Add the custom MADT. */
    xsdt->table_offset_entry[0] = madt_addr;

    /* Copy the addresses of the rest of the allowed tables. */
    for( i = 0, j = 1; i < acpi_gbl_root_table_list.count; i++ )
    {
        if ( pvh_acpi_xsdt_table_allowed(tables[i].signature.ascii,
                                         tables[i].address, tables[i].length) )
            xsdt->table_offset_entry[j++] = tables[i].address;
    }

    xsdt->header.revision = 1;
    xsdt->header.length = size;
    /*
     * Calling acpi_tb_checksum here is a layering violation, but
     * introducing a wrapper for such simple usage seems overkill.
     */
    xsdt->header.checksum -= acpi_tb_checksum(ACPI_CAST_PTR(u8, xsdt), size);

    /* Place the new XSDT in guest memory space. */
    if ( pvh_steal_ram(d, size, 0, GB(4), addr) )
    {
        printk("Unable to find guest RAM for XSDT\n");
        rc = -ENOMEM;
        goto out;
    }

    /* Mark this region as E820_ACPI. */
    if ( pvh_add_mem_range(d, *addr, *addr + size, E820_ACPI) )
        printk("Unable to add XSDT region to memory map\n");

    rc = hvm_copy_to_guest_phys(*addr, xsdt, size, d->vcpu[0]);
    if ( rc )
    {
        printk("Unable to copy XSDT into guest memory\n");
        goto out;
    }

    rc = 0;

 out:
    xfree(xsdt);

    return rc;
}

static int __init pvh_setup_acpi(struct domain *d, paddr_t start_info)
{
    unsigned long pfn, nr_pages;
    paddr_t madt_paddr, xsdt_paddr, rsdp_paddr;
    unsigned int i;
    int rc;
    struct acpi_table_rsdp *native_rsdp, rsdp = {
        .signature = ACPI_SIG_RSDP,
        .revision = 2,
        .length = sizeof(rsdp),
    };


    /* Scan top-level tables and add their regions to the guest memory map. */
    for( i = 0; i < acpi_gbl_root_table_list.count; i++ )
    {
        const char *sig = acpi_gbl_root_table_list.tables[i].signature.ascii;
        unsigned long addr = acpi_gbl_root_table_list.tables[i].address;
        unsigned long size = acpi_gbl_root_table_list.tables[i].length;

        /*
         * Make sure the original MADT is also mapped, so that Dom0 can
         * properly access the data returned by _MAT methods in case it's
         * re-using MADT memory.
         */
        if ( strncmp(sig, ACPI_SIG_MADT, ACPI_NAME_SIZE)
             ? pvh_acpi_table_allowed(sig, addr, size)
             : !acpi_memory_banned(addr, size) )
             pvh_add_mem_range(d, addr, addr + size, E820_ACPI);
    }

    /* Identity map ACPI e820 regions. */
    for ( i = 0; i < d->arch.nr_e820; i++ )
    {
        if ( d->arch.e820[i].type != E820_ACPI &&
             d->arch.e820[i].type != E820_NVS )
            continue;

        pfn = PFN_DOWN(d->arch.e820[i].addr);
        nr_pages = PFN_UP((d->arch.e820[i].addr & ~PAGE_MASK) +
                          d->arch.e820[i].size);

        /* Memory below 1MB has been dealt with by pvh_populate_p2m(). */
        if ( pfn < PFN_DOWN(MB(1)) )
        {
            if ( pfn + nr_pages <= PFN_DOWN(MB(1)) )
                continue;

            /* This shouldn't happen, but is easy to deal with. */
            nr_pages -= PFN_DOWN(MB(1)) - pfn;
            pfn = PFN_DOWN(MB(1));
        }

        rc = modify_identity_mmio(d, pfn, nr_pages, true);
        if ( rc )
        {
            printk("Failed to map ACPI region [%#lx, %#lx) into Dom0 memory map\n",
                   pfn, pfn + nr_pages);
            return rc;
        }
    }

    rc = pvh_setup_acpi_madt(d, &madt_paddr);
    if ( rc )
        return rc;

    rc = pvh_setup_acpi_xsdt(d, madt_paddr, &xsdt_paddr);
    if ( rc )
        return rc;

    /* Craft a custom RSDP. */
    native_rsdp = acpi_os_map_memory(acpi_os_get_root_pointer(), sizeof(rsdp));
    if ( !native_rsdp )
    {
        printk("Failed to map native RSDP\n");
        return -ENOMEM;
    }
    memcpy(rsdp.oem_id, native_rsdp->oem_id, sizeof(rsdp.oem_id));
    acpi_os_unmap_memory(native_rsdp, sizeof(rsdp));
    rsdp.xsdt_physical_address = xsdt_paddr;
    /*
     * Calling acpi_tb_checksum here is a layering violation, but
     * introducing a wrapper for such simple usage seems overkill.
     */
    rsdp.checksum -= acpi_tb_checksum(ACPI_CAST_PTR(u8, &rsdp),
                                      ACPI_RSDP_REV0_SIZE);
    rsdp.extended_checksum -= acpi_tb_checksum(ACPI_CAST_PTR(u8, &rsdp),
                                               sizeof(rsdp));

    /*
     * Place the new RSDP in guest memory space.
     *
     * NB: this RSDP is not going to replace the original RSDP, which should
     * still be accessible to the guest. However that RSDP is going to point to
     * the native RSDT, and should not be used for the Dom0 kernel's boot
     * purposes (we keep it visible for post boot access).
     */
    if ( pvh_steal_ram(d, sizeof(rsdp), 0, GB(4), &rsdp_paddr) )
    {
        printk("Unable to allocate guest RAM for RSDP\n");
        return -ENOMEM;
    }

    /* Mark this region as E820_ACPI. */
    if ( pvh_add_mem_range(d, rsdp_paddr, rsdp_paddr + sizeof(rsdp),
                           E820_ACPI) )
        printk("Unable to add RSDP region to memory map\n");

    /* Copy RSDP into guest memory. */
    rc = hvm_copy_to_guest_phys(rsdp_paddr, &rsdp, sizeof(rsdp), d->vcpu[0]);
    if ( rc )
    {
        printk("Unable to copy RSDP into guest memory\n");
        return rc;
    }

    /* Copy RSDP address to start_info. */
    rc = hvm_copy_to_guest_phys(start_info +
                                offsetof(struct hvm_start_info, rsdp_paddr),
                                &rsdp_paddr,
                                sizeof_field(struct hvm_start_info, rsdp_paddr),
                                d->vcpu[0]);
    if ( rc )
    {
        printk("Unable to copy RSDP address to start info\n");
        return rc;
    }

    return 0;
}

static void __hwdom_init pvh_setup_mmcfg(struct domain *d)
{
    unsigned int i;
    int rc;

    for ( i = 0; i < pci_mmcfg_config_num; i++ )
    {
        rc = register_vpci_mmcfg_handler(d, pci_mmcfg_config[i].address,
                                         pci_mmcfg_config[i].start_bus_number,
                                         pci_mmcfg_config[i].end_bus_number,
                                         pci_mmcfg_config[i].pci_segment);
        if ( rc )
            printk("Unable to setup MMCFG handler at %#lx for segment %u\n",
                   pci_mmcfg_config[i].address,
                   pci_mmcfg_config[i].pci_segment);
    }
}

int __init dom0_construct_pvh(const struct boot_domain *bd)
{
    paddr_t entry, start_info;
    struct domain *d = bd->d;
    int rc;

    printk(XENLOG_INFO "*** Building a PVH Dom%d ***\n", d->domain_id);

    if ( bd->kernel == NULL )
        panic("Missing kernel boot module for %pd construction\n", d);

    if ( is_hardware_domain(d) )
    {
        /*
         * MMCFG initialization must be performed before setting domain
         * permissions, as the MCFG areas must not be part of the domain IOMEM
         * accessible regions.
         */
        pvh_setup_mmcfg(d);

        /*
         * Setup permissions early so that calls to add MMIO regions to the
         * p2m as part of vPCI setup don't fail due to permission checks.
         */
        rc = dom0_setup_permissions(d);
        if ( rc )
        {
            printk("%pd unable to setup permissions: %d\n", d, rc);
            return rc;
        }
    }

    /*
     * Craft dom0 physical memory map and set the paging allocation. This must
     * be done before the iommu initializion, since iommu initialization code
     * will likely add mappings required by devices to the p2m (ie: RMRRs).
     */
    pvh_init_p2m(d);

    iommu_hwdom_init(d);

    rc = pvh_populate_p2m(d);
    if ( rc )
    {
        printk("Failed to setup Dom0 physical memory map\n");
        return rc;
    }

    rc = pvh_load_kernel(bd, &entry, &start_info);
    if ( rc )
    {
        printk("Failed to load Dom0 kernel\n");
        return rc;
    }

    rc = pvh_setup_cpus(d, entry, start_info);
    if ( rc )
    {
        printk("Failed to setup Dom0 CPUs: %d\n", rc);
        return rc;
    }

    rc = pvh_setup_acpi(d, start_info);
    if ( rc )
    {
        printk("Failed to setup Dom0 ACPI tables: %d\n", rc);
        return rc;
    }

    if ( opt_dom0_verbose )
    {
        printk("Dom%u memory map:\n", d->domain_id);
        print_e820_memory_map(d->arch.e820, d->arch.nr_e820);
    }

    return 0;
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
