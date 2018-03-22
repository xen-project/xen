/*
 * hvm/dom0_build.c
 *
 * Dom0 builder for PVH guest.
 *
 * Copyright (C) 2017 Citrix Systems R&D
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/acpi.h>
#include <xen/init.h>
#include <xen/libelf.h>
#include <xen/multiboot.h>
#include <xen/pci.h>
#include <xen/softirq.h>

#include <acpi/actables.h>

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

static unsigned int __initdata acpi_nmi_sources;
static struct acpi_madt_nmi_source __initdata *nmisrc;

static int __init modify_identity_mmio(struct domain *d, unsigned long pfn,
                                       unsigned long nr_pages, const bool map)
{
    int rc;

    for ( ; ; )
    {
        rc = (map ? map_mmio_regions : unmap_mmio_regions)
             (d, _gfn(pfn), nr_pages, _mfn(pfn));
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
    unsigned int order = MAX_ORDER, i = 0;
    struct page_info *page;
    int rc;
#define MAP_MAX_ITER 64

    while ( nr_pages != 0 )
    {
        unsigned int range_order = get_order_from_pages(nr_pages + 1);

        order = min(range_order ? range_order - 1 : 0, order);
        page = alloc_domheap_pages(d, order, dom0_memflags);
        if ( page == NULL )
        {
            if ( order == 0 && dom0_memflags )
            {
                /* Try again without any dom0_memflags. */
                dom0_memflags = 0;
                order = MAX_ORDER;
                continue;
            }
            if ( order == 0 )
            {
                printk("Unable to allocate memory with order 0!\n");
                return -ENOMEM;
            }
            order--;
            continue;
        }

        rc = guest_physmap_add_page(d, _gfn(start), _mfn(page_to_mfn(page)),
                                    order);
        if ( rc != 0 )
        {
            printk("Failed to populate memory: [%#lx,%lx): %d\n",
                   start, start + (1UL << order), rc);
            return -ENOMEM;
        }
        start += 1UL << order;
        nr_pages -= 1UL << order;
        if ( (++i % MAP_MAX_ITER) == 0 )
            process_pending_softirqs();
    }

    return 0;
#undef MAP_MAX_ITER
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

        if ( entry->type != E820_RAM || entry->addr + entry->size > limit ||
             entry->addr < MB(1) )
            continue;

        *addr = (entry->addr + entry->size - size) & ~(align - 1);
        if ( *addr < entry->addr )
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
    p2m_type_t p2mt;
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
        d->arch.hvm_domain.params[HVM_PARAM_VM86_TSS_SIZED] =
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
                              &mfn, &p2mt, 0, &rc);
    if ( ident_pt == NULL )
    {
        printk("Unable to map identity page tables\n");
        return -ENOMEM;
    }
    write_32bit_pse_identmap(ident_pt);
    unmap_domain_page(ident_pt);
    put_page(mfn_to_page(mfn_x(mfn)));
    d->arch.hvm_domain.params[HVM_PARAM_IDENT_PT] = gaddr;
    if ( pvh_add_mem_range(d, gaddr, gaddr + PAGE_SIZE, E820_RESERVED) )
            printk("Unable to set identity page tables as reserved in the memory map\n");

    return 0;
}

/* Assign the low 1MB to Dom0. */
static void __init pvh_steal_low_ram(struct domain *d, unsigned long start,
                                     unsigned long nr_pages)
{
    unsigned long mfn;

    ASSERT(start + nr_pages <= PFN_DOWN(MB(1)));

    for ( mfn = start; mfn < start + nr_pages; mfn++ )
    {
        struct page_info *pg = mfn_to_page(mfn);
        int rc;

        rc = unshare_xen_page_with_guest(pg, dom_io);
        if ( rc )
        {
            printk("Unable to unshare Xen mfn %#lx: %d\n", mfn, rc);
            continue;
        }

        share_xen_page_with_guest(pg, d, SHARE_rw);
        rc = guest_physmap_add_entry(d, _gfn(mfn), _mfn(mfn), 0, p2m_ram_rw);
        if ( rc )
            printk("Unable to add mfn %#lx to p2m: %d\n", mfn, rc);
    }
}

static __init void pvh_setup_e820(struct domain *d, unsigned long nr_pages)
{
    struct e820entry *entry, *entry_guest;
    unsigned int i;
    unsigned long pages, cur_pages = 0;
    uint64_t start, end;

    /*
     * Craft the e820 memory map for Dom0 based on the hardware e820 map.
     */
    d->arch.e820 = xzalloc_array(struct e820entry, e820.nr_map);
    if ( !d->arch.e820 )
        panic("Unable to allocate memory for Dom0 e820 map");
    entry_guest = d->arch.e820;

    /* Clamp e820 memory map to match the memory assigned to Dom0 */
    for ( i = 0, entry = e820.map; i < e820.nr_map; i++, entry++ )
    {
        if ( entry->type != E820_RAM )
        {
            *entry_guest = *entry;
            goto next;
        }

        if ( nr_pages == cur_pages )
        {
            /*
             * We already have all the assigned memory,
             * skip this entry
             */
            continue;
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
            cur_pages = nr_pages;
        }
        else
        {
            cur_pages += pages;
        }
 next:
        d->arch.nr_e820++;
        entry_guest++;
    }
    ASSERT(cur_pages == nr_pages);
    ASSERT(d->arch.nr_e820 <= e820.nr_map);
}

static int __init pvh_setup_p2m(struct domain *d)
{
    struct vcpu *v = d->vcpu[0];
    unsigned long nr_pages = dom0_compute_nr_pages(d, NULL, 0);
    unsigned int i;
    int rc;
    bool preempted;
#define MB1_PAGES PFN_DOWN(MB(1))

    pvh_setup_e820(d, nr_pages);
    do {
        preempted = false;
        paging_set_allocation(d, dom0_paging_pages(d, nr_pages),
                              &preempted);
        process_pending_softirqs();
    } while ( preempted );

    /*
     * Memory below 1MB is identity mapped.
     * NB: this only makes sense when booted from legacy BIOS.
     */
    rc = modify_identity_mmio(d, 0, MB1_PAGES, true);
    if ( rc )
    {
        printk("Failed to identity map low 1MB: %d\n", rc);
        return rc;
    }

    /* Populate memory map. */
    for ( i = 0; i < d->arch.nr_e820; i++ )
    {
        unsigned long addr, size;

        if ( d->arch.e820[i].type != E820_RAM )
            continue;

        addr = PFN_DOWN(d->arch.e820[i].addr);
        size = PFN_DOWN(d->arch.e820[i].size);

        if ( addr >= MB1_PAGES )
            rc = pvh_populate_memory_range(d, addr, size);
        else
        {
            ASSERT(addr + size < MB1_PAGES);
            pvh_steal_low_ram(d, addr, size);
        }

        if ( rc )
            return rc;
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

    return 0;
#undef MB1_PAGES
}

static int __init pvh_load_kernel(struct domain *d, const module_t *image,
                                  unsigned long image_headroom,
                                  module_t *initrd, void *image_base,
                                  char *cmdline, paddr_t *entry,
                                  paddr_t *start_info_addr)
{
    void *image_start = image_base + image_headroom;
    unsigned long image_len = image->mod_end;
    struct elf_binary elf;
    struct elf_dom_parms parms;
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
#ifdef VERBOSE
    elf_set_verbose(&elf);
#endif
    elf_parse_binary(&elf);
    if ( (rc = elf_xen_parse(&elf, &parms)) != 0 )
    {
        printk("Unable to parse kernel for ELFNOTES\n");
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

    elf_set_vcpu(&elf, v);
    rc = elf_load_binary(&elf);
    if ( rc < 0 )
    {
        printk("Failed to load kernel: %d\n", rc);
        printk("Xen dom0 kernel broken ELF: %s\n", elf_check_broken(&elf));
        return rc;
    }

    last_addr = ROUNDUP(parms.virt_kend - parms.virt_base, PAGE_SIZE);

    if ( initrd != NULL )
    {
        rc = hvm_copy_to_guest_phys(last_addr, mfn_to_virt(initrd->mod_start),
                                    initrd->mod_end, v);
        if ( rc )
        {
            printk("Unable to copy initrd to guest\n");
            return rc;
        }

        mod.paddr = last_addr;
        mod.size = initrd->mod_end;
        last_addr += ROUNDUP(initrd->mod_end, PAGE_SIZE);
    }

    /* Free temporary buffers. */
    discard_initial_images();

    if ( cmdline != NULL )
    {
        rc = hvm_copy_to_guest_phys(last_addr, cmdline, strlen(cmdline) + 1, v);
        if ( rc )
        {
            printk("Unable to copy guest command line\n");
            return rc;
        }
        start_info.cmdline_paddr = last_addr;
        /*
         * Round up to 32/64 bits (depending on the guest kernel bitness) so
         * the modlist/start_info is aligned.
         */
        last_addr += ROUNDUP(strlen(cmdline) + 1, elf_64bit(&elf) ? 8 : 4);
    }
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
    unsigned int cpu = v->processor, i;
    int rc;
    /*
     * This sets the vCPU state according to the state described in
     * docs/misc/hvmlite.markdown.
     */
    vcpu_hvm_context_t cpu_ctx = {
        .mode = VCPU_HVM_MODE_32B,
        .cpu_regs.x86_32.ebx = start_info,
        .cpu_regs.x86_32.eip = entry,
        .cpu_regs.x86_32.cr0 = X86_CR0_PE | X86_CR0_ET,
        .cpu_regs.x86_32.cs_limit = ~0u,
        .cpu_regs.x86_32.ds_limit = ~0u,
        .cpu_regs.x86_32.ss_limit = ~0u,
        .cpu_regs.x86_32.tr_limit = 0x67,
        .cpu_regs.x86_32.cs_ar = 0xc9b,
        .cpu_regs.x86_32.ds_ar = 0xc93,
        .cpu_regs.x86_32.ss_ar = 0xc93,
        .cpu_regs.x86_32.tr_ar = 0x8b,
    };

    for ( i = 1; i < d->max_vcpus; i++ )
    {
        const struct vcpu *p = dom0_setup_vcpu(d, i, cpu);

        if ( p )
            cpu = p->processor;
    }

    rc = arch_set_info_hvm_guest(v, &cpu_ctx);
    if ( rc )
    {
        printk("Unable to setup Dom0 BSP context: %d\n", rc);
        return rc;
    }

    rc = dom0_setup_permissions(d);
    if ( rc )
    {
        panic("Unable to setup Dom0 permissions: %d\n", rc);
        return rc;
    }

    update_domain_wallclock_time(d);

    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);

    return 0;
}

static int __init acpi_count_intr_ovr(struct acpi_subtable_header *header,
                                     const unsigned long end)
{
    acpi_intr_overrides++;
    return 0;
}

static int __init acpi_set_intr_ovr(struct acpi_subtable_header *header,
                                    const unsigned long end)
{
    const struct acpi_madt_interrupt_override *intr =
        container_of(header, struct acpi_madt_interrupt_override, header);

    *intsrcovr = *intr;
    intsrcovr++;

    return 0;
}

static int __init acpi_count_nmi_src(struct acpi_subtable_header *header,
                                     const unsigned long end)
{
    acpi_nmi_sources++;
    return 0;
}

static int __init acpi_set_nmi_src(struct acpi_subtable_header *header,
                                   const unsigned long end)
{
    const struct acpi_madt_nmi_source *src =
        container_of(header, struct acpi_madt_nmi_source, header);

    *nmisrc = *src;
    nmisrc++;

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
    unsigned int i, max_vcpus;
    int rc;

    /* Count number of interrupt overrides in the MADT. */
    acpi_table_parse_madt(ACPI_MADT_TYPE_INTERRUPT_OVERRIDE,
                          acpi_count_intr_ovr, UINT_MAX);

    /* Count number of NMI sources in the MADT. */
    acpi_table_parse_madt(ACPI_MADT_TYPE_NMI_SOURCE, acpi_count_nmi_src,
                          UINT_MAX);

    max_vcpus = dom0_max_vcpus();
    /* Calculate the size of the crafted MADT. */
    size = sizeof(*madt);
    size += sizeof(*io_apic) * nr_ioapics;
    size += sizeof(*intsrcovr) * acpi_intr_overrides;
    size += sizeof(*nmisrc) * acpi_nmi_sources;
    size += sizeof(*x2apic) * max_vcpus;

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
    for ( i = 0; i < max_vcpus; i++ )
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

    /* Setup NMI sources. */
    nmisrc = (void *)intsrcovr;
    acpi_table_parse_madt(ACPI_MADT_TYPE_NMI_SOURCE, acpi_set_nmi_src,
                          acpi_nmi_sources);

    ASSERT(((void *)nmisrc - (void *)madt) == size);
    madt->header.length = size;
    /*
     * Calling acpi_tb_checksum here is a layering violation, but
     * introducing a wrapper for such simple usage seems overkill.
     */
    madt->header.checksum -= acpi_tb_checksum(ACPI_CAST_PTR(u8, madt), size);

    /* Place the new MADT in guest memory space. */
    if ( pvh_steal_ram(d, size, 0, GB(4), addr) )
    {
        printk("Unable to find allocate guest RAM for MADT\n");
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
            printk("Skipping table %.4s in non-ACPI non-reserved region\n",
                   sig);
            return false;
        }
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
    xsdt_paddr = rsdp->xsdt_physical_address;
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
                                sizeof(((struct hvm_start_info *)
                                        0)->rsdp_paddr),
                                d->vcpu[0]);
    if ( rc )
    {
        printk("Unable to copy RSDP into guest memory\n");
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

int __init dom0_construct_pvh(struct domain *d, const module_t *image,
                              unsigned long image_headroom,
                              module_t *initrd,
                              char *cmdline)
{
    paddr_t entry, start_info;
    int rc;

    printk(XENLOG_INFO "*** Building a PVH Dom%d ***\n", d->domain_id);

    iommu_hwdom_init(d);

    rc = pvh_setup_p2m(d);
    if ( rc )
    {
        printk("Failed to setup Dom0 physical memory map\n");
        return rc;
    }

    rc = pvh_load_kernel(d, image, image_headroom, initrd, bootstrap_map(image),
                         cmdline, &entry, &start_info);
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

    pvh_setup_mmcfg(d);

    printk("WARNING: PVH is an experimental mode with limited functionality\n");
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
