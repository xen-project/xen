/******************************************************************************
 *
 * Copyright (c) 2007 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <xen/types.h>
#include <xen/version.h>
#include <xen/errno.h>
#include <xen/sched.h>

#include <asm/fpswa.h>
#include <asm/dom_fw.h>
#include <asm/dom_fw_common.h>

#include <linux/sort.h>

uint32_t
xen_ia64_version(struct domain *unused)
{
    return (xen_major_version() << 16) | xen_minor_version();
}

int
xen_ia64_fpswa_revision(struct domain *d, unsigned int *revision)
{
    if (fpswa_interface == NULL)
        return -ENOSYS;

    *revision = fpswa_interface->revision;
    return 0;
}

int
xen_ia64_is_vcpu_allocated(struct domain *d, uint32_t vcpu)
{
    return d->vcpu[vcpu] != NULL;
}

int xen_ia64_is_running_on_sim(struct domain *unused)
{
    extern unsigned long running_on_sim;
    return running_on_sim;
}

int
xen_ia64_is_dom0(struct domain *d)
{
    return d == dom0;
}

static void
dom_fw_domain_init(struct domain *d, struct fw_tables *tables)
{
    /* Initialise for EFI_SET_VIRTUAL_ADDRESS_MAP emulation */
    d->arch.efi_runtime = &tables->efi_runtime;
    d->arch.fpswa_inf   = &tables->fpswa_inf;
    d->arch.sal_data    = &tables->sal_data;
}

static int
dom_fw_set_convmem_end(struct domain *d)
{
    xen_ia64_memmap_info_t* memmap_info;
    efi_memory_desc_t *md;
    void *p;
    void *memmap_start;
    void *memmap_end;

    if (d->shared_info->arch.memmap_info_pfn == 0)
        return -EINVAL;

    memmap_info = domain_mpa_to_imva(d, d->shared_info->arch.memmap_info_pfn << PAGE_SHIFT);
    if (memmap_info->efi_memmap_size == 0 ||
        memmap_info->efi_memdesc_size != sizeof(*md) ||
        memmap_info->efi_memdesc_version !=
        EFI_MEMORY_DESCRIPTOR_VERSION)
        return -EINVAL;

    /* only 1page case is supported */
    if (d->shared_info->arch.memmap_info_num_pages != 1)
        return -ENOSYS;

    memmap_start = &memmap_info->memdesc;
    memmap_end = memmap_start + memmap_info->efi_memmap_size;

    /* XXX Currently the table must be in a single page. */
    if ((unsigned long)memmap_end > (unsigned long)memmap_info + PAGE_SIZE)
        return -EINVAL;

    /* sort it bofore use
     * XXX: this is created by user space domain builder so that
     * we should check its integrity */
    sort(&memmap_info->memdesc,
         memmap_info->efi_memmap_size / memmap_info->efi_memdesc_size,
         memmap_info->efi_memdesc_size,
         efi_mdt_cmp, NULL);

    if (d->arch.convmem_end == 0)
        d->arch.convmem_end = d->max_pages << PAGE_SHIFT;

    for (p = memmap_start; p < memmap_end; p += memmap_info->efi_memdesc_size) {
        unsigned long end;

        md = p;
        end = md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT);

        if (md->attribute == EFI_MEMORY_WB &&
            md->type == EFI_CONVENTIONAL_MEMORY &&
            md->num_pages > 0 &&
            d->arch.convmem_end < end)
            d->arch.convmem_end = end;
    }
    return 0;
}

/* allocate a page for fw
 * guest_setup() @ libxc/xc_linux_build.c does for domU
 */
static inline void
assign_new_domain_page_if_dom0(struct domain *d, unsigned long mpaddr)
{
    if (d == dom0)
        assign_new_domain0_page(d, mpaddr);
}

int
dom_fw_setup(domain_t *d, unsigned long bp_mpa, unsigned long maxmem)
{
    int old_domu_builder = 0;
    struct xen_ia64_boot_param *bp;
    struct fw_tables *imva_tables_base;

    BUILD_BUG_ON(sizeof(struct fw_tables) >
                 (FW_TABLES_END_PADDR - FW_TABLES_BASE_PADDR));

    /* Create page for boot_param.  */
    assign_new_domain_page_if_dom0(d, bp_mpa);
    bp = domain_mpa_to_imva(d, bp_mpa);
    if (d != dom0) {
        /*
         * XXX kludge.
         * when XEN_DOMCTL_arch_setup is called, shared_info can't
         * be accessed by libxc so that memmap_info_pfn isn't
         * initialized. But dom_fw_set_convmem_end() requires it, 
         * so here we initialize it.
         * note: domain builder may overwrite memmap_info_num_pages,
         *       memmap_info_pfns later.
         */
        if (bp->efi_memmap_size == 0 || 
            XEN_IA64_MEMMAP_INFO_NUM_PAGES(bp) == 0 ||
            XEN_IA64_MEMMAP_INFO_PFN(bp) == 0) {
            /* old domain builder compatibility */
            d->shared_info->arch.memmap_info_num_pages = 1;
            d->shared_info->arch.memmap_info_pfn = (maxmem >> PAGE_SHIFT) - 1;
            old_domu_builder = 1;
        } else {
            d->shared_info->arch.memmap_info_num_pages =
                XEN_IA64_MEMMAP_INFO_NUM_PAGES(bp);
            d->shared_info->arch.memmap_info_pfn =
                XEN_IA64_MEMMAP_INFO_PFN(bp);
            /* currently multi page memmap isn't supported */
            if (d->shared_info->arch.memmap_info_num_pages != 1)
                return -ENOSYS;
        }
    }

    /* Create page for FW tables.  */
    assign_new_domain_page_if_dom0(d, FW_TABLES_BASE_PADDR);
    imva_tables_base = (struct fw_tables *)domain_mpa_to_imva
                                      (d, FW_TABLES_BASE_PADDR);
    /* Create page for acpi tables.  */
    if (d != dom0 && old_domu_builder) {
        struct fake_acpi_tables *imva;
        imva = domain_mpa_to_imva(d, FW_ACPI_BASE_PADDR);
        dom_fw_fake_acpi(d, imva);
    }
    if (d == dom0 || old_domu_builder) {
        int ret;
        unsigned long imva_hypercall_base;

        /* Create page for hypercalls.  */
        assign_new_domain_page_if_dom0(d, FW_HYPERCALL_BASE_PADDR);
        imva_hypercall_base = (unsigned long)domain_mpa_to_imva
            (d, FW_HYPERCALL_BASE_PADDR);

        ret = dom_fw_init(d, d->arch.breakimm, bp,
                          imva_tables_base, imva_hypercall_base, maxmem);
        if (ret < 0)
            return ret;
    }

    dom_fw_domain_init(d, imva_tables_base);
    return dom_fw_set_convmem_end(d);
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
