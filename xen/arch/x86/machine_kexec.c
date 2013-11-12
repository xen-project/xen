/******************************************************************************
 * machine_kexec.c
 *
 * Copyright (C) 2013 Citrix Systems R&D Ltd.
 *
 * Portions derived from Linux's arch/x86/kernel/machine_kexec_64.c.
 *
 *   Copyright (C) 2002-2005 Eric Biederman  <ebiederm@xmission.com>
 *
 * Xen port written by:
 * - Simon 'Horms' Horman <horms@verge.net.au>
 * - Magnus Damm <magnus@valinux.co.jp>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <xen/types.h>
#include <xen/kexec.h>
#include <xen/guest_access.h>
#include <asm/fixmap.h>
#include <asm/hpet.h>
#include <asm/page.h>
#include <asm/machine_kexec.h>

/*
 * Add a mapping for a page to the page tables used during kexec.
 */
int machine_kexec_add_page(struct kexec_image *image, unsigned long vaddr,
                           unsigned long maddr)
{
    struct page_info *l4_page;
    struct page_info *l3_page;
    struct page_info *l2_page;
    struct page_info *l1_page;
    l4_pgentry_t *l4 = NULL;
    l3_pgentry_t *l3 = NULL;
    l2_pgentry_t *l2 = NULL;
    l1_pgentry_t *l1 = NULL;
    int ret = -ENOMEM;

    l4_page = image->aux_page;
    if ( !l4_page )
    {
        l4_page = kimage_alloc_control_page(image, 0);
        if ( !l4_page )
            goto out;
        image->aux_page = l4_page;
    }

    l4 = __map_domain_page(l4_page);
    l4 += l4_table_offset(vaddr);
    if ( !(l4e_get_flags(*l4) & _PAGE_PRESENT) )
    {
        l3_page = kimage_alloc_control_page(image, 0);
        if ( !l3_page )
            goto out;
        l4e_write(l4, l4e_from_page(l3_page, __PAGE_HYPERVISOR));
    }
    else
        l3_page = l4e_get_page(*l4);

    l3 = __map_domain_page(l3_page);
    l3 += l3_table_offset(vaddr);
    if ( !(l3e_get_flags(*l3) & _PAGE_PRESENT) )
    {
        l2_page = kimage_alloc_control_page(image, 0);
        if ( !l2_page )
            goto out;
        l3e_write(l3, l3e_from_page(l2_page, __PAGE_HYPERVISOR));
    }
    else
        l2_page = l3e_get_page(*l3);

    l2 = __map_domain_page(l2_page);
    l2 += l2_table_offset(vaddr);
    if ( !(l2e_get_flags(*l2) & _PAGE_PRESENT) )
    {
        l1_page = kimage_alloc_control_page(image, 0);
        if ( !l1_page )
            goto out;
        l2e_write(l2, l2e_from_page(l1_page, __PAGE_HYPERVISOR));
    }
    else
        l1_page = l2e_get_page(*l2);

    l1 = __map_domain_page(l1_page);
    l1 += l1_table_offset(vaddr);
    l1e_write(l1, l1e_from_pfn(maddr >> PAGE_SHIFT, __PAGE_HYPERVISOR));

    ret = 0;
out:
    if ( l1 )
        unmap_domain_page(l1);
    if ( l2 )
        unmap_domain_page(l2);
    if ( l3 )
        unmap_domain_page(l3);
    if ( l4 )
        unmap_domain_page(l4);
    return ret;
}

int machine_kexec_load(struct kexec_image *image)
{
    void *code_page;
    int ret;

    switch ( image->arch )
    {
    case EM_386:
    case EM_X86_64:
        break;
    default:
        return -EINVAL;
    }

    code_page = __map_domain_page(image->control_code_page);
    memcpy(code_page, kexec_reloc, kexec_reloc_size);
    unmap_domain_page(code_page);

    /*
     * Add a mapping for the control code page to the same virtual
     * address as kexec_reloc.  This allows us to keep running after
     * these page tables are loaded in kexec_reloc.
     */
    ret = machine_kexec_add_page(image, (unsigned long)kexec_reloc,
                                 page_to_maddr(image->control_code_page));
    if ( ret < 0 )
        return ret;

    return 0;
}

void machine_kexec_unload(struct kexec_image *image)
{
    /* no-op. kimage_free() frees all control pages. */
}

void machine_reboot_kexec(struct kexec_image *image)
{
    BUG_ON(smp_processor_id() != 0);
    smp_send_stop();
    machine_kexec(image);
    BUG();
}

void machine_kexec(struct kexec_image *image)
{
    int i;
    unsigned long reloc_flags = 0;

    /* We are about to permenantly jump out of the Xen context into the kexec
     * purgatory code.  We really dont want to be still servicing interupts.
     */
    local_irq_disable();

    /* Now regular interrupts are disabled, we need to reduce the impact
     * of interrupts not disabled by 'cli'.
     *
     * The NMI handlers have already been set up nmi_shootdown_cpus().  All
     * pcpus other than us have the nmi_crash handler, while we have the nop
     * handler.
     *
     * The MCE handlers touch extensive areas of Xen code and data.  At this
     * point, there is nothing we can usefully do, so set the nop handler.
     */
    for ( i = 0; i < nr_cpu_ids; i++ )
    {
        if ( idt_tables[i] == NULL )
            continue;
        _update_gate_addr_lower(&idt_tables[i][TRAP_machine_check], &trap_nop);
    }

    /* Explicitly enable NMIs on this CPU.  Some crashdump kernels do
     * not like running with NMIs disabled. */
    enable_nmis();

    if ( image->arch == EM_386 )
        reloc_flags |= KEXEC_RELOC_FLAG_COMPAT;

    kexec_reloc(page_to_maddr(image->control_code_page),
                page_to_maddr(image->aux_page),
                image->head, image->entry_maddr, reloc_flags);
}

int machine_kexec_get(xen_kexec_range_t *range)
{
	if (range->range != KEXEC_RANGE_MA_XEN)
		return -EINVAL;
	return machine_kexec_get_xen(range);
}

void arch_crash_save_vmcoreinfo(void)
{
	VMCOREINFO_SYMBOL(dom_xen);
	VMCOREINFO_SYMBOL(dom_io);

	VMCOREINFO_SYMBOL_ALIAS(pgd_l4, idle_pg_table);
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
