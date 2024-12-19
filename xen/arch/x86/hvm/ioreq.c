/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * hvm/io.c: hardware virtual machine I/O emulation
 *
 * Copyright (c) 2016 Citrix Systems Inc.
 */

#include <xen/domain.h>
#include <xen/event.h>
#include <xen/init.h>
#include <xen/ioreq.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/paging.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/trace.h>
#include <xen/vpci.h>

#include <asm/hvm/emulate.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/vmx/vmx.h>

#include <public/hvm/ioreq.h>
#include <public/hvm/params.h>

bool arch_ioreq_complete_mmio(void)
{
    return handle_mmio();
}

#ifdef CONFIG_ARCH_VCPU_IOREQ_COMPLETION
bool arch_vcpu_ioreq_completion(enum vio_completion completion)
{
    switch ( completion )
    {
    case VIO_realmode_completion:
    {
        struct hvm_emulate_ctxt ctxt;

        hvm_emulate_init_once(&ctxt, NULL, guest_cpu_user_regs());
        vmx_realmode_emulate_one(&ctxt);
        hvm_emulate_writeback(&ctxt);

        break;
    }

    default:
        ASSERT_UNREACHABLE();
        break;
    }

    return true;
}
#endif

static gfn_t hvm_alloc_legacy_ioreq_gfn(struct ioreq_server *s)
{
    struct domain *d = s->target;
    unsigned int i;

    BUILD_BUG_ON(HVM_PARAM_BUFIOREQ_PFN != HVM_PARAM_IOREQ_PFN + 1);

    for ( i = HVM_PARAM_IOREQ_PFN; i <= HVM_PARAM_BUFIOREQ_PFN; i++ )
    {
        if ( !test_and_clear_bit(i, &d->arch.hvm.ioreq_gfn.legacy_mask) )
            return _gfn(d->arch.hvm.params[i]);
    }

    return INVALID_GFN;
}

static gfn_t hvm_alloc_ioreq_gfn(struct ioreq_server *s)
{
    struct domain *d = s->target;
    unsigned int i;

    for ( i = 0; i < sizeof(d->arch.hvm.ioreq_gfn.mask) * 8; i++ )
    {
        if ( test_and_clear_bit(i, &d->arch.hvm.ioreq_gfn.mask) )
            return _gfn(d->arch.hvm.ioreq_gfn.base + i);
    }

    /*
     * If we are out of 'normal' GFNs then we may still have a 'legacy'
     * GFN available.
     */
    return hvm_alloc_legacy_ioreq_gfn(s);
}

static bool hvm_free_legacy_ioreq_gfn(struct ioreq_server *s,
                                      gfn_t gfn)
{
    struct domain *d = s->target;
    unsigned int i;

    for ( i = HVM_PARAM_IOREQ_PFN; i <= HVM_PARAM_BUFIOREQ_PFN; i++ )
    {
        if ( gfn_eq(gfn, _gfn(d->arch.hvm.params[i])) )
             break;
    }
    if ( i > HVM_PARAM_BUFIOREQ_PFN )
        return false;

    set_bit(i, &d->arch.hvm.ioreq_gfn.legacy_mask);
    return true;
}

static void hvm_free_ioreq_gfn(struct ioreq_server *s, gfn_t gfn)
{
    struct domain *d = s->target;
    unsigned int i = gfn_x(gfn) - d->arch.hvm.ioreq_gfn.base;

    ASSERT(!gfn_eq(gfn, INVALID_GFN));

    if ( !hvm_free_legacy_ioreq_gfn(s, gfn) )
    {
        ASSERT(i < sizeof(d->arch.hvm.ioreq_gfn.mask) * 8);
        set_bit(i, &d->arch.hvm.ioreq_gfn.mask);
    }
}

static void hvm_unmap_ioreq_gfn(struct ioreq_server *s, bool buf)
{
    struct ioreq_page *iorp = buf ? &s->bufioreq : &s->ioreq;

    if ( gfn_eq(iorp->gfn, INVALID_GFN) )
        return;

    destroy_ring_for_helper(&iorp->va, iorp->page);
    iorp->page = NULL;

    hvm_free_ioreq_gfn(s, iorp->gfn);
    iorp->gfn = INVALID_GFN;
}

static int hvm_map_ioreq_gfn(struct ioreq_server *s, bool buf)
{
    struct domain *d = s->target;
    struct ioreq_page *iorp = buf ? &s->bufioreq : &s->ioreq;
    int rc;

    if ( iorp->page )
    {
        /*
         * If a page has already been allocated (which will happen on
         * demand if ioreq_server_get_frame() is called), then
         * mapping a guest frame is not permitted.
         */
        if ( gfn_eq(iorp->gfn, INVALID_GFN) )
            return -EPERM;

        return 0;
    }

    if ( d->is_dying )
        return -EINVAL;

    iorp->gfn = hvm_alloc_ioreq_gfn(s);

    if ( gfn_eq(iorp->gfn, INVALID_GFN) )
        return -ENOMEM;

    rc = prepare_ring_for_helper(d, gfn_x(iorp->gfn), &iorp->page,
                                 &iorp->va);

    if ( rc )
        hvm_unmap_ioreq_gfn(s, buf);

    return rc;
}

static void hvm_remove_ioreq_gfn(struct ioreq_server *s, bool buf)
{
    struct domain *d = s->target;
    struct ioreq_page *iorp = buf ? &s->bufioreq : &s->ioreq;

    if ( gfn_eq(iorp->gfn, INVALID_GFN) )
        return;

    if ( p2m_remove_page(d, iorp->gfn, page_to_mfn(iorp->page), 0) )
        domain_crash(d);
    clear_page(iorp->va);
}

static int hvm_add_ioreq_gfn(struct ioreq_server *s, bool buf)
{
    struct domain *d = s->target;
    struct ioreq_page *iorp = buf ? &s->bufioreq : &s->ioreq;
    int rc;

    if ( gfn_eq(iorp->gfn, INVALID_GFN) )
        return 0;

    clear_page(iorp->va);

    rc = p2m_add_page(d, iorp->gfn, page_to_mfn(iorp->page), 0, p2m_ram_rw);
    if ( rc == 0 )
        paging_mark_pfn_dirty(d, _pfn(gfn_x(iorp->gfn)));

    return rc;
}

int arch_ioreq_server_map_pages(struct ioreq_server *s)
{
    int rc;

    rc = hvm_map_ioreq_gfn(s, false);

    if ( !rc && HANDLE_BUFIOREQ(s) )
        rc = hvm_map_ioreq_gfn(s, true);

    if ( rc )
        hvm_unmap_ioreq_gfn(s, false);

    return rc;
}

void arch_ioreq_server_unmap_pages(struct ioreq_server *s)
{
    hvm_unmap_ioreq_gfn(s, true);
    hvm_unmap_ioreq_gfn(s, false);
}

void arch_ioreq_server_enable(struct ioreq_server *s)
{
    hvm_remove_ioreq_gfn(s, false);
    hvm_remove_ioreq_gfn(s, true);
}

void arch_ioreq_server_disable(struct ioreq_server *s)
{
    hvm_add_ioreq_gfn(s, true);
    hvm_add_ioreq_gfn(s, false);
}

/* Called when target domain is paused */
void arch_ioreq_server_destroy(struct ioreq_server *s)
{
    p2m_set_ioreq_server(s->target, 0, s);
}

/* Called with ioreq_server lock held */
int arch_ioreq_server_map_mem_type(struct domain *d,
                                   struct ioreq_server *s,
                                   uint32_t flags)
{
    return p2m_set_ioreq_server(d, flags, s);
}

void arch_ioreq_server_map_mem_type_completed(struct domain *d,
                                              struct ioreq_server *s,
                                              uint32_t flags)
{
    if ( flags == 0 && read_atomic(&p2m_get_hostp2m(d)->ioreq.entry_count) )
        p2m_change_entry_type_global(d, p2m_ioreq_server, p2m_ram_rw);
}

bool arch_ioreq_server_destroy_all(struct domain *d)
{
    return relocate_portio_handler(d, 0xcf8, 0xcf8, 4);
}

bool arch_ioreq_server_get_type_addr(const struct domain *d,
                                     const ioreq_t *p,
                                     uint8_t *type,
                                     uint64_t *addr)
{
    unsigned int cf8 = d->arch.hvm.pci_cf8;

    if ( p->type != IOREQ_TYPE_COPY && p->type != IOREQ_TYPE_PIO )
        return false;

    if ( p->type == IOREQ_TYPE_PIO &&
         (p->addr & ~3) == 0xcfc &&
         CF8_ENABLED(cf8) )
    {
        unsigned int x86_fam, reg;
        pci_sbdf_t sbdf;

        reg = hvm_pci_decode_addr(cf8, p->addr, &sbdf);

        /* PCI config data cycle */
        *type = XEN_DMOP_IO_RANGE_PCI;
        *addr = ((uint64_t)sbdf.sbdf << 32) | reg;
        /* AMD extended configuration space access? */
        if ( CF8_ADDR_HI(cf8) &&
             d->arch.cpuid->x86_vendor == X86_VENDOR_AMD &&
             (x86_fam = get_cpu_family(
                 d->arch.cpuid->basic.raw_fms, NULL, NULL)) >= 0x10 &&
             x86_fam < 0x17 )
        {
            uint64_t msr_val;

            if ( !rdmsr_safe(MSR_AMD64_NB_CFG, msr_val) &&
                 (msr_val & (1ULL << AMD64_NB_CFG_CF8_EXT_ENABLE_BIT)) )
                *addr |= CF8_ADDR_HI(cf8);
        }
    }
    else
    {
        *type = (p->type == IOREQ_TYPE_PIO) ?
                 XEN_DMOP_IO_RANGE_PORT : XEN_DMOP_IO_RANGE_MEMORY;
        *addr = p->addr;
    }

    return true;
}

static int cf_check hvm_access_cf8(
    int dir, unsigned int port, unsigned int bytes, uint32_t *val)
{
    struct domain *d = current->domain;

    if ( dir == IOREQ_WRITE && bytes == 4 )
        d->arch.hvm.pci_cf8 = *val;

    /* We always need to fall through to the catch all emulator */
    return X86EMUL_UNHANDLEABLE;
}

void arch_ioreq_domain_init(struct domain *d)
{
    register_portio_handler(d, 0xcf8, 4, hvm_access_cf8);
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
