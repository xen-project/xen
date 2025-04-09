/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * MMIO related routines.
 *
 * Copyright (c) 2025 Cloud Software Group
 */

#include <xen/io.h>
#include <xen/mm.h>

#include <asm/p2m.h>

static int cf_check subpage_mmio_accept(struct vcpu *v, unsigned long addr)
{
    p2m_type_t t;
    mfn_t mfn = get_gfn_query_unlocked(v->domain, PFN_DOWN(addr), &t);

    return !mfn_eq(mfn, INVALID_MFN) && t == p2m_mmio_direct &&
           subpage_mmio_find_page(mfn);
}

/*
 * The guest has read access to those regions, and consequently read accesses
 * shouldn't fault.  However read-modify-write operations may take this path,
 * so handling of reads is necessary.
 */
static int cf_check subpage_mmio_read(
    struct vcpu *v, unsigned long addr, unsigned int len, unsigned long *data)
{
    struct domain *d = v->domain;
    unsigned long gfn = PFN_DOWN(addr);
    p2m_type_t t;
    mfn_t mfn;
    struct subpage_ro_range *entry;
    volatile void __iomem *mem;

    *data = ~0UL;

    if ( !len || len > 8 || (len & (len - 1)) || !IS_ALIGNED(addr, len) )
    {
        gprintk(XENLOG_ERR, "ignoring read to r/o MMIO subpage %#lx size %u\n",
                addr, len);
        return X86EMUL_OKAY;
    }

    mfn = get_gfn_query(d, gfn, &t);
    if ( mfn_eq(mfn, INVALID_MFN) || t != p2m_mmio_direct )
    {
        put_gfn(d, gfn);
        return X86EMUL_RETRY;
    }

    entry = subpage_mmio_find_page(mfn);
    if ( !entry )
    {
        put_gfn(d, gfn);
        return X86EMUL_OKAY;
    }

    mem = subpage_mmio_map_page(entry);
    if ( !mem )
    {
        put_gfn(d, gfn);
        gprintk(XENLOG_ERR,
                "Failed to map page for MMIO read at %#lx -> %#lx\n",
                addr, mfn_to_maddr(mfn) + PAGE_OFFSET(addr));
        return X86EMUL_OKAY;
    }

    *data = read_mmio(mem + PAGE_OFFSET(addr), len);

    put_gfn(d, gfn);
    return X86EMUL_OKAY;
}

static int cf_check subpage_mmio_write(
    struct vcpu *v, unsigned long addr, unsigned int len, unsigned long data)
{
    struct domain *d = v->domain;
    unsigned long gfn = PFN_DOWN(addr);
    p2m_type_t t;
    mfn_t mfn;

    if ( !len || len > 8 || (len & (len - 1)) || !IS_ALIGNED(addr, len) )
    {
        gprintk(XENLOG_ERR, "ignoring write to r/o MMIO subpage %#lx size %u\n",
                addr, len);
        return X86EMUL_OKAY;
    }

    mfn = get_gfn_query(d, gfn, &t);
    if ( mfn_eq(mfn, INVALID_MFN) || t != p2m_mmio_direct )
    {
        put_gfn(d, gfn);
        return X86EMUL_RETRY;
    }

    subpage_mmio_write_emulate(mfn, PAGE_OFFSET(addr), data, len);

    put_gfn(d, gfn);
    return X86EMUL_OKAY;
}

void register_subpage_ro_handler(struct domain *d)
{
    static const struct hvm_mmio_ops subpage_mmio_ops = {
        .check = subpage_mmio_accept,
        .read = subpage_mmio_read,
        .write = subpage_mmio_write,
    };

    register_mmio_handler(d, &subpage_mmio_ops);
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
