/*
 * Copyright (C) 2009, Mukesh Rathor, Oracle Corp.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/compile.h>
#include <xen/mm.h>
#include <xen/domain_page.h>
#include <xen/guest_access.h>
#include <asm/debugger.h>
#include <asm/p2m.h>

/* 
 * This file for general routines common to more than one debugger, like kdb,
 * gdbsx, etc..
 */

#ifdef XEN_KDB_CONFIG
#include "../kdb/include/kdbdefs.h"
#include "../kdb/include/kdbproto.h"
#define DBGP(...) {(kdbdbg) ? kdbp(__VA_ARGS__):0;}
#define DBGP1(...) {(kdbdbg>1) ? kdbp(__VA_ARGS__):0;}
#define DBGP2(...) {(kdbdbg>2) ? kdbp(__VA_ARGS__):0;}
#else
#define DBGP1(...) ((void)0)
#define DBGP2(...) ((void)0)
#endif

typedef unsigned long dbgva_t;
typedef unsigned char dbgbyte_t;

/* Returns: mfn for the given (hvm guest) vaddr */
static unsigned long 
dbg_hvm_va2mfn(dbgva_t vaddr, struct domain *dp, int toaddr,
                unsigned long *gfn)
{
    unsigned long mfn;
    uint32_t pfec = PFEC_page_present;
    p2m_type_t gfntype;

    DBGP2("vaddr:%lx domid:%d\n", vaddr, dp->domain_id);

    *gfn = paging_gva_to_gfn(dp->vcpu[0], vaddr, &pfec);
    if ( *gfn == INVALID_GFN )
    {
        DBGP2("kdb:bad gfn from gva_to_gfn\n");
        return INVALID_MFN;
    }

    mfn = mfn_x(get_gfn(dp, *gfn, &gfntype)); 
    if ( p2m_is_readonly(gfntype) && toaddr )
    {
        DBGP2("kdb:p2m_is_readonly: gfntype:%x\n", gfntype);
        mfn = INVALID_MFN;
    }
    else
        DBGP2("X: vaddr:%lx domid:%d mfn:%lx\n", vaddr, dp->domain_id, mfn);

    if ( mfn == INVALID_MFN )
    {
        put_gfn(dp, *gfn);
        *gfn = INVALID_GFN;
    }

    return mfn;
}

/* 
 * pgd3val: this is the value of init_mm.pgd[3] in a PV guest. It is optional.
 *          This to assist debug of modules in the guest. The kernel address 
 *          space seems is always mapped, but modules are not necessarily 
 *          mapped in any arbitraty guest cr3 that we pick if pgd3val is 0. 
 *          Modules should always be addressible if we use cr3 from init_mm. 
 *          Since pgd3val is already a pgd value, cr3->pgd[3], we just need to 
 *          do 2 level lookups.
 *
 * NOTE: 4 level paging works for 32 PAE guests also because cpu runs in IA32-e
 *       mode.
 * Returns: mfn for the given (pv guest) vaddr 
 */
static unsigned long 
dbg_pv_va2mfn(dbgva_t vaddr, struct domain *dp, uint64_t pgd3val)
{
    l4_pgentry_t l4e, *l4t;
    l3_pgentry_t l3e, *l3t;
    l2_pgentry_t l2e, *l2t;
    l1_pgentry_t l1e, *l1t;
    unsigned long cr3 = (pgd3val ? pgd3val : dp->vcpu[0]->arch.cr3);
    unsigned long mfn = cr3 >> PAGE_SHIFT;

    DBGP2("vaddr:%lx domid:%d cr3:%lx pgd3:%lx\n", vaddr, dp->domain_id, 
          cr3, pgd3val);

    if ( pgd3val == 0 )
    {
        l4t = map_domain_page(_mfn(mfn));
        l4e = l4t[l4_table_offset(vaddr)];
        unmap_domain_page(l4t);
        mfn = l4e_get_pfn(l4e);
        DBGP2("l4t:%p l4to:%lx l4e:%lx mfn:%lx\n", l4t, 
              l4_table_offset(vaddr), l4e, mfn);
        if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
        {
            DBGP1("l4 PAGE not present. vaddr:%lx cr3:%lx\n", vaddr, cr3);
            return INVALID_MFN;
        }

        l3t = map_domain_page(_mfn(mfn));
        l3e = l3t[l3_table_offset(vaddr)];
        unmap_domain_page(l3t);
        mfn = l3e_get_pfn(l3e);
        DBGP2("l3t:%p l3to:%lx l3e:%lx mfn:%lx\n", l3t, 
              l3_table_offset(vaddr), l3e, mfn);
        if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) ||
             (l3e_get_flags(l3e) & _PAGE_PSE) )
        {
            DBGP1("l3 PAGE not present. vaddr:%lx cr3:%lx\n", vaddr, cr3);
            return INVALID_MFN;
        }
    }

    l2t = map_domain_page(_mfn(mfn));
    l2e = l2t[l2_table_offset(vaddr)];
    unmap_domain_page(l2t);
    mfn = l2e_get_pfn(l2e);
    DBGP2("l2t:%p l2to:%lx l2e:%lx mfn:%lx\n", l2t, l2_table_offset(vaddr),
          l2e, mfn);
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) ||
         (l2e_get_flags(l2e) & _PAGE_PSE) )
    {
        DBGP1("l2 PAGE not present. vaddr:%lx cr3:%lx\n", vaddr, cr3);
        return INVALID_MFN;
    }
    l1t = map_domain_page(_mfn(mfn));
    l1e = l1t[l1_table_offset(vaddr)];
    unmap_domain_page(l1t);
    mfn = l1e_get_pfn(l1e);
    DBGP2("l1t:%p l1to:%lx l1e:%lx mfn:%lx\n", l1t, l1_table_offset(vaddr),
          l1e, mfn);

    return mfn_valid(mfn) ? mfn : INVALID_MFN;
}

/* Returns: number of bytes remaining to be copied */
unsigned int dbg_rw_guest_mem(struct domain *dp, void * __user gaddr,
                              void * __user buf, unsigned int len,
                              bool_t toaddr, uint64_t pgd3)
{
    while ( len > 0 )
    {
        char *va;
        unsigned long addr = (unsigned long)gaddr;
        unsigned long mfn, gfn = INVALID_GFN, pagecnt;

        pagecnt = min_t(long, PAGE_SIZE - (addr & ~PAGE_MASK), len);

        mfn = (has_hvm_container_domain(dp)
               ? dbg_hvm_va2mfn(addr, dp, toaddr, &gfn)
               : dbg_pv_va2mfn(addr, dp, pgd3));
        if ( mfn == INVALID_MFN ) 
            break;

        va = map_domain_page(_mfn(mfn));
        va = va + (addr & (PAGE_SIZE-1));

        if ( toaddr )
        {
            copy_from_user(va, buf, pagecnt);    /* va = buf */
            paging_mark_dirty(dp, mfn);
        }
        else
        {
            copy_to_user(buf, va, pagecnt);    /* buf = va */
        }

        unmap_domain_page(va);
        if ( gfn != INVALID_GFN )
            put_gfn(dp, gfn);

        addr += pagecnt;
        buf += pagecnt;
        len -= pagecnt;
    }

    return len;
}

/* 
 * addr is hypervisor addr if domid == DOMID_IDLE, else it's guest addr
 * buf is debugger buffer.
 * if toaddr, then addr = buf (write to addr), else buf = addr (rd from guest)
 * pgd3: value of init_mm.pgd[3] in guest. see above.
 * Returns: number of bytes remaining to be copied. 
 */
unsigned int dbg_rw_mem(void * __user addr, void * __user buf,
                        unsigned int len, domid_t domid, bool_t toaddr,
                        uint64_t pgd3)
{
    DBGP2("gmem:addr:%lx buf:%p len:$%u domid:%d toaddr:%x\n",
          addr, buf, len, domid, toaddr);

    if ( domid == DOMID_IDLE )
    {
        if ( toaddr )
            len = __copy_to_user(addr, buf, len);
        else
            len = __copy_from_user(buf, addr, len);
    }
    else
    {
        struct domain *d = get_domain_by_id(domid);

        if ( d )
        {
            if ( !d->is_dying )
                len = dbg_rw_guest_mem(d, addr, buf, len, toaddr, pgd3);
            put_domain(d);
        }
    }

    DBGP2("gmem:exit:len:$%d\n", len);
    return len;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
