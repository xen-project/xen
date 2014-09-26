/*
 * nested_ept.c: Handling virtulized EPT for guest in nested case.
 *
 * Copyright (c) 2012, Intel Corporation
 *  Xiantao Zhang <xiantao.zhang@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */
#include <xen/mem_event.h>
#include <xen/event.h>
#include <public/mem_event.h>
#include <asm/domain.h>
#include <asm/page.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/mem_sharing.h>
#include <asm/hap.h>
#include <asm/hvm/support.h>

#include <asm/hvm/nestedhvm.h>

#include "private.h"

#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vvmx.h>

/* EPT always use 4-level paging structure */
#define GUEST_PAGING_LEVELS 4
#include <asm/guest_pt.h>

/* Must reserved bits in all level entries  */
#define EPT_MUST_RSV_BITS (((1ull << PADDR_BITS) - 1) & \
                           ~((1ull << paddr_bits) - 1))

#define NEPT_CAP_BITS       \
        (VMX_EPT_INVEPT_ALL_CONTEXT | VMX_EPT_INVEPT_SINGLE_CONTEXT | \
         VMX_EPT_INVEPT_INSTRUCTION | VMX_EPT_SUPERPAGE_1GB |         \
         VMX_EPT_SUPERPAGE_2MB | VMX_EPT_MEMORY_TYPE_WB |             \
         VMX_EPT_MEMORY_TYPE_UC | VMX_EPT_WALK_LENGTH_4_SUPPORTED |   \
         VMX_EPT_EXEC_ONLY_SUPPORTED)

#define NVPID_CAP_BITS \
        (VMX_VPID_INVVPID_INSTRUCTION | VMX_VPID_INVVPID_INDIVIDUAL_ADDR | \
         VMX_VPID_INVVPID_SINGLE_CONTEXT | VMX_VPID_INVVPID_ALL_CONTEXT |  \
         VMX_VPID_INVVPID_SINGLE_CONTEXT_RETAINING_GLOBAL)

#define NEPT_1G_ENTRY_FLAG (1 << 11)
#define NEPT_2M_ENTRY_FLAG (1 << 10)
#define NEPT_4K_ENTRY_FLAG (1 << 9)

bool_t nept_sp_entry(ept_entry_t e)
{
    return !!(e.sp);
}

static bool_t nept_rsv_bits_check(ept_entry_t e, uint32_t level)
{
    uint64_t rsv_bits = EPT_MUST_RSV_BITS;

    switch ( level )
    {
    case 1:
        break;
    case 2 ... 3:
        if ( nept_sp_entry(e) )
            rsv_bits |=  ((1ull << (9 * (level - 1))) - 1) << PAGE_SHIFT;
        else
            rsv_bits |= EPTE_EMT_MASK | EPTE_IGMT_MASK;
        break;
    case 4:
        rsv_bits |= EPTE_EMT_MASK | EPTE_IGMT_MASK | EPTE_SUPER_PAGE_MASK;
        break;
    default:
        gdprintk(XENLOG_ERR,"Unsupported EPT paging level: %d\n", level);
        BUG();
        break;
    }
    return !!(e.epte & rsv_bits);
}

/* EMT checking*/
static bool_t nept_emt_bits_check(ept_entry_t e, uint32_t level)
{
    if ( e.sp || level == 1 )
    {
        if ( e.emt == EPT_EMT_RSV0 || e.emt == EPT_EMT_RSV1 ||
             e.emt == EPT_EMT_RSV2 )
            return 1;
    }
    return 0;
}

static bool_t nept_permission_check(uint32_t rwx_acc, uint32_t rwx_bits)
{
    return !(EPTE_RWX_MASK & rwx_acc & ~rwx_bits);
}

/* nept's non-present check */
static bool_t nept_non_present_check(ept_entry_t e)
{
    if ( e.epte & EPTE_RWX_MASK )
        return 0;
    return 1;
}

uint64_t nept_get_ept_vpid_cap(void)
{
    uint64_t caps = 0;

    if ( cpu_has_vmx_ept )
        caps |= NEPT_CAP_BITS;
    if ( !cpu_has_vmx_ept_exec_only_supported )
        caps &= ~VMX_EPT_EXEC_ONLY_SUPPORTED;
    if ( cpu_has_vmx_vpid )
        caps |= NVPID_CAP_BITS;

    return caps;
}

static bool_t nept_rwx_bits_check(ept_entry_t e)
{
    /*write only or write/execute only*/
    uint8_t rwx_bits = e.epte & EPTE_RWX_MASK;

    if ( rwx_bits == ept_access_w || rwx_bits == ept_access_wx )
        return 1;

    if ( rwx_bits == ept_access_x &&
         !(nept_get_ept_vpid_cap() & VMX_EPT_EXEC_ONLY_SUPPORTED) )
        return 1;

    return 0;
}

/* nept's misconfiguration check */
static bool_t nept_misconfiguration_check(ept_entry_t e, uint32_t level)
{
    return nept_rsv_bits_check(e, level) ||
           nept_emt_bits_check(e, level) ||
           nept_rwx_bits_check(e);
}

static int ept_lvl_table_offset(unsigned long gpa, int lvl)
{
    return (gpa >> (EPT_L4_PAGETABLE_SHIFT -(4 - lvl) * 9)) &
           (EPT_PAGETABLE_ENTRIES - 1);
}

static uint32_t
nept_walk_tables(struct vcpu *v, unsigned long l2ga, ept_walk_t *gw)
{
    int lvl;
    p2m_type_t p2mt;
    uint32_t rc = 0, ret = 0, gflags;
    struct domain *d = v->domain;
    struct p2m_domain *p2m = d->arch.p2m;
    gfn_t base_gfn = _gfn(nhvm_vcpu_p2m_base(v) >> PAGE_SHIFT);
    mfn_t lxmfn;
    ept_entry_t *lxp = NULL;

    memset(gw, 0, sizeof(*gw));

    for (lvl = 4; lvl > 0; lvl--)
    {
        lxp = map_domain_gfn(p2m, base_gfn, &lxmfn, &p2mt, P2M_ALLOC, &rc);
        if ( !lxp )
            goto map_err;
        gw->lxe[lvl] = lxp[ept_lvl_table_offset(l2ga, lvl)];
        unmap_domain_page(lxp);
        put_page(mfn_to_page(mfn_x(lxmfn)));

        if ( nept_non_present_check(gw->lxe[lvl]) )
            goto non_present;

        if ( nept_misconfiguration_check(gw->lxe[lvl], lvl) )
            goto misconfig_err;

        if ( (lvl == 2 || lvl == 3) && nept_sp_entry(gw->lxe[lvl]) )
        {
            /* Generate a fake l1 table entry so callers don't all
             * have to understand superpages. */
            unsigned long gfn_lvl_mask =  (1ull << ((lvl - 1) * 9)) - 1;
            gfn_t start = _gfn(gw->lxe[lvl].mfn);
            /* Increment the pfn by the right number of 4k pages. */
            start = _gfn((gfn_x(start) & ~gfn_lvl_mask) +
                     ((l2ga >> PAGE_SHIFT) & gfn_lvl_mask));
            gflags = (gw->lxe[lvl].epte & EPTE_FLAG_MASK) |
                     (lvl == 3 ? NEPT_1G_ENTRY_FLAG: NEPT_2M_ENTRY_FLAG);
            gw->lxe[0].epte = (gfn_x(start) << PAGE_SHIFT) | gflags;
            goto done;
        }
        if ( lvl > 1 )
            base_gfn = _gfn(gw->lxe[lvl].mfn);
    }

    /* If this is not a super entry, we can reach here. */
    gflags = (gw->lxe[1].epte & EPTE_FLAG_MASK) | NEPT_4K_ENTRY_FLAG;
    gw->lxe[0].epte = (gw->lxe[1].epte & PAGE_MASK) | gflags;

done:
    ret = EPT_TRANSLATE_SUCCEED;
    goto out;

map_err:
    if ( rc == _PAGE_PAGED )
    {
        ret = EPT_TRANSLATE_RETRY;
        goto out;
    }
    /* fall through to misconfig error */
misconfig_err:
    ret =  EPT_TRANSLATE_MISCONFIG;
    goto out;

non_present:
    ret = EPT_TRANSLATE_VIOLATION;
    /* fall through. */
out:
    return ret;
}

/* Translate a L2 guest address to L1 gpa via L1 EPT paging structure */

int nept_translate_l2ga(struct vcpu *v, paddr_t l2ga,
                        unsigned int *page_order, uint32_t rwx_acc,
                        unsigned long *l1gfn, uint8_t *p2m_acc,
                        uint64_t *exit_qual, uint32_t *exit_reason)
{
    uint32_t rc, rwx_bits = 0;
    ept_walk_t gw;
    rwx_acc &= EPTE_RWX_MASK;

    *l1gfn = INVALID_GFN;

    rc = nept_walk_tables(v, l2ga, &gw);
    switch ( rc )
    {
    case EPT_TRANSLATE_SUCCEED:
        if ( likely(gw.lxe[0].epte & NEPT_2M_ENTRY_FLAG) )
        {
            rwx_bits = gw.lxe[4].epte & gw.lxe[3].epte & gw.lxe[2].epte &
                       EPTE_RWX_MASK;
            *page_order = 9;
        }
        else if ( gw.lxe[0].epte & NEPT_4K_ENTRY_FLAG )
        {
            rwx_bits = gw.lxe[4].epte & gw.lxe[3].epte & gw.lxe[2].epte &
                       gw.lxe[1].epte & EPTE_RWX_MASK;
            *page_order = 0;
        }
        else if ( gw.lxe[0].epte & NEPT_1G_ENTRY_FLAG  )
        {
            rwx_bits = gw.lxe[4].epte & gw.lxe[3].epte  & EPTE_RWX_MASK;
            *page_order = 18;
        }
        else
        {
            gdprintk(XENLOG_ERR, "Uncorrect l1 entry!\n");
            BUG();
        }
        if ( nept_permission_check(rwx_acc, rwx_bits) )
        {
            *l1gfn = gw.lxe[0].mfn;
            *p2m_acc = (uint8_t)rwx_bits;
            break;
        }
        rc = EPT_TRANSLATE_VIOLATION;
    /* Fall through to EPT violation if permission check fails. */
    case EPT_TRANSLATE_VIOLATION:
        *exit_qual = (*exit_qual & 0xffffffc0) | (rwx_bits << 3) | rwx_acc;
        *exit_reason = EXIT_REASON_EPT_VIOLATION;
        break;

    case EPT_TRANSLATE_MISCONFIG:
        rc = EPT_TRANSLATE_MISCONFIG;
        *exit_qual = 0;
        *exit_reason = EXIT_REASON_EPT_MISCONFIG;
        break;
    case EPT_TRANSLATE_RETRY:
        break;
    default:
        gdprintk(XENLOG_ERR, "Unsupported ept translation type!:%d\n", rc);
        BUG();
        break;
    }
    return rc;
}
