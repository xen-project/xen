/******************************************************************************
 * arch/x86/pv/shim.c
 *
 * Functionaltiy for PV Shim mode
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */
#include <xen/hypercall.h>
#include <xen/init.h>
#include <xen/types.h>

#include <asm/apic.h>
#include <asm/dom0_build.h>
#include <asm/guest.h>
#include <asm/pv/mm.h>

#ifndef CONFIG_PV_SHIM_EXCLUSIVE
bool pv_shim;
boolean_param("pv-shim", pv_shim);
#endif

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_USER| \
                 _PAGE_GUEST_KERNEL)
#define COMPAT_L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)

static void __init replace_va_mapping(struct domain *d, l4_pgentry_t *l4start,
                                      unsigned long va, unsigned long mfn)
{
    struct page_info *page;
    l4_pgentry_t *pl4e;
    l3_pgentry_t *pl3e;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;

    pl4e = l4start + l4_table_offset(va);
    pl3e = l4e_to_l3e(*pl4e);
    pl3e += l3_table_offset(va);
    pl2e = l3e_to_l2e(*pl3e);
    pl2e += l2_table_offset(va);
    pl1e = l2e_to_l1e(*pl2e);
    pl1e += l1_table_offset(va);

    page = mfn_to_page(l1e_get_pfn(*pl1e));
    put_page_and_type(page);

    *pl1e = l1e_from_pfn(mfn, (!is_pv_32bit_domain(d) ? L1_PROT
                                                      : COMPAT_L1_PROT));
}

void __init pv_shim_setup_dom(struct domain *d, l4_pgentry_t *l4start,
                              unsigned long va_start, unsigned long store_va,
                              unsigned long console_va, unsigned long vphysmap,
                              start_info_t *si)
{
    uint64_t param = 0;
    long rc;

#define SET_AND_MAP_PARAM(p, si, va) ({                                        \
    rc = xen_hypercall_hvm_get_param(p, &param);                               \
    if ( rc )                                                                  \
        panic("Unable to get " #p "\n");                                       \
    (si) = param;                                                              \
    if ( va )                                                                  \
    {                                                                          \
        share_xen_page_with_guest(mfn_to_page(param), d, XENSHARE_writable);   \
        replace_va_mapping(d, l4start, va, param);                             \
        dom0_update_physmap(d, PFN_DOWN((va) - va_start), param, vphysmap);    \
    }                                                                          \
})
    SET_AND_MAP_PARAM(HVM_PARAM_STORE_PFN, si->store_mfn, store_va);
    SET_AND_MAP_PARAM(HVM_PARAM_STORE_EVTCHN, si->store_evtchn, 0);
    if ( !pv_console )
    {
        SET_AND_MAP_PARAM(HVM_PARAM_CONSOLE_PFN, si->console.domU.mfn,
                          console_va);
        SET_AND_MAP_PARAM(HVM_PARAM_CONSOLE_EVTCHN, si->console.domU.evtchn, 0);
    }
#undef SET_AND_MAP_PARAM
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
