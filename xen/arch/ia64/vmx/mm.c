/******************************************************************************
 * arch/ia64/mm.c
 * 
 * Copyright (c) 2002-2005 K A Fraser
 * Copyright (c) 2004 Christian Limpach
 * Copyright (c) 2005, Intel Corporation.
 *  Xuefei Xu (Anthony Xu) (Anthony.xu@intel.com)
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
 */

/*
 * A description of the x86 page table API:
 * 
 * Domains trap to do_mmu_update with a list of update requests.
 * This is a list of (ptr, val) pairs, where the requested operation
 * is *ptr = val.
 * 
 * Reference counting of pages:
 * ----------------------------
 * Each page has two refcounts: tot_count and type_count.
 * 
 * TOT_COUNT is the obvious reference count. It counts all uses of a
 * physical page frame by a domain, including uses as a page directory,
 * a page table, or simple mappings via a PTE. This count prevents a
 * domain from releasing a frame back to the free pool when it still holds
 * a reference to it.
 * 
 * TYPE_COUNT is more subtle. A frame can be put to one of three
 * mutually-exclusive uses: it might be used as a page directory, or a
 * page table, or it may be mapped writable by the domain [of course, a
 * frame may not be used in any of these three ways!].
 * So, type_count is a count of the number of times a frame is being 
 * referred to in its current incarnation. Therefore, a page can only
 * change its type when its type count is zero.
 * 
 * Pinning the page type:
 * ----------------------
 * The type of a page can be pinned/unpinned with the commands
 * MMUEXT_[UN]PIN_L?_TABLE. Each page can be pinned exactly once (that is,
 * pinning is not reference counted, so it can't be nested).
 * This is useful to prevent a page's type count falling to zero, at which
 * point safety checks would need to be carried out next time the count
 * is increased again.
 * 
 * A further note on writable page mappings:
 * -----------------------------------------
 * For simplicity, the count of writable mappings for a page may not
 * correspond to reality. The 'writable count' is incremented for every
 * PTE which maps the page with the _PAGE_RW flag set. However, for
 * write access to be possible the page directory entry must also have
 * its _PAGE_RW bit set. We do not check this as it complicates the 
 * reference counting considerably [consider the case of multiple
 * directory entries referencing a single page table, some with the RW
 * bit set, others not -- it starts getting a bit messy].
 * In normal use, this simplification shouldn't be a problem.
 * However, the logic can be added if required.
 * 
 * One more note on read-only page mappings:
 * -----------------------------------------
 * We want domains to be able to map pages for read-only access. The
 * main reason is that page tables and directories should be readable
 * by a domain, but it would not be safe for them to be writable.
 * However, domains have free access to rings 1 & 2 of the Intel
 * privilege model. In terms of page protection, these are considered
 * to be part of 'supervisor mode'. The WP bit in CR0 controls whether
 * read-only restrictions are respected in supervisor mode -- if the 
 * bit is clear then any mapped page is writable.
 * 
 * We get round this by always setting the WP bit and disallowing 
 * updates to it. This is very unlikely to cause a problem for guest
 * OS's, which will generally use the WP bit to simplify copy-on-write
 * implementation (in that case, OS wants a fault when it writes to
 * an application-supplied buffer).
 */

#include <xen/config.h>
//#include <public/xen.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/errno.h>
#include <asm/vmx_vcpu.h>
#include <asm/vmmu.h>
#include <asm/regionreg.h>
#include <asm/vmx_mm_def.h>
/*
        uregs->ptr is virtual address
        uregs->val is pte value
 */
int vmx_do_mmu_update(mmu_update_t *ureqs,u64 count,u64 *pdone,u64 foreigndom)
{
    int i,cmd;
    u64 mfn, gpfn;
    VCPU *vcpu;
    mmu_update_t req;
    ia64_rr rr;
    thash_cb_t *hcb;
    thash_data_t entry={0},*ovl;
    vcpu = current;
    search_section_t sections;
    hcb = vmx_vcpu_get_vtlb(vcpu);
    for ( i = 0; i < count; i++ )
    {
        copy_from_user(&req, ureqs, sizeof(req));
        cmd = req.ptr&3;
        req.ptr &= ~3;
        if(cmd ==MMU_NORMAL_PT_UPDATE){
            entry.page_flags = req.val;
            entry.locked = 1;
            entry.tc = 1;
            entry.cl = DSIDE_TLB;
            rr = vmx_vcpu_rr(vcpu, req.ptr);
            entry.ps = rr.ps;
            entry.key = rr.rid;
            entry.rid = rr.rid;
            entry.vadr = PAGEALIGN(req.ptr,entry.ps);
            sections.tr = 1;
            sections.tc = 0;
            ovl = thash_find_overlap(hcb, &entry, sections);
            if (ovl) {
                  // generate MCA.
                panic("Tlb conflict!!");
                return -1;
            }
            thash_purge_and_insert(hcb, &entry);
        }else if(cmd == MMU_MACHPHYS_UPDATE){
            mfn = req.ptr >>PAGE_SHIFT;
            gpfn = req.val;
            set_machinetophys(mfn,gpfn);
        }else{
            printf("Unkown command of mmu_update:ptr: %lx,val: %lx \n",req.ptr,req.val);
            while(1);
        }
        ureqs ++;
    }
    return 0;
}
