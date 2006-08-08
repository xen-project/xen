/*
 *  Copyright (C) 2005 Intel Co
 *	Kun Tian (Kevin Tian) <kevin.tian@intel.com>
 *
 * 05/04/29 Kun Tian (Kevin Tian) <kevin.tian@intel.com> Add VTI domain support
 *
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *                    dom0 vp model support
 */

/*
 * NOTES on SMP
 * 
 * * shared structures
 * There are some structures which are accessed by CPUs concurrently.
 * Here is the list of shared structures and operations on them which
 * read/write the structures.
 * 
 * - struct page_info
 *   This is a xen global resource. This structure is accessed by
 *   any CPUs.
 * 
 *   operations on this structure:
 *   - get_page() and its variant
 *   - put_page() and its variant
 * 
 * - vTLB
 *   vcpu->arch.{d, i}tlb: Software tlb cache. These are per VCPU data.
 *   DEFINE_PER_CPU (unsigned long, vhpt_paddr): VHPT table per physical CPU.
 * 
 *   domain_flush_vtlb_range() and domain_flush_vtlb_all()
 *   write vcpu->arch.{d, i}tlb and VHPT table of vcpu which isn't current.
 *   So there are potential races to read/write VHPT and vcpu->arch.{d, i}tlb.
 *   Please note that reading VHPT is done by hardware page table walker.
 * 
 *   operations on this structure:
 *   - global tlb purge
 *     vcpu_ptc_g(), vcpu_ptc_ga() and domain_page_flush()
 *     I.e. callers of domain_flush_vtlb_range() and domain_flush_vtlb_all()
 *     These functions invalidate VHPT entry and vcpu->arch.{i, d}tlb
 * 
 *   - tlb insert and fc
 *     vcpu_itc_i()
 *     vcpu_itc_d()
 *     ia64_do_page_fault()
 *     vcpu_fc()
 *     These functions set VHPT entry and vcpu->arch.{i, d}tlb.
 *     Actually vcpu_itc_no_srlz() does.
 * 
 * - the P2M table
 *   domain->mm and pgd, pud, pmd, pte table page.
 *   This structure is used to convert domain pseudo physical address
 *   to machine address. This is per domain resource.
 * 
 *   operations on this structure:
 *   - populate the P2M table tree
 *     lookup_alloc_domain_pte() and its variants.
 *   - set p2m entry
 *     assign_new_domain_page() and its variants.
 *     assign_domain_page() and its variants.
 *   - xchg p2m entry
 *     assign_domain_page_replace()
 *   - cmpxchg p2m entry
 *     assign_domain_page_cmpxchg_rel()
 *     destroy_grant_host_mapping()
 *     steal_page()
 *     zap_domain_page_one()
 *   - read p2m entry
 *     lookup_alloc_domain_pte() and its variants.
 *     
 * - the M2P table
 *   mpt_table (or machine_to_phys_mapping)
 *   This is a table which converts from machine address to pseudo physical
 *   address. This is a global structure.
 * 
 *   operations on this structure:
 *   - set m2p entry
 *     set_gpfn_from_mfn()
 *   - zap m2p entry
 *     set_gpfn_from_mfn(INVALID_P2M_ENTRY)
 *   - get m2p entry
 *     get_gpfn_from_mfn()
 * 
 * 
 * * avoiding races
 * The resources which are shared by CPUs must be accessed carefully
 * to avoid race.
 * IA64 has weak memory ordering so that attention must be paid
 * to access shared structures. [SDM vol2 PartII chap. 2]
 * 
 * - struct page_info memory ordering
 *   get_page() has acquire semantics.
 *   put_page() has release semantics.
 * 
 * - populating the p2m table
 *   pgd, pud, pmd are append only.
 * 
 * - races when updating the P2M tables and the M2P table
 *   The P2M entry are shared by more than one vcpu.
 *   So they are accessed atomic operations.
 *   I.e. xchg or cmpxchg must be used to update the p2m entry.
 *   NOTE: When creating/destructing a domain, we don't need to take care of
 *         this race.
 * 
 *   The M2P table is inverse of the P2M table.
 *   I.e. P2M(M2P(p)) = p and M2P(P2M(m)) = m
 *   The M2P table and P2M table must be updated consistently.
 *   Here is the update sequence
 * 
 *   xchg or cmpxchg case
 *   - set_gpfn_from_mfn(new_mfn, gpfn)
 *   - memory barrier
 *   - atomic update of the p2m entry (xchg or cmpxchg the p2m entry)
 *     get old_mfn entry as a result.
 *   - memory barrier
 *   - set_gpfn_from_mfn(old_mfn, INVALID_P2M_ENTRY)
 * 
 *   Here memory barrier can be achieved by release semantics.
 * 
 * - races between global tlb purge and tlb insert
 *   This is a race between reading/writing vcpu->arch.{d, i}tlb or VHPT entry.
 *   When a vcpu is about to insert tlb, another vcpu may purge tlb
 *   cache globally. Inserting tlb (vcpu_itc_no_srlz()) or global tlb purge
 *   (domain_flush_vtlb_range() and domain_flush_vtlb_all()) can't update
 *   cpu->arch.{d, i}tlb, VHPT and mTLB. So there is a race here.
 * 
 *   Here check vcpu->arch.{d, i}tlb.p bit
 *   After inserting tlb entry, check the p bit and retry to insert.
 *   This means that when global tlb purge and tlb insert are issued
 *   simultaneously, always global tlb purge happens after tlb insert.
 * 
 * - races between p2m entry update and tlb insert
 *   This is a race between reading/writing the p2m entry.
 *   reader: vcpu_itc_i(), vcpu_itc_d(), ia64_do_page_fault(), vcpu_fc()
 *   writer: assign_domain_page_cmpxchg_rel(), destroy_grant_host_mapping(), 
 *           steal_page(), zap_domain_page_one()
 * 
 *   For example, vcpu_itc_i() is about to insert tlb by calling
 *   vcpu_itc_no_srlz() after reading the p2m entry.
 *   At the same time, the p2m entry is replaced by xchg or cmpxchg and
 *   tlb cache of the page is flushed.
 *   There is a possibility that the p2m entry doesn't already point to the
 *   old page, but tlb cache still points to the old page.
 *   This can be detected similar to sequence lock using the p2m entry itself.
 *   reader remember the read value of the p2m entry, and insert tlb.
 *   Then read the p2m entry again. If the new p2m entry value is different
 *   from the used p2m entry value, the retry.
 * 
 * - races between referencing page and p2m entry update
 *   This is a race between reading/writing the p2m entry.
 *   reader: vcpu_get_domain_bundle(), vmx_get_domain_bundle(),
 *           efi_emulate_get_time()
 *   writer: assign_domain_page_cmpxchg_rel(), destroy_grant_host_mapping(), 
 *           steal_page(), zap_domain_page_one()
 * 
 *   A page which assigned to a domain can be de-assigned by another vcpu.
 *   So before read/write to a domain page, the page's reference count 
 *   must be incremented.
 *   vcpu_get_domain_bundle(), vmx_get_domain_bundle() and
 *   efi_emulate_get_time()
 * 
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <asm/xentypes.h>
#include <asm/mm.h>
#include <asm/pgalloc.h>
#include <asm/vhpt.h>
#include <asm/vcpu.h>
#include <asm/shadow.h>
#include <linux/efi.h>

static void domain_page_flush(struct domain* d, unsigned long mpaddr,
                              unsigned long old_mfn, unsigned long new_mfn);

extern unsigned long ia64_iobase;

static struct domain *dom_xen, *dom_io;

// followings are stolen from arch_init_memory() @ xen/arch/x86/mm.c
void
alloc_dom_xen_and_dom_io(void)
{
    /*
     * Initialise our DOMID_XEN domain.
     * Any Xen-heap pages that we will allow to be mapped will have
     * their domain field set to dom_xen.
     */
    dom_xen = alloc_domain(DOMID_XEN);
    BUG_ON(dom_xen == NULL);

    /*
     * Initialise our DOMID_IO domain.
     * This domain owns I/O pages that are within the range of the page_info
     * array. Mappings occur at the priv of the caller.
     */
    dom_io = alloc_domain(DOMID_IO);
    BUG_ON(dom_io == NULL);
}

// heavily depends on the struct page_info layout.
// if (page_get_owner(page) == d &&
//     test_and_clear_bit(_PGC_allocated, &page->count_info)) {
//     put_page(page);
// }
static void
try_to_clear_PGC_allocate(struct domain* d, struct page_info* page)
{
    u32 _d, _nd;
    u64 x, nx, y;

    _d = pickle_domptr(d);
    y = *((u64*)&page->count_info);
    do {
        x = y;
        _nd = x >> 32;
        nx = x - 1;
        __clear_bit(_PGC_allocated, &nx);

        if (unlikely(!(x & PGC_allocated)) || unlikely(_nd != _d)) {
            struct domain* nd = unpickle_domptr(_nd);
            if (nd == NULL) {
                DPRINTK("gnttab_transfer: Bad page %p: ed=%p(%u) 0x%x, "
                        "sd=%p 0x%x,"
                        " caf=%016lx, taf=%" PRtype_info "\n",
                        (void *) page_to_mfn(page),
                        d, d->domain_id, _d,
                        nd, _nd,
                        x,
                        page->u.inuse.type_info);
            }
            break;
        }

        BUG_ON((nx & PGC_count_mask) < 1);
        y = cmpxchg((u64*)&page->count_info, x, nx);
    } while (unlikely(y != x));
}

static void
relinquish_pte(struct domain* d, pte_t* pte)
{
    unsigned long mfn = pte_pfn(*pte);
    struct page_info* page;

    // vmx domain use bit[58:56] to distinguish io region from memory.
    // see vmx_build_physmap_table() in vmx_init.c
    if (!pte_mem(*pte))
        return;

    // domain might map IO space or acpi table pages. check it.
    if (!mfn_valid(mfn))
        return;
    page = mfn_to_page(mfn);
    // struct page_info corresponding to mfn may exist or not depending
    // on CONFIG_VIRTUAL_FRAME_TABLE.
    // This check is too easy.
    // The right way is to check whether this page is of io area or acpi pages
    if (page_get_owner(page) == NULL) {
        BUG_ON(page->count_info != 0);
        return;
    }

    if (page_get_owner(page) == d) {
        BUG_ON(get_gpfn_from_mfn(mfn) == INVALID_M2P_ENTRY);
        set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
    }

    try_to_clear_PGC_allocate(d, page);
    put_page(page);
}

static void
relinquish_pmd(struct domain* d, pmd_t* pmd, unsigned long offset)
{
    unsigned long i;
    pte_t* pte = pte_offset_map(pmd, offset);

    for (i = 0; i < PTRS_PER_PTE; i++, pte++) {
        if (!pte_present(*pte))
            continue;

        relinquish_pte(d, pte);
    }
    pte_free_kernel(pte_offset_map(pmd, offset));
}

static void
relinquish_pud(struct domain* d, pud_t *pud, unsigned long offset)
{
    unsigned long i;
    pmd_t *pmd = pmd_offset(pud, offset);

    for (i = 0; i < PTRS_PER_PMD; i++, pmd++) {
        if (!pmd_present(*pmd))
            continue;

        relinquish_pmd(d, pmd, offset + (i << PMD_SHIFT));
    }
    pmd_free(pmd_offset(pud, offset));
}

static void
relinquish_pgd(struct domain* d, pgd_t *pgd, unsigned long offset)
{
    unsigned long i;
    pud_t *pud = pud_offset(pgd, offset);

    for (i = 0; i < PTRS_PER_PUD; i++, pud++) {
        if (!pud_present(*pud))
            continue;

        relinquish_pud(d, pud, offset + (i << PUD_SHIFT));
    }
    pud_free(pud_offset(pgd, offset));
}

void
relinquish_mm(struct domain* d)
{
    struct mm_struct* mm = &d->arch.mm;
    unsigned long i;
    pgd_t* pgd;

    if (mm->pgd == NULL)
        return;

    pgd = pgd_offset(mm, 0);
    for (i = 0; i < PTRS_PER_PGD; i++, pgd++) {
        if (!pgd_present(*pgd))
            continue;

        relinquish_pgd(d, pgd, i << PGDIR_SHIFT);
    }
    pgd_free(mm->pgd);
    mm->pgd = NULL;
}

// stolen from share_xen_page_with_guest() in xen/arch/x86/mm.c
void
share_xen_page_with_guest(struct page_info *page,
                          struct domain *d, int readonly)
{
    if ( page_get_owner(page) == d )
        return;

#if 1
    if (readonly) {
        printk("%s:%d readonly is not supported yet\n", __func__, __LINE__);
    }
#endif

    // alloc_xenheap_pages() doesn't initialize page owner.
    //BUG_ON(page_get_owner(page) != NULL);

    spin_lock(&d->page_alloc_lock);

#ifndef __ia64__
    /* The incremented type count pins as writable or read-only. */
    page->u.inuse.type_info  = (readonly ? PGT_none : PGT_writable_page);
    page->u.inuse.type_info |= PGT_validated | 1;
#endif

    page_set_owner(page, d);
    wmb(); /* install valid domain ptr before updating refcnt. */
    ASSERT(page->count_info == 0);
    page->count_info |= PGC_allocated | 1;

    if ( unlikely(d->xenheap_pages++ == 0) )
        get_knownalive_domain(d);
    list_add_tail(&page->list, &d->xenpage_list);

    // grant_table_destroy() releases these pages.
    // but it doesn't clear their m2p entry. So there might remain stale
    // entries. such a stale entry is cleared here.
    set_gpfn_from_mfn(page_to_mfn(page), INVALID_M2P_ENTRY);

    spin_unlock(&d->page_alloc_lock);
}

void
share_xen_page_with_privileged_guests(struct page_info *page, int readonly)
{
    share_xen_page_with_guest(page, dom_xen, readonly);
}

unsigned long
gmfn_to_mfn_foreign(struct domain *d, unsigned long gpfn)
{
	unsigned long pte;

	pte = lookup_domain_mpa(d,gpfn << PAGE_SHIFT, NULL);
	if (!pte) {
		panic("gmfn_to_mfn_foreign: bad gpfn. spinning...\n");
	}
	return ((pte & _PFN_MASK) >> PAGE_SHIFT);
}

// given a domain virtual address, pte and pagesize, extract the metaphysical
// address, convert the pte for a physical address for (possibly different)
// Xen PAGE_SIZE and return modified pte.  (NOTE: TLB insert should use
// PAGE_SIZE!)
u64 translate_domain_pte(u64 pteval, u64 address, u64 itir__, u64* logps,
                         struct p2m_entry* entry)
{
	struct domain *d = current->domain;
	ia64_itir_t itir = {.itir = itir__};
	u64 mask, mpaddr, pteval2;
	u64 arflags;
	u64 arflags2;
	u64 maflags2;

	pteval &= ((1UL << 53) - 1);// ignore [63:53] bits

	// FIXME address had better be pre-validated on insert
	mask = ~itir_mask(itir.itir);
	mpaddr = ((pteval & _PAGE_PPN_MASK) & ~mask) | (address & mask);

	if (itir.ps > PAGE_SHIFT)
		itir.ps = PAGE_SHIFT;

	*logps = itir.ps;

	pteval2 = lookup_domain_mpa(d, mpaddr, entry);

	/* Check access rights.  */
	arflags  = pteval  & _PAGE_AR_MASK;
	arflags2 = pteval2 & _PAGE_AR_MASK;
	if (arflags != _PAGE_AR_R && arflags2 == _PAGE_AR_R) {
#if 0
		DPRINTK("%s:%d "
		        "pteval 0x%lx arflag 0x%lx address 0x%lx itir 0x%lx "
		        "pteval2 0x%lx arflags2 0x%lx mpaddr 0x%lx\n",
		        __func__, __LINE__,
		        pteval, arflags, address, itir__,
		        pteval2, arflags2, mpaddr);
#endif
		pteval = (pteval & ~_PAGE_AR_MASK) | _PAGE_AR_R;
	}

	/* Check memory attribute. The switch is on the *requested* memory
	   attribute.  */
	maflags2 = pteval2 & _PAGE_MA_MASK;
	switch (pteval & _PAGE_MA_MASK) {
	case _PAGE_MA_NAT:
		/* NaT pages are always accepted!  */                
		break;
	case _PAGE_MA_UC:
	case _PAGE_MA_UCE:
	case _PAGE_MA_WC:
		if (maflags2 == _PAGE_MA_WB) {
			/* Don't let domains WB-map uncached addresses.
			   This can happen when domU tries to touch i/o
			   port space.  Also prevents possible address
			   aliasing issues.  */
			printf("Warning: UC to WB for mpaddr=%lx\n", mpaddr);
			pteval = (pteval & ~_PAGE_MA_MASK) | _PAGE_MA_WB;
		}
		break;
	case _PAGE_MA_WB:
		if (maflags2 != _PAGE_MA_WB) {
			/* Forbid non-coherent access to coherent memory. */
			panic_domain(NULL, "try to use WB mem attr on "
			             "UC page, mpaddr=%lx\n", mpaddr);
		}
		break;
	default:
		panic_domain(NULL, "try to use unknown mem attribute\n");
	}

	/* If shadow mode is enabled, virtualize dirty bit.  */
	if (shadow_mode_enabled(d) && (pteval & _PAGE_D)) {
		u64 mp_page = mpaddr >> PAGE_SHIFT;
		pteval |= _PAGE_VIRT_D;

		/* If the page is not already dirty, don't set the dirty bit! */
		if (mp_page < d->arch.shadow_bitmap_size * 8
    		    && !test_bit(mp_page, d->arch.shadow_bitmap))
    			pteval &= ~_PAGE_D;
	}
    
	/* Ignore non-addr bits of pteval2 and force PL0->2
	   (PL3 is unaffected) */
	return (pteval & ~_PAGE_PPN_MASK) |
	       (pteval2 & _PAGE_PPN_MASK) | _PAGE_PL_2;
}

// given a current domain metaphysical address, return the physical address
unsigned long translate_domain_mpaddr(unsigned long mpaddr,
                                      struct p2m_entry* entry)
{
	unsigned long pteval;

	pteval = lookup_domain_mpa(current->domain, mpaddr, entry);
	return ((pteval & _PAGE_PPN_MASK) | (mpaddr & ~PAGE_MASK));
}

//XXX !xxx_present() should be used instread of !xxx_none()?
// __assign_new_domain_page(), assign_new_domain_page() and
// assign_new_domain0_page() are used only when domain creation.
// their accesses aren't racy so that returned pte_t doesn't need
// volatile qualifier
static pte_t*
__lookup_alloc_domain_pte(struct domain* d, unsigned long mpaddr)
{
    struct mm_struct *mm = &d->arch.mm;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

    BUG_ON(mm->pgd == NULL);
    pgd = pgd_offset(mm, mpaddr);
    if (pgd_none(*pgd)) {
        pgd_populate(mm, pgd, pud_alloc_one(mm,mpaddr));
    }

    pud = pud_offset(pgd, mpaddr);
    if (pud_none(*pud)) {
        pud_populate(mm, pud, pmd_alloc_one(mm,mpaddr));
    }

    pmd = pmd_offset(pud, mpaddr);
    if (pmd_none(*pmd)) {
        pmd_populate_kernel(mm, pmd, pte_alloc_one_kernel(mm, mpaddr));
    }

    return pte_offset_map(pmd, mpaddr);
}

//XXX !xxx_present() should be used instread of !xxx_none()?
// pud, pmd, pte page is zero cleared when they are allocated.
// Their area must be visible before population so that
// cmpxchg must have release semantics.
static volatile pte_t*
lookup_alloc_domain_pte(struct domain* d, unsigned long mpaddr)
{
    struct mm_struct *mm = &d->arch.mm;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

    BUG_ON(mm->pgd == NULL);

    pgd = pgd_offset(mm, mpaddr);
 again_pgd:
    if (unlikely(pgd_none(*pgd))) {
        pud_t *old_pud = NULL;
        pud = pud_alloc_one(mm, mpaddr);
        if (unlikely(!pgd_cmpxchg_rel(mm, pgd, old_pud, pud))) {
            pud_free(pud);
            goto again_pgd;
        }
    }

    pud = pud_offset(pgd, mpaddr);
 again_pud:
    if (unlikely(pud_none(*pud))) {
        pmd_t* old_pmd = NULL;
        pmd = pmd_alloc_one(mm, mpaddr);
        if (unlikely(!pud_cmpxchg_rel(mm, pud, old_pmd, pmd))) {
            pmd_free(pmd);
            goto again_pud;
        }
    }

    pmd = pmd_offset(pud, mpaddr);
 again_pmd:
    if (unlikely(pmd_none(*pmd))) {
        pte_t* old_pte = NULL;
        pte_t* pte = pte_alloc_one_kernel(mm, mpaddr);
        if (unlikely(!pmd_cmpxchg_kernel_rel(mm, pmd, old_pte, pte))) {
            pte_free_kernel(pte);
            goto again_pmd;
        }
    }

    return (volatile pte_t*)pte_offset_map(pmd, mpaddr);
}

//XXX xxx_none() should be used instread of !xxx_present()?
volatile pte_t*
lookup_noalloc_domain_pte(struct domain* d, unsigned long mpaddr)
{
    struct mm_struct *mm = &d->arch.mm;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

    BUG_ON(mm->pgd == NULL);
    pgd = pgd_offset(mm, mpaddr);
    if (unlikely(!pgd_present(*pgd)))
        return NULL;

    pud = pud_offset(pgd, mpaddr);
    if (unlikely(!pud_present(*pud)))
        return NULL;

    pmd = pmd_offset(pud, mpaddr);
    if (unlikely(!pmd_present(*pmd)))
        return NULL;

    return (volatile pte_t*)pte_offset_map(pmd, mpaddr);
}

static volatile pte_t*
lookup_noalloc_domain_pte_none(struct domain* d, unsigned long mpaddr)
{
    struct mm_struct *mm = &d->arch.mm;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

    BUG_ON(mm->pgd == NULL);
    pgd = pgd_offset(mm, mpaddr);
    if (unlikely(pgd_none(*pgd)))
        return NULL;

    pud = pud_offset(pgd, mpaddr);
    if (unlikely(pud_none(*pud)))
        return NULL;

    pmd = pmd_offset(pud, mpaddr);
    if (unlikely(pmd_none(*pmd)))
        return NULL;

    return (volatile pte_t*)pte_offset_map(pmd, mpaddr);
}

unsigned long
____lookup_domain_mpa(struct domain *d, unsigned long mpaddr)
{
    volatile pte_t *pte;

    pte = lookup_noalloc_domain_pte(d, mpaddr);
    if (pte == NULL)
        return INVALID_MFN;

    if (pte_present(*pte))
        return (pte->pte & _PFN_MASK);
    else if (VMX_DOMAIN(d->vcpu[0]))
        return GPFN_INV_MASK;
    return INVALID_MFN;
}

unsigned long lookup_domain_mpa(struct domain *d, unsigned long mpaddr,
                                struct p2m_entry* entry)
{
    volatile pte_t *pte = lookup_noalloc_domain_pte(d, mpaddr);

    if (pte != NULL) {
        pte_t tmp_pte = *pte;// pte is volatile. copy the value.
        if (pte_present(tmp_pte)) {
//printk("lookup_domain_page: found mapping for %lx, pte=%lx\n",mpaddr,pte_val(*pte));
            if (entry != NULL)
                p2m_entry_set(entry, pte, tmp_pte);
            return pte_val(tmp_pte);
        } else if (VMX_DOMAIN(d->vcpu[0]))
            return GPFN_INV_MASK;
    }

    printk("%s: d 0x%p id %d current 0x%p id %d\n",
           __func__, d, d->domain_id, current, current->vcpu_id);
    if ((mpaddr >> PAGE_SHIFT) < d->max_pages)
        printk("%s: non-allocated mpa 0x%lx (< 0x%lx)\n", __func__,
               mpaddr, (unsigned long)d->max_pages << PAGE_SHIFT);
    else
        printk("%s: bad mpa 0x%lx (=> 0x%lx)\n", __func__,
               mpaddr, (unsigned long)d->max_pages << PAGE_SHIFT);

    if (entry != NULL)
        p2m_entry_set(entry, NULL, __pte(0));
    //XXX This is a work around until the emulation memory access to a region
    //    where memory or device are attached is implemented.
    return pte_val(pfn_pte(0, __pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RWX)));
}

// FIXME: ONLY USE FOR DOMAIN PAGE_SIZE == PAGE_SIZE
#if 1
void *domain_mpa_to_imva(struct domain *d, unsigned long mpaddr)
{
    unsigned long pte = lookup_domain_mpa(d, mpaddr, NULL);
    unsigned long imva;

    pte &= _PAGE_PPN_MASK;
    imva = (unsigned long) __va(pte);
    imva |= mpaddr & ~PAGE_MASK;
    return (void*)imva;
}
#else
void *domain_mpa_to_imva(struct domain *d, unsigned long mpaddr)
{
    unsigned long imva = __gpa_to_mpa(d, mpaddr);

    return (void *)__va(imva);
}
#endif

/* Allocate a new page for domain and map it to the specified metaphysical
   address.  */
static struct page_info *
__assign_new_domain_page(struct domain *d, unsigned long mpaddr, pte_t* pte)
{
    struct page_info *p;
    unsigned long maddr;
    int ret;

    BUG_ON(!pte_none(*pte));

    p = alloc_domheap_page(d);
    if (unlikely(!p)) {
        printf("assign_new_domain_page: Can't alloc!!!! Aaaargh!\n");
        return(p);
    }

    // zero out pages for security reasons
    clear_page(page_to_virt(p));
    maddr = page_to_maddr (p);
    if (unlikely(maddr > __get_cpu_var(vhpt_paddr)
                 && maddr < __get_cpu_var(vhpt_pend))) {
        /* FIXME: how can this happen ?
           vhpt is allocated by alloc_domheap_page.  */
        printf("assign_new_domain_page: reassigned vhpt page %lx!!\n",
               maddr);
    }

    ret = get_page(p, d);
    BUG_ON(ret == 0);
    set_gpfn_from_mfn(page_to_mfn(p), mpaddr >> PAGE_SHIFT);
    // clear_page() and set_gpfn_from_mfn() become visible before set_pte_rel()
    // because set_pte_rel() has release semantics
    set_pte_rel(pte,
                pfn_pte(maddr >> PAGE_SHIFT,
                        __pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RWX)));

    smp_mb();
    return p;
}

struct page_info *
assign_new_domain_page(struct domain *d, unsigned long mpaddr)
{
    pte_t *pte = __lookup_alloc_domain_pte(d, mpaddr);

    if (!pte_none(*pte))
        return NULL;

    return __assign_new_domain_page(d, mpaddr, pte);
}

void
assign_new_domain0_page(struct domain *d, unsigned long mpaddr)
{
    pte_t *pte;

    BUG_ON(d != dom0);
    pte = __lookup_alloc_domain_pte(d, mpaddr);
    if (pte_none(*pte)) {
        struct page_info *p = __assign_new_domain_page(d, mpaddr, pte);
        if (p == NULL) {
            panic("%s: can't allocate page for dom0", __func__);
        }
    }
}

static unsigned long
flags_to_prot (unsigned long flags)
{
    unsigned long res = _PAGE_PL_2 | __DIRTY_BITS;

    res |= flags & ASSIGN_readonly ? _PAGE_AR_R: _PAGE_AR_RWX;
    res |= flags & ASSIGN_nocache ? _PAGE_MA_UC: _PAGE_MA_WB;
    
    return res;
}

/* map a physical address to the specified metaphysical addr */
// flags: currently only ASSIGN_readonly, ASSIGN_nocache
// This is called by assign_domain_mmio_page().
// So accessing to pte is racy.
void
__assign_domain_page(struct domain *d,
                     unsigned long mpaddr, unsigned long physaddr,
                     unsigned long flags)
{
    volatile pte_t *pte;
    pte_t old_pte;
    pte_t new_pte;
    pte_t ret_pte;
    unsigned long prot = flags_to_prot(flags);

    pte = lookup_alloc_domain_pte(d, mpaddr);

    old_pte = __pte(0);
    new_pte = pfn_pte(physaddr >> PAGE_SHIFT, __pgprot(prot));
    ret_pte = ptep_cmpxchg_rel(&d->arch.mm, mpaddr, pte, old_pte, new_pte);
    if (pte_val(ret_pte) == pte_val(old_pte))
        smp_mb();
}

/* get_page() and map a physical address to the specified metaphysical addr */
void
assign_domain_page(struct domain *d,
                   unsigned long mpaddr, unsigned long physaddr)
{
    struct page_info* page = mfn_to_page(physaddr >> PAGE_SHIFT);
    int ret;

    BUG_ON((physaddr & GPFN_IO_MASK) != GPFN_MEM);
    ret = get_page(page, d);
    BUG_ON(ret == 0);
    set_gpfn_from_mfn(physaddr >> PAGE_SHIFT, mpaddr >> PAGE_SHIFT);
    // because __assign_domain_page() uses set_pte_rel() which has
    // release semantics, smp_mb() isn't needed.
    __assign_domain_page(d, mpaddr, physaddr, ASSIGN_writable);
}

int
ioports_permit_access(struct domain *d, unsigned long fp, unsigned long lp)
{
    int ret;
    unsigned long off;
    unsigned long fp_offset;
    unsigned long lp_offset;

    ret = rangeset_add_range(d->arch.ioport_caps, fp, lp);
    if (ret != 0)
        return ret;

    /* Domain 0 doesn't virtualize IO ports space. */
    if (d == dom0)
        return 0;

    fp_offset = IO_SPACE_SPARSE_ENCODING(fp) & ~PAGE_MASK;
    lp_offset = PAGE_ALIGN(IO_SPACE_SPARSE_ENCODING(lp));

    for (off = fp_offset; off <= lp_offset; off += PAGE_SIZE)
        __assign_domain_page(d, IO_PORTS_PADDR + off,
                             __pa(ia64_iobase) + off, ASSIGN_nocache);

    return 0;
}

static int
ioports_has_allowed(struct domain *d, unsigned long fp, unsigned long lp)
{
    unsigned long i;
    for (i = fp; i < lp; i++)
        if (rangeset_contains_singleton(d->arch.ioport_caps, i))
            return 1;
    return 0;
}

int
ioports_deny_access(struct domain *d, unsigned long fp, unsigned long lp)
{
    int ret;
    struct mm_struct *mm = &d->arch.mm;
    unsigned long off;
    unsigned long io_ports_base;
    unsigned long fp_offset;
    unsigned long lp_offset;

    ret = rangeset_remove_range(d->arch.ioport_caps, fp, lp);
    if (ret != 0)
        return ret;
    if (d == dom0)
        io_ports_base = __pa(ia64_iobase);
    else
        io_ports_base = IO_PORTS_PADDR;

    fp_offset = IO_SPACE_SPARSE_ENCODING(fp) & PAGE_MASK;
    lp_offset = PAGE_ALIGN(IO_SPACE_SPARSE_ENCODING(lp));

    for (off = fp_offset; off < lp_offset; off += PAGE_SIZE) {
        unsigned long mpaddr = io_ports_base + off;
        unsigned long port;
        volatile pte_t *pte;
        pte_t old_pte;

        port = IO_SPACE_SPARSE_DECODING (off);
        if (port < fp || port + IO_SPACE_SPARSE_PORTS_PER_PAGE > lp) {
            /* Maybe this covers an allowed port.  */
            if (ioports_has_allowed(d, port,
                                    port + IO_SPACE_SPARSE_PORTS_PER_PAGE))
                continue;
        }

        pte = lookup_noalloc_domain_pte_none(d, mpaddr);
        BUG_ON(pte == NULL);
        BUG_ON(pte_none(*pte));

        // clear pte
        old_pte = ptep_get_and_clear(mm, mpaddr, pte);
    }
    domain_flush_vtlb_all();
    return 0;
}

static void
assign_domain_same_page(struct domain *d,
                        unsigned long mpaddr, unsigned long size,
                        unsigned long flags)
{
    //XXX optimization
    unsigned long end = PAGE_ALIGN(mpaddr + size);
    for (mpaddr &= PAGE_MASK; mpaddr < end; mpaddr += PAGE_SIZE) {
        __assign_domain_page(d, mpaddr, mpaddr, flags);
    }
}

int
efi_mmio(unsigned long physaddr, unsigned long size)
{
    void *efi_map_start, *efi_map_end;
    u64 efi_desc_size;
    void* p;

    efi_map_start = __va(ia64_boot_param->efi_memmap);
    efi_map_end   = efi_map_start + ia64_boot_param->efi_memmap_size;
    efi_desc_size = ia64_boot_param->efi_memdesc_size;

    for (p = efi_map_start; p < efi_map_end; p += efi_desc_size) {
        efi_memory_desc_t* md = (efi_memory_desc_t *)p;
        unsigned long start = md->phys_addr;
        unsigned long end = md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT);

        if (start <= physaddr && physaddr < end) {
            if ((physaddr + size) > end) {
                DPRINTK("%s:%d physaddr 0x%lx size = 0x%lx\n",
                        __func__, __LINE__, physaddr, size);
                return 0;
            }

            // for io space
            if (md->type == EFI_MEMORY_MAPPED_IO ||
                md->type == EFI_MEMORY_MAPPED_IO_PORT_SPACE) {
                return 1;
            }

            // for runtime
            // see efi_enter_virtual_mode(void)
            // in linux/arch/ia64/kernel/efi.c
            if ((md->attribute & EFI_MEMORY_RUNTIME) &&
                !(md->attribute & EFI_MEMORY_WB)) {
                return 1;
            }

            DPRINTK("%s:%d physaddr 0x%lx size = 0x%lx\n",
                    __func__, __LINE__, physaddr, size);
            return 0;
        }

        if (physaddr < start) {
            break;
        }
    }

    return 1;
}

unsigned long
assign_domain_mmio_page(struct domain *d,
                        unsigned long mpaddr, unsigned long size)
{
    if (size == 0) {
        DPRINTK("%s: domain %p mpaddr 0x%lx size = 0x%lx\n",
                __func__, d, mpaddr, size);
    }
    if (!efi_mmio(mpaddr, size)) {
        DPRINTK("%s:%d domain %p mpaddr 0x%lx size = 0x%lx\n",
                __func__, __LINE__, d, mpaddr, size);
        return -EINVAL;
    }
    assign_domain_same_page(d, mpaddr, size, ASSIGN_writable | ASSIGN_nocache);
    return mpaddr;
}

unsigned long
assign_domain_mach_page(struct domain *d,
                        unsigned long mpaddr, unsigned long size,
                        unsigned long flags)
{
    assign_domain_same_page(d, mpaddr, size, flags);
    return mpaddr;
}

// caller must get_page(mfn_to_page(mfn)) before call.
// caller must call set_gpfn_from_mfn() before call if necessary.
// because set_gpfn_from_mfn() result must be visible before pte xchg
// caller must use memory barrier. NOTE: xchg has acquire semantics.
// flags: currently only ASSIGN_readonly
static void
assign_domain_page_replace(struct domain *d, unsigned long mpaddr,
                           unsigned long mfn, unsigned long flags)
{
    struct mm_struct *mm = &d->arch.mm;
    volatile pte_t* pte;
    pte_t old_pte;
    pte_t npte;
    unsigned long prot = flags_to_prot(flags);

    pte = lookup_alloc_domain_pte(d, mpaddr);

    // update pte
    npte = pfn_pte(mfn, __pgprot(prot));
    old_pte = ptep_xchg(mm, mpaddr, pte, npte);
    if (pte_mem(old_pte)) {
        unsigned long old_mfn = pte_pfn(old_pte);

        // mfn = old_mfn case can happen when domain maps a granted page
        // twice with the same pseudo physial address.
        // It's non sense, but allowed.
        // __gnttab_map_grant_ref()
        //   => create_host_mapping()
        //      => assign_domain_page_replace()
        if (mfn != old_mfn) {
            struct page_info* old_page = mfn_to_page(old_mfn);

            if (page_get_owner(old_page) == d ||
                page_get_owner(old_page) == NULL) {
                BUG_ON(get_gpfn_from_mfn(old_mfn) != (mpaddr >> PAGE_SHIFT));
                set_gpfn_from_mfn(old_mfn, INVALID_M2P_ENTRY);
            }

            domain_page_flush(d, mpaddr, old_mfn, mfn);

            try_to_clear_PGC_allocate(d, old_page);
            put_page(old_page);
        }
    }
}

// caller must get_page(new_page) before
// Only steal_page() calls this function.
static int
assign_domain_page_cmpxchg_rel(struct domain* d, unsigned long mpaddr,
                               struct page_info* old_page,
                               struct page_info* new_page,
                               unsigned long flags)
{
    struct mm_struct *mm = &d->arch.mm;
    volatile pte_t* pte;
    unsigned long old_mfn;
    unsigned long old_arflags;
    pte_t old_pte;
    unsigned long new_mfn;
    unsigned long new_prot;
    pte_t new_pte;
    pte_t ret_pte;

    pte = lookup_alloc_domain_pte(d, mpaddr);

 again:
    old_arflags = pte_val(*pte) & ~_PAGE_PPN_MASK;
    old_mfn = page_to_mfn(old_page);
    old_pte = pfn_pte(old_mfn, __pgprot(old_arflags));
    if (!pte_present(old_pte)) {
        DPRINTK("%s: old_pte 0x%lx old_arflags 0x%lx old_mfn 0x%lx\n",
                __func__, pte_val(old_pte), old_arflags, old_mfn);
        return -EINVAL;
    }

    new_prot = flags_to_prot(flags);
    new_mfn = page_to_mfn(new_page);
    new_pte = pfn_pte(new_mfn, __pgprot(new_prot));

    // update pte
    ret_pte = ptep_cmpxchg_rel(mm, mpaddr, pte, old_pte, new_pte);
    if (unlikely(pte_val(old_pte) != pte_val(ret_pte))) {
        if (pte_pfn(old_pte) == pte_pfn(ret_pte)) {
            goto again;
        }

        DPRINTK("%s: old_pte 0x%lx old_arflags 0x%lx old_mfn 0x%lx "
                "ret_pte 0x%lx ret_mfn 0x%lx\n",
                __func__,
                pte_val(old_pte), old_arflags, old_mfn,
                pte_val(ret_pte), pte_pfn(ret_pte));
        return -EINVAL;
    }

    BUG_ON(!pte_mem(old_pte));
    BUG_ON(page_get_owner(old_page) != d);
    BUG_ON(get_gpfn_from_mfn(old_mfn) != (mpaddr >> PAGE_SHIFT));
    BUG_ON(old_mfn == new_mfn);

    set_gpfn_from_mfn(old_mfn, INVALID_M2P_ENTRY);

    domain_page_flush(d, mpaddr, old_mfn, new_mfn);
    put_page(old_page);
    return 0;
}

static void
zap_domain_page_one(struct domain *d, unsigned long mpaddr, unsigned long mfn)
{
    struct mm_struct *mm = &d->arch.mm;
    volatile pte_t *pte;
    pte_t old_pte;
    struct page_info *page;

    pte = lookup_noalloc_domain_pte_none(d, mpaddr);
    if (pte == NULL)
        return;
    if (pte_none(*pte))
        return;

    if (mfn == INVALID_MFN) {
        // clear pte
        old_pte = ptep_get_and_clear(mm, mpaddr, pte);
        mfn = pte_pfn(old_pte);
    } else {
        unsigned long old_arflags;
        pte_t new_pte;
        pte_t ret_pte;

    again:
        // memory_exchange() calls guest_physmap_remove_page() with
        // a stealed page. i.e. page owner = NULL.
        BUG_ON(page_get_owner(mfn_to_page(mfn)) != d &&
               page_get_owner(mfn_to_page(mfn)) != NULL);
        old_arflags = pte_val(*pte) & ~_PAGE_PPN_MASK;
        old_pte = pfn_pte(mfn, __pgprot(old_arflags));
        new_pte = __pte(0);
        
        // update pte
        ret_pte = ptep_cmpxchg_rel(mm, mpaddr, pte, old_pte, new_pte);
        if (unlikely(pte_val(old_pte) != pte_val(ret_pte))) {
            if (pte_pfn(old_pte) == pte_pfn(ret_pte)) {
                goto again;
            }

            DPRINTK("%s: old_pte 0x%lx old_arflags 0x%lx mfn 0x%lx "
                    "ret_pte 0x%lx ret_mfn 0x%lx\n",
                    __func__,
                    pte_val(old_pte), old_arflags, mfn,
                    pte_val(ret_pte), pte_pfn(ret_pte));
            return;
        }
        BUG_ON(mfn != pte_pfn(ret_pte));
    }

    page = mfn_to_page(mfn);
    BUG_ON((page->count_info & PGC_count_mask) == 0);

    if (page_get_owner(page) == d ||
        page_get_owner(page) == NULL) {
        // exchange_memory() calls
        //   steal_page()
        //     page owner is set to NULL
        //   guest_physmap_remove_page()
        //     zap_domain_page_one()
        BUG_ON(get_gpfn_from_mfn(mfn) != (mpaddr >> PAGE_SHIFT));
        set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
    }

    domain_page_flush(d, mpaddr, mfn, INVALID_MFN);

    if (page_get_owner(page) != NULL) {
        try_to_clear_PGC_allocate(d, page);
    }
    put_page(page);
}

unsigned long
dom0vp_zap_physmap(struct domain *d, unsigned long gpfn,
                   unsigned int extent_order)
{
    if (extent_order != 0) {
        //XXX
        return -ENOSYS;
    }

    zap_domain_page_one(d, gpfn << PAGE_SHIFT, INVALID_MFN);
    return 0;
}

unsigned long
dom0vp_add_physmap(struct domain* d, unsigned long gpfn, unsigned long mfn,
                   unsigned long flags, domid_t domid)
{
    int error = 0;
    struct domain* rd;

    /* Not allowed by a domain.  */
    if (flags & ASSIGN_nocache)
        return -EINVAL;

    rd = find_domain_by_id(domid);
    if (unlikely(rd == NULL)) {
        switch (domid) {
        case DOMID_XEN:
            rd = dom_xen;
            break;
        case DOMID_IO:
            rd = dom_io;
            break;
        default:
            DPRINTK("d 0x%p domid %d "
                    "pgfn 0x%lx mfn 0x%lx flags 0x%lx domid %d\n",
                    d, d->domain_id, gpfn, mfn, flags, domid);
            return -ESRCH;
        }
        BUG_ON(rd == NULL);
        get_knownalive_domain(rd);
    }

    if (unlikely(rd == d || !mfn_valid(mfn))) {
        error = -EINVAL;
        goto out1;
    }
    if (unlikely(get_page(mfn_to_page(mfn), rd) == 0)) {
        error = -EINVAL;
        goto out1;
    }
    BUG_ON(page_get_owner(mfn_to_page(mfn)) == d &&
           get_gpfn_from_mfn(mfn) != INVALID_M2P_ENTRY);
    assign_domain_page_replace(d, gpfn << PAGE_SHIFT, mfn, flags);
    //don't update p2m table because this page belongs to rd, not d.
out1:
    put_domain(rd);
    return error;
}

// grant table host mapping
// mpaddr: host_addr: pseudo physical address
// mfn: frame: machine page frame
// flags: GNTMAP_readonly | GNTMAP_application_map | GNTMAP_contains_pte
int
create_grant_host_mapping(unsigned long gpaddr,
              unsigned long mfn, unsigned int flags)
{
    struct domain* d = current->domain;
    struct page_info* page;
    int ret;

    if (flags & (GNTMAP_device_map |
                 GNTMAP_application_map | GNTMAP_contains_pte)) {
        DPRINTK("%s: flags 0x%x\n", __func__, flags);
        return GNTST_general_error;
    }

    BUG_ON(!mfn_valid(mfn));
    page = mfn_to_page(mfn);
    ret = get_page(page, page_get_owner(page));
    BUG_ON(ret == 0);
    BUG_ON(page_get_owner(mfn_to_page(mfn)) == d &&
           get_gpfn_from_mfn(mfn) != INVALID_M2P_ENTRY);
    assign_domain_page_replace(d, gpaddr, mfn, (flags & GNTMAP_readonly)?
                                              ASSIGN_readonly: ASSIGN_writable);
    return GNTST_okay;
}

// grant table host unmapping
int
destroy_grant_host_mapping(unsigned long gpaddr,
               unsigned long mfn, unsigned int flags)
{
    struct domain* d = current->domain;
    volatile pte_t* pte;
    unsigned long cur_arflags;
    pte_t cur_pte;
    pte_t new_pte;
    pte_t old_pte;
    struct page_info* page;

    if (flags & (GNTMAP_application_map | GNTMAP_contains_pte)) {
        DPRINTK("%s: flags 0x%x\n", __func__, flags);
        return GNTST_general_error;
    }

    pte = lookup_noalloc_domain_pte(d, gpaddr);
    if (pte == NULL) {
        DPRINTK("%s: gpaddr 0x%lx mfn 0x%lx\n", __func__, gpaddr, mfn);
        return GNTST_general_error;
    }

 again:
    cur_arflags = pte_val(*pte) & ~_PAGE_PPN_MASK;
    cur_pte = pfn_pte(mfn, __pgprot(cur_arflags));
    if (!pte_present(cur_pte)) {
        DPRINTK("%s: gpaddr 0x%lx mfn 0x%lx cur_pte 0x%lx\n",
                __func__, gpaddr, mfn, pte_val(cur_pte));
        return GNTST_general_error;
    }
    new_pte = __pte(0);

    old_pte = ptep_cmpxchg_rel(&d->arch.mm, gpaddr, pte, cur_pte, new_pte);
    if (unlikely(!pte_present(old_pte))) {
        DPRINTK("%s: gpaddr 0x%lx mfn 0x%lx cur_pte 0x%lx old_pte 0x%lx\n",
                __func__, gpaddr, mfn, pte_val(cur_pte), pte_val(old_pte));
        return GNTST_general_error;
    }
    if (unlikely(pte_val(cur_pte) != pte_val(old_pte))) {
        if (pte_pfn(old_pte) == mfn) {
            goto again;
        }
        DPRINTK("%s gpaddr 0x%lx mfn 0x%lx cur_pte 0x%lx old_pte 0x%lx\n",
                __func__, gpaddr, mfn, pte_val(cur_pte), pte_val(old_pte));
        return GNTST_general_error;
    }
    BUG_ON(pte_pfn(old_pte) != mfn);

    domain_page_flush(d, gpaddr, mfn, INVALID_MFN);

    page = mfn_to_page(mfn);
    BUG_ON(page_get_owner(page) == d);//try_to_clear_PGC_allocate(d, page) is not needed.
    put_page(page);

    return GNTST_okay;
}

// heavily depends on the struct page layout.
// gnttab_transfer() calls steal_page() with memflags = 0
//   For grant table transfer, we must fill the page.
// memory_exchange() calls steal_page() with memflags = MEMF_no_refcount
//   For memory exchange, we don't have to fill the page because
//   memory_exchange() does it.
int
steal_page(struct domain *d, struct page_info *page, unsigned int memflags)
{
#if 0 /* if big endian */
# error "implement big endian version of steal_page()"
#endif
    u32 _d, _nd;
    u64 x, nx, y;

    if (page_get_owner(page) != d) {
        DPRINTK("%s d 0x%p owner 0x%p\n", __func__, d, page_get_owner(page));
        return -1;
    }
    
    if (!(memflags & MEMF_no_refcount)) {
        unsigned long gpfn;
        struct page_info *new;
        unsigned long new_mfn;
        int ret;

        new = alloc_domheap_page(d);
        if (new == NULL) {
            DPRINTK("alloc_domheap_page() failed\n");
            return -1;
        }
        // zero out pages for security reasons
        clear_page(page_to_virt(new));
        // assign_domain_page_cmpxchg_rel() has release semantics
        // so smp_mb() isn't needed.

        ret = get_page(new, d);
        BUG_ON(ret == 0);

        gpfn = get_gpfn_from_mfn(page_to_mfn(page));
        if (gpfn == INVALID_M2P_ENTRY) {
            free_domheap_page(new);
            return -1;
        }
        new_mfn = page_to_mfn(new);
        set_gpfn_from_mfn(new_mfn, gpfn);
        // smp_mb() isn't needed because assign_domain_pge_cmpxchg_rel()
        // has release semantics.

        ret = assign_domain_page_cmpxchg_rel(d, gpfn << PAGE_SHIFT, page, new,
                                             ASSIGN_writable);
        if (ret < 0) {
            DPRINTK("assign_domain_page_cmpxchg_rel failed %d\n", ret);
            set_gpfn_from_mfn(new_mfn, INVALID_M2P_ENTRY);
            free_domheap_page(new);
            return -1;
        }
    }

    spin_lock(&d->page_alloc_lock);

    /*
     * The tricky bit: atomically release ownership while there is just one
     * benign reference to the page (PGC_allocated). If that reference
     * disappears then the deallocation routine will safely spin.
     */
    _d  = pickle_domptr(d);
    y = *((u64*)&page->count_info);
    do {
        x = y;
        nx = x & 0xffffffff;
        // page->count_info: untouched
        // page->u.inused._domain = 0;
        _nd = x >> 32;

        if (unlikely(!(memflags & MEMF_no_refcount) &&
                     ((x & (PGC_count_mask | PGC_allocated)) !=
                      (1 | PGC_allocated))) ||

            // when MEMF_no_refcount, page isn't de-assigned from
            // this domain yet. So count_info = 2
            unlikely((memflags & MEMF_no_refcount) &&
                     ((x & (PGC_count_mask | PGC_allocated)) !=
                      (2 | PGC_allocated))) ||

            unlikely(_nd != _d)) {
            struct domain* nd = unpickle_domptr(_nd);
            if (nd == NULL) {
                DPRINTK("gnttab_transfer: Bad page %p: ed=%p(%u) 0x%x, "
                        "sd=%p 0x%x,"
                        " caf=%016lx, taf=%" PRtype_info
                        " memflags 0x%x\n",
                        (void *) page_to_mfn(page),
                        d, d->domain_id, _d,
                        nd, _nd,
                        x,
                        page->u.inuse.type_info,
                        memflags);
            } else {
                DPRINTK("gnttab_transfer: Bad page %p: ed=%p(%u) 0x%x, "
                        "sd=%p(%u) 0x%x,"
                        " caf=%016lx, taf=%" PRtype_info
                        " memflags 0x%x\n",
                        (void *) page_to_mfn(page),
                        d, d->domain_id, _d,
                        nd, nd->domain_id, _nd,
                        x,
                        page->u.inuse.type_info,
                        memflags);
            }
            spin_unlock(&d->page_alloc_lock);
            return -1;
        }

        y = cmpxchg((u64*)&page->count_info, x, nx);
    } while (unlikely(y != x));

    /*
     * Unlink from 'd'. At least one reference remains (now anonymous), so
     * noone else is spinning to try to delete this page from 'd'.
     */
    if ( !(memflags & MEMF_no_refcount) )
        d->tot_pages--;
    list_del(&page->list);

    spin_unlock(&d->page_alloc_lock);
    return 0;
}

void
guest_physmap_add_page(struct domain *d, unsigned long gpfn,
                       unsigned long mfn)
{
    int ret;

    BUG_ON(!mfn_valid(mfn));
    ret = get_page(mfn_to_page(mfn), d);
    BUG_ON(ret == 0);
    set_gpfn_from_mfn(mfn, gpfn);
    smp_mb();
    assign_domain_page_replace(d, gpfn << PAGE_SHIFT, mfn, ASSIGN_writable);

    //BUG_ON(mfn != ((lookup_domain_mpa(d, gpfn << PAGE_SHIFT) & _PFN_MASK) >> PAGE_SHIFT));
}

void
guest_physmap_remove_page(struct domain *d, unsigned long gpfn,
                          unsigned long mfn)
{
    BUG_ON(mfn == 0);//XXX
    zap_domain_page_one(d, gpfn << PAGE_SHIFT, mfn);
}

//XXX sledgehammer.
//    flush finer range.
static void
domain_page_flush(struct domain* d, unsigned long mpaddr,
                  unsigned long old_mfn, unsigned long new_mfn)
{
    if (shadow_mode_enabled(d))
        shadow_mark_page_dirty(d, mpaddr >> PAGE_SHIFT);

    domain_flush_vtlb_all();
}

int
domain_page_mapped(struct domain* d, unsigned long mpaddr)
{
    volatile pte_t * pte;

    pte = lookup_noalloc_domain_pte(d, mpaddr);
    if(pte != NULL && !pte_none(*pte))
       return 1;
    return 0;
}

/* Flush cache of domain d.  */
void domain_cache_flush (struct domain *d, int sync_only)
{
    struct mm_struct *mm = &d->arch.mm;
    pgd_t *pgd = mm->pgd;
    unsigned long maddr;
    int i,j,k, l;
    int nbr_page = 0;
    void (*flush_func)(unsigned long start, unsigned long end);
    extern void flush_dcache_range (unsigned long, unsigned long);

    if (sync_only)
        flush_func = &flush_icache_range;
    else
        flush_func = &flush_dcache_range;

    for (i = 0; i < PTRS_PER_PGD; pgd++, i++) {
        pud_t *pud;
        if (!pgd_present(*pgd))
            continue;
        pud = pud_offset(pgd, 0);
        for (j = 0; j < PTRS_PER_PUD; pud++, j++) {
            pmd_t *pmd;
            if (!pud_present(*pud))
                continue;
            pmd = pmd_offset(pud, 0);
            for (k = 0; k < PTRS_PER_PMD; pmd++, k++) {
                pte_t *pte;
                if (!pmd_present(*pmd))
                    continue;
                pte = pte_offset_map(pmd, 0);
                for (l = 0; l < PTRS_PER_PTE; pte++, l++) {
                    if (!pte_present(*pte))
                        continue;
                    /* Convert PTE to maddr.  */
                    maddr = __va_ul (pte_val(*pte)
                             & _PAGE_PPN_MASK);
                    (*flush_func)(maddr, maddr+ PAGE_SIZE);
                    nbr_page++;
                }
            }
        }
    }
    //printf ("domain_cache_flush: %d %d pages\n", d->domain_id, nbr_page);
}

#ifdef VERBOSE
#define MEM_LOG(_f, _a...)                           \
  printk("DOM%u: (file=mm.c, line=%d) " _f "\n", \
         current->domain->domain_id , __LINE__ , ## _a )
#else
#define MEM_LOG(_f, _a...) ((void)0)
#endif

static void free_page_type(struct page_info *page, u32 type)
{
}

static int alloc_page_type(struct page_info *page, u32 type)
{
	return 1;
}

unsigned long __get_free_pages(unsigned int mask, unsigned int order)
{
	void *p = alloc_xenheap_pages(order);

	memset(p,0,PAGE_SIZE<<order);
	return (unsigned long)p;
}

void __free_pages(struct page_info *page, unsigned int order)
{
	if (order) BUG();
	free_xenheap_page(page);
}

void *pgtable_quicklist_alloc(void)
{
    void *p;
    p = alloc_xenheap_pages(0);
    if (p)
        clear_page(p);
    return p;
}

void pgtable_quicklist_free(void *pgtable_entry)
{
	free_xenheap_page(pgtable_entry);
}

void cleanup_writable_pagetable(struct domain *d)
{
  return;
}

void put_page_type(struct page_info *page)
{
    u32 nx, x, y = page->u.inuse.type_info;

 again:
    do {
        x  = y;
        nx = x - 1;

        ASSERT((x & PGT_count_mask) != 0);

        /*
         * The page should always be validated while a reference is held. The
         * exception is during domain destruction, when we forcibly invalidate
         * page-table pages if we detect a referential loop.
         * See domain.c:relinquish_list().
         */
        ASSERT((x & PGT_validated) ||
               test_bit(_DOMF_dying, &page_get_owner(page)->domain_flags));

        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            /* Record TLB information for flush later. Races are harmless. */
            page->tlbflush_timestamp = tlbflush_current_time();

            if ( unlikely((nx & PGT_type_mask) <= PGT_l4_page_table) &&
                 likely(nx & PGT_validated) )
            {
                /*
                 * Page-table pages must be unvalidated when count is zero. The
                 * 'free' is safe because the refcnt is non-zero and validated
                 * bit is clear => other ops will spin or fail.
                 */
                if ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x,
                                           x & ~PGT_validated)) != x) )
                    goto again;
                /* We cleared the 'valid bit' so we do the clean up. */
                free_page_type(page, x);
                /* Carry on, but with the 'valid bit' now clear. */
                x  &= ~PGT_validated;
                nx &= ~PGT_validated;
            }
        }
        else if ( unlikely(((nx & (PGT_pinned | PGT_count_mask)) ==
                            (PGT_pinned | 1)) &&
                           ((nx & PGT_type_mask) != PGT_writable_page)) )
        {
            /* Page is now only pinned. Make the back pointer mutable again. */
            nx |= PGT_va_mutable;
        }
    }
    while ( unlikely((y = cmpxchg_rel(&page->u.inuse.type_info, x, nx)) != x) );
}


int get_page_type(struct page_info *page, u32 type)
{
    u32 nx, x, y = page->u.inuse.type_info;

 again:
    do {
        x  = y;
        nx = x + 1;
        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            MEM_LOG("Type count overflow on pfn %lx", page_to_mfn(page));
            return 0;
        }
        else if ( unlikely((x & PGT_count_mask) == 0) )
        {
            if ( (x & (PGT_type_mask|PGT_va_mask)) != type )
            {
                if ( (x & PGT_type_mask) != (type & PGT_type_mask) )
                {
                    /*
                     * On type change we check to flush stale TLB
                     * entries. This may be unnecessary (e.g., page
                     * was GDT/LDT) but those circumstances should be
                     * very rare.
                     */
                    cpumask_t mask =
                        page_get_owner(page)->domain_dirty_cpumask;
                    tlbflush_filter(mask, page->tlbflush_timestamp);

                    if ( unlikely(!cpus_empty(mask)) )
                    {
                        perfc_incrc(need_flush_tlb_flush);
                        flush_tlb_mask(mask);
                    }
                }

                /* We lose existing type, back pointer, and validity. */
                nx &= ~(PGT_type_mask | PGT_va_mask | PGT_validated);
                nx |= type;

                /* No special validation needed for writable pages. */
                /* Page tables and GDT/LDT need to be scanned for validity. */
                if ( type == PGT_writable_page )
                    nx |= PGT_validated;
            }
        }
        else
        {
            if ( unlikely((x & (PGT_type_mask|PGT_va_mask)) != type) )
            {
                if ( unlikely((x & PGT_type_mask) != (type & PGT_type_mask) ) )
                {
                    if ( current->domain == page_get_owner(page) )
                    {
                        /*
                         * This ensures functions like set_gdt() see up-to-date
                         * type info without needing to clean up writable p.t.
                         * state on the fast path.
                         */
                        LOCK_BIGLOCK(current->domain);
                        cleanup_writable_pagetable(current->domain);
                        y = page->u.inuse.type_info;
                        UNLOCK_BIGLOCK(current->domain);
                        /* Can we make progress now? */
                        if ( ((y & PGT_type_mask) == (type & PGT_type_mask)) ||
                             ((y & PGT_count_mask) == 0) )
                            goto again;
                    }
                    if ( ((x & PGT_type_mask) != PGT_l2_page_table) ||
                         ((type & PGT_type_mask) != PGT_l1_page_table) )
                        MEM_LOG("Bad type (saw %08x != exp %08x) "
                                "for mfn %016lx (pfn %016lx)",
                                x, type, page_to_mfn(page),
                                get_gpfn_from_mfn(page_to_mfn(page)));
                    return 0;
                }
                else if ( (x & PGT_va_mask) == PGT_va_mutable )
                {
                    /* The va backpointer is mutable, hence we update it. */
                    nx &= ~PGT_va_mask;
                    nx |= type; /* we know the actual type is correct */
                }
                else if ( ((type & PGT_va_mask) != PGT_va_mutable) &&
                          ((type & PGT_va_mask) != (x & PGT_va_mask)) )
                {
#ifdef CONFIG_X86_PAE
                    /* We use backptr as extra typing. Cannot be unknown. */
                    if ( (type & PGT_type_mask) == PGT_l2_page_table )
                        return 0;
#endif
                    /* This table is possibly mapped at multiple locations. */
                    nx &= ~PGT_va_mask;
                    nx |= PGT_va_unknown;
                }
            }
            if ( unlikely(!(x & PGT_validated)) )
            {
                /* Someone else is updating validation of this page. Wait... */
                while ( (y = page->u.inuse.type_info) == x )
                    cpu_relax();
                goto again;
            }
        }
    }
    while ( unlikely((y = cmpxchg_acq(&page->u.inuse.type_info, x, nx)) != x) );

    if ( unlikely(!(nx & PGT_validated)) )
    {
        /* Try to validate page type; drop the new reference on failure. */
        if ( unlikely(!alloc_page_type(page, type)) )
        {
            MEM_LOG("Error while validating mfn %lx (pfn %lx) for type %08x"
                    ": caf=%08x taf=%" PRtype_info,
                    page_to_mfn(page), get_gpfn_from_mfn(page_to_mfn(page)),
                    type, page->count_info, page->u.inuse.type_info);
            /* Noone else can get a reference. We hold the only ref. */
            page->u.inuse.type_info = 0;
            return 0;
        }

        /* Noone else is updating simultaneously. */
        __set_bit(_PGT_validated, &page->u.inuse.type_info);
    }

    return 1;
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
