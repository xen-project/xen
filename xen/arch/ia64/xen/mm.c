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
 *     vcpu_ptc_g(), vcpu_ptc_ga() and domain_page_flush_and_put()
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
 *     replace_grant_host_mapping()
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
 *   writer: assign_domain_page_cmpxchg_rel(), replace_grant_host_mapping(), 
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
 *   writer: assign_domain_page_cmpxchg_rel(), replace_grant_host_mapping(), 
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
#include <xen/mm.h>
#include <xen/errno.h>
#include <asm/pgalloc.h>
#include <asm/vhpt.h>
#include <asm/vcpu.h>
#include <asm/shadow.h>
#include <asm/p2m_entry.h>
#include <asm/tlb_track.h>
#include <linux/efi.h>
#include <linux/sort.h>
#include <xen/guest_access.h>
#include <asm/page.h>
#include <asm/dom_fw_common.h>
#include <public/memory.h>
#include <asm/event.h>
#include <asm/debugger.h>


#define MEM_LOG(_f, _a...) gdprintk(XENLOG_WARNING, _f "\n", ## _a)

static void domain_page_flush_and_put(struct domain* d, unsigned long mpaddr,
                                      volatile pte_t* ptep, pte_t old_pte, 
                                      struct page_info* page);

static void __xencomm_mark_dirty(struct domain *d,
                                 unsigned long addr, unsigned int len);

extern unsigned long ia64_iobase;

struct domain *dom_xen, *dom_io, *dom_cow;

/*
 * This number is bigger than DOMID_SELF, DOMID_XEN and DOMID_IO.
 * If more reserved domain ids are introduced, this might be increased.
 */
#define DOMID_P2M       (0x7FF8U)
static struct domain *dom_p2m;

// followings are stolen from arch_init_memory() @ xen/arch/x86/mm.c
void
alloc_dom_xen_and_dom_io(void)
{
    /*
     * Initialise our DOMID_XEN domain.
     * Any Xen-heap pages that we will allow to be mapped will have
     * their domain field set to dom_xen.
     */
    dom_xen = domain_create(DOMID_XEN, DOMCRF_dummy, 0);
    BUG_ON(dom_xen == NULL);

    /*
     * Initialise our DOMID_IO domain.
     * This domain owns I/O pages that are within the range of the page_info
     * array. Mappings occur at the priv of the caller.
     */
    dom_io = domain_create(DOMID_IO, DOMCRF_dummy, 0);
    BUG_ON(dom_io == NULL);
    
    /*
     * Initialise our DOMID_IO domain.
     * This domain owns sharable pages.
     */
    dom_cow = domain_create(DOMID_COW, DOMCRF_dummy, 0);
    BUG_ON(dom_cow == NULL);
}

static int
mm_teardown_can_skip(struct domain* d, unsigned long offset)
{
    return d->arch.mm_teardown_offset > offset;
}

static void
mm_teardown_update_offset(struct domain* d, unsigned long offset)
{
    d->arch.mm_teardown_offset = offset;
}

static void
mm_teardown_pte(struct domain* d, volatile pte_t* pte, unsigned long offset)
{
    pte_t old_pte;
    unsigned long mfn;
    struct page_info* page;

    old_pte = ptep_get_and_clear(&d->arch.mm, offset, pte);// acquire semantics
    
    // vmx domain use bit[58:56] to distinguish io region from memory.
    // see vmx_build_physmap_table() in vmx_init.c
    if (!pte_mem(old_pte))
        return;

    // domain might map IO space or acpi table pages. check it.
    mfn = pte_pfn(old_pte);
    if (!mfn_valid(mfn))
        return;
    page = mfn_to_page(mfn);
    BUG_ON(page_get_owner(page) == NULL);

    // struct page_info corresponding to mfn may exist or not depending
    // on CONFIG_VIRTUAL_FRAME_TABLE.
    // The above check is too easy.
    // The right way is to check whether this page is of io area or acpi pages

    if (pte_pgc_allocated(old_pte)) {
        BUG_ON(page_get_owner(page) != d);
        BUG_ON(get_gpfn_from_mfn(mfn) == INVALID_M2P_ENTRY);
        set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
        if (test_and_clear_bit(_PGC_allocated, &page->count_info))
            put_page(page);
    } else {
        put_page(page);
    }
}

static int
mm_teardown_pmd(struct domain* d, volatile pmd_t* pmd, unsigned long offset)
{
    unsigned long i;
    volatile pte_t* pte = pte_offset_map(pmd, offset);

    for (i = 0; i < PTRS_PER_PTE; i++, pte++) {
        unsigned long cur_offset = offset + (i << PAGE_SHIFT);
        if (mm_teardown_can_skip(d, cur_offset + PAGE_SIZE))
            continue;
        if (!pte_present(*pte)) { // acquire semantics
            mm_teardown_update_offset(d, cur_offset);
            continue;
        }
        mm_teardown_update_offset(d, cur_offset);
        mm_teardown_pte(d, pte, cur_offset);
        if (hypercall_preempt_check())
            return -EAGAIN;
    }
    return 0;
}

static int
mm_teardown_pud(struct domain* d, volatile pud_t *pud, unsigned long offset)
{
    unsigned long i;
    volatile pmd_t *pmd = pmd_offset(pud, offset);

    for (i = 0; i < PTRS_PER_PMD; i++, pmd++) {
        unsigned long cur_offset = offset + (i << PMD_SHIFT);
        if (mm_teardown_can_skip(d, cur_offset + PMD_SIZE))
            continue;
        if (!pmd_present(*pmd)) { // acquire semantics
            mm_teardown_update_offset(d, cur_offset);
            continue;
        }
        if (mm_teardown_pmd(d, pmd, cur_offset))
            return -EAGAIN;
    }
    return 0;
}

static int
mm_teardown_pgd(struct domain* d, volatile pgd_t *pgd, unsigned long offset)
{
    unsigned long i;
    volatile pud_t *pud = pud_offset(pgd, offset);

    for (i = 0; i < PTRS_PER_PUD; i++, pud++) {
        unsigned long cur_offset = offset + (i << PUD_SHIFT);
#ifndef __PAGETABLE_PUD_FOLDED
        if (mm_teardown_can_skip(d, cur_offset + PUD_SIZE))
            continue;
#endif
        if (!pud_present(*pud)) { // acquire semantics
#ifndef __PAGETABLE_PUD_FOLDED
            mm_teardown_update_offset(d, cur_offset);
#endif
            continue;
        }
        if (mm_teardown_pud(d, pud, cur_offset))
            return -EAGAIN;
    }
    return 0;
}

int
mm_teardown(struct domain* d)
{
    struct mm_struct* mm = &d->arch.mm;
    unsigned long i;
    volatile pgd_t* pgd;

    if (mm->pgd == NULL)
        return 0;

    pgd = pgd_offset(mm, 0);
    for (i = 0; i < PTRS_PER_PGD; i++, pgd++) {
        unsigned long cur_offset = i << PGDIR_SHIFT;

        if (mm_teardown_can_skip(d, cur_offset + PGDIR_SIZE))
            continue;
        if (!pgd_present(*pgd)) { // acquire semantics
            mm_teardown_update_offset(d, cur_offset);
            continue;
        }
        if (mm_teardown_pgd(d, pgd, cur_offset))
            return -EAGAIN;
    }

    foreign_p2m_destroy(d);
    return 0;
}

static void
mm_p2m_teardown_pmd(struct domain* d, volatile pmd_t* pmd,
                    unsigned long offset)
{
    pte_free_kernel(pte_offset_map(pmd, offset));
}

static void
mm_p2m_teardown_pud(struct domain* d, volatile pud_t *pud,
                    unsigned long offset)
{
    unsigned long i;
    volatile pmd_t *pmd = pmd_offset(pud, offset);

    for (i = 0; i < PTRS_PER_PMD; i++, pmd++) {
        if (!pmd_present(*pmd))
            continue;
        mm_p2m_teardown_pmd(d, pmd, offset + (i << PMD_SHIFT));
    }
    pmd_free(pmd_offset(pud, offset));
}

static void
mm_p2m_teardown_pgd(struct domain* d, volatile pgd_t *pgd,
                    unsigned long offset)
{
    unsigned long i;
    volatile pud_t *pud = pud_offset(pgd, offset);

    for (i = 0; i < PTRS_PER_PUD; i++, pud++) {
        if (!pud_present(*pud))
            continue;
        mm_p2m_teardown_pud(d, pud, offset + (i << PUD_SHIFT));
    }
    pud_free(pud_offset(pgd, offset));
}

static void
mm_p2m_teardown(struct domain* d)
{
    struct mm_struct* mm = &d->arch.mm;
    unsigned long i;
    volatile pgd_t* pgd;

    BUG_ON(mm->pgd == NULL);
    pgd = pgd_offset(mm, 0);
    for (i = 0; i < PTRS_PER_PGD; i++, pgd++) {
        if (!pgd_present(*pgd))
            continue;
        mm_p2m_teardown_pgd(d, pgd, i << PGDIR_SHIFT);
    }
    pgd_free(mm->pgd);
    mm->pgd = NULL;
}

void
mm_final_teardown(struct domain* d)
{
    if (d->arch.shadow_bitmap != NULL) {
        xfree(d->arch.shadow_bitmap);
        d->arch.shadow_bitmap = NULL;
    }
    mm_p2m_teardown(d);
}

unsigned long
domain_get_maximum_gpfn(struct domain *d)
{
    return (d->arch.convmem_end - 1) >> PAGE_SHIFT;
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
    ASSERT((page->count_info & ~PGC_xen_heap)== 0);

    /* Only add to the allocation list if the domain isn't dying. */
    if ( !d->is_dying )
    {
        page->count_info |= PGC_allocated | 1;
        if ( unlikely(d->xenheap_pages++ == 0) )
            get_knownalive_domain(d);
        page_list_add_tail(page, &d->xenpage_list);
    }

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

	if ((pte & _PAGE_IO) && is_hvm_domain(d))
		return INVALID_MFN;

	return ((pte & _PFN_MASK) >> PAGE_SHIFT);
}

// given a domain virtual address, pte and pagesize, extract the metaphysical
// address, convert the pte for a physical address for (possibly different)
// Xen PAGE_SIZE and return modified pte.  (NOTE: TLB insert should use
// current->arch.vhpt_pg_shift!)
u64 translate_domain_pte(u64 pteval, u64 address, u64 itir__, u64* itir,
                         struct p2m_entry* entry)
{
	struct domain *d = current->domain;
	ia64_itir_t _itir = {.itir = itir__};
	u64 mask, mpaddr, pteval2;
	u64 arflags;
	u64 arflags2;
	u64 maflags2;

	pteval &= ((1UL << 53) - 1);// ignore [63:53] bits

	// FIXME address had better be pre-validated on insert
	mask = ~itir_mask(_itir.itir);
	mpaddr = ((pteval & _PAGE_PPN_MASK) & ~mask) | (address & mask);

	if (_itir.ps > PAGE_SHIFT)
		_itir.ps = PAGE_SHIFT;

	((ia64_itir_t*)itir)->itir = _itir.itir;/* Copy the whole register. */
	((ia64_itir_t*)itir)->ps = _itir.ps;	/* Overwrite ps part! */

	pteval2 = lookup_domain_mpa(d, mpaddr, entry);
	if (_itir.ps < PAGE_SHIFT)
		pteval2 |= mpaddr & ~PAGE_MASK & ~((1L << _itir.ps) - 1);

	/* Check access rights.  */
	arflags  = pteval  & _PAGE_AR_MASK;
	arflags2 = pteval2 & _PAGE_AR_MASK;
	if (arflags != _PAGE_AR_R && arflags2 == _PAGE_AR_R) {
#if 0
		dprintk(XENLOG_WARNING,
                "%s:%d "
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
			if (!(mpaddr - IO_PORTS_PADDR < IO_PORTS_SIZE)) {
				u64 ucwb;
				
				/*
				 * If dom0 page has both UC & WB attributes
				 * don't warn about attempted UC access.
				 */
				ucwb = efi_mem_attribute(mpaddr, PAGE_SIZE);
				ucwb &= EFI_MEMORY_UC | EFI_MEMORY_WB;
				ucwb ^= EFI_MEMORY_UC | EFI_MEMORY_WB;

				if (d != dom0 || ucwb != 0)
					gdprintk(XENLOG_WARNING, "Warning: UC"
						 " to WB for mpaddr=%lx\n",
						 mpaddr);
			}
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
    
	/* Ignore non-addr bits of pteval2 and force PL0->1
	   (PL3 is unaffected) */
	return (pteval & ~(_PAGE_PPN_MASK | _PAGE_PL_MASK)) |
	       (pteval2 & _PAGE_PPN_MASK) |
	       (vcpu_pl_adjust(pteval, 7) & _PAGE_PL_MASK);
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
// pud, pmd, pte page is zero cleared when they are allocated.
// Their area must be visible before population so that
// cmpxchg must have release semantics.
static volatile pte_t*
lookup_alloc_domain_pte(struct domain* d, unsigned long mpaddr)
{
    struct mm_struct *mm = &d->arch.mm;
    volatile pgd_t *pgd;
    volatile pud_t *pud;
    volatile pmd_t *pmd;

    BUG_ON(mm->pgd == NULL);

    pgd = pgd_offset(mm, mpaddr);
 again_pgd:
    if (unlikely(pgd_none(*pgd))) { // acquire semantics
        pud_t *old_pud = NULL;
        pud = pud_alloc_one(mm, mpaddr);
        if (unlikely(!pgd_cmpxchg_rel(mm, pgd, old_pud, pud))) {
            pud_free(pud);
            goto again_pgd;
        }
    }

    pud = pud_offset(pgd, mpaddr);
 again_pud:
    if (unlikely(pud_none(*pud))) { // acquire semantics
        pmd_t* old_pmd = NULL;
        pmd = pmd_alloc_one(mm, mpaddr);
        if (unlikely(!pud_cmpxchg_rel(mm, pud, old_pmd, pmd))) {
            pmd_free(pmd);
            goto again_pud;
        }
    }

    pmd = pmd_offset(pud, mpaddr);
 again_pmd:
    if (unlikely(pmd_none(*pmd))) { // acquire semantics
        pte_t* old_pte = NULL;
        pte_t* pte = pte_alloc_one_kernel(mm, mpaddr);
        if (unlikely(!pmd_cmpxchg_kernel_rel(mm, pmd, old_pte, pte))) {
            pte_free_kernel(pte);
            goto again_pmd;
        }
    }

    return pte_offset_map(pmd, mpaddr);
}

//XXX xxx_none() should be used instread of !xxx_present()?
volatile pte_t*
lookup_noalloc_domain_pte(struct domain* d, unsigned long mpaddr)
{
    struct mm_struct *mm = &d->arch.mm;
    volatile pgd_t *pgd;
    volatile pud_t *pud;
    volatile pmd_t *pmd;

    BUG_ON(mm->pgd == NULL);
    pgd = pgd_offset(mm, mpaddr);
    if (unlikely(!pgd_present(*pgd))) // acquire semantics
        return NULL;

    pud = pud_offset(pgd, mpaddr);
    if (unlikely(!pud_present(*pud))) // acquire semantics
        return NULL;

    pmd = pmd_offset(pud, mpaddr);
    if (unlikely(!pmd_present(*pmd))) // acquire semantics
        return NULL;

    return pte_offset_map(pmd, mpaddr);
}

static volatile pte_t*
lookup_noalloc_domain_pte_none(struct domain* d, unsigned long mpaddr)
{
    struct mm_struct *mm = &d->arch.mm;
    volatile pgd_t *pgd;
    volatile pud_t *pud;
    volatile pmd_t *pmd;

    BUG_ON(mm->pgd == NULL);
    pgd = pgd_offset(mm, mpaddr);
    if (unlikely(pgd_none(*pgd))) // acquire semantics
        return NULL;

    pud = pud_offset(pgd, mpaddr);
    if (unlikely(pud_none(*pud))) // acquire semantics
        return NULL;

    pmd = pmd_offset(pud, mpaddr);
    if (unlikely(pmd_none(*pmd))) // acquire semantics
        return NULL;

    return pte_offset_map(pmd, mpaddr);
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
    return INVALID_MFN;
}

unsigned long lookup_domain_mpa(struct domain *d, unsigned long mpaddr,
                                struct p2m_entry* entry)
{
    volatile pte_t *pte = lookup_noalloc_domain_pte(d, mpaddr);

    if (pte != NULL) {
        pte_t tmp_pte = *pte;// pte is volatile. copy the value.
        if (pte_present(tmp_pte)) {
            if (entry != NULL)
                p2m_entry_set(entry, pte, tmp_pte);
            return pte_val(tmp_pte);
        } else if (is_hvm_domain(d))
            return INVALID_MFN;
    }

    if (mpaddr < d->arch.convmem_end && !d->is_dying) {
        gdprintk(XENLOG_WARNING, "vcpu %d iip 0x%016lx: non-allocated mpa "
                 "d %"PRId16" 0x%lx (< 0x%lx)\n",
                 current->vcpu_id, PSCB(current, iip),
                 d->domain_id, mpaddr, d->arch.convmem_end);
    } else if (mpaddr - IO_PORTS_PADDR < IO_PORTS_SIZE) {
        /* Log I/O port probing, but complain less loudly about it */
        gdprintk(XENLOG_INFO, "vcpu %d iip 0x%016lx: bad I/O port access "
                 "d %"PRId16" 0x%lx\n",
                 current->vcpu_id, PSCB(current, iip), d->domain_id,
                 IO_SPACE_SPARSE_DECODING(mpaddr - IO_PORTS_PADDR));
    } else {
        gdprintk(XENLOG_WARNING, "vcpu %d iip 0x%016lx: bad mpa "
                 "d %"PRId16" 0x%lx (=> 0x%lx)\n",
                 current->vcpu_id, PSCB(current, iip),
                 d->domain_id, mpaddr, d->arch.convmem_end);
    }

    debugger_event (XEN_IA64_DEBUG_ON_BAD_MPA);

    if (entry != NULL)
        p2m_entry_set(entry, NULL, __pte(0));
    //XXX This is a work around until the emulation memory access to a region
    //    where memory or device are attached is implemented.
    return pte_val(pfn_pte(0, __pgprot(__DIRTY_BITS | _PAGE_PL_PRIV |
                                       _PAGE_AR_RWX)));
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

unsigned long
paddr_to_maddr(unsigned long paddr)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    u64 pa;

    pa = ____lookup_domain_mpa(d, paddr);
    if (pa == INVALID_MFN) {
        printk("%s: called with bad memory address: 0x%lx - iip=%lx\n",
               __func__, paddr, vcpu_regs(v)->cr_iip);
        return 0;
    }
    return (pa & _PFN_MASK) | (paddr & ~PAGE_MASK);
}

/* Allocate a new page for domain and map it to the specified metaphysical
   address.  */
static struct page_info *
__assign_new_domain_page(struct domain *d, unsigned long mpaddr,
                         volatile pte_t* pte)
{
    struct page_info *p;
    unsigned long maddr;

    BUG_ON(!pte_none(*pte));

    p = alloc_domheap_page(d, 0);
    if (unlikely(!p)) {
        printk("assign_new_domain_page: Can't alloc!!!! Aaaargh!\n");
        return(p);
    }

    // zero out pages for security reasons
    clear_page(page_to_virt(p));
    maddr = page_to_maddr (p);
    if (unlikely(maddr > __get_cpu_var(vhpt_paddr)
                 && maddr < __get_cpu_var(vhpt_pend))) {
        /* FIXME: how can this happen ?
           vhpt is allocated by alloc_domheap_page.  */
        printk("assign_new_domain_page: reassigned vhpt page %lx!!\n",
               maddr);
    }

    set_gpfn_from_mfn(page_to_mfn(p), mpaddr >> PAGE_SHIFT);
    // clear_page() and set_gpfn_from_mfn() become visible before set_pte_rel()
    // because set_pte_rel() has release semantics
    set_pte_rel(pte,
                pfn_pte(maddr >> PAGE_SHIFT,
                        __pgprot(_PAGE_PGC_ALLOCATED | __DIRTY_BITS |
                                 _PAGE_PL_PRIV | _PAGE_AR_RWX)));

    smp_mb();
    return p;
}

struct page_info *
assign_new_domain_page(struct domain *d, unsigned long mpaddr)
{
    volatile pte_t *pte = lookup_alloc_domain_pte(d, mpaddr);

    if (!pte_none(*pte))
        return NULL;

    return __assign_new_domain_page(d, mpaddr, pte);
}

void __init
assign_new_domain0_page(struct domain *d, unsigned long mpaddr)
{
    volatile pte_t *pte;

    BUG_ON(d != dom0);
    pte = lookup_alloc_domain_pte(d, mpaddr);
    if (pte_none(*pte)) {
        struct page_info *p = __assign_new_domain_page(d, mpaddr, pte);
        if (p == NULL) {
            panic("%s: can't allocate page for dom0\n", __func__);
        }
    }
}

static unsigned long
flags_to_prot (unsigned long flags)
{
    unsigned long res = _PAGE_PL_PRIV | __DIRTY_BITS;

    res |= flags & ASSIGN_readonly ? _PAGE_AR_R: _PAGE_AR_RWX;
    res |= flags & ASSIGN_nocache ? _PAGE_MA_UC: _PAGE_MA_WB;
#ifdef CONFIG_XEN_IA64_TLB_TRACK
    res |= flags & ASSIGN_tlb_track ? _PAGE_TLB_TRACKING: 0;
#endif
    res |= flags & ASSIGN_pgc_allocated ? _PAGE_PGC_ALLOCATED: 0;
    res |= flags & ASSIGN_io ? _PAGE_IO: 0;
    
    return res;
}

/* map a physical address to the specified metaphysical addr */
// flags: currently only ASSIGN_readonly, ASSIGN_nocache, ASSIGN_tlb_tack
// This is called by assign_domain_mmio_page().
// So accessing to pte is racy.
int
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
 again_hvm_page_io:
    ret_pte = ptep_cmpxchg_rel(&d->arch.mm, mpaddr, pte, old_pte, new_pte);
    if (pte_val(ret_pte) == pte_val(old_pte)) {
        smp_mb();
        return 0;
    }
    /* in HVM guest, when VTD is enabled,
     * P2M entry may change from _PAGE_IO type to real MMIO page 
     */
    if(is_hvm_domain(d) && (pte_val(ret_pte) & _PAGE_IO) &&
       !mfn_valid(physaddr >> PAGE_SHIFT)) {
        old_pte = ret_pte;
        goto again_hvm_page_io;
    }

    // dom0 tries to map real machine's I/O region, but failed.
    // It is very likely that dom0 doesn't boot correctly because
    // it can't access I/O. So complain here.
    if (flags & ASSIGN_nocache) {
        int warn = 0;

        if (pte_pfn(ret_pte) != (physaddr >> PAGE_SHIFT))
            warn = 1;
        else if (!(pte_val(ret_pte) & _PAGE_MA_UC)) {
            u32 type;
            u64 attr;

            warn = 1;

            /*
             * See
             * complete_dom0_memmap()
             * case EFI_RUNTIME_SERVICES_CODE:
             * case EFI_RUNTIME_SERVICES_DATA:
             * case EFI_ACPI_RECLAIM_MEMORY:
             * case EFI_ACPI_MEMORY_NVS:
             * case EFI_RESERVED_TYPE:
             * 
             * Currently only EFI_RUNTIME_SERVICES_CODE is found
             * so that we suppress only EFI_RUNTIME_SERVICES_CODE case.
             */
            type = efi_mem_type(physaddr);
            attr = efi_mem_attributes(physaddr);
            if (type == EFI_RUNTIME_SERVICES_CODE &&
                (attr & EFI_MEMORY_UC) && (attr & EFI_MEMORY_WB))
                warn = 0;
        }
        if (warn)
            printk("%s:%d WARNING can't assign page domain 0x%p id %d\n"
                   "\talready assigned pte_val 0x%016lx\n"
                   "\tmpaddr 0x%016lx physaddr 0x%016lx flags 0x%lx\n",
                   __func__, __LINE__,
                   d, d->domain_id, pte_val(ret_pte),
                   mpaddr, physaddr, flags);
    }

    return -EAGAIN;
}

/* get_page() and map a physical address to the specified metaphysical addr */
void
assign_domain_page(struct domain *d,
                   unsigned long mpaddr, unsigned long physaddr)
{
    struct page_info* page = mfn_to_page(physaddr >> PAGE_SHIFT);

    BUG_ON((physaddr & _PAGE_PPN_MASK) != physaddr);
    BUG_ON((page->count_info & ~PGC_xen_heap) != (PGC_allocated | 1));
    set_gpfn_from_mfn(physaddr >> PAGE_SHIFT, mpaddr >> PAGE_SHIFT);
    // because __assign_domain_page() uses set_pte_rel() which has
    // release semantics, smp_mb() isn't needed.
    (void)__assign_domain_page(d, mpaddr, physaddr,
                               ASSIGN_writable | ASSIGN_pgc_allocated);
}

static void
ioports_get_mmio_addr(const struct io_space *space,
                      unsigned long fp, unsigned long lp,
                      unsigned long *mmio_start, unsigned long *mmio_end)
{
    if (space->sparse) {
        *mmio_start = IO_SPACE_SPARSE_ENCODING(fp) & PAGE_MASK;
        *mmio_end = PAGE_ALIGN(IO_SPACE_SPARSE_ENCODING(lp));
    } else {
        *mmio_start = fp & PAGE_MASK;
        *mmio_end = PAGE_ALIGN(lp);
    }
}

static unsigned long
ioports_get_mmio_base(const struct io_space *space, struct domain *d)
{
    if (VMX_DOMAIN(d->vcpu[0]))
        return LEGACY_IO_START;

    if (space == &io_space[0] && d != dom0)
        return IO_PORTS_PADDR;

    return __pa(space->mmio_base);
}

/* 
 * Inpurt
 * fgp: first guest port
 * fmp: first machine port
 * lmp: last machine port
 */
int
ioports_permit_access(struct domain *d, unsigned int fgp,
        unsigned int fmp, unsigned int lmp)
{
    struct io_space *space;
    unsigned long mmio_start, mach_start, mach_end;
    int ret;

    if (IO_SPACE_NR(fmp) >= num_io_spaces) {
        dprintk(XENLOG_WARNING, "Unknown I/O Port range 0x%x - 0x%x\n", fmp, lmp);
        return -EFAULT;
    }

    /*
     * The ioport_cap rangeset tracks the I/O port address including
     * the port space ID.  This means port space IDs need to match
     * between Xen and dom0.  This is also a requirement because
     * the hypercall to pass these port ranges only uses a u32.
     *
     * NB - non-dom0 driver domains may only have a subset of the
     * I/O port spaces and thus will number port spaces differently.
     * This is ok, they don't make use of this interface.
     */
    ret = rangeset_add_range(d->arch.ioport_caps, fmp, lmp);
    if (ret != 0)
        return ret;

    space = &io_space[IO_SPACE_NR(fmp)];

    /* Legacy I/O on dom0 is already setup */
    if (d == dom0 && space == &io_space[0])
        return 0;

    fmp = IO_SPACE_PORT(fmp);
    lmp = IO_SPACE_PORT(lmp);

    ioports_get_mmio_addr(space, fmp, lmp, &mach_start, &mach_end);

    /*
     * The "machine first port" is not necessarily identity mapped
     * to the guest first port.  At least for the legacy range.
     */
    mach_start = mach_start | __pa(space->mmio_base);
    mach_end = mach_end | __pa(space->mmio_base);

    mmio_start = IO_SPACE_SPARSE_ENCODING(fgp) & PAGE_MASK;
    mmio_start |= ioports_get_mmio_base(space, d);

    while (mach_start < mach_end) {
        (void)__assign_domain_page(d, mmio_start, mach_start, ASSIGN_nocache); 
        mmio_start += PAGE_SIZE;
        mach_start += PAGE_SIZE;
    }

    return 0;
}

static int
ioports_has_allowed(struct domain *d, unsigned int fp, unsigned int lp)
{
    for (; fp < lp; fp++)
        if (rangeset_contains_singleton(d->arch.ioport_caps, fp))
            return 1;

    return 0;
}

int
ioports_deny_access(struct domain *d, unsigned int fp, unsigned int lp)
{
    int ret;
    struct mm_struct *mm = &d->arch.mm;
    unsigned long mmio_start, mmio_end, mmio_base;
    unsigned int fp_base, lp_base;
    struct io_space *space;

    if (IO_SPACE_NR(fp) >= num_io_spaces) {
        dprintk(XENLOG_WARNING, "Unknown I/O Port range 0x%x - 0x%x\n", fp, lp);
        return -EFAULT;
    }

    ret = rangeset_remove_range(d->arch.ioport_caps, fp, lp);
    if (ret != 0)
        return ret;

    space = &io_space[IO_SPACE_NR(fp)];
    fp_base = IO_SPACE_PORT(fp);
    lp_base = IO_SPACE_PORT(lp);

    ioports_get_mmio_addr(space, fp_base, lp_base, &mmio_start, &mmio_end);

    mmio_base = ioports_get_mmio_base(space, d);

    for (; mmio_start < mmio_end; mmio_start += PAGE_SIZE) {
        unsigned int port, range;
        unsigned long mpaddr;
        volatile pte_t *pte;
        pte_t old_pte;

        if (space->sparse) {
            port = IO_SPACE_SPARSE_DECODING(mmio_start);
            range = IO_SPACE_SPARSE_PORTS_PER_PAGE - 1;
        } else {
            port = mmio_start;
            range = PAGE_SIZE - 1;
        }

        port |= IO_SPACE_BASE(IO_SPACE_NR(fp));

        if (port < fp || port + range > lp) {
            /* Maybe this covers an allowed port.  */
            if (ioports_has_allowed(d, port, port + range))
                continue;
        }

        mpaddr = mmio_start | mmio_base;
        pte = lookup_noalloc_domain_pte_none(d, mpaddr);
        BUG_ON(pte == NULL);
        BUG_ON(pte_none(*pte));

        /* clear pte */
        old_pte = ptep_get_and_clear(mm, mpaddr, pte);
    }
    domain_flush_vtlb_all(d);
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
        (void)__assign_domain_page(d, mpaddr, mpaddr, flags);
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
                gdprintk(XENLOG_INFO, "%s: physaddr 0x%lx size = 0x%lx\n",
                        __func__, physaddr, size);
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

            return 0;
        }

        if (physaddr < start) {
            break;
        }
    }

    return 1;
}

unsigned long
assign_domain_mmio_page(struct domain *d, unsigned long mpaddr,
                        unsigned long phys_addr, unsigned long size,
                        unsigned long flags)
{
    unsigned long addr = mpaddr & PAGE_MASK;
    unsigned long end = PAGE_ALIGN(mpaddr + size);

    if (size == 0) {
        gdprintk(XENLOG_INFO, "%s: domain %p mpaddr 0x%lx size = 0x%lx\n",
                __func__, d, mpaddr, size);
    }
    if (!efi_mmio(phys_addr, size)) {
#ifndef NDEBUG
        gdprintk(XENLOG_INFO, "%s: domain %p mpaddr 0x%lx size = 0x%lx\n",
                __func__, d, mpaddr, size);
#endif
        return -EINVAL;
    }

    for (phys_addr &= PAGE_MASK; addr < end;
         addr += PAGE_SIZE, phys_addr += PAGE_SIZE) {
        __assign_domain_page(d, addr, phys_addr, flags);
    }

    return mpaddr;
}

unsigned long
assign_domain_mach_page(struct domain *d,
                        unsigned long mpaddr, unsigned long size,
                        unsigned long flags)
{
    BUG_ON(flags & ASSIGN_pgc_allocated);
    assign_domain_same_page(d, mpaddr, size, flags);
    return mpaddr;
}

static void
adjust_page_count_info(struct page_info* page)
{
    struct domain* d = page_get_owner(page);
    BUG_ON((page->count_info & PGC_count_mask) < 1);
    if (d != NULL) {
        int ret = get_page(page, d);
        BUG_ON(ret == 0);
    } else {
        unsigned long x, nx, y;

        y = page->count_info;
        do {
            x = y;
            nx = x + 1;

            BUG_ON((x >> 32) != 0);
            BUG_ON((nx & PGC_count_mask) != 2);
            y = cmpxchg(&page->count_info, x, nx);
        } while (unlikely(y != x));
        BUG_ON(page_get_owner(page) != NULL);
    }
}

static void
domain_put_page(struct domain* d, unsigned long mpaddr,
                volatile pte_t* ptep, pte_t old_pte, int clear_PGC_allocate)
{
    unsigned long mfn = pte_pfn(old_pte);
    struct page_info* page = mfn_to_page(mfn);

    if (pte_pgc_allocated(old_pte)) {
        if (page_get_owner(page) == d || page_get_owner(page) == NULL) {
            BUG_ON(get_gpfn_from_mfn(mfn) != (mpaddr >> PAGE_SHIFT));
	    set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
        } else {
            BUG();
        }

        if (likely(clear_PGC_allocate)) {
            if (!test_and_clear_bit(_PGC_allocated, &page->count_info))
                BUG();
            /* put_page() is done by domain_page_flush_and_put() */
        } else {
            // In this case, page reference count mustn't touched.
            // domain_page_flush_and_put() decrements it, we increment
            // it in advence. This patch is slow path.
            //
            // guest_remove_page(): owner = d, count_info = 1
            // memory_exchange(): owner = NULL, count_info = 1
            // XENMEM_add_to_physmap: ower = d, count_info >= 1
            adjust_page_count_info(page);
        }
    }
    domain_page_flush_and_put(d, mpaddr, ptep, old_pte, page);
}

// caller must get_page(mfn_to_page(mfn)) before call.
// caller must call set_gpfn_from_mfn() before call if necessary.
// because set_gpfn_from_mfn() result must be visible before pte xchg
// caller must use memory barrier. NOTE: xchg has acquire semantics.
// flags: ASSIGN_xxx
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
            domain_put_page(d, mpaddr, pte, old_pte, 1);
        }
    }
    perfc_incr(assign_domain_page_replace);
}

// caller must get_page(new_page) before
// Only steal_page() calls this function.
static int
assign_domain_page_cmpxchg_rel(struct domain* d, unsigned long mpaddr,
                               struct page_info* old_page,
                               struct page_info* new_page,
                               unsigned long flags, int clear_PGC_allocate)
{
    struct mm_struct *mm = &d->arch.mm;
    volatile pte_t* pte;
    unsigned long old_mfn;
    unsigned long old_prot;
    pte_t old_pte;
    unsigned long new_mfn;
    unsigned long new_prot;
    pte_t new_pte;
    pte_t ret_pte;

    BUG_ON((flags & ASSIGN_pgc_allocated) == 0);
    pte = lookup_alloc_domain_pte(d, mpaddr);

 again:
    old_prot = pte_val(*pte) & ~_PAGE_PPN_MASK;
    old_mfn = page_to_mfn(old_page);
    old_pte = pfn_pte(old_mfn, __pgprot(old_prot));
    if (!pte_present(old_pte)) {
        gdprintk(XENLOG_INFO,
                "%s: old_pte 0x%lx old_prot 0x%lx old_mfn 0x%lx\n",
                __func__, pte_val(old_pte), old_prot, old_mfn);
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

        gdprintk(XENLOG_INFO,
                "%s: old_pte 0x%lx old_prot 0x%lx old_mfn 0x%lx "
                "ret_pte 0x%lx ret_mfn 0x%lx\n",
                __func__,
                pte_val(old_pte), old_prot, old_mfn,
                pte_val(ret_pte), pte_pfn(ret_pte));
        return -EINVAL;
    }

    BUG_ON(!pte_mem(old_pte));
    BUG_ON(!pte_pgc_allocated(old_pte));
    BUG_ON(page_get_owner(old_page) != d);
    BUG_ON(get_gpfn_from_mfn(old_mfn) != (mpaddr >> PAGE_SHIFT));
    BUG_ON(old_mfn == new_mfn);

    set_gpfn_from_mfn(old_mfn, INVALID_M2P_ENTRY);
    if (likely(clear_PGC_allocate)) {
        if (!test_and_clear_bit(_PGC_allocated, &old_page->count_info))
            BUG();
    } else {
        int ret;
        // adjust for count_info for domain_page_flush_and_put()
        // This is slow path.
        BUG_ON(!test_bit(_PGC_allocated, &old_page->count_info));
        BUG_ON(d == NULL);
        ret = get_page(old_page, d);
        BUG_ON(ret == 0);
    }

    domain_page_flush_and_put(d, mpaddr, pte, old_pte, old_page);
    perfc_incr(assign_domain_pge_cmpxchg_rel);
    return 0;
}

static void
zap_domain_page_one(struct domain *d, unsigned long mpaddr,
                    int clear_PGC_allocate, unsigned long mfn)
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
        if(!pte_mem(old_pte))
            return;
        mfn = pte_pfn(old_pte);
    } else {
        unsigned long old_arflags;
        pte_t new_pte;
        pte_t ret_pte;

    again:
        // memory_exchange() calls guest_physmap_remove_page() with
        // a stealed page. i.e. page owner = NULL.
        BUG_ON(mfn_valid(mfn) &&
               page_get_owner(mfn_to_page(mfn)) != d &&
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

            gdprintk(XENLOG_INFO, "%s: old_pte 0x%lx old_arflags 0x%lx mfn 0x%lx "
                    "ret_pte 0x%lx ret_mfn 0x%lx\n",
                    __func__,
                    pte_val(old_pte), old_arflags, mfn,
                    pte_val(ret_pte), pte_pfn(ret_pte));
            return;
        }
        BUG_ON(mfn != pte_pfn(ret_pte));
    }

    perfc_incr(zap_domain_page_one);
    if(!mfn_valid(mfn))
        return;

    if ( iommu_enabled && need_iommu(d) ){
        int i, j;
        j = 1 << (PAGE_SHIFT-PAGE_SHIFT_4K);
        for(i = 0 ; i < j; i++)
            iommu_unmap_page(d, (mpaddr>>PAGE_SHIFT)*j + i);
    }

    page = mfn_to_page(mfn);
    BUG_ON((page->count_info & PGC_count_mask) == 0);

    BUG_ON(clear_PGC_allocate && (page_get_owner(page) == NULL));
    domain_put_page(d, mpaddr, pte, old_pte, clear_PGC_allocate);
}

int
deassign_domain_mmio_page(struct domain *d, unsigned long mpaddr,
                        unsigned long phys_addr, unsigned long size )
{
    unsigned long addr = mpaddr & PAGE_MASK;
    unsigned long end = PAGE_ALIGN(mpaddr + size);

    if (size == 0) {
        gdprintk(XENLOG_INFO, "%s: domain %p mpaddr 0x%lx size = 0x%lx\n",
                __func__, d, mpaddr, size);
    }
    if (!efi_mmio(phys_addr, size)) {
#ifndef NDEBUG
        gdprintk(XENLOG_INFO, "%s: domain %p mpaddr 0x%lx size = 0x%lx\n",
                __func__, d, mpaddr, size);
#endif
        return -EINVAL;
    }

    for (; addr < end; addr += PAGE_SIZE )
        zap_domain_page_one(d, addr, 0, INVALID_MFN);
    return 0;
}

unsigned long
dom0vp_zap_physmap(struct domain *d, unsigned long gpfn,
                   unsigned int extent_order)
{
    if (extent_order != 0) {
        //XXX
        return -ENOSYS;
    }

    zap_domain_page_one(d, gpfn << PAGE_SHIFT, 1, INVALID_MFN);
    perfc_incr(dom0vp_zap_physmap);
    return 0;
}

static unsigned long
__dom0vp_add_physmap(struct domain* d, unsigned long gpfn,
                     unsigned long mfn_or_gmfn,
                     unsigned long flags, domid_t domid, int is_gmfn)
{
    int error = -EINVAL;
    struct domain* rd;
    unsigned long mfn;

    /* Not allowed by a domain.  */
    if (flags & (ASSIGN_nocache | ASSIGN_pgc_allocated))
        return -EINVAL;

    rd = rcu_lock_domain_by_id(domid);
    if (unlikely(rd == NULL)) {
        switch (domid) {
        case DOMID_XEN:
            rd = dom_xen;
            break;
        case DOMID_IO:
            rd = dom_io;
            break;
        default:
            gdprintk(XENLOG_INFO, "d 0x%p domid %d "
                    "gpfn 0x%lx mfn_or_gmfn 0x%lx flags 0x%lx domid %d\n",
                    d, d->domain_id, gpfn, mfn_or_gmfn, flags, domid);
            return -ESRCH;
        }
        BUG_ON(rd == NULL);
        rcu_lock_domain(rd);
    }

    if (unlikely(rd == d))
        goto out1;
    /*
     * DOMID_XEN and DOMID_IO don't have their own p2m table.
     * It can be considered that their p2m conversion is p==m.
     */
    if (likely(is_gmfn && domid != DOMID_XEN && domid != DOMID_IO))
        mfn = gmfn_to_mfn(rd, mfn_or_gmfn);
    else 
        mfn = mfn_or_gmfn;
    if (unlikely(!mfn_valid(mfn) || get_page(mfn_to_page(mfn), rd) == 0))
        goto out1;

    error = 0;
    BUG_ON(page_get_owner(mfn_to_page(mfn)) == d &&
           get_gpfn_from_mfn(mfn) != INVALID_M2P_ENTRY);
    assign_domain_page_replace(d, gpfn << PAGE_SHIFT, mfn, flags);
    //don't update p2m table because this page belongs to rd, not d.
    perfc_incr(dom0vp_add_physmap);
out1:
    rcu_unlock_domain(rd);
    return error;
}

unsigned long
dom0vp_add_physmap(struct domain* d, unsigned long gpfn, unsigned long mfn,
                   unsigned long flags, domid_t domid)
{
    return __dom0vp_add_physmap(d, gpfn, mfn, flags, domid, 0);
}

unsigned long
dom0vp_add_physmap_with_gmfn(struct domain* d, unsigned long gpfn,
                             unsigned long gmfn, unsigned long flags,
                             domid_t domid)
{
    return __dom0vp_add_physmap(d, gpfn, gmfn, flags, domid, 1);
}

#ifdef CONFIG_XEN_IA64_EXPOSE_P2M
#define P2M_PFN_ROUNDUP(x)      (((x) + PTRS_PER_PTE - 1) & \
                                 ~(PTRS_PER_PTE - 1))
#define P2M_PFN_ROUNDDOWN(x)    ((x) & ~(PTRS_PER_PTE - 1))
#define P2M_NUM_PFN(x)          (((x) + PTRS_PER_PTE - 1) / PTRS_PER_PTE)
#define MD_END(md)              ((md)->phys_addr + \
                                 ((md)->num_pages << EFI_PAGE_SHIFT))
static struct page_info* p2m_pte_zero_page = NULL;

/* This must called before dom0 p2m table allocation */
void __init
expose_p2m_init(void)
{
    pte_t* pte;

    /*
     * Initialise our DOMID_P2M domain.
     * This domain owns m2p table pages.
     */
    dom_p2m = domain_create(DOMID_P2M, DOMCRF_dummy, 0);
    BUG_ON(dom_p2m == NULL);
    dom_p2m->max_pages = ~0U;

    pte = pte_alloc_one_kernel(NULL, 0);
    BUG_ON(pte == NULL);
    smp_mb();// make contents of the page visible.
    p2m_pte_zero_page = virt_to_page(pte);
}

// allocate pgd, pmd of dest_dom if necessary
static int
allocate_pgd_pmd(struct domain* dest_dom, unsigned long dest_gpfn,
                 struct domain* src_dom,
                 unsigned long src_gpfn, unsigned long num_src_gpfn)
{
    unsigned long i = 0;

    BUG_ON((src_gpfn % PTRS_PER_PTE) != 0);
    BUG_ON((num_src_gpfn % PTRS_PER_PTE) != 0);

    while (i < num_src_gpfn) {
        volatile pte_t* src_pte;
        volatile pte_t* dest_pte;

        src_pte = lookup_noalloc_domain_pte(src_dom,
                                            (src_gpfn + i) << PAGE_SHIFT);
        if (src_pte == NULL) {
            i++;
            continue;
        }
        
        dest_pte = lookup_alloc_domain_pte(dest_dom,
                                           (dest_gpfn << PAGE_SHIFT) +
                                           i * sizeof(pte_t));
        if (dest_pte == NULL) {
            gdprintk(XENLOG_INFO, "%s failed to allocate pte page\n",
                     __func__);
            return -ENOMEM;
        }

        // skip to next pte page
        i = P2M_PFN_ROUNDDOWN(i + PTRS_PER_PTE);
    }
    return 0;
}

static int
expose_p2m_page(struct domain* d, unsigned long mpaddr, struct page_info* page)
{
    int ret = get_page(page, dom_p2m);
    BUG_ON(ret != 1);
    return __assign_domain_page(d, mpaddr, page_to_maddr(page),
                                ASSIGN_readonly);
}

// expose pte page
static int
expose_p2m_range(struct domain* dest_dom, unsigned long dest_gpfn,
                 struct domain* src_dom,
                 unsigned long src_gpfn, unsigned long num_src_gpfn)
{
    unsigned long i = 0;

    BUG_ON((src_gpfn % PTRS_PER_PTE) != 0);
    BUG_ON((num_src_gpfn % PTRS_PER_PTE) != 0);

    while (i < num_src_gpfn) {
        volatile pte_t* pte;

        pte = lookup_noalloc_domain_pte(src_dom, (src_gpfn + i) << PAGE_SHIFT);
        if (pte == NULL) {
            i++;
            continue;
        }

        if (expose_p2m_page(dest_dom,
                            (dest_gpfn << PAGE_SHIFT) + i * sizeof(pte_t),
                            virt_to_page(pte)) < 0) {
            gdprintk(XENLOG_INFO, "%s failed to assign page\n", __func__);
            return -EAGAIN;
        }

        // skip to next pte page
        i = P2M_PFN_ROUNDDOWN(i + PTRS_PER_PTE);
    }
    return 0;
}

// expose p2m_pte_zero_page 
static int
expose_zero_page(struct domain* dest_dom, unsigned long dest_gpfn,
                 unsigned long num_src_gpfn)
{
    unsigned long i;
    
    for (i = 0; i < P2M_NUM_PFN(num_src_gpfn); i++) {
        volatile pte_t* pte;
        pte = lookup_noalloc_domain_pte(dest_dom,
                                        (dest_gpfn + i) << PAGE_SHIFT);
        if (pte == NULL || pte_present(*pte))
            continue;

        if (expose_p2m_page(dest_dom, (dest_gpfn + i) << PAGE_SHIFT,
                            p2m_pte_zero_page) < 0) {
            gdprintk(XENLOG_INFO, "%s failed to assign zero-pte page\n",
                     __func__);
            return -EAGAIN;
        }
    }
    return 0;
}

static int
expose_p2m(struct domain* dest_dom, unsigned long dest_gpfn,
           struct domain* src_dom,
           unsigned long src_gpfn, unsigned long num_src_gpfn)
{
    if (allocate_pgd_pmd(dest_dom, dest_gpfn,
                         src_dom, src_gpfn, num_src_gpfn))
        return -ENOMEM;

    if (expose_p2m_range(dest_dom, dest_gpfn,
                         src_dom, src_gpfn, num_src_gpfn))
        return -EAGAIN;

    if (expose_zero_page(dest_dom, dest_gpfn, num_src_gpfn))
        return -EAGAIN;
    
    return 0;
}

static void
unexpose_p2m(struct domain* dest_dom,
             unsigned long dest_gpfn, unsigned long num_dest_gpfn)
{
    unsigned long i;

    for (i = 0; i < num_dest_gpfn; i++) {
        zap_domain_page_one(dest_dom, (dest_gpfn + i) << PAGE_SHIFT,
                            0, INVALID_MFN);
    }
}

// It is possible to optimize loop, But this isn't performance critical.
unsigned long
dom0vp_expose_p2m(struct domain* d,
                  unsigned long conv_start_gpfn,
                  unsigned long assign_start_gpfn,
                  unsigned long expose_size, unsigned long granule_pfn)
{
    unsigned long ret;
    unsigned long expose_num_pfn = expose_size >> PAGE_SHIFT;

    if ((expose_size % PAGE_SIZE) != 0 ||
        (granule_pfn % PTRS_PER_PTE) != 0 ||
        (expose_num_pfn % PTRS_PER_PTE) != 0 ||
        (conv_start_gpfn % granule_pfn) != 0 ||
        (assign_start_gpfn % granule_pfn) != 0 ||
        (expose_num_pfn % granule_pfn) != 0) {
        gdprintk(XENLOG_INFO,
                "%s conv_start_gpfn 0x%016lx assign_start_gpfn 0x%016lx "
                "expose_size 0x%016lx granulte_pfn 0x%016lx\n", __func__, 
                conv_start_gpfn, assign_start_gpfn, expose_size, granule_pfn);
        return -EINVAL;
    }

    if (granule_pfn != PTRS_PER_PTE) {
        gdprintk(XENLOG_INFO,
                "%s granule_pfn 0x%016lx PTRS_PER_PTE 0x%016lx\n",
                __func__, granule_pfn, PTRS_PER_PTE);
        return -ENOSYS;
    }
    ret = expose_p2m(d, assign_start_gpfn,
                     d, conv_start_gpfn, expose_num_pfn);
    return ret;
}

static int
memmap_info_copy_from_guest(struct xen_ia64_memmap_info* memmap_info,
                            char** memmap_p,
                            XEN_GUEST_HANDLE(char) buffer)
{
    char *memmap;
    char *p;
    char *memmap_end;
    efi_memory_desc_t *md;
    unsigned long start;
    unsigned long end;
    efi_memory_desc_t *prev_md;

    if (copy_from_guest((char*)memmap_info, buffer, sizeof(*memmap_info)))
        return -EFAULT;
    if (memmap_info->efi_memdesc_size < sizeof(efi_memory_desc_t) ||
        memmap_info->efi_memmap_size < memmap_info->efi_memdesc_size ||
        (memmap_info->efi_memmap_size % memmap_info->efi_memdesc_size) != 0)
        return -EINVAL;
    
    memmap = _xmalloc(memmap_info->efi_memmap_size,
                      __alignof__(efi_memory_desc_t));
    if (memmap == NULL)
        return -ENOMEM;
    if (copy_from_guest_offset(memmap, buffer, sizeof(*memmap_info),
                               memmap_info->efi_memmap_size)) {
        xfree(memmap);
        return -EFAULT;
    }

    /* intergirty check & simplify */
    sort(memmap, memmap_info->efi_memmap_size / memmap_info->efi_memdesc_size,
         memmap_info->efi_memdesc_size, efi_mdt_cmp, NULL);

    /* alignement & overlap check */
    prev_md = NULL;
    p = memmap;
    memmap_end = memmap + memmap_info->efi_memmap_size;
    for (p = memmap; p < memmap_end; p += memmap_info->efi_memmap_size) {
        md = (efi_memory_desc_t*)p;
        start = md->phys_addr;
        
        if (start & ((1UL << EFI_PAGE_SHIFT) - 1) || md->num_pages == 0) {
            xfree(memmap);
            return -EINVAL;
        }

        if (prev_md != NULL) {
            unsigned long prev_end = MD_END(prev_md);
            if (prev_end > start) {
                xfree(memmap);
                return -EINVAL;
            }
        }

        prev_md = (efi_memory_desc_t *)p;
    }

    /* coalease */
    prev_md = NULL;
    p = memmap;
    while (p < memmap_end) {
        md = (efi_memory_desc_t*)p;
        start = md->phys_addr;
        end = MD_END(md);

        start = P2M_PFN_ROUNDDOWN(start >> PAGE_SHIFT) << PAGE_SHIFT;
        end = P2M_PFN_ROUNDUP(end >> PAGE_SHIFT) << PAGE_SHIFT;
        md->phys_addr = start;
        md->num_pages = (end - start) >> EFI_PAGE_SHIFT;

        if (prev_md != NULL) {
            unsigned long prev_end = MD_END(prev_md);
            if (prev_end >= start) {
                size_t left;
                end = max(prev_end, end);
                prev_md->num_pages = (end - prev_md->phys_addr) >> EFI_PAGE_SHIFT;

                left = memmap_end - p;
                if (left > memmap_info->efi_memdesc_size) {
                    left -= memmap_info->efi_memdesc_size;
                    memmove(p, p + memmap_info->efi_memdesc_size, left);
                }

                memmap_info->efi_memmap_size -= memmap_info->efi_memdesc_size;
                memmap_end -= memmap_info->efi_memdesc_size;
                continue;
            }
        }

        prev_md = md;
        p += memmap_info->efi_memdesc_size;
    }

    if (copy_to_guest(buffer, (char*)memmap_info, sizeof(*memmap_info)) ||
        copy_to_guest_offset(buffer, sizeof(*memmap_info),
                             (char*)memmap, memmap_info->efi_memmap_size)) {
        xfree(memmap);
        return -EFAULT;
    }
    
    *memmap_p = memmap;
    return 0;
}

static int
foreign_p2m_allocate_pte(struct domain* d,
                         const struct xen_ia64_memmap_info* memmap_info,
                         const void* memmap)
{
    const void* memmap_end = memmap + memmap_info->efi_memmap_size;
    const void* p;

    for (p = memmap; p < memmap_end; p += memmap_info->efi_memdesc_size) {
        const efi_memory_desc_t* md = p;
        unsigned long start = md->phys_addr;
        unsigned long end = MD_END(md);
        unsigned long gpaddr;

        for (gpaddr = start; gpaddr < end; gpaddr += PAGE_SIZE) {
            if (lookup_alloc_domain_pte(d, gpaddr) == NULL) {
                return -ENOMEM;
            }
        }
    }

    return 0;
}

struct foreign_p2m_region {
    unsigned long       gpfn;
    unsigned long       num_gpfn;
};

struct foreign_p2m_entry {
    struct list_head            list;
    int                         busy;

    /* src domain  */
    struct domain*              src_dom;

    /* region into which foreign p2m table is mapped */
    unsigned long               gpfn;
    unsigned long               num_gpfn;
    unsigned int                num_region;
    struct foreign_p2m_region   region[0];
};

/* caller must increment the reference count of src_dom */
static int
foreign_p2m_alloc(struct foreign_p2m* foreign_p2m,
                  unsigned long dest_gpfn, struct domain* src_dom,
                  struct xen_ia64_memmap_info* memmap_info, void* memmap,
                  struct foreign_p2m_entry** entryp)
{
    void* memmap_end = memmap + memmap_info->efi_memmap_size;
    efi_memory_desc_t* md;
    unsigned long dest_gpfn_end;
    unsigned long src_gpfn;
    unsigned long src_gpfn_end;

    unsigned int num_region;
    struct foreign_p2m_entry* entry;
    struct foreign_p2m_entry* prev;
    struct foreign_p2m_entry* pos;

    num_region = (memmap_end - memmap) / memmap_info->efi_memdesc_size;

    md = memmap;
    src_gpfn = P2M_PFN_ROUNDDOWN(md->phys_addr >> PAGE_SHIFT);

    md = memmap + (num_region - 1) * memmap_info->efi_memdesc_size;
    src_gpfn_end = MD_END(md) >> PAGE_SHIFT;
    if (src_gpfn_end >
        P2M_PFN_ROUNDUP(src_dom->arch.convmem_end >> PAGE_SHIFT))
        return -EINVAL;

    src_gpfn_end = P2M_PFN_ROUNDUP(src_gpfn_end);
    dest_gpfn_end = dest_gpfn + P2M_NUM_PFN(src_gpfn_end - src_gpfn);
    entry = _xmalloc(sizeof(*entry) + num_region * sizeof(entry->region[0]),
                     __alignof__(*entry));
    if (entry == NULL)
        return -ENOMEM;

    entry->busy = 1;
    entry->gpfn = dest_gpfn;
    entry->num_gpfn = dest_gpfn_end - dest_gpfn;
    entry->src_dom = src_dom;
    entry->num_region = 0;
    memset(entry->region, 0, sizeof(entry->region[0]) * num_region);
    prev = NULL;

    spin_lock(&foreign_p2m->lock);
    if (list_empty(&foreign_p2m->head))
        prev = (struct foreign_p2m_entry*)&foreign_p2m->head;

    list_for_each_entry(pos, &foreign_p2m->head, list) {
        if (pos->gpfn + pos->num_gpfn < dest_gpfn) {
            prev = pos;
            continue;
        }

        if (dest_gpfn_end < pos->gpfn) {
            if (prev != NULL && prev->gpfn + prev->num_gpfn > dest_gpfn)
                prev = NULL;/* overlap */
            break;
        }

        /* overlap */
        prev = NULL;
        break;
    }
    if (prev != NULL) {
            list_add(&entry->list, &prev->list);
            spin_unlock(&foreign_p2m->lock);
            *entryp = entry;
            return 0;
    }
    spin_unlock(&foreign_p2m->lock);
    xfree(entry);
    return -EBUSY;
}

static void
foreign_p2m_unexpose(struct domain* dest_dom, struct foreign_p2m_entry* entry)
{
    unsigned int i;

    BUG_ON(!entry->busy);
    for (i = 0; i < entry->num_region; i++)
        unexpose_p2m(dest_dom,
                     entry->region[i].gpfn, entry->region[i].num_gpfn);
}

static void
foreign_p2m_unbusy(struct foreign_p2m* foreign_p2m,
                   struct foreign_p2m_entry* entry)
{
    spin_lock(&foreign_p2m->lock);
    BUG_ON(!entry->busy);
    entry->busy = 0;
    spin_unlock(&foreign_p2m->lock);
}

static void
foreign_p2m_free(struct foreign_p2m* foreign_p2m, 
                 struct foreign_p2m_entry* entry)
{
    spin_lock(&foreign_p2m->lock);
    BUG_ON(!entry->busy);
    list_del(&entry->list);
    spin_unlock(&foreign_p2m->lock);

    put_domain(entry->src_dom);
    xfree(entry);
}

void
foreign_p2m_init(struct domain* d)
{
    struct foreign_p2m* foreign_p2m = &d->arch.foreign_p2m;
    INIT_LIST_HEAD(&foreign_p2m->head);
    spin_lock_init(&foreign_p2m->lock);
}

void
foreign_p2m_destroy(struct domain* d)
{
    struct foreign_p2m* foreign_p2m = &d->arch.foreign_p2m;
    struct foreign_p2m_entry* entry;
    struct foreign_p2m_entry* n;

    spin_lock(&foreign_p2m->lock);
    list_for_each_entry_safe(entry, n, &foreign_p2m->head, list) {
        /* mm_teardown() cleared p2m table already */
        /* foreign_p2m_unexpose(d, entry);*/
        list_del(&entry->list);
        put_domain(entry->src_dom);
        xfree(entry);
    }
    spin_unlock(&foreign_p2m->lock);
}

unsigned long
dom0vp_expose_foreign_p2m(struct domain* dest_dom,
                          unsigned long dest_gpfn,
                          domid_t domid,
                          XEN_GUEST_HANDLE(char) buffer,
                          unsigned long flags)
{
    unsigned long ret = 0;
    struct domain* src_dom;
    struct xen_ia64_memmap_info memmap_info;
    char* memmap;
    void* memmap_end;
    void* p;

    struct foreign_p2m_entry* entry;

    ret = memmap_info_copy_from_guest(&memmap_info, &memmap, buffer);
    if (ret != 0)
        return ret;

    dest_dom = rcu_lock_domain(dest_dom);
    if (dest_dom == NULL) {
        ret = -EINVAL;
        goto out;
    }
#if 1
    // Self foreign domain p2m exposure isn't allowed.
    // Otherwise the domain can't be destroyed because
    // no one decrements the domain reference count.
    if (domid == dest_dom->domain_id) {
        ret = -EINVAL;
        goto out;
    }
#endif    

    src_dom = get_domain_by_id(domid);
    if (src_dom == NULL) {
        ret = -EINVAL;
        goto out_unlock;
    }

    if (flags & IA64_DOM0VP_EFP_ALLOC_PTE) {
        ret = foreign_p2m_allocate_pte(src_dom, &memmap_info, memmap);
        if (ret != 0)
            goto out_unlock;
    }

    ret = foreign_p2m_alloc(&dest_dom->arch.foreign_p2m, dest_gpfn,
                            src_dom, &memmap_info, memmap, &entry);
    if (ret != 0)
        goto out_unlock;

    memmap_end = memmap + memmap_info.efi_memmap_size;
    for (p = memmap; p < memmap_end; p += memmap_info.efi_memdesc_size) {
        efi_memory_desc_t* md = p;
        unsigned long src_gpfn =
            P2M_PFN_ROUNDDOWN(md->phys_addr >> PAGE_SHIFT);
        unsigned long src_gpfn_end =
            P2M_PFN_ROUNDUP(MD_END(md) >> PAGE_SHIFT);
        unsigned long num_src_gpfn = src_gpfn_end - src_gpfn;
        
        ret = expose_p2m(dest_dom, dest_gpfn + src_gpfn / PTRS_PER_PTE,
                         src_dom, src_gpfn, num_src_gpfn);
        if (ret != 0)
            break;

        entry->region[entry->num_region].gpfn =
            dest_gpfn + src_gpfn / PTRS_PER_PTE;
        entry->region[entry->num_region].num_gpfn = P2M_NUM_PFN(num_src_gpfn);
        entry->num_region++;
    }

    if (ret == 0) {
        foreign_p2m_unbusy(&dest_dom->arch.foreign_p2m, entry);
    } else {
        foreign_p2m_unexpose(dest_dom, entry);
        foreign_p2m_free(&dest_dom->arch.foreign_p2m, entry);
    }

 out_unlock:
    rcu_unlock_domain(dest_dom);
 out:
    xfree(memmap);
    return ret;
}

unsigned long
dom0vp_unexpose_foreign_p2m(struct domain* dest_dom,
                            unsigned long dest_gpfn,
                            domid_t domid)
{
    int ret = -ENOENT;
    struct foreign_p2m* foreign_p2m = &dest_dom->arch.foreign_p2m;
    struct foreign_p2m_entry* entry;

    dest_dom = rcu_lock_domain(dest_dom);
    if (dest_dom == NULL)
        return ret;
    spin_lock(&foreign_p2m->lock);
    list_for_each_entry(entry, &foreign_p2m->head, list) {
        if (entry->gpfn < dest_gpfn)
              continue;
        if (dest_gpfn < entry->gpfn)
            break;

        if (domid == entry->src_dom->domain_id)
            ret = 0;
        else
            ret = -EINVAL;
        break;
    }
    if (ret == 0) {
        if (entry->busy == 0)
            entry->busy = 1;
        else
            ret = -EBUSY;
    }
    spin_unlock(&foreign_p2m->lock);

    if (ret == 0) {
        foreign_p2m_unexpose(dest_dom, entry);
        foreign_p2m_free(&dest_dom->arch.foreign_p2m, entry);
    }
    rcu_unlock_domain(dest_dom);
    return ret;
}

/* this lock can be only for memmap_info. domain_lock() is abused here */
static void
memmap_lock(struct domain *d)
{
    domain_lock(d);
}

static void
memmap_unlock(struct domain *d)
{
    domain_unlock(d);
}

/* copy memory range to domain pseudo physical address space */
static int
__memmap_copy_to(struct domain *d, unsigned long dest_gpfn,
               void *src, unsigned long num_pages)
{
    BUG_ON(((unsigned long)src & ~PAGE_MASK) != 0);
    
    while (num_pages > 0) {
        unsigned long mfn;
        struct page_info *page;
        void *virt;

        mfn = gmfn_to_mfn_foreign(d, dest_gpfn);
        if (mfn == 0 || mfn == INVALID_MFN)
            return -EFAULT;
        page = mfn_to_page(mfn);
        if (get_page(page, d) == 0)
            return -EFAULT;
        virt = mfn_to_virt(mfn);
        copy_page(virt, src);
        __xencomm_mark_dirty(d, (unsigned long)virt, PAGE_SIZE);
        put_page(page);

        src += PAGE_SIZE;
        dest_gpfn++;
        num_pages--;
    }

    return 0;
}

/* copy memory range from domain pseudo physical address space */
static int
__memmap_copy_from(void *dest, struct domain *d, unsigned long src_gpfn,
                   unsigned long num_pages)
{
    BUG_ON(((unsigned long)dest & ~PAGE_MASK) != 0);

    while (num_pages > 0) {
        unsigned long mfn;
        struct page_info *page;

        mfn = gmfn_to_mfn_foreign(d, src_gpfn);
        if (mfn == 0 || mfn == INVALID_MFN)
            return -EFAULT;
        page = mfn_to_page(mfn);
        if (get_page(page, d) == 0)
            return -EFAULT;
        copy_page(dest, mfn_to_virt(mfn));
        put_page(page);

        dest += PAGE_SIZE;
        src_gpfn++;
        num_pages--;
    }

    return 0;
}

/* This function unlock/lock memmeap_lock.
 * caller must free (*page, *order) even if error case by ckecking
 * *page = NULL.
 */
static int
memmap_copy_from(struct domain *d,
                 struct page_info **page, unsigned long *order)
{
    unsigned long num_pages;
    struct xen_ia64_memmap_info *memmap_info;
    unsigned long memmap_info_pfn;

    num_pages = d->shared_info->arch.memmap_info_num_pages;
    memmap_unlock(d);

 again:
    *order = get_order(num_pages << PAGE_SHIFT);
    *page = alloc_domheap_pages(NULL, *order, 0);
    if (*page == NULL)
        return -ENOMEM;
    memmap_info = page_to_virt(*page);

    memmap_lock(d);
    if (d->shared_info->arch.memmap_info_num_pages != num_pages) {
        num_pages = d->shared_info->arch.memmap_info_num_pages;
        memmap_unlock(d);
        free_domheap_pages(*page, *order);
        goto again;
    }
    memmap_info_pfn = d->shared_info->arch.memmap_info_pfn;

    /* copy into local to make them virtually contiguous */
    return __memmap_copy_from(memmap_info, d, memmap_info_pfn, num_pages);
}

static int
memdesc_can_expand(const struct xen_ia64_memmap_info *memmap_info,
                   unsigned long num_pages)
{
    /* Is there room for one more md? */
    if ((num_pages << PAGE_SHIFT) <
        (sizeof(*memmap_info) + memmap_info->efi_memmap_size +
         memmap_info->efi_memdesc_size))
        return 0;

    return 1;
}

static int
memdesc_can_collapse(const efi_memory_desc_t *lhs,
                     const efi_memory_desc_t *rhs)
{
    return (lhs->type == rhs->type && lhs->attribute == rhs->attribute);
}

static int
__dom0vp_add_memdesc_one(struct xen_ia64_memmap_info *memmap_info,
                         unsigned long num_pages,
                         const efi_memory_desc_t *md)
{
    void* const memmap_end = (void*)memmap_info->memdesc +
        memmap_info->efi_memmap_size;
    void *p;
    efi_memory_desc_t *tmp_md;
    efi_memory_desc_t *s_md;
    efi_memory_desc_t *e_md;
    u64 phys_addr;
    u64 phys_addr_end;

    /* fast path. appending to the last entry */
    tmp_md = (efi_memory_desc_t*)(memmap_end - memmap_info->efi_memdesc_size);
    if (MD_END(tmp_md) < md->phys_addr) {
        /* append one */
        if (!memdesc_can_expand(memmap_info, num_pages))
            return -ENOMEM;

        memcpy(memmap_end, md, memmap_info->efi_memdesc_size);
        memmap_info->efi_memmap_size += memmap_info->efi_memdesc_size;
        return 0;
    }
    /* fast path. expand the last entry */
    if (tmp_md->phys_addr <= md->phys_addr) {
        if (!memdesc_can_collapse(tmp_md, md))
            return -EINVAL;

        phys_addr_end = max(MD_END(tmp_md), MD_END(md));
        tmp_md->num_pages =
            (phys_addr_end - tmp_md->phys_addr) >> EFI_PAGE_SHIFT;
        return 0;
    }

    /* slow path */
    s_md = NULL;
    e_md = NULL;
    for (p = memmap_info->memdesc;
         p < memmap_end;
         p += memmap_info->efi_memdesc_size) {
        tmp_md = p;

        if (MD_END(tmp_md) < md->phys_addr)
            continue;

        if (MD_END(md) < tmp_md->phys_addr) {
            if (s_md == NULL) {
                void *next_md = p + memmap_info->efi_memdesc_size;
                size_t left_size = memmap_end - (void*)tmp_md;

                /* found hole. just insert md here*/
                if (!memdesc_can_expand(memmap_info, num_pages))
                    return -ENOMEM;

                memmove(next_md, tmp_md, left_size);
                memcpy(tmp_md, md, memmap_info->efi_memdesc_size);
                memmap_info->efi_memmap_size += memmap_info->efi_memdesc_size;
                return 0;
            }
            break;
        }

        if (s_md == NULL)
            s_md = tmp_md;
        e_md = tmp_md;

        if (!memdesc_can_collapse(tmp_md, md))
            return -EINVAL;
    }
    BUG_ON(s_md == NULL || e_md == NULL);

    /* collapse into one */
    phys_addr = min(md->phys_addr, s_md->phys_addr);
    phys_addr_end = max(MD_END(md), MD_END(e_md));
    s_md->phys_addr = phys_addr;
    s_md->num_pages = (phys_addr_end - phys_addr) >> EFI_PAGE_SHIFT;
    if (s_md != e_md) {
        void *next_s_md = (void*)s_md + memmap_info->efi_memdesc_size;
        void *next_e_md = (void*)e_md + memmap_info->efi_memdesc_size;
        size_t left_size = memmap_end - (void*)next_e_md;

        memmap_info->efi_memmap_size -= (void*)e_md - (void*)s_md;
        if (left_size > 0)
            memmove(next_s_md, next_e_md, left_size);
    }

    return 0;
}

/*
 * d->arch.convmem_end is mostly read only and sometimes increased.
 * It is protected by memmap_lock
 *
 * d->arch.convmem_end is also referned by guest(self p2m exposure)
 * d->shared_info.arch.memmap_info_xxx and memmap_info are
 * referenced by tools stack(save/dump-core/foreign p2m exposure).
 *
 * reader side:
 *  - get d->arch.convmem_end (via XENMEM_maximum_gpfn)
 *  - issue get_memmap hypercall to get memmap
 *    In VMM
 *    - lock memmap_lock
 *    - copy memmap from target guest
 *    - unlock memmap_lock
 *    - copy memmap into tools stack address space.
 *  - check d->shared_info.memmap_info_num_pages. try again if necessary
 *  - get d->arch.convmem_end. try again if changed.
 *
 * writer side:
 *  - lock memmap_lock
 *  - increase d->arch.convmem_end at first if necessary
 *  - unlock memmap_lock
 *  - allocate memory
 *    In fact page allocation isn't blocking, so unlock/lock isn't necessary.
 *  - lock memmap_lock
 *  - update memmap_info
 *  - unlock memmap_lock
 */
static int
__dom0vp_add_memdesc(struct domain *targ_d,
                     const struct xen_ia64_memmap_info *u_memmap_info,
                     const char *u_memmap)
{
    int ret = 0;
    const void* const u_memmap_end = u_memmap + u_memmap_info->efi_memmap_size;
    const efi_memory_desc_t *md;

    unsigned long md_end_max;
    unsigned long num_pages;
    unsigned long order;
    unsigned long memmap_info_pfn;

    struct page_info *page = NULL;
    struct xen_ia64_memmap_info *memmap_info;
    size_t unused_size;

    const void *p;

    /* update d->arch.convmem_end */
    md_end_max = 0;
    for (p = u_memmap; p < u_memmap_end;
         p += u_memmap_info->efi_memdesc_size) {
        md = p;
        if (MD_END(md) > md_end_max)
            md_end_max = MD_END(md);
    }
    memmap_lock(targ_d);
    /* convmem_end is also protected memdesc lock */
    if (md_end_max > targ_d->arch.convmem_end)
        targ_d->arch.convmem_end = md_end_max;

    /* memmap_copy_from_guest() unlock/lock memmap_lock() */
    ret = memmap_copy_from(targ_d, &page, &order);
    if (ret != 0)
        goto out;
    memmap_info = page_to_virt(page);
    num_pages = targ_d->shared_info->arch.memmap_info_num_pages;
    memmap_info_pfn = targ_d->shared_info->arch.memmap_info_pfn;

    if (memmap_info->efi_memdesc_size != u_memmap_info->efi_memdesc_size ||
        memmap_info->efi_memdesc_version !=
        u_memmap_info->efi_memdesc_version) {
        ret = -EINVAL;
        goto out;
    }

    /* update memdesc */
    for (p = u_memmap;
         p < u_memmap_end;
         p += u_memmap_info->efi_memdesc_size) {
        md = p;
        ret = __dom0vp_add_memdesc_one(memmap_info, num_pages, md);
        if (ret != 0)
            goto out;
    }

    /* zero out the unused region to avoid hypervisor bit leak */
    unused_size = (num_pages << PAGE_SHIFT) -
        (sizeof(*memmap_info) + memmap_info->efi_memmap_size);
    if (unused_size > 0)
        memset((void*)memmap_info->memdesc + memmap_info->efi_memmap_size,
               0, unused_size);

    /* copy back into domain. */
    ret = __memmap_copy_to(targ_d, memmap_info_pfn, memmap_info, num_pages);

 out:
    memmap_unlock(targ_d);

    if (page != NULL)
        free_domheap_pages(page, order);
    return ret;
}

unsigned long
dom0vp_get_memmap(domid_t domid, XEN_GUEST_HANDLE(char) buffer)
{
    unsigned long ret = 0;
    struct domain *targ_d;

    struct page_info *page = NULL;
    unsigned long order;

    struct xen_ia64_memmap_info *memmap_info;
    unsigned long num_pages;
    
    ret = rcu_lock_target_domain_by_id(domid, &targ_d);
    if (ret != 0)
        return ret;

    memmap_lock(targ_d);

    ret = memmap_copy_from(targ_d, &page, &order);
    if (ret != 0)
        goto unlock_out;

    memmap_info = page_to_virt(page);
    num_pages = targ_d->shared_info->arch.memmap_info_num_pages;
    if ((num_pages << PAGE_SHIFT) - sizeof(*memmap_info) <
        memmap_info->efi_memmap_size) {
        ret = -EFAULT;
        goto unlock_out;
    }
    memmap_unlock(targ_d);
    rcu_unlock_domain(targ_d);
    
    if (copy_to_guest(buffer, (char*)memmap_info, sizeof(*memmap_info)) ||
        copy_to_guest_offset(buffer, sizeof(*memmap_info),
                             (char*)memmap_info->memdesc,
                             memmap_info->efi_memmap_size))
        ret = -EFAULT;

 out:
    if (page != NULL)
        free_domheap_pages(page, order);
    return ret;

 unlock_out:
    memmap_unlock(targ_d);
    rcu_unlock_domain(targ_d);
    goto out;
}
#endif

// grant table host mapping
// mpaddr: host_addr: pseudo physical address
// mfn: frame: machine page frame
// flags: GNTMAP_readonly | GNTMAP_application_map | GNTMAP_contains_pte
int
create_grant_host_mapping(unsigned long gpaddr, unsigned long mfn, 
                          unsigned int flags, unsigned int cache_flags)
{
    struct domain* d = current->domain;
    struct page_info* page;
    int ret;

    if ((flags & (GNTMAP_device_map | 
                  GNTMAP_application_map | GNTMAP_contains_pte)) ||
        (cache_flags)) {
        gdprintk(XENLOG_INFO, "%s: flags 0x%x cache_flags 0x%x\n",
                 __func__, flags, cache_flags);
        return GNTST_general_error;
    }

    BUG_ON(!mfn_valid(mfn));
    page = mfn_to_page(mfn);
    ret = get_page(page, page_get_owner(page));
    BUG_ON(ret == 0);
    assign_domain_page_replace(d, gpaddr, mfn,
#ifdef CONFIG_XEN_IA64_TLB_TRACK
                               ASSIGN_tlb_track |
#endif
                               ((flags & GNTMAP_readonly) ?
                                ASSIGN_readonly : ASSIGN_writable));
    perfc_incr(create_grant_host_mapping);
    return GNTST_okay;
}

// grant table host unmapping
int
replace_grant_host_mapping(unsigned long gpaddr,
	       unsigned long mfn, unsigned long new_gpaddr, unsigned int flags)
{
    struct domain* d = current->domain;
    unsigned long gpfn = gpaddr >> PAGE_SHIFT;
    volatile pte_t* pte;
    unsigned long cur_arflags;
    pte_t cur_pte;
    pte_t new_pte = __pte(0);
    pte_t old_pte;
    struct page_info* page = mfn_to_page(mfn);
    struct page_info* new_page = NULL;
    volatile pte_t* new_page_pte = NULL;
    unsigned long new_page_mfn = INVALID_MFN;

    if (new_gpaddr) {
        new_page_pte = lookup_noalloc_domain_pte_none(d, new_gpaddr);
        if (likely(new_page_pte != NULL)) {
            new_pte = ptep_get_and_clear(&d->arch.mm,
                                         new_gpaddr, new_page_pte);
            if (likely(pte_present(new_pte))) {
                struct domain* page_owner;

                new_page_mfn = pte_pfn(new_pte);
                new_page = mfn_to_page(new_page_mfn);
                page_owner = page_get_owner(new_page);
                if (unlikely(page_owner == NULL)) {
                    gdprintk(XENLOG_INFO,
                             "%s: page_owner == NULL "
                             "gpaddr 0x%lx mfn 0x%lx "
                             "new_gpaddr 0x%lx mfn 0x%lx\n",
                             __func__, gpaddr, mfn, new_gpaddr, new_page_mfn);
                    new_page = NULL; /* prevent domain_put_page() */
                    return GNTST_general_error;
                }

                /*
		 * domain_put_page(clear_PGC_allcoated = 0)
                 * doesn't decrement refcount of page with
                 * pte_ptc_allocated() = 1. Be carefull.
		 */
                if (unlikely(!pte_pgc_allocated(new_pte))) {
                    /* domain_put_page() decrements page refcount. adjust it. */
                    if (get_page(new_page, page_owner)) {
                        gdprintk(XENLOG_INFO,
                                 "%s: get_page() failed. "
                                 "gpaddr 0x%lx mfn 0x%lx "
                                 "new_gpaddr 0x%lx mfn 0x%lx\n",
                                 __func__, gpaddr, mfn,
                                 new_gpaddr, new_page_mfn);
                        return GNTST_general_error;
                    }
                }
                domain_put_page(d, new_gpaddr, new_page_pte, new_pte, 0);
            } else
                new_pte = __pte(0);
        }
    }

    if (flags & (GNTMAP_application_map | GNTMAP_contains_pte)) {
        gdprintk(XENLOG_INFO, "%s: flags 0x%x\n", __func__, flags);
        return GNTST_general_error;
    }

    pte = lookup_noalloc_domain_pte(d, gpaddr);
    if (pte == NULL) {
        gdprintk(XENLOG_INFO, "%s: gpaddr 0x%lx mfn 0x%lx\n",
                __func__, gpaddr, mfn);
        return GNTST_general_error;
    }

 again:
    cur_arflags = pte_val(*pte) & ~_PAGE_PPN_MASK;
    cur_pte = pfn_pte(mfn, __pgprot(cur_arflags));
    if (!pte_present(cur_pte) ||
        (page_get_owner(page) == d && get_gpfn_from_mfn(mfn) == gpfn)) {
        gdprintk(XENLOG_INFO, "%s: gpaddr 0x%lx mfn 0x%lx cur_pte 0x%lx\n",
                __func__, gpaddr, mfn, pte_val(cur_pte));
        return GNTST_general_error;
    }

    if (new_page) {
        BUG_ON(new_page_mfn == INVALID_MFN);
        set_gpfn_from_mfn(new_page_mfn, gpfn);
        /* smp_mb() isn't needed because assign_domain_pge_cmpxchg_rel()
           has release semantics. */
    }
    old_pte = ptep_cmpxchg_rel(&d->arch.mm, gpaddr, pte, cur_pte, new_pte);
    if (unlikely(pte_val(cur_pte) != pte_val(old_pte))) {
        if (pte_pfn(old_pte) == mfn) {
            goto again;
        }
        if (new_page) {
            BUG_ON(new_page_mfn == INVALID_MFN);
            set_gpfn_from_mfn(new_page_mfn, INVALID_M2P_ENTRY);
            domain_put_page(d, new_gpaddr, new_page_pte, new_pte, 1);
        }
        goto out;
    }
    if (unlikely(!pte_present(old_pte)))
        goto out;
    BUG_ON(pte_pfn(old_pte) != mfn);

    /* try_to_clear_PGC_allocate(d, page) is not needed. */
    BUG_ON(page_get_owner(page) == d &&
           get_gpfn_from_mfn(mfn) == gpfn);
    BUG_ON(pte_pgc_allocated(old_pte));
    domain_page_flush_and_put(d, gpaddr, pte, old_pte, page);

    perfc_incr(replace_grant_host_mapping);
    return GNTST_okay;

 out:
    gdprintk(XENLOG_INFO, "%s gpaddr 0x%lx mfn 0x%lx cur_pte "
             "0x%lx old_pte 0x%lx\n",
             __func__, gpaddr, mfn, pte_val(cur_pte), pte_val(old_pte));
    return GNTST_general_error;
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
    unsigned long x, y;

    if (page_get_owner(page) != d) {
        gdprintk(XENLOG_INFO, "%s d 0x%p owner 0x%p\n",
                __func__, d, page_get_owner(page));
        return -1;
    }
    
    if (!(memflags & MEMF_no_refcount)) {
        unsigned long gpfn;
        struct page_info *new;
        unsigned long new_mfn;
        int ret;

        new = alloc_domheap_page(d, 0);
        if (new == NULL) {
            gdprintk(XENLOG_INFO, "alloc_domheap_page() failed\n");
            return -1;
        }
        // zero out pages for security reasons
        clear_page(page_to_virt(new));
        // assign_domain_page_cmpxchg_rel() has release semantics
        // so smp_mb() isn't needed.

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
                                             ASSIGN_writable |
                                             ASSIGN_pgc_allocated, 0);
        if (ret < 0) {
            gdprintk(XENLOG_INFO, "assign_domain_page_cmpxchg_rel failed %d\n",
                    ret);
            set_gpfn_from_mfn(new_mfn, INVALID_M2P_ENTRY);
            free_domheap_page(new);
            return -1;
        }
        perfc_incr(steal_page_refcount);
    }

    spin_lock(&d->page_alloc_lock);
    /* check again */
    if (is_xen_heap_page(page) || page_get_owner(page) != d) {
        goto fail;
    }

    /*
     * We require there is just one reference (PGC_allocated). We temporarily
     * drop this reference now so that we can safely swizzle the owner.
     */
    y = page->count_info;
    do {
        x = y;

        if (unlikely(((x & (PGC_count_mask | PGC_allocated)) !=
                      (1 | PGC_allocated)))) {
            struct domain* nd = page_get_owner(page);
            if (nd == NULL) {
                gdprintk(XENLOG_INFO, "gnttab_transfer: "
                        "Bad page %p: ed=%p(%u), "
                        "sd=%p,"
                        " caf=%016lx, taf=%" PRtype_info
                        " memflags 0x%x\n",
                        (void *) page_to_mfn(page),
                        d, d->domain_id,
                        nd,
                        x,
                        page->u.inuse.type_info,
                        memflags);
            } else {
                gdprintk(XENLOG_WARNING, "gnttab_transfer: "
                        "Bad page %p: ed=%p(%u), "
                        "sd=%p(%u),"
                        " caf=%016lx, taf=%" PRtype_info
                        " memflags 0x%x\n",
                        (void *) page_to_mfn(page),
                        d, d->domain_id,
                        nd, nd->domain_id,
                        x,
                        page->u.inuse.type_info,
                        memflags);
            }
            goto fail;
        }

        y = cmpxchg(&page->count_info, x, x & ~PGC_count_mask);
    } while (unlikely(y != x));

    /* Swizzle the owner then reinstate the PGC_allocated reference. */
    page_set_owner(page, NULL);
    y = page->count_info;
    do {
        x = y;
        BUG_ON((x & (PGC_count_mask | PGC_allocated)) != PGC_allocated);
        y = cmpxchg(&page->count_info, x, x | 1);
    } while (unlikely(y != x));

    /* Unlink from original owner. */
    if ( !(memflags & MEMF_no_refcount) )
        d->tot_pages--;
    page_list_del(page, &d->page_list);

    spin_unlock(&d->page_alloc_lock);
    perfc_incr(steal_page);
    return 0;

 fail:
    spin_unlock(&d->page_alloc_lock);
    MEM_LOG("Bad page %p: ed=%p(%u), sd=%p, caf=%016lx, taf=%" PRtype_info,
            (void *)page_to_mfn(page), d, d->domain_id,
            page_get_owner(page), page->count_info, page->u.inuse.type_info);
    return -1;
}

int
donate_page(struct domain *d, struct page_info *page, unsigned int memflags)
{
    /* needs to be implemented for transcendent memory (tmem) */
    ASSERT(0);
    return -ENOSYS;
}

static void
__guest_physmap_add_page(struct domain *d, unsigned long gpfn,
                         unsigned long mfn)
{
    set_gpfn_from_mfn(mfn, gpfn);
    smp_mb();
    assign_domain_page_replace(d, gpfn << PAGE_SHIFT, mfn,
                               ASSIGN_writable | ASSIGN_pgc_allocated);
    if ( iommu_enabled && need_iommu(d) ){
        int i, j;
        j = 1 << (PAGE_SHIFT-PAGE_SHIFT_4K);
        for(i = 0 ; i < j; i++)
            iommu_map_page(d, gpfn*j + i, mfn*j + i);
    }
}

int
guest_physmap_add_page(struct domain *d, unsigned long gpfn,
                       unsigned long mfn, unsigned int page_order)
{
    unsigned long i;

    for (i = 0; i < (1UL << page_order); i++) {
        BUG_ON(!mfn_valid(mfn));
        BUG_ON((mfn_to_page(mfn)->count_info & ~PGC_xen_heap) !=
               (PGC_allocated | 1));
        __guest_physmap_add_page(d, gpfn, mfn);
        mfn++;
        gpfn++;
    }

    perfc_incr(guest_physmap_add_page);
    return 0;
}

void
guest_physmap_remove_page(struct domain *d, unsigned long gpfn,
                          unsigned long mfn, unsigned int page_order)
{
    unsigned long i;

    BUG_ON(mfn == 0);//XXX

    for (i = 0; i < (1UL << page_order); i++)
        zap_domain_page_one(d, (gpfn+i) << PAGE_SHIFT, 0, mfn+i);

    perfc_incr(guest_physmap_remove_page);
}

static void
domain_page_flush_and_put(struct domain* d, unsigned long mpaddr,
                          volatile pte_t* ptep, pte_t old_pte,
                          struct page_info* page)
{
#ifdef CONFIG_XEN_IA64_TLB_TRACK
    struct tlb_track_entry* entry;
#endif

    if (shadow_mode_enabled(d))
        shadow_mark_page_dirty(d, mpaddr >> PAGE_SHIFT);

#ifndef CONFIG_XEN_IA64_TLB_TRACK
    //XXX sledgehammer.
    //    flush finer range.
    domain_flush_vtlb_all(d);
    put_page(page);
#else
    switch (tlb_track_search_and_remove(d->arch.tlb_track,
                                        ptep, old_pte, &entry)) {
    case TLB_TRACK_NOT_TRACKED:
        // dprintk(XENLOG_WARNING, "%s TLB_TRACK_NOT_TRACKED\n", __func__);
        /* This page is zapped from this domain
         * by memory decrease or exchange or dom0vp_zap_physmap.
         * I.e. the page is zapped for returning this page to xen
         * (balloon driver or DMA page allocation) or
         * foreign domain mapped page is unmapped from the domain.
         * In the former case the page is to be freed so that
         * we can defer freeing page to batch.
         * In the latter case the page is unmapped so that
         * we need to flush it. But to optimize it, we
         * queue the page and flush vTLB only once.
         * I.e. The caller must call dfree_flush() explicitly.
         */
        domain_flush_vtlb_all(d);
        put_page(page);
        break;
    case TLB_TRACK_NOT_FOUND:
        // dprintk(XENLOG_WARNING, "%s TLB_TRACK_NOT_FOUND\n", __func__);
        /* This page is zapped from this domain
         * by grant table page unmap.
         * Luckily the domain that mapped this page didn't
         * access this page so that we don't have to flush vTLB.
         * Probably the domain did only DMA.
         */
        /* do nothing */
        put_page(page);
        break;
    case TLB_TRACK_FOUND:
        // dprintk(XENLOG_WARNING, "%s TLB_TRACK_FOUND\n", __func__);
        /* This page is zapped from this domain
         * by grant table page unmap.
         * Fortunately this page is accessced via only one virtual
         * memory address. So it is easy to flush it.
         */
        domain_flush_vtlb_track_entry(d, entry);
        tlb_track_free_entry(d->arch.tlb_track, entry);
        put_page(page);
        break;
    case TLB_TRACK_MANY:
        gdprintk(XENLOG_INFO, "%s TLB_TRACK_MANY\n", __func__);
        /* This page is zapped from this domain
         * by grant table page unmap.
         * Unfortunately this page is accessced via many virtual
         * memory address (or too many times with single virtual address).
         * So we abondaned to track virtual addresses.
         * full vTLB flush is necessary.
         */
        domain_flush_vtlb_all(d);
        put_page(page);
        break;
    case TLB_TRACK_AGAIN:
        gdprintk(XENLOG_ERR, "%s TLB_TRACK_AGAIN\n", __func__);
        BUG();
        break;
    }
#endif
    perfc_incr(domain_page_flush_and_put);
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
    volatile pgd_t *pgd = mm->pgd;
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
        volatile pud_t *pud;
        if (!pgd_present(*pgd)) // acquire semantics
            continue;
        pud = pud_offset(pgd, 0);
        for (j = 0; j < PTRS_PER_PUD; pud++, j++) {
            volatile pmd_t *pmd;
            if (!pud_present(*pud)) // acquire semantics
                continue;
            pmd = pmd_offset(pud, 0);
            for (k = 0; k < PTRS_PER_PMD; pmd++, k++) {
                volatile pte_t *pte;
                if (!pmd_present(*pmd)) // acquire semantics
                    continue;
                pte = pte_offset_map(pmd, 0);
                for (l = 0; l < PTRS_PER_PTE; pte++, l++) {
                    if (!pte_present(*pte)) // acquire semantics
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
    //printk ("domain_cache_flush: %d %d pages\n", d->domain_id, nbr_page);
}

static void free_page_type(struct page_info *page, unsigned long type)
{
}

static int alloc_page_type(struct page_info *page, unsigned long type)
{
	return 1;
}

void *pgtable_quicklist_alloc(void)
{
    struct page_info *page;
    void *p;

    BUG_ON(dom_p2m == NULL);
    page = alloc_domheap_page(dom_p2m, 0);
    if (page == NULL)
        return NULL;

    p = page_to_virt(page);
    clear_page(p);
    return p;
}

void pgtable_quicklist_free(void *pgtable_entry)
{
    struct page_info* page = virt_to_page(pgtable_entry);

    BUG_ON(page_get_owner(page) != dom_p2m);
    BUG_ON(page->count_info != (1 | PGC_allocated));

    put_page(page);
}

void put_page_type(struct page_info *page)
{
    u64 nx, x, y = page->u.inuse.type_info;

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
        ASSERT((x & PGT_validated) || page_get_owner(page)->is_dying);

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
    }
    while ( unlikely((y = cmpxchg_rel(&page->u.inuse.type_info, x, nx)) != x) );
}


static int get_page_from_pagenr(unsigned long page_nr, struct domain *d)
{
    struct page_info *page = mfn_to_page(page_nr);

    if ( unlikely(!mfn_valid(page_nr)) || unlikely(!get_page(page, d)) )
    {
        MEM_LOG("Could not get page ref for pfn %lx", page_nr);
        return 0;
    }

    return 1;
}


int get_page_type(struct page_info *page, unsigned long type)
{
    u64 nx, x, y = page->u.inuse.type_info;

    ASSERT(!(type & ~PGT_type_mask));

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
            if ( (x & PGT_type_mask) != type )
            {
                /*
                 * On type change we check to flush stale TLB entries. This 
                 * may be unnecessary (e.g., page was GDT/LDT) but those 
                 * circumstances should be very rare.
                 */
                cpumask_t mask =
                    page_get_owner(page)->domain_dirty_cpumask;
                tlbflush_filter(mask, page->tlbflush_timestamp);

                if ( unlikely(!cpus_empty(mask)) )
                {
                    perfc_incr(need_flush_tlb_flush);
                    flush_tlb_mask(&mask);
                }

                /* We lose existing type, back pointer, and validity. */
                nx &= ~(PGT_type_mask | PGT_validated);
                nx |= type;

                /* No special validation needed for writable pages. */
                /* Page tables and GDT/LDT need to be scanned for validity. */
                if ( type == PGT_writable_page )
                    nx |= PGT_validated;
            }
        }
        else if ( unlikely((x & PGT_type_mask) != type) )
        {
            if ( ((x & PGT_type_mask) != PGT_l2_page_table) ||
                 (type != PGT_l1_page_table) )
                MEM_LOG("Bad type (saw %08lx != exp %08lx) "
                        "for mfn %016lx (pfn %016lx)",
                        x, type, page_to_mfn(page),
                        get_gpfn_from_mfn(page_to_mfn(page)));
            return 0;
        }
        else if ( unlikely(!(x & PGT_validated)) )
        {
            /* Someone else is updating validation of this page. Wait... */
            while ( (y = page->u.inuse.type_info) == x )
                cpu_relax();
            goto again;
        }
    }
    while ( unlikely((y = cmpxchg_acq(&page->u.inuse.type_info, x, nx)) != x) );

    if ( unlikely(!(nx & PGT_validated)) )
    {
        /* Try to validate page type; drop the new reference on failure. */
        if ( unlikely(!alloc_page_type(page, type)) )
        {
            MEM_LOG("Error while validating mfn %lx (pfn %lx) for type %08lx"
                    ": caf=%016lx taf=%" PRtype_info,
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

int page_is_ram_type(unsigned long mfn, unsigned long type)
{
    u32 mem_type = efi_mem_type(pfn_to_paddr(mfn));

    if (type & RAM_TYPE_CONVENTIONAL)
    {
        switch (mem_type)
        {
        case EFI_BOOT_SERVICES_CODE:
        case EFI_BOOT_SERVICES_DATA:
        case EFI_LOADER_CODE:
        case EFI_LOADER_DATA:
        case EFI_CONVENTIONAL_MEMORY:
            return 1;
        default:
            break;
        }       
    }
    if (type & RAM_TYPE_RESERVED)
    {
        switch (mem_type)
        {
        case EFI_RUNTIME_SERVICES_CODE:
        case EFI_RUNTIME_SERVICES_DATA:
        case EFI_RESERVED_TYPE:
        case EFI_MEMORY_MAPPED_IO:
        case EFI_MEMORY_MAPPED_IO_PORT_SPACE:
        case EFI_PAL_CODE:
            return 1;
        default:
            break;
        }
    }
    if (type & RAM_TYPE_ACPI)
    {
        switch (mem_type)
        {
        case EFI_ACPI_RECLAIM_MEMORY:
        case EFI_ACPI_MEMORY_NVS:
            return 1;
        default:
            break;
        }
    }
    else if (type & RAM_TYPE_UNUSABLE)
    {
        return (mem_type == EFI_UNUSABLE_MEMORY);
    }

    return 0;
}


long
arch_memory_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    struct page_info *page = NULL;
    long rc;

    switch (op) {
    case XENMEM_add_to_physmap:
    {
        struct xen_add_to_physmap xatp;
        unsigned long prev_mfn, mfn = 0, gpfn;
        struct domain *d;

        if (copy_from_guest(&xatp, arg, 1))
            return -EFAULT;

        rc = rcu_lock_target_domain_by_id(xatp.domid, &d);
        if (rc)
            return rc;

        /* This hypercall is used for VT-i domain only */
        if (!is_hvm_domain(d)) {
            rcu_unlock_domain(d);
            return -ENOSYS;
        }

        switch (xatp.space) {
        case XENMAPSPACE_shared_info:
            if (xatp.idx == 0)
                mfn = virt_to_mfn(d->shared_info);
            break;
        case XENMAPSPACE_grant_table:
            spin_lock(&d->grant_table->lock);

            if (d->grant_table->gt_version == 0)
                d->grant_table->gt_version = 1;

            if (d->grant_table->gt_version == 2 &&
                (xatp.idx & XENMAPIDX_grant_table_status))
            {
                xatp.idx &= ~XENMAPIDX_grant_table_status;
                if (xatp.idx < nr_status_frames(d->grant_table))
                    mfn = virt_to_mfn(d->grant_table->status[xatp.idx]);
            }
            else
            {
                if ((xatp.idx >= nr_grant_frames(d->grant_table)) &&
                    (xatp.idx < max_nr_grant_frames))
                    gnttab_grow_table(d, xatp.idx + 1);

                if (xatp.idx < nr_grant_frames(d->grant_table))
                    mfn = virt_to_mfn(d->grant_table->shared_raw[xatp.idx]);
            }

            spin_unlock(&d->grant_table->lock);
            break;
        case XENMAPSPACE_gmfn: {
            struct xen_ia64_memmap_info memmap_info;
            efi_memory_desc_t md;
            int ret;

            xatp.idx = gmfn_to_mfn(d, xatp.idx);
            if ( !get_page_from_pagenr(xatp.idx, d) )
                break;

            mfn = xatp.idx;
            page = mfn_to_page(mfn);

            memmap_info.efi_memmap_size = sizeof(md);
            memmap_info.efi_memdesc_size = sizeof(md);
            memmap_info.efi_memdesc_version =
                EFI_MEMORY_DESCRIPTOR_VERSION;

            md.type = EFI_CONVENTIONAL_MEMORY;
            md.pad = 0;
            md.phys_addr = xatp.gpfn << PAGE_SHIFT;
            md.virt_addr = 0;
            md.num_pages = 1UL << (PAGE_SHIFT - EFI_PAGE_SHIFT);
            md.attribute = EFI_MEMORY_WB;

            ret = __dom0vp_add_memdesc(d, &memmap_info, (char*)&md);
            if (ret != 0) {
                put_page(page);
                rcu_unlock_domain(d);
                gdprintk(XENLOG_DEBUG,
                         "%s:%d td %d gpfn 0x%lx mfn 0x%lx ret %d\n",
                         __func__, __LINE__,
                         d->domain_id, xatp.gpfn, xatp.idx, ret);
                return ret;
            }
            break;
        }
        default:
            break;
        }

        if (mfn == 0) {
            if ( page )
                put_page(page);
            rcu_unlock_domain(d);
            return -EINVAL;
        }

        domain_lock(d);

        /* Check remapping necessity */
        prev_mfn = gmfn_to_mfn(d, xatp.gpfn);
        if (mfn == prev_mfn)
            goto out;

        /* Remove previously mapped page if it was present. */
        if (prev_mfn && mfn_valid(prev_mfn)) {
            if (is_xen_heap_mfn(prev_mfn))
                /* Xen heap frames are simply unhooked from this phys slot. */
                guest_physmap_remove_page(d, xatp.gpfn, prev_mfn, 0);
            else
                /* Normal domain memory is freed, to avoid leaking memory. */
                guest_remove_page(d, xatp.gpfn);
        }

        /* Unmap from old location, if any. */
        gpfn = get_gpfn_from_mfn(mfn);
        if (gpfn != INVALID_M2P_ENTRY)
            guest_physmap_remove_page(d, gpfn, mfn, 0);

        /* Map at new location. */
        /* Here page->count_info = PGC_allocated | N where N >= 1*/
        __guest_physmap_add_page(d, xatp.gpfn, mfn);

    out:
        domain_unlock(d);

        if ( page )
            put_page(page);

        rcu_unlock_domain(d);

        break;
    }

    case XENMEM_machine_memory_map:
    {
        struct xen_memory_map memmap;
        struct xen_ia64_memmap_info memmap_info;
        XEN_GUEST_HANDLE(char) buffer;

        if (!IS_PRIV(current->domain))
            return -EINVAL;
        if (copy_from_guest(&memmap, arg, 1))
            return -EFAULT;
        if (memmap.nr_entries <
            sizeof(memmap_info) + ia64_boot_param->efi_memmap_size)
            return -EINVAL;

        memmap.nr_entries =
            sizeof(memmap_info) + ia64_boot_param->efi_memmap_size;
        memset(&memmap_info, 0, sizeof(memmap_info));
        memmap_info.efi_memmap_size = ia64_boot_param->efi_memmap_size;
        memmap_info.efi_memdesc_size = ia64_boot_param->efi_memdesc_size;
        memmap_info.efi_memdesc_version = ia64_boot_param->efi_memdesc_version;

        buffer = guest_handle_cast(memmap.buffer, char);
        if (copy_to_guest(buffer, (char*)&memmap_info, sizeof(memmap_info)) ||
            copy_to_guest_offset(buffer, sizeof(memmap_info),
                                 (char*)__va(ia64_boot_param->efi_memmap),
                                 ia64_boot_param->efi_memmap_size) ||
            copy_to_guest(arg, &memmap, 1))
            return -EFAULT;
        return 0;
    }

    case XENMEM_get_pod_target:
    case XENMEM_set_pod_target: {
        /* XXX: PoD populate on demand isn't supported yet. */
        xen_pod_target_t target;
        struct domain *d;

        /* Support DOMID_SELF? */
        if ( !IS_PRIV(current->domain) )
            return -EINVAL;

        if ( copy_from_guest(&target, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_target_domain_by_id(target.domid, &d);
        if ( rc != 0 )
            return rc;

        if ( op == XENMEM_set_pod_target )
        {
            /* if -ENOSYS is returned,
               domain builder aborts domain creation. */
            /* rc = -ENOSYS; */
        }

        target.tot_pages       = d->tot_pages;
        target.pod_cache_pages = 0;
        target.pod_entries     = 0;

        if ( copy_to_guest(arg, &target, 1) )
        {
            rc= -EFAULT;
            goto pod_target_out_unlock;
        }
        
    pod_target_out_unlock:
        rcu_unlock_domain(d);
        return rc;
    }

    default:
        return -ENOSYS;
    }

    return 0;
}

int is_iomem_page(unsigned long mfn)
{
    return (!mfn_valid(mfn) || (page_get_owner(mfn_to_page(mfn)) == dom_io));
}

static void __xencomm_mark_dirty(struct domain *d,
                                 unsigned long addr, unsigned int len)
{
    unsigned long gpfn;
    unsigned long end_addr = addr + len;

    if (shadow_mode_enabled(d)) {
        for (addr &= PAGE_MASK; addr < end_addr; addr += PAGE_SIZE) {
            gpfn = get_gpfn_from_mfn(virt_to_mfn(addr));
            shadow_mark_page_dirty(d, gpfn);
        }
    }
}

void xencomm_mark_dirty(unsigned long addr, unsigned int len)
{
    __xencomm_mark_dirty(current->domain, addr, len);
}

/* stubs for populate on demand */
int
guest_physmap_mark_populate_on_demand(struct domain *d, unsigned long gfn,
                                      unsigned int order)
{
    gdprintk(XENLOG_WARNING, "populate on demand isn't supported yet\n");
    return -ENOSYS;
}

int
p2m_pod_decrease_reservation(struct domain *d, xen_pfn_t gpfn,
                             unsigned int order)
{
    gdprintk(XENLOG_WARNING, "populate on demand isn't supported yet\n");
    return 0;
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
