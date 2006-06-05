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

#include <xen/config.h>
#include <asm/xentypes.h>
#include <asm/mm.h>
#include <asm/pgalloc.h>
#include <asm/vhpt.h>
#include <linux/efi.h>

#ifndef CONFIG_XEN_IA64_DOM0_VP
#define CONFIG_DOMAIN0_CONTIGUOUS
#else
static void domain_page_flush(struct domain* d, unsigned long mpaddr,
                              unsigned long old_mfn, unsigned long new_mfn);
#endif

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
    dom_xen = alloc_domain();
    BUG_ON(dom_xen == NULL);
    spin_lock_init(&dom_xen->page_alloc_lock);
    INIT_LIST_HEAD(&dom_xen->page_list);
    INIT_LIST_HEAD(&dom_xen->xenpage_list);
    atomic_set(&dom_xen->refcnt, 1);
    dom_xen->domain_id = DOMID_XEN;

    /*
     * Initialise our DOMID_IO domain.
     * This domain owns I/O pages that are within the range of the page_info
     * array. Mappings occur at the priv of the caller.
     */
    dom_io = alloc_domain();
    BUG_ON(dom_io == NULL);
    spin_lock_init(&dom_io->page_alloc_lock);
    INIT_LIST_HEAD(&dom_io->page_list);
    INIT_LIST_HEAD(&dom_io->xenpage_list);
    atomic_set(&dom_io->refcnt, 1);
    dom_io->domain_id = DOMID_IO;
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
    if (((mfn << PAGE_SHIFT) & GPFN_IO_MASK) != GPFN_MEM)
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

#ifdef CONFIG_XEN_IA64_DOM0_VP
    if (page_get_owner(page) == d) {
        BUG_ON(get_gpfn_from_mfn(mfn) == INVALID_M2P_ENTRY);
        set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
    }
#endif
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
#if 0
    if (get_gpfn_from_mfn(page_to_mfn(page)) != INVALID_M2P_ENTRY) {
        printk("%s:%d page 0x%p mfn 0x%lx gpfn 0x%lx\n", __func__, __LINE__,
               page, page_to_mfn(page), get_gpfn_from_mfn(page_to_mfn(page)));
    }
#endif
    // grant_table_destroy() release these pages.
    // but it doesn't clear m2p entry. So there might remain stale entry.
    // We clear such a stale entry here.
    set_gpfn_from_mfn(page_to_mfn(page), INVALID_M2P_ENTRY);

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

    spin_unlock(&d->page_alloc_lock);
}

void
share_xen_page_with_privileged_guests(struct page_info *page, int readonly)
{
    share_xen_page_with_guest(page, dom_xen, readonly);
}

//XXX !xxx_present() should be used instread of !xxx_none()?
static pte_t*
lookup_alloc_domain_pte(struct domain* d, unsigned long mpaddr)
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

//XXX xxx_none() should be used instread of !xxx_present()?
static pte_t*
lookup_noalloc_domain_pte(struct domain* d, unsigned long mpaddr)
{
    struct mm_struct *mm = &d->arch.mm;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

    BUG_ON(mm->pgd == NULL);
    pgd = pgd_offset(mm, mpaddr);
    if (!pgd_present(*pgd))
        goto not_present;

    pud = pud_offset(pgd, mpaddr);
    if (!pud_present(*pud))
        goto not_present;

    pmd = pmd_offset(pud, mpaddr);
    if (!pmd_present(*pmd))
        goto not_present;

    return pte_offset_map(pmd, mpaddr);

not_present:
    return NULL;
}

#ifdef CONFIG_XEN_IA64_DOM0_VP
static pte_t*
lookup_noalloc_domain_pte_none(struct domain* d, unsigned long mpaddr)
{
    struct mm_struct *mm = &d->arch.mm;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

    BUG_ON(mm->pgd == NULL);
    pgd = pgd_offset(mm, mpaddr);
    if (pgd_none(*pgd))
        goto not_present;

    pud = pud_offset(pgd, mpaddr);
    if (pud_none(*pud))
        goto not_present;

    pmd = pmd_offset(pud, mpaddr);
    if (pmd_none(*pmd))
        goto not_present;

    return pte_offset_map(pmd, mpaddr);

not_present:
    return NULL;
}

unsigned long
____lookup_domain_mpa(struct domain *d, unsigned long mpaddr)
{
    pte_t *pte;

    pte = lookup_noalloc_domain_pte(d, mpaddr);
    if (pte == NULL)
        goto not_present;

    if (pte_present(*pte))
        return (pte->pte & _PFN_MASK);
    else if (VMX_DOMAIN(d->vcpu[0]))
        return GPFN_INV_MASK;

not_present:
    return INVALID_MFN;
}

unsigned long
__lookup_domain_mpa(struct domain *d, unsigned long mpaddr)
{
    unsigned long machine = ____lookup_domain_mpa(d, mpaddr);
    if (machine != INVALID_MFN)
        return machine;

    printk("%s: d 0x%p id %d current 0x%p id %d\n",
           __func__, d, d->domain_id, current, current->vcpu_id);
    printk("%s: bad mpa 0x%lx (max_pages 0x%lx)\n",
           __func__, mpaddr, (unsigned long)d->max_pages << PAGE_SHIFT);
    return INVALID_MFN;
}
#endif

void mpafoo(unsigned long mpaddr)
{
    extern unsigned long privop_trace;
    if (mpaddr == 0x3800)
        privop_trace = 1;
}

unsigned long lookup_domain_mpa(struct domain *d, unsigned long mpaddr)
{
    pte_t *pte;

#ifdef CONFIG_DOMAIN0_CONTIGUOUS
    if (d == dom0) {
        pte_t pteval;
        if (mpaddr < dom0_start || mpaddr >= dom0_start + dom0_size) {
            //printk("lookup_domain_mpa: bad dom0 mpaddr 0x%lx!\n",mpaddr);
            //printk("lookup_domain_mpa: start=0x%lx,end=0x%lx!\n",dom0_start,dom0_start+dom0_size);
            mpafoo(mpaddr);
        }
        pteval = pfn_pte(mpaddr >> PAGE_SHIFT,
            __pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RWX));
        return pte_val(pteval);
    }
#endif
    pte = lookup_noalloc_domain_pte(d, mpaddr);
    if (pte != NULL) {
        if (pte_present(*pte)) {
//printk("lookup_domain_page: found mapping for %lx, pte=%lx\n",mpaddr,pte_val(*pte));
            return pte_val(*pte);
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
    mpafoo(mpaddr);

    //XXX This is a work around until the emulation memory access to a region
    //    where memory or device are attached is implemented.
    return pte_val(pfn_pte(0, __pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RWX)));
}

// FIXME: ONLY USE FOR DOMAIN PAGE_SIZE == PAGE_SIZE
#if 1
unsigned long domain_mpa_to_imva(struct domain *d, unsigned long mpaddr)
{
    unsigned long pte = lookup_domain_mpa(d,mpaddr);
    unsigned long imva;

    pte &= _PAGE_PPN_MASK;
    imva = (unsigned long) __va(pte);
    imva |= mpaddr & ~PAGE_MASK;
    return(imva);
}
#else
unsigned long domain_mpa_to_imva(struct domain *d, unsigned long mpaddr)
{
    unsigned long imva = __gpa_to_mpa(d, mpaddr);

    return __va(imva);
}
#endif

/* Allocate a new page for domain and map it to the specified metaphysical
   address.  */
struct page_info *
__assign_new_domain_page(struct domain *d, unsigned long mpaddr, pte_t* pte)
{
    struct page_info *p = NULL;
    unsigned long maddr;
    int ret;

    BUG_ON(!pte_none(*pte));

#ifdef CONFIG_DOMAIN0_CONTIGUOUS
    if (d == dom0) {
#if 0
        if (mpaddr < dom0_start || mpaddr >= dom0_start + dom0_size) {
            /* FIXME: is it true ?
               dom0 memory is not contiguous!  */
            panic("assign_new_domain_page: bad domain0 "
                  "mpaddr=%lx, start=%lx, end=%lx!\n",
                  mpaddr, dom0_start, dom0_start+dom0_size);
        }
#endif
        p = mfn_to_page((mpaddr >> PAGE_SHIFT));
        return p;
    }
#endif

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
    set_pte(pte, pfn_pte(maddr >> PAGE_SHIFT,
                         __pgprot(__DIRTY_BITS | _PAGE_PL_2 | _PAGE_AR_RWX)));

    mb ();
    //XXX CONFIG_XEN_IA64_DOM0_VP
    //    TODO racy
    set_gpfn_from_mfn(page_to_mfn(p), mpaddr >> PAGE_SHIFT);
    return p;
}

struct page_info *
assign_new_domain_page(struct domain *d, unsigned long mpaddr)
{
#ifdef CONFIG_DOMAIN0_CONTIGUOUS
    pte_t dummy_pte = __pte(0);
    return __assign_new_domain_page(d, mpaddr, &dummy_pte);
#else
    struct page_info *p = NULL;
    pte_t *pte;

    pte = lookup_alloc_domain_pte(d, mpaddr);
    if (pte_none(*pte)) {
        p = __assign_new_domain_page(d, mpaddr, pte);
    } else {
        DPRINTK("%s: d 0x%p mpaddr %lx already mapped!\n",
                __func__, d, mpaddr);
    }

    return p;
#endif
}

void
assign_new_domain0_page(struct domain *d, unsigned long mpaddr)
{
#ifndef CONFIG_DOMAIN0_CONTIGUOUS
    pte_t *pte;

    BUG_ON(d != dom0);
    pte = lookup_alloc_domain_pte(d, mpaddr);
    if (pte_none(*pte)) {
        struct page_info *p = __assign_new_domain_page(d, mpaddr, pte);
        if (p == NULL) {
            panic("%s: can't allocate page for dom0", __func__);
        }
    }
#endif
}

/* map a physical address to the specified metaphysical addr */
// flags: currently only ASSIGN_readonly
void
__assign_domain_page(struct domain *d,
                     unsigned long mpaddr, unsigned long physaddr,
                     unsigned long flags)
{
    pte_t *pte;
    unsigned long arflags = (flags & ASSIGN_readonly)? _PAGE_AR_R: _PAGE_AR_RWX;

    pte = lookup_alloc_domain_pte(d, mpaddr);
    if (pte_none(*pte)) {
        set_pte(pte, pfn_pte(physaddr >> PAGE_SHIFT,
                             __pgprot(__DIRTY_BITS | _PAGE_PL_2 | arflags)));
        mb ();
    } else
        printk("%s: mpaddr %lx already mapped!\n", __func__, mpaddr);
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
    __assign_domain_page(d, mpaddr, physaddr, ASSIGN_writable);

    //XXX CONFIG_XEN_IA64_DOM0_VP
    //    TODO racy
    set_gpfn_from_mfn(physaddr >> PAGE_SHIFT, mpaddr >> PAGE_SHIFT);
}

#ifdef CONFIG_XEN_IA64_DOM0_VP
static void
assign_domain_same_page(struct domain *d,
                        unsigned long mpaddr, unsigned long size,
                        unsigned long flags)
{
    //XXX optimization
    unsigned long end = mpaddr + size;
    for (; mpaddr < end; mpaddr += PAGE_SIZE) {
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
    assign_domain_same_page(d, mpaddr, size, ASSIGN_writable);
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

// caller must get_page(mfn_to_page(mfn)) before
// caller must call set_gpfn_from_mfn().
// flags: currently only ASSIGN_readonly
static void
assign_domain_page_replace(struct domain *d, unsigned long mpaddr,
                           unsigned long mfn, unsigned long flags)
{
    struct mm_struct *mm = &d->arch.mm;
    pte_t* pte;
    pte_t old_pte;
    pte_t npte;
    unsigned long arflags = (flags & ASSIGN_readonly)? _PAGE_AR_R: _PAGE_AR_RWX;

    pte = lookup_alloc_domain_pte(d, mpaddr);

    // update pte
    npte = pfn_pte(mfn, __pgprot(__DIRTY_BITS | _PAGE_PL_2 | arflags));
    old_pte = ptep_xchg(mm, mpaddr, pte, npte);
    if (pte_mem(old_pte)) {
        unsigned long old_mfn;
        struct page_info* old_page;

        // XXX should previous underlying page be removed?
        //  or should error be returned because it is a due to a domain?
        old_mfn = pte_pfn(old_pte);//XXX
        old_page = mfn_to_page(old_mfn);

        if (page_get_owner(old_page) == d) {
            BUG_ON(get_gpfn_from_mfn(old_mfn) != (mpaddr >> PAGE_SHIFT));
            set_gpfn_from_mfn(old_mfn, INVALID_M2P_ENTRY);
        }

        domain_page_flush(d, mpaddr, old_mfn, mfn);

        try_to_clear_PGC_allocate(d, old_page);
        put_page(old_page);
    } else {
        BUG_ON(!mfn_valid(mfn));
        BUG_ON(page_get_owner(mfn_to_page(mfn)) == d &&
               get_gpfn_from_mfn(mfn) != INVALID_M2P_ENTRY);
    }
}

static void
zap_domain_page_one(struct domain *d, unsigned long mpaddr, int do_put_page)
{
    struct mm_struct *mm = &d->arch.mm;
    pte_t *pte;
    pte_t old_pte;
    unsigned long mfn;
    struct page_info *page;

    pte = lookup_noalloc_domain_pte_none(d, mpaddr);
    if (pte == NULL)
        return;
    if (pte_none(*pte))
        return;

    // update pte
    old_pte = ptep_get_and_clear(mm, mpaddr, pte);
    mfn = pte_pfn(old_pte);
    page = mfn_to_page(mfn);
    BUG_ON((page->count_info & PGC_count_mask) == 0);

    if (page_get_owner(page) == d) {
        BUG_ON(get_gpfn_from_mfn(mfn) != (mpaddr >> PAGE_SHIFT));
        set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
    }

    domain_page_flush(d, mpaddr, mfn, INVALID_MFN);

    if (do_put_page) {
        try_to_clear_PGC_allocate(d, page);
        put_page(page);
    }
}

//XXX SMP
unsigned long
dom0vp_zap_physmap(struct domain *d, unsigned long gpfn,
                   unsigned int extent_order)
{
    unsigned long ret = 0;
    if (extent_order != 0) {
        //XXX
        ret = -ENOSYS;
        goto out;
    }

    zap_domain_page_one(d, gpfn << PAGE_SHIFT, 1);

out:
    return ret;
}

unsigned long
dom0vp_add_physmap(struct domain* d, unsigned long gpfn, unsigned long mfn,
                   unsigned long flags, domid_t domid)
{
    int error = 0;
    struct domain* rd;

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
            error = -ESRCH;
            goto out0;
        }
        BUG_ON(rd == NULL);
        get_knownalive_domain(rd);
    }

    if (unlikely(rd == d)) {
        error = -EINVAL;
        goto out1;
    }
    if (unlikely(get_page(mfn_to_page(mfn), rd) == 0)) {
        error = -EINVAL;
        goto out1;
    }

    assign_domain_page_replace(d, gpfn << PAGE_SHIFT, mfn, flags);
    //don't update p2m table because this page belongs to rd, not d.
out1:
    put_domain(rd);
out0:
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

    page = mfn_to_page(mfn);
    ret = get_page(page, page_get_owner(page));
    BUG_ON(ret == 0);

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
    pte_t* pte;
    pte_t old_pte;
    unsigned long old_mfn = INVALID_MFN;
    struct page_info* old_page;

    if (flags & (GNTMAP_application_map | GNTMAP_contains_pte)) {
        DPRINTK("%s: flags 0x%x\n", __func__, flags);
        return GNTST_general_error;
    }

    pte = lookup_noalloc_domain_pte(d, gpaddr);
    if (pte == NULL || !pte_present(*pte) || pte_pfn(*pte) != mfn)
        return GNTST_general_error;

    // update pte
    old_pte = ptep_get_and_clear(&d->arch.mm, gpaddr, pte);
    if (pte_present(old_pte)) {
        old_mfn = pte_pfn(old_pte);
    } else {
        return GNTST_general_error;
    }
    domain_page_flush(d, gpaddr, old_mfn, INVALID_MFN);

    old_page = mfn_to_page(old_mfn);
    BUG_ON(page_get_owner(old_page) == d);//try_to_clear_PGC_allocate(d, page) is not needed.
    put_page(old_page);

    return GNTST_okay;
}

// heavily depends on the struct page layout.
//XXX SMP
int
steal_page_for_grant_transfer(struct domain *d, struct page_info *page)
{
#if 0 /* if big endian */
# error "implement big endian version of steal_page_for_grant_transfer()"
#endif
    u32 _d, _nd;
    u64 x, nx, y;
    unsigned long mpaddr = get_gpfn_from_mfn(page_to_mfn(page)) << PAGE_SHIFT;
    struct page_info *new;

    zap_domain_page_one(d, mpaddr, 0);
    put_page(page);

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

        if (unlikely((x & (PGC_count_mask | PGC_allocated)) !=
                     (1 | PGC_allocated)) ||
            unlikely(_nd != _d)) {
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
            } else {
                DPRINTK("gnttab_transfer: Bad page %p: ed=%p(%u) 0x%x, "
                        "sd=%p(%u) 0x%x,"
                        " caf=%016lx, taf=%" PRtype_info "\n",
                        (void *) page_to_mfn(page),
                        d, d->domain_id, _d,
                        nd, nd->domain_id, _nd,
                        x,
                        page->u.inuse.type_info);
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
    d->tot_pages--;
    list_del(&page->list);

    spin_unlock(&d->page_alloc_lock);

#if 1
    //XXX Until net_rx_action() fix
    // assign new page for this mpaddr
    new = assign_new_domain_page(d, mpaddr);
    BUG_ON(new == NULL);//XXX
#endif

    return 0;
}

void
guest_physmap_add_page(struct domain *d, unsigned long gpfn,
                       unsigned long mfn)
{
    int ret;

    ret = get_page(mfn_to_page(mfn), d);
    BUG_ON(ret == 0);
    assign_domain_page_replace(d, gpfn << PAGE_SHIFT, mfn, ASSIGN_writable);
    set_gpfn_from_mfn(mfn, gpfn);//XXX SMP

    //BUG_ON(mfn != ((lookup_domain_mpa(d, gpfn << PAGE_SHIFT) & _PFN_MASK) >> PAGE_SHIFT));
}

void
guest_physmap_remove_page(struct domain *d, unsigned long gpfn,
                          unsigned long mfn)
{
    BUG_ON(mfn == 0);//XXX
    zap_domain_page_one(d, gpfn << PAGE_SHIFT, 1);
}

//XXX sledgehammer.
//    flush finer range.
void
domain_page_flush(struct domain* d, unsigned long mpaddr,
                  unsigned long old_mfn, unsigned long new_mfn)
{
    domain_flush_vtlb_all();
}

int
domain_page_mapped(struct domain* d, unsigned long mpaddr)
{
    pte_t * pte;

    pte=lookup_noalloc_domain_pte(d, mpaddr);
    if(!pte_none(*pte))
       return 1;
    return 0;
}
#endif

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

#ifdef CONFIG_DOMAIN0_CONTIGUOUS
    if (d == dom0) {
        /* This is not fully correct (because of hole), but it should
           be enough for now.  */
        (*flush_func)(__va_ul (dom0_start),
                  __va_ul (dom0_start + dom0_size));
        return;
    }
#endif
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
