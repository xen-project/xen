/* -*-  Mode:C++; c-file-style:BSD; c-basic-offset:4; tab-width:4 -*- */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <asm/shadow.h>
#include <asm/domain_page.h>
#include <asm/page.h>
#include <xen/event.h>
#include <xen/trace.h>

/********

To use these shadow page tables, guests must not rely on the ACCESSED
and DIRTY bits on L2 pte's being accurate -- they will typically all be set.

I doubt this will break anything. (If guests want to use the va_update
mechanism they've signed up for this anyhow...)

There's a per-domain shadow table spin lock which works fine for SMP
hosts. We don't have to worry about interrupts as no shadow operations
happen in an interrupt context. It's probably not quite ready for SMP
guest operation as we have to worry about synchonisation between gpte
and spte updates. Its possible that this might only happen in a
hypercall context, in which case we'll probably at have a per-domain
hypercall lock anyhow (at least initially).

********/

static inline void free_shadow_page(
    struct mm_struct *m, struct pfn_info *page)
{
    m->shadow_page_count--;

    switch ( page->u.inuse.type_info & PGT_type_mask )
    {
    case PGT_l1_page_table:
        perfc_decr(shadow_l1_pages);
        break;

    case PGT_l2_page_table:
        perfc_decr(shadow_l2_pages);
        break;

    default:
        printk("Free shadow weird page type pfn=%08x type=%08x\n",
               frame_table-page, page->u.inuse.type_info);
        break;
    }

    free_domheap_page(page);
}

static void free_shadow_state(struct mm_struct *m)
{
    int                   i, free = 0;
    struct shadow_status *x, *n;
 
    /*
     * WARNING! The shadow page table must not currently be in use!
     * e.g., You are expected to have paused the domain and synchronized CR3.
     */

    shadow_audit(m, 1);

    /* Free each hash chain in turn. */
    for ( i = 0; i < shadow_ht_buckets; i++ )
    {
        /* Skip empty buckets. */
        x = &m->shadow_ht[i];
        if ( x->pfn == 0 )
            continue;

        /* Free the head page. */
        free_shadow_page(
            m, &frame_table[x->spfn_and_flags & PSH_pfn_mask]);

        /* Reinitialise the head node. */
        x->pfn            = 0;
        x->spfn_and_flags = 0;
        n                 = x->next;
        x->next           = NULL;

        free++;

        /* Iterate over non-head nodes. */
        for ( x = n; x != NULL; x = n )
        { 
            /* Free the shadow page. */
            free_shadow_page(
                m, &frame_table[x->spfn_and_flags & PSH_pfn_mask]);

            /* Re-initialise the chain node. */
            x->pfn            = 0;
            x->spfn_and_flags = 0;

            /* Add to the free list. */
            n                 = x->next;
            x->next           = m->shadow_ht_free;
            m->shadow_ht_free = x;

            free++;
        }

        shadow_audit(m, 0);
    }

    SH_LOG("Free shadow table. Freed=%d.", free);
}

static inline int clear_shadow_page(
    struct mm_struct *m, struct shadow_status *x)
{
    unsigned long   *p;
    int              restart = 0;
    struct pfn_info *spage = &frame_table[x->spfn_and_flags & PSH_pfn_mask];

    switch ( spage->u.inuse.type_info & PGT_type_mask )
    {
        /* We clear L2 pages by zeroing the guest entries. */
    case PGT_l2_page_table:
        p = map_domain_mem((spage - frame_table) << PAGE_SHIFT);
        if (m->shadow_mode == SHM_full_32)
            memset(p, 0, ENTRIES_PER_L2_PAGETABLE * sizeof(*p));
        else 
            memset(p, 0, DOMAIN_ENTRIES_PER_L2_PAGETABLE * sizeof(*p));
        unmap_domain_mem(p);
        break;

        /* We clear L1 pages by freeing them: no benefit from zeroing them. */
    case PGT_l1_page_table:
        delete_shadow_status(m, x->pfn);
        free_shadow_page(m, spage);
        restart = 1; /* We need to go to start of list again. */
        break;
    }

    return restart;
}

static void clear_shadow_state(struct mm_struct *m)
{
    int                   i;
    struct shadow_status *x;
 
    shadow_audit(m, 1);

    for ( i = 0; i < shadow_ht_buckets; i++ )
    {
    retry:
        /* Skip empty buckets. */
        x = &m->shadow_ht[i];
        if ( x->pfn == 0 )
            continue;

        if ( clear_shadow_page(m, x) )
            goto retry;

        for ( x = x->next; x != NULL; x = x->next )
            if ( clear_shadow_page(m, x) )
                goto retry;

        shadow_audit(m, 0);
    }

    SH_VLOG("Scan shadow table. l1=%d l2=%d",
            perfc_value(shadow_l1_pages), perfc_value(shadow_l2_pages));
}


void shadow_mode_init(void)
{
}

int shadow_mode_enable(struct domain *p, unsigned int mode)
{
    struct mm_struct *m = &p->exec_domain[0]->mm;

    m->shadow_ht = xmalloc(
        shadow_ht_buckets * sizeof(struct shadow_status));
    if ( m->shadow_ht == NULL )
        goto nomem;
    memset(m->shadow_ht, 0, shadow_ht_buckets * sizeof(struct shadow_status));

    if ( mode == SHM_logdirty )
    {
        m->shadow_dirty_bitmap_size = (p->max_pages + 63) & ~63;
        m->shadow_dirty_bitmap = 
            xmalloc(m->shadow_dirty_bitmap_size/8);
        if ( m->shadow_dirty_bitmap == NULL )
        {
            m->shadow_dirty_bitmap_size = 0;
            goto nomem;
        }
        memset(m->shadow_dirty_bitmap, 0, m->shadow_dirty_bitmap_size/8);
    }

    m->shadow_mode = mode;

    __shadow_mk_pagetable(m);
    return 0;

 nomem:
    if ( m->shadow_ht != NULL )
        xfree( m->shadow_ht );
    m->shadow_ht = NULL;
    return -ENOMEM;
}

void __shadow_mode_disable(struct domain *d)
{
    struct mm_struct *m = &d->exec_domain[0]->mm;
    struct shadow_status *x, *n;

    free_shadow_state(m);
    m->shadow_mode = 0;

    SH_VLOG("freed tables count=%d l1=%d l2=%d",
            m->shadow_page_count, perfc_value(shadow_l1_pages), 
            perfc_value(shadow_l2_pages));

    n = m->shadow_ht_extras;
    while ( (x = n) != NULL )
    {
        m->shadow_extras_count--;
        n = *((struct shadow_status **)(&x[shadow_ht_extra_size]));
        xfree(x);
    }

    m->shadow_ht_extras = NULL;
    ASSERT(m->shadow_extras_count == 0);
    SH_LOG("freed extras, now %d", m->shadow_extras_count);

    if ( m->shadow_dirty_bitmap != NULL )
    {
        xfree(m->shadow_dirty_bitmap);
        m->shadow_dirty_bitmap = 0;
        m->shadow_dirty_bitmap_size = 0;
    }

    xfree(m->shadow_ht);
    m->shadow_ht = NULL;
}

static int shadow_mode_table_op(
    struct domain *d, dom0_shadow_control_t *sc)
{
    unsigned int      op = sc->op;
    struct mm_struct *m = &d->exec_domain[0]->mm;
    int               i, rc = 0;

    ASSERT(spin_is_locked(&m->shadow_lock));

    SH_VLOG("shadow mode table op %08lx %08lx count %d",
            pagetable_val(m->pagetable), pagetable_val(m->shadow_table),
            m->shadow_page_count);

    shadow_audit(m, 1);

    switch ( op )
    {
    case DOM0_SHADOW_CONTROL_OP_FLUSH:
        free_shadow_state(m);

        m->shadow_fault_count       = 0;
        m->shadow_dirty_count       = 0;
        m->shadow_dirty_net_count   = 0;
        m->shadow_dirty_block_count = 0;

        break;
   
    case DOM0_SHADOW_CONTROL_OP_CLEAN:
        clear_shadow_state(m);

        sc->stats.fault_count       = m->shadow_fault_count;
        sc->stats.dirty_count       = m->shadow_dirty_count;
        sc->stats.dirty_net_count   = m->shadow_dirty_net_count;
        sc->stats.dirty_block_count = m->shadow_dirty_block_count;

        m->shadow_fault_count       = 0;
        m->shadow_dirty_count       = 0;
        m->shadow_dirty_net_count   = 0;
        m->shadow_dirty_block_count = 0;
 
        if ( (d->max_pages > sc->pages) || 
             (sc->dirty_bitmap == NULL) || 
             (m->shadow_dirty_bitmap == NULL) )
        {
            rc = -EINVAL;
            break;
        }
 
        sc->pages = d->max_pages;

#define chunk (8*1024) /* Transfer and clear in 1kB chunks for L1 cache. */
        for ( i = 0; i < d->max_pages; i += chunk )
        {
            int bytes = ((((d->max_pages - i) > chunk) ?
                          chunk : (d->max_pages - i)) + 7) / 8;
     
            if (copy_to_user(
                    sc->dirty_bitmap + (i/(8*sizeof(unsigned long))),
                    m->shadow_dirty_bitmap +(i/(8*sizeof(unsigned long))),
                    bytes))
            {
                // copy_to_user can fail when copying to guest app memory.
                // app should zero buffer after mallocing, and pin it
                rc = -EINVAL;
                memset(
                    m->shadow_dirty_bitmap + (i/(8*sizeof(unsigned long))),
                    0, (d->max_pages/8) - (i/(8*sizeof(unsigned long))));
                break;
            }

            memset(
                m->shadow_dirty_bitmap + (i/(8*sizeof(unsigned long))),
                0, bytes);
        }

        break;

    case DOM0_SHADOW_CONTROL_OP_PEEK:
        sc->stats.fault_count       = m->shadow_fault_count;
        sc->stats.dirty_count       = m->shadow_dirty_count;
        sc->stats.dirty_net_count   = m->shadow_dirty_net_count;
        sc->stats.dirty_block_count = m->shadow_dirty_block_count;
 
        if ( (d->max_pages > sc->pages) || 
             (sc->dirty_bitmap == NULL) || 
             (m->shadow_dirty_bitmap == NULL) )
        {
            rc = -EINVAL;
            break;
        }
 
        sc->pages = d->max_pages;
        if (copy_to_user(
            sc->dirty_bitmap, m->shadow_dirty_bitmap, (d->max_pages+7)/8))
        {
            rc = -EINVAL;
            break;
        }

        break;

    default:
        rc = -EINVAL;
        break;
    }

    SH_VLOG("shadow mode table op : page count %d", m->shadow_page_count);
    shadow_audit(m, 1);
    __shadow_mk_pagetable(m);
    return rc;
}

int shadow_mode_control(struct domain *d, dom0_shadow_control_t *sc)
{
    unsigned int op = sc->op;
    int          rc = 0;

    if ( unlikely(d == current->domain) )
    {
        DPRINTK("Don't try to do a shadow op on yourself!\n");
        return -EINVAL;
    }   

    domain_pause(d);
    synchronise_pagetables(~0UL);

    shadow_lock(&d->exec_domain[0]->mm);

    switch ( op )
    {
    case DOM0_SHADOW_CONTROL_OP_OFF:
        shadow_mode_disable(d);
        break;

    case DOM0_SHADOW_CONTROL_OP_ENABLE_TEST:
        shadow_mode_disable(d);
        rc = shadow_mode_enable(d, SHM_test);
        break;

    case DOM0_SHADOW_CONTROL_OP_ENABLE_LOGDIRTY:
        shadow_mode_disable(d);
        rc = shadow_mode_enable(d, SHM_logdirty);
        break;

    default:
        rc = shadow_mode(d->exec_domain[0]) ? shadow_mode_table_op(d, sc) : -EINVAL;
        break;
    }

    shadow_unlock(&d->exec_domain[0]->mm);

    domain_unpause(d);

    return rc;
}

static inline struct pfn_info *alloc_shadow_page(struct mm_struct *m)
{
    struct pfn_info *page = alloc_domheap_page(NULL);

    m->shadow_page_count++;

    if ( unlikely(page == NULL) )
    {
        printk("Couldn't alloc shadow page! count=%d\n",
               m->shadow_page_count);
        SH_VLOG("Shadow tables l1=%d l2=%d",
                perfc_value(shadow_l1_pages), 
                perfc_value(shadow_l2_pages));
        BUG(); /* XXX FIXME: try a shadow flush to free up some memory. */
    }

    return page;
}

void unshadow_table(unsigned long gpfn, unsigned int type)
{
    unsigned long  spfn;
    struct domain *d = frame_table[gpfn].u.inuse.domain;

    SH_VLOG("unshadow_table type=%08x gpfn=%08lx", type, gpfn);

    perfc_incrc(unshadow_table_count);

    /*
     * This function is the same for all p.t. pages. Even for multi-processor 
     * guests there won't be a race here as this CPU was the one that 
     * cmpxchg'ed the page to invalid.
     */
    spfn = __shadow_status(&d->exec_domain[0]->mm, gpfn) & PSH_pfn_mask;
    delete_shadow_status(&d->exec_domain[0]->mm, gpfn);
    free_shadow_page(&d->exec_domain[0]->mm, &frame_table[spfn]);
}

#ifdef CONFIG_VMX
void vmx_shadow_clear_state(struct mm_struct *m) 
{
    SH_VVLOG("vmx_clear_shadow_state: \n");
    clear_shadow_state(m);
}
#endif


unsigned long shadow_l2_table( 
    struct mm_struct *m, unsigned long gpfn)
{
    struct pfn_info *spfn_info;
    unsigned long    spfn;
    l2_pgentry_t    *spl2e = 0, *gpl2e;
    unsigned long guest_gpfn;

    __get_machine_to_phys(m, guest_gpfn, gpfn);

    SH_VVLOG("shadow_l2_table( %08lx )", gpfn);

    perfc_incrc(shadow_l2_table_count);

    if ( (spfn_info = alloc_shadow_page(m)) == NULL )
        BUG(); /* XXX Deal gracefully with failure. */

    spfn_info->u.inuse.type_info = PGT_l2_page_table;
    perfc_incr(shadow_l2_pages);

    spfn = spfn_info - frame_table;
  /* Mark pfn as being shadowed; update field to point at shadow. */
    set_shadow_status(m, guest_gpfn, spfn | PSH_shadowed);
 
#ifdef __i386__
    /* Install hypervisor and 2x linear p.t. mapings. */
    if (m->shadow_mode == SHM_full_32) 
        vmx_update_shadow_state(m, gpfn, spfn);
    else {
        spl2e = (l2_pgentry_t *)map_domain_mem(spfn << PAGE_SHIFT);
        // can't use the linear map as we may not be in the right PT
        gpl2e = (l2_pgentry_t *) map_domain_mem(gpfn << PAGE_SHIFT);
        /*
         * We could proactively fill in PDEs for pages that are already shadowed.
         * However, we tried it and it didn't help performance. This is simpler.
         */
        memset(spl2e, 0, DOMAIN_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));

        /* Install hypervisor and 2x linear p.t. mapings. */
        memcpy(&spl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 
               &idle_pg_table[DOMAIN_ENTRIES_PER_L2_PAGETABLE],
               HYPERVISOR_ENTRIES_PER_L2_PAGETABLE * sizeof(l2_pgentry_t));
        spl2e[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
            mk_l2_pgentry((gpfn << PAGE_SHIFT) | __PAGE_HYPERVISOR);
        spl2e[SH_LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
            mk_l2_pgentry((spfn << PAGE_SHIFT) | __PAGE_HYPERVISOR);
        spl2e[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT] =
            mk_l2_pgentry(__pa(frame_table[gpfn].u.inuse.domain->mm_perdomain_pt) |
			  __PAGE_HYPERVISOR);
    }
#endif

    if (m->shadow_mode != SHM_full_32) 
    {                           
        unmap_domain_mem(spl2e);
    }

    SH_VLOG("shadow_l2_table( %08lx -> %08lx)", gpfn, spfn);
    return spfn;
}

static void shadow_map_l1_into_current_l2(unsigned long va)
{ 
    struct mm_struct *m = &current->mm;
    unsigned long    *gpl1e, *spl1e, gpl2e, spl2e, gl1pfn, sl1pfn=0, sl1ss;
    struct pfn_info  *sl1pfn_info;
    int               i;

    __guest_get_pl2e(m, va, &gpl2e);

    gl1pfn = gpl2e >> PAGE_SHIFT;

    sl1ss = __shadow_status(m, gl1pfn);
    if ( !(sl1ss & PSH_shadowed) )
    {
        /* This L1 is NOT already shadowed so we need to shadow it. */
        SH_VVLOG("4a: l1 not shadowed ( %08lx )", sl1pfn);

        sl1pfn_info = alloc_shadow_page(m);
        sl1pfn_info->u.inuse.type_info = PGT_l1_page_table;
   
        sl1pfn = sl1pfn_info - frame_table;

        perfc_incrc(shadow_l1_table_count);
        perfc_incr(shadow_l1_pages);

        set_shadow_status(m, gl1pfn, PSH_shadowed | sl1pfn);

        l2pde_general(m, &gpl2e, &spl2e, sl1pfn);

        __guest_set_pl2e(m, va, gpl2e);
        __shadow_set_pl2e(m, va, spl2e);

        gpl1e = (unsigned long *) &(linear_pg_table[
            (va>>PAGE_SHIFT) & ~(ENTRIES_PER_L1_PAGETABLE-1)]);

        spl1e = (unsigned long *) &shadow_linear_pg_table[
            (va>>PAGE_SHIFT) & ~(ENTRIES_PER_L1_PAGETABLE-1)];

        for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
            l1pte_propagate_from_guest(m, &gpl1e[i], &spl1e[i]);
    }
    else
    {
        /* This L1 is shadowed already, but the L2 entry is missing. */
        SH_VVLOG("4b: was shadowed, l2 missing ( %08lx )", sl1pfn);

        sl1pfn = sl1ss & PSH_pfn_mask;
        l2pde_general(m, &gpl2e, &spl2e, sl1pfn);
        __guest_set_pl2e(m, va, gpl2e);
        __shadow_set_pl2e(m, va, spl2e);
    }              
}

#ifdef CONFIG_VMX
void vmx_shadow_invlpg(struct mm_struct *m, unsigned long va)
{
    unsigned long gpte, spte, host_pfn;

    if (__put_user(0L, (unsigned long *)
                   &shadow_linear_pg_table[va >> PAGE_SHIFT])) {
        vmx_shadow_clear_state(m);
        return;
    }

    if (__get_user(gpte, (unsigned long *)
                   &linear_pg_table[va >> PAGE_SHIFT])) {
        return;
    }

    host_pfn = phys_to_machine_mapping[gpte >> PAGE_SHIFT];
    spte = (host_pfn << PAGE_SHIFT) | (gpte & ~PAGE_MASK);

    if (__put_user(spte, (unsigned long *)
                   &shadow_linear_pg_table[va >> PAGE_SHIFT])) {
        return;
    }
}
#endif

int shadow_fault(unsigned long va, long error_code)
{
    unsigned long gpte, spte;
    struct mm_struct *m = &current->mm;

    SH_VVLOG("shadow_fault( va=%08lx, code=%ld )", va, error_code );

    check_pagetable(m, current->mm.pagetable, "pre-sf");

    /*
     * STEP 1. A fast-reject set of checks with no locking.
     */

    if ( unlikely(__get_user(gpte, (unsigned long *)
                             &linear_pg_table[va >> PAGE_SHIFT])) )
    {
        SH_VVLOG("shadow_fault - EXIT: read gpte faulted" );
        return 0;
    }

    if ( !(gpte & _PAGE_PRESENT) )
    {
        SH_VVLOG("shadow_fault - EXIT: gpte not present (%lx)",gpte );
        return 0;
    }

    if ( (error_code & 2)  && !(gpte & _PAGE_RW) )
    {
        /* Write fault on a read-only mapping. */
        return 0;
    }

    /*
     * STEP 2. Take the shadow lock and re-check the guest PTE.
     */

    shadow_lock(m);
 
    if ( unlikely(__get_user(gpte, (unsigned long *)
                             &linear_pg_table[va >> PAGE_SHIFT])) )
    {
        SH_VVLOG("shadow_fault - EXIT: read gpte faulted" );
        shadow_unlock(m);
        return 0;
    }

    if ( unlikely(!(gpte & _PAGE_PRESENT)) )
    {
        SH_VVLOG("shadow_fault - EXIT: gpte not present (%lx)",gpte );
        shadow_unlock(m);
        return 0;
    }

    /* Write fault? */
    if ( error_code & 2 )  
    {
        if ( unlikely(!(gpte & _PAGE_RW)) )
        {
            /* Write fault on a read-only mapping. */
            SH_VVLOG("shadow_fault - EXIT: wr fault on RO page (%lx)", gpte);
            shadow_unlock(m);
            return 0;
        }

        l1pte_write_fault(m, &gpte, &spte);
    }
    else
    {
        l1pte_read_fault(m, &gpte, &spte);
    }

    /*
     * STEP 3. Write the modified shadow PTE and guest PTE back to the tables.
     */

    /* XXX Watch out for read-only L2 entries! (not used in Linux). */
    if ( unlikely(__put_user(gpte, (unsigned long *)
                             &linear_pg_table[va >> PAGE_SHIFT])) )
        domain_crash();

    /*
     * Update of shadow PTE can fail because the L1 p.t. is not shadowed,
     * or because the shadow isn't linked into this shadow L2 p.t.
     */
    if ( unlikely(__put_user(spte, (unsigned long *)
                             &shadow_linear_pg_table[va >> PAGE_SHIFT])) )
    {
        SH_VVLOG("3: not shadowed/mapped gpte=%08lx spte=%08lx", gpte, spte);
        shadow_map_l1_into_current_l2(va);
        shadow_linear_pg_table[va >> PAGE_SHIFT] = mk_l1_pgentry(spte);
    }

    perfc_incrc(shadow_fixup_count);
    m->shadow_fault_count++;

    shadow_unlock(m);

    check_pagetable(m, current->mm.pagetable, "post-sf");
    return EXCRET_fault_fixed;
}


void shadow_l1_normal_pt_update(
    unsigned long pa, unsigned long gpte,
    unsigned long *prev_spfn_ptr,
    l1_pgentry_t **prev_spl1e_ptr)
{
    unsigned long spfn, spte, prev_spfn = *prev_spfn_ptr;    
    l1_pgentry_t *spl1e, *prev_spl1e = *prev_spl1e_ptr;

    /* N.B. To get here, we know the l1 page *must* be shadowed. */
    SH_VVLOG("shadow_l1_normal_pt_update pa=%08lx, gpte=%08lx, "
             "prev_spfn=%08lx, prev_spl1e=%p\n",
             pa, gpte, prev_spfn, prev_spl1e);

    spfn = __shadow_status(&current->mm, pa >> PAGE_SHIFT) & PSH_pfn_mask;

    if ( spfn == prev_spfn )
    {
        spl1e = prev_spl1e;
    }
    else
    {
        if ( prev_spl1e != NULL )
            unmap_domain_mem( prev_spl1e );
        spl1e = (l1_pgentry_t *)map_domain_mem(spfn << PAGE_SHIFT);
        *prev_spfn_ptr  = spfn;
        *prev_spl1e_ptr = spl1e;
    }

    l1pte_propagate_from_guest(&current->mm, &gpte, &spte);
    spl1e[(pa & ~PAGE_MASK) / sizeof(l1_pgentry_t)] = mk_l1_pgentry(spte);
}

void shadow_l2_normal_pt_update(unsigned long pa, unsigned long gpte)
{
    unsigned long spfn, spte;
    l2_pgentry_t *spl2e;
    unsigned long s_sh;

    /* N.B. To get here, we know the l2 page *must* be shadowed. */
    SH_VVLOG("shadow_l2_normal_pt_update pa=%08lx, gpte=%08lx",pa,gpte);

    spfn = __shadow_status(&current->mm, pa >> PAGE_SHIFT) & PSH_pfn_mask;

    s_sh = (gpte & _PAGE_PRESENT) ?
        __shadow_status(&current->mm, gpte >> PAGE_SHIFT) : 0;

    /* XXXX Should mark guest pte as DIRTY and ACCESSED too! */
    l2pde_general(&current->mm, &gpte, &spte, s_sh);
    spl2e = (l2_pgentry_t *)map_domain_mem(spfn << PAGE_SHIFT);
    spl2e[(pa & ~PAGE_MASK) / sizeof(l2_pgentry_t)] = mk_l2_pgentry(spte);
    unmap_domain_mem(spl2e);
}




/************************************************************************/
/************************************************************************/
/************************************************************************/

#if SHADOW_DEBUG

static int sh_l2_present;
static int sh_l1_present;
char * sh_check_name;

#define FAIL(_f, _a...)                                        \
    do {                                                       \
        printk("XXX %s-FAIL (%d,%d)" _f " g=%08lx s=%08lx\n",  \
               sh_check_name, level, i, ## _a , gpte, spte);   \
        BUG();                                                 \
    } while ( 0 )

static int check_pte(
    struct mm_struct *m, unsigned long gpte, unsigned long spte, 
    int level, int i)
{
    unsigned long mask, gpfn, spfn;
#ifdef CONFIG_VMX
    unsigned long guest_gpfn;
#endif

    if ( (spte == 0) || (spte == 0xdeadface) || (spte == 0x00000E00) )
        return 1;  /* always safe */

    if ( !(spte & _PAGE_PRESENT) )
        FAIL("Non zero not present spte");

    if ( level == 2 ) sh_l2_present++;
    if ( level == 1 ) sh_l1_present++;

    if ( !(gpte & _PAGE_PRESENT) )
        FAIL("Guest not present yet shadow is");

    mask = ~(_PAGE_DIRTY|_PAGE_ACCESSED|_PAGE_RW|0xFFFFF000);

    if ( (spte & mask) != (gpte & mask) )
        FAIL("Corrupt?");

    if ( (spte & _PAGE_DIRTY ) && !(gpte & _PAGE_DIRTY) )
        FAIL("Dirty coherence");

    if ( (spte & _PAGE_ACCESSED ) && !(gpte & _PAGE_ACCESSED) )
        FAIL("Accessed coherence");

    if ( (spte & _PAGE_RW ) && !(gpte & _PAGE_RW) )
        FAIL("RW coherence");

    if ( (spte & _PAGE_RW ) && !((gpte & _PAGE_RW) && (gpte & _PAGE_DIRTY)) )
        FAIL("RW2 coherence");
 
    spfn = spte >> PAGE_SHIFT;
    gpfn = gpte >> PAGE_SHIFT;

    if ( gpfn == spfn )
    {
        if ( level > 1 )
            FAIL("Linear map ???");    /* XXX this will fail on BSD */
    }
    else
    {
        if ( level < 2 )
            FAIL("Shadow in L1 entry?");

        if (m->shadow_mode == SHM_full_32) {

            guest_gpfn = phys_to_machine_mapping[gpfn];

            if ( __shadow_status(m, guest_gpfn) != (PSH_shadowed | spfn) )
                FAIL("spfn problem g.sf=%08lx", 
                     __shadow_status(m, guest_gpfn) );
            
        } else {
            if ( __shadow_status(m, gpfn) != (PSH_shadowed | spfn) )
                FAIL("spfn problem g.sf=%08lx", 
                     __shadow_status(m, gpfn) );
        }

    }

    return 1;
}


static int check_l1_table(
    struct mm_struct *m, unsigned long va, 
    unsigned long g2, unsigned long s2)
{
    int i;
    unsigned long *gpl1e, *spl1e;

    gpl1e = map_domain_mem(g2 << PAGE_SHIFT);
    spl1e = map_domain_mem(s2 << PAGE_SHIFT);

    for ( i = 0; i < ENTRIES_PER_L1_PAGETABLE; i++ )
        check_pte(m, gpl1e[i], spl1e[i], 1, i);
 
    unmap_domain_mem(spl1e);
    unmap_domain_mem(gpl1e);

    return 1;
}

#define FAILPT(_f, _a...)                                      \
    do {                                                       \
        printk("XXX FAIL %s-PT" _f "\n", s, ## _a );           \
        BUG();                                                 \
    } while ( 0 )

int check_pagetable(struct mm_struct *m, pagetable_t pt, char *s)
{
    unsigned long gptbase = pagetable_val(pt);
    unsigned long gpfn, spfn;
    int           i;
    l2_pgentry_t *gpl2e, *spl2e;
    unsigned long host_gpfn = 0;

    sh_check_name = s;

    SH_VVLOG("%s-PT Audit", s);

    sh_l2_present = sh_l1_present = 0;

    gpfn = gptbase >> PAGE_SHIFT;

    __get_phys_to_machine(m, host_gpfn, gpfn);
  
    if ( ! (__shadow_status(m, gpfn) & PSH_shadowed) )
    {
        printk("%s-PT %08lx not shadowed\n", s, gptbase);

        if( __shadow_status(m, gpfn) != 0 ) BUG();
            return 0;
    }   
 
    spfn = __shadow_status(m, gpfn) & PSH_pfn_mask;

    if ( ! __shadow_status(m, gpfn) == (PSH_shadowed | spfn) )
            FAILPT("ptbase shadow inconsistent1");

    if (m->shadow_mode == SHM_full_32) 
    {
        host_gpfn = phys_to_machine_mapping[gpfn];
        gpl2e = (l2_pgentry_t *) map_domain_mem( host_gpfn << PAGE_SHIFT );

    } else
        gpl2e = (l2_pgentry_t *) map_domain_mem( gpfn << PAGE_SHIFT );

    spl2e = (l2_pgentry_t *) map_domain_mem( spfn << PAGE_SHIFT );

    if ( memcmp(&spl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE],
                &gpl2e[DOMAIN_ENTRIES_PER_L2_PAGETABLE], 
                ((SH_LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT) -
                 DOMAIN_ENTRIES_PER_L2_PAGETABLE) * sizeof(l2_pgentry_t)) )
    {
        for ( i = DOMAIN_ENTRIES_PER_L2_PAGETABLE; 
              i < (SH_LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT);
              i++ )
            printk("+++ (%d) %08lx %08lx\n",i,
                   l2_pgentry_val(gpl2e[i]), l2_pgentry_val(spl2e[i]));
        FAILPT("hypervisor entries inconsistent");
    }

    if ( (l2_pgentry_val(spl2e[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT]) != 
          l2_pgentry_val(gpl2e[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT])) )
        FAILPT("hypervisor linear map inconsistent");

    if ( (l2_pgentry_val(spl2e[SH_LINEAR_PT_VIRT_START >> 
                              L2_PAGETABLE_SHIFT]) != 
          ((spfn << PAGE_SHIFT) | __PAGE_HYPERVISOR)) )
        FAILPT("hypervisor shadow linear map inconsistent %08lx %08lx",
               l2_pgentry_val(spl2e[SH_LINEAR_PT_VIRT_START >>
                                   L2_PAGETABLE_SHIFT]),
               (spfn << PAGE_SHIFT) | __PAGE_HYPERVISOR);

    if (m->shadow_mode != SHM_full_32) {
        if ( (l2_pgentry_val(spl2e[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT]) !=
              ((__pa(frame_table[gpfn].u.inuse.domain->mm.perdomain_pt) | 
            __PAGE_HYPERVISOR))) )
            FAILPT("hypervisor per-domain map inconsistent");
    }

    /* Check the whole L2. */
    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
        check_pte(m, l2_pgentry_val(gpl2e[i]), l2_pgentry_val(spl2e[i]), 2, i);

    /* Go back and recurse. */
    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
    {
        if ( l2_pgentry_val(spl2e[i]) != 0 )
            check_l1_table(
                m, i << L2_PAGETABLE_SHIFT,
                l2_pgentry_val(gpl2e[i]) >> PAGE_SHIFT, 
                l2_pgentry_val(spl2e[i]) >> PAGE_SHIFT);
    }

    unmap_domain_mem(spl2e);
    unmap_domain_mem(gpl2e);

    SH_VVLOG("PT verified : l2_present = %d, l1_present = %d\n",
             sh_l2_present, sh_l1_present);
 
    return 1;
}

#endif
