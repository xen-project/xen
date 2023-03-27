/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/mm/shadow/set.c
 *
 * Simple, mostly-synchronous shadow page tables.
 * Parts of this code are Copyright (c) 2006 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
 */

#define GUEST_PAGING_LEVELS 0

#include <xen/sched.h>
#include <xsm/xsm.h>
#include <asm/shadow.h>
#include "private.h"
#include "types.h"

/*
 * These functions update shadow entries (and do bookkeeping on the shadow
 * tables they are in).  It is intended that they are the only
 * functions which ever write (non-zero) data onto a shadow page.
 */

static inline void
shadow_write_entries(void *d, const void *s, unsigned int entries, mfn_t mfn)
/*
 * This function does the actual writes to shadow pages.
 * It must not be called directly, since it doesn't do the bookkeeping
 * that shadow_set_l*e() functions do.
 *
 * Copy PTEs safely when processors might be running on the
 * destination pagetable.  This does *not* give safety against
 * concurrent writes (that's what the paging lock is for), just
 * stops the hardware picking up partially written entries.
 */
{
    shadow_l1e_t *dst = d;
    const shadow_l1e_t *src = s;
    void *map = NULL;
    unsigned int i = 0;

    /*
     * Because we mirror access rights at all levels in the shadow, an
     * l2 (or higher) entry with the RW bit cleared will leave us with
     * no write access through the linear map.
     * We detect that by writing to the shadow with put_unsafe() and
     * using map_domain_page() to get a writeable mapping if we need to.
     */
    if ( put_unsafe(*src, dst) )
    {
        perfc_incr(shadow_linear_map_failed);
        map = map_domain_page(mfn);
        dst = map + PAGE_OFFSET(dst);
    }
    else
    {
        ++src;
        ++dst;
        i = 1;
    }

    ASSERT(IS_ALIGNED((unsigned long)dst, sizeof(*dst)));

    for ( ; i < entries; i++ )
        write_atomic(&dst++->l1, src++->l1);

    unmap_domain_page(map);
}

/*
 * "type" is only used to distinguish grant map pages from ordinary RAM
 * i.e. non-p2m_is_grant() pages are treated as p2m_ram_rw.
 */
static int inline
shadow_get_page_from_l1e(shadow_l1e_t sl1e, struct domain *d, p2m_type_t type)
{
    int res;
    mfn_t mfn = shadow_l1e_get_mfn(sl1e);
    const struct page_info *pg = NULL;
    struct domain *owner = NULL;

    ASSERT(!sh_l1e_is_magic(sl1e));
    ASSERT(shadow_mode_refcounts(d));

    if ( mfn_valid(mfn) )
    {
        pg = mfn_to_page(mfn);
        owner = page_get_owner(pg);
    }

    if ( owner == dom_io )
        owner = NULL;

    /*
     * If a privileged domain is attempting to install a map of a page it does
     * not own, we let it succeed anyway.
     */
    if ( owner && (d != owner) &&
         !(res = xsm_priv_mapping(XSM_TARGET, d, owner)) )
    {
        res = get_page_from_l1e(sl1e, d, owner);
        SHADOW_PRINTK("privileged %pd installs map of %pd's mfn %"PRI_mfn": %s\n",
                      d, owner, mfn_x(mfn),
                      res >= 0 ? "success" : "failed");
    }
    /* Okay, it might still be a grant mapping PTE.  Try it. */
    else if ( owner &&
              (type == p2m_grant_map_rw ||
               (type == p2m_grant_map_ro &&
                !(shadow_l1e_get_flags(sl1e) & _PAGE_RW))) )
    {
        /*
         * It's a grant mapping.  The grant table implementation will
         * already have checked that we're supposed to have access, so
         * we can just grab a reference directly.
         */
        res = get_page_from_l1e(sl1e, d, owner);
    }
    else
        res = get_page_from_l1e(sl1e, d, d);

    if ( unlikely(res < 0) )
    {
        perfc_incr(shadow_get_page_fail);
        SHADOW_PRINTK("failed: l1e=" SH_PRI_pte "\n");
    }

    return res;
}

int shadow_set_l4e(struct domain *d, shadow_l4e_t *sl4e,
                   shadow_l4e_t new_sl4e, mfn_t sl4mfn)
{
    int flags = 0;
    shadow_l4e_t old_sl4e;
    paddr_t paddr;

    ASSERT(sl4e != NULL);
    old_sl4e = *sl4e;

    if ( old_sl4e.l4 == new_sl4e.l4 ) return 0; /* Nothing to do */

    paddr = mfn_to_maddr(sl4mfn) | PAGE_OFFSET(sl4e);

    if ( shadow_l4e_get_flags(new_sl4e) & _PAGE_PRESENT )
    {
        /* About to install a new reference */
        mfn_t sl3mfn = shadow_l4e_get_mfn(new_sl4e);

        if ( !sh_get_ref(d, sl3mfn, paddr) )
        {
            domain_crash(d);
            return SHADOW_SET_ERROR;
        }

        /* Are we pinning l3 shadows to handle weird Linux behaviour? */
        if ( sh_type_is_pinnable(d, SH_type_l3_64_shadow) )
            sh_pin(d, sl3mfn);
    }

    /* Write the new entry */
    shadow_write_entries(sl4e, &new_sl4e, 1, sl4mfn);
    flush_root_pgtbl_domain(d);

    flags |= SHADOW_SET_CHANGED;

    if ( shadow_l4e_get_flags(old_sl4e) & _PAGE_PRESENT )
    {
        /* We lost a reference to an old mfn. */
        mfn_t osl3mfn = shadow_l4e_get_mfn(old_sl4e);

        if ( !mfn_eq(osl3mfn, shadow_l4e_get_mfn(new_sl4e)) ||
             !perms_strictly_increased(shadow_l4e_get_flags(old_sl4e),
                                       shadow_l4e_get_flags(new_sl4e)) )
            flags |= SHADOW_SET_FLUSH;

        sh_put_ref(d, osl3mfn, paddr);
    }

    return flags;
}

int shadow_set_l3e(struct domain *d, shadow_l3e_t *sl3e,
                   shadow_l3e_t new_sl3e, mfn_t sl3mfn)
{
    int flags = 0;
    shadow_l3e_t old_sl3e;
    paddr_t paddr;

    ASSERT(sl3e != NULL);
    old_sl3e = *sl3e;

    if ( old_sl3e.l3 == new_sl3e.l3 ) return 0; /* Nothing to do */

    paddr = mfn_to_maddr(sl3mfn) | PAGE_OFFSET(sl3e);

    if ( shadow_l3e_get_flags(new_sl3e) & _PAGE_PRESENT )
    {
        /* About to install a new reference */
        if ( !sh_get_ref(d, shadow_l3e_get_mfn(new_sl3e), paddr) )
        {
            domain_crash(d);
            return SHADOW_SET_ERROR;
        }
    }

    /* Write the new entry */
    shadow_write_entries(sl3e, &new_sl3e, 1, sl3mfn);
    flags |= SHADOW_SET_CHANGED;

    if ( shadow_l3e_get_flags(old_sl3e) & _PAGE_PRESENT )
    {
        /* We lost a reference to an old mfn. */
        mfn_t osl2mfn = shadow_l3e_get_mfn(old_sl3e);

        if ( !mfn_eq(osl2mfn, shadow_l3e_get_mfn(new_sl3e)) ||
             !perms_strictly_increased(shadow_l3e_get_flags(old_sl3e),
                                       shadow_l3e_get_flags(new_sl3e)) )
            flags |= SHADOW_SET_FLUSH;

        sh_put_ref(d, osl2mfn, paddr);
    }

    return flags;
}

int shadow_set_l2e(struct domain *d, shadow_l2e_t *sl2e,
                   shadow_l2e_t new_sl2e, mfn_t sl2mfn,
                   unsigned int type_fl1_shadow,
                   mfn_t (*next_page)(mfn_t smfn))
{
    int flags = 0;
    shadow_l2e_t old_sl2e;
    paddr_t paddr;
    /*
     * In 2-on-3 we work with pairs of l2es pointing at two-page
     * shadows.  Reference counting and up-pointers track from the first
     * page of the shadow to the first l2e, so make sure that we're
     * working with those:
     * Start with a pair of identical entries.
     */
    shadow_l2e_t pair[2] = { new_sl2e, new_sl2e };

    if ( next_page )
    {
        /* Align the pointer down so it's pointing at the first of the pair */
        sl2e = (shadow_l2e_t *)((unsigned long)sl2e & ~sizeof(shadow_l2e_t));
    }

    ASSERT(sl2e != NULL);
    old_sl2e = *sl2e;

    if ( old_sl2e.l2 == new_sl2e.l2 ) return 0; /* Nothing to do */

    paddr = mfn_to_maddr(sl2mfn) | PAGE_OFFSET(sl2e);

    if ( shadow_l2e_get_flags(new_sl2e) & _PAGE_PRESENT )
    {
        mfn_t sl1mfn = shadow_l2e_get_mfn(new_sl2e);
        ASSERT(mfn_to_page(sl1mfn)->u.sh.head);

        /* About to install a new reference */
        if ( !sh_get_ref(d, sl1mfn, paddr) )
        {
            domain_crash(d);
            return SHADOW_SET_ERROR;
        }

#if (SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC)
        {
            struct page_info *sp = mfn_to_page(sl1mfn);
            mfn_t gl1mfn;

            ASSERT(sp->u.sh.head);
            gl1mfn = backpointer(sp);
            /*
             * If the shadow is a fl1 then the backpointer contains the
             * GFN instead of the GMFN, and it's definitely not OOS.
             */
            if ( (sp->u.sh.type != type_fl1_shadow) && mfn_valid(gl1mfn)
                 && mfn_is_out_of_sync(gl1mfn) )
                sh_resync(d, gl1mfn);
        }
#endif

        if ( next_page )
        {
            /* Update the second entry to point to the second half of the l1 */
            sl1mfn = next_page(sl1mfn);
            pair[1] = shadow_l2e_from_mfn(sl1mfn,
                                          shadow_l2e_get_flags(new_sl2e));
        }
    }

    /* Write the new entry / entries */
    shadow_write_entries(sl2e, &pair, !next_page ? 1 : 2, sl2mfn);

    flags |= SHADOW_SET_CHANGED;

    if ( shadow_l2e_get_flags(old_sl2e) & _PAGE_PRESENT )
    {
        /* We lost a reference to an old mfn. */
        mfn_t osl1mfn = shadow_l2e_get_mfn(old_sl2e);

        if ( !mfn_eq(osl1mfn, shadow_l2e_get_mfn(new_sl2e)) ||
             !perms_strictly_increased(shadow_l2e_get_flags(old_sl2e),
                                       shadow_l2e_get_flags(new_sl2e)) )
            flags |= SHADOW_SET_FLUSH;

        sh_put_ref(d, osl1mfn, paddr);
    }

    return flags;
}

int shadow_set_l1e(struct domain *d, shadow_l1e_t *sl1e,
                   shadow_l1e_t new_sl1e, p2m_type_t new_type,
                   mfn_t sl1mfn)
{
    int flags = 0;
    shadow_l1e_t old_sl1e;
    unsigned int old_sl1f;
#if SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC
    mfn_t new_gmfn = shadow_l1e_get_mfn(new_sl1e);
#endif

    ASSERT(sl1e != NULL);

#if SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC
    if ( mfn_valid(new_gmfn) && mfn_oos_may_write(new_gmfn) &&
         ((shadow_l1e_get_flags(new_sl1e) & (_PAGE_RW | _PAGE_PRESENT)) ==
          (_PAGE_RW | _PAGE_PRESENT)) )
        oos_fixup_add(d, new_gmfn, sl1mfn, pgentry_ptr_to_slot(sl1e));
#endif

    old_sl1e = *sl1e;

    if ( old_sl1e.l1 == new_sl1e.l1 ) return 0; /* Nothing to do */

    if ( (shadow_l1e_get_flags(new_sl1e) & _PAGE_PRESENT) &&
         !sh_l1e_is_magic(new_sl1e) )
    {
        /* About to install a new reference */
        if ( shadow_mode_refcounts(d) )
        {
#define PAGE_FLIPPABLE (_PAGE_RW | _PAGE_PWT | _PAGE_PCD | _PAGE_PAT)
            int rc;

            TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_SHADOW_L1_GET_REF);
            switch ( rc = shadow_get_page_from_l1e(new_sl1e, d, new_type) )
            {
            default:
                /* Doesn't look like a pagetable. */
                flags |= SHADOW_SET_ERROR;
                new_sl1e = shadow_l1e_empty();
                break;
            case PAGE_FLIPPABLE & -PAGE_FLIPPABLE ... PAGE_FLIPPABLE:
                ASSERT(!(rc & ~PAGE_FLIPPABLE));
                new_sl1e = shadow_l1e_flip_flags(new_sl1e, rc);
                /* fall through */
            case 0:
                shadow_vram_get_mfn(shadow_l1e_get_mfn(new_sl1e),
                                    shadow_l1e_get_flags(new_sl1e),
                                    sl1mfn, sl1e, d);
                break;
            }
#undef PAGE_FLIPPABLE
        }
    }

    /* Write the new entry */
    shadow_write_entries(sl1e, &new_sl1e, 1, sl1mfn);
    flags |= SHADOW_SET_CHANGED;

    old_sl1f = shadow_l1e_get_flags(old_sl1e);
    if ( (old_sl1f & _PAGE_PRESENT) && !sh_l1e_is_magic(old_sl1e) &&
         shadow_mode_refcounts(d) )
    {
        /*
         * We lost a reference to an old mfn.
         *
         * N.B. Unlike higher-level sets, never need an extra flush when
         * writing an l1e.  Because it points to the same guest frame as the
         * guest l1e did, it's the guest's responsibility to trigger a flush
         * later.
         */
        shadow_vram_put_mfn(shadow_l1e_get_mfn(old_sl1e), old_sl1f,
                            sl1mfn, sl1e, d);
        shadow_put_page_from_l1e(old_sl1e, d);
        TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_SHADOW_L1_PUT_REF);
    }

    return flags;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
