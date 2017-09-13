#ifndef __PV_MM_H__
#define __PV_MM_H__

/* Read a PV guest's l1e that maps this linear address. */
static inline l1_pgentry_t guest_get_eff_l1e(unsigned long linear)
{
    l1_pgentry_t l1e;

    ASSERT(!paging_mode_translate(current->domain));
    ASSERT(!paging_mode_external(current->domain));

    if ( unlikely(!__addr_ok(linear)) ||
         __copy_from_user(&l1e,
                          &__linear_l1_table[l1_linear_offset(linear)],
                          sizeof(l1_pgentry_t)) )
        l1e = l1e_empty();

    return l1e;
}

/*
 * PTE updates can be done with ordinary writes except:
 *  1. Debug builds get extra checking by using CMPXCHG[8B].
 */
#ifndef NDEBUG
#define PTE_UPDATE_WITH_CMPXCHG
#else
#undef PTE_UPDATE_WITH_CMPXCHG
#endif

/*
 * How to write an entry to the guest pagetables.
 * Returns false for failure (pointer not valid), true for success.
 */
static inline bool update_intpte(intpte_t *p, intpte_t old, intpte_t new,
                                 unsigned long mfn, struct vcpu *v,
                                 bool preserve_ad)
{
    bool rv = true;

#ifndef PTE_UPDATE_WITH_CMPXCHG
    if ( !preserve_ad )
    {
        rv = paging_write_guest_entry(v, p, new, _mfn(mfn));
    }
    else
#endif
    {
        intpte_t t = old;

        for ( ; ; )
        {
            intpte_t _new = new;

            if ( preserve_ad )
                _new |= old & (_PAGE_ACCESSED | _PAGE_DIRTY);

            rv = paging_cmpxchg_guest_entry(v, p, &t, _new, _mfn(mfn));
            if ( unlikely(rv == 0) )
            {
                gdprintk(XENLOG_WARNING,
                         "Failed to update %" PRIpte " -> %" PRIpte
                         ": saw %" PRIpte "\n", old, _new, t);
                break;
            }

            if ( t == old )
                break;

            /* Allowed to change in Accessed/Dirty flags only. */
            BUG_ON((t ^ old) & ~(intpte_t)(_PAGE_ACCESSED|_PAGE_DIRTY));

            old = t;
        }
    }
    return rv;
}

/*
 * Macro that wraps the appropriate type-changes around update_intpte().
 * Arguments are: type, ptr, old, new, mfn, vcpu
 */
#define UPDATE_ENTRY(_t,_p,_o,_n,_m,_v,_ad)                         \
    update_intpte(&_t ## e_get_intpte(*(_p)),                       \
                  _t ## e_get_intpte(_o), _t ## e_get_intpte(_n),   \
                  (_m), (_v), (_ad))

#endif /* __PV_MM_H__ */
