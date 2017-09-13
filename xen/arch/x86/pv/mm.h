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

#endif /* __PV_MM_H__ */
