/******************************************************************************
 * include/asm-ia64/grant_table.h
 */

#ifndef __ASM_GRANT_TABLE_H__
#define __ASM_GRANT_TABLE_H__

#define ORDER_GRANT_FRAMES 0

#define create_grant_host_mapping(a, f, fl)  0
#define destroy_grant_host_mapping(a, f, fl) 0

#define steal_page_for_grant_transfer(d, p)  0

#define gnttab_create_shared_mfn(d, t, i) ((void)0)

#define gnttab_shared_mfn(d, t, i)                                      \
    ( ((d) == dom0) ?                                                   \
      ((virt_to_phys((t)->shared) >> PAGE_SHIFT) + (i)) :               \
      (map_domain_page((d), 1UL<<40, virt_to_phys((t)->shared)),        \
       1UL << (40 - PAGE_SHIFT))                                        \
    )

#define gnttab_log_dirty(d, f) ((void)0)

#endif /* __ASM_GRANT_TABLE_H__ */
