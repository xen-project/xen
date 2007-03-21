/******************************************************************************
 * include/asm-x86/grant_table.h
 * 
 * Copyright (c) 2004-2005 K A Fraser
 */

#ifndef __ASM_GRANT_TABLE_H__
#define __ASM_GRANT_TABLE_H__

#define INITIAL_NR_GRANT_FRAMES 4

/*
 * Caller must own caller's BIGLOCK, is responsible for flushing the TLB, and
 * must hold a reference to the page.
 */
int create_grant_host_mapping(
    uint64_t addr, unsigned long frame, unsigned int flags);
int destroy_grant_host_mapping(
    uint64_t addr, unsigned long frame, unsigned int flags);

#define gnttab_create_shared_page(d, t, i)                               \
    do {                                                                 \
        share_xen_page_with_guest(                                       \
            virt_to_page((char *)(t)->shared[i]),                        \
            (d), XENSHARE_writable);                                     \
    } while ( 0 )

#define gnttab_shared_mfn(d, t, i)                      \
    ((virt_to_maddr((t)->shared[i]) >> PAGE_SHIFT))

#define gnttab_shared_gmfn(d, t, i)                     \
    (mfn_to_gmfn(d, gnttab_shared_mfn(d, t, i)))

#define gnttab_mark_dirty(d, f) mark_dirty((d), (f))

static inline void gnttab_clear_flag(unsigned long nr, uint16_t *addr)
{
    clear_bit(nr, addr);
}

#define gnttab_release_put_page(page)                           \
    do {                                                        \
        /* Done implicitly when page tables are destroyed. */   \
    } while (0)

#define gnttab_release_put_page_and_type(page)                  \
    do {                                                        \
        /* Done implicitly when page tables are destroyed. */   \
    } while (0)

#endif /* __ASM_GRANT_TABLE_H__ */
