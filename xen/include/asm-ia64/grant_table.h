/******************************************************************************
 * include/asm-ia64/grant_table.h
 */

#ifndef __ASM_GRANT_TABLE_H__
#define __ASM_GRANT_TABLE_H__

#define ORDER_GRANT_FRAMES 0

#ifndef CONFIG_XEN_IA64_DOM0_VP
// for grant map/unmap
#define create_grant_host_mapping(a, f, fl)  0
#define destroy_grant_host_mapping(a, f, fl) 0

// for grant transfer
#define steal_page_for_grant_transfer(d, p)  0
#else
// for grant map/unmap
int create_grant_host_mapping(unsigned long gpaddr, unsigned long mfn, unsigned int flags);
int destroy_grant_host_mapping(unsigned long gpaddr, unsigned long mfn, unsigned int flags);

// for grant transfer
int steal_page_for_grant_transfer(struct domain *d, struct page_info *page);
void guest_physmap_add_page(struct domain *d, unsigned long gpfn, unsigned long mfn);
#endif

#define gnttab_create_shared_page(d, t, i) ((void)0)

/* Guest physical address of the grant table.  */
#define IA64_GRANT_TABLE_PADDR (1UL << 40)

#define gnttab_shared_maddr(d, t, i)                        \
    virt_to_maddr((char*)(t)->shared + ((i) << PAGE_SHIFT))

#ifndef CONFIG_XEN_IA64_DOM0_VP
# define gnttab_shared_gmfn(d, t, i)                                         \
    ({ ((d) == dom0) ?                                                       \
            (virt_to_maddr((t)->shared) >> PAGE_SHIFT) + (i):                \
            assign_domain_page((d),                                          \
                               IA64_GRANT_TABLE_PADDR + ((i) << PAGE_SHIFT), \
                               gnttab_shared_maddr(d, t, i)),                \
            (IA64_GRANT_TABLE_PADDR >> PAGE_SHIFT) + (i);})
#else
# define gnttab_shared_gmfn(d, t, i)                                    \
    ({ assign_domain_page((d),                                          \
                          IA64_GRANT_TABLE_PADDR + ((i) << PAGE_SHIFT), \
                          gnttab_shared_maddr((d), (t), (i)));          \
        (IA64_GRANT_TABLE_PADDR >> PAGE_SHIFT) + (i);})
#endif

#define gnttab_log_dirty(d, f) ((void)0)

#endif /* __ASM_GRANT_TABLE_H__ */
