/******************************************************************************
 * include/asm-ia64/grant_table.h
 */

#ifndef __ASM_GRANT_TABLE_H__
#define __ASM_GRANT_TABLE_H__

#define INITIAL_NR_GRANT_FRAMES 1

// for grant map/unmap
int create_grant_host_mapping(unsigned long gpaddr, unsigned long mfn, unsigned int flags);
int destroy_grant_host_mapping(unsigned long gpaddr, unsigned long mfn, unsigned int flags);

// for grant transfer
void guest_physmap_add_page(struct domain *d, unsigned long gpfn, unsigned long mfn);

// for grant table shared page
#define gnttab_create_shared_page(d, t, i)                              \
    do {                                                                \
        share_xen_page_with_guest(                                      \
            virt_to_page((char *)(t)->shared + ((i) << PAGE_SHIFT)),    \
            (d), XENSHARE_writable);                                    \
    } while (0)


/* XXX
 * somewhere appropriate
 * those constand shouldn't be pre-defined and
 * those area should be reserved by EFI MD.
 */
/* Guest phsyical address of shared_info */
#define IA64_SHARED_INFO_PADDR	(1UL << 40)
/* Guest phsyical address of mapped_regs */
#define IA64_XMAPPEDREGS_BASE_PADDR     (IA64_SHARED_INFO_PADDR + XSI_SIZE)
#define IA64_XMAPPEDREGS_PADDR(vcpu_id)             \
    (IA64_XMAPPEDREGS_BASE_PADDR +                  \
     (vcpu_id) * max_t(unsigned long, PAGE_SIZE, XMAPPEDREGS_SIZE))

/* Guest physical address of the grant table.  */
#define IA64_GRANT_TABLE_PADDR  IA64_XMAPPEDREGS_PADDR(NR_CPUS)

#define gnttab_shared_maddr(d, t, i)                        \
    virt_to_maddr((char*)(t)->shared + ((i) << PAGE_SHIFT))

# define gnttab_shared_gmfn(d, t, i)                                    \
    ({ assign_domain_page((d),                                          \
                          IA64_GRANT_TABLE_PADDR + ((i) << PAGE_SHIFT), \
                          gnttab_shared_maddr((d), (t), (i)));          \
        (IA64_GRANT_TABLE_PADDR >> PAGE_SHIFT) + (i);})

#define gnttab_mark_dirty(d, f) ((void)f)

static inline void gnttab_clear_flag(unsigned long nr, uint16_t *addr)
{
	clear_bit(nr, addr);
}

#endif /* __ASM_GRANT_TABLE_H__ */
