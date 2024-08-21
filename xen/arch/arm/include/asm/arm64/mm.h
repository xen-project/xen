#ifndef __ARM_ARM64_MM_H__
#define __ARM_ARM64_MM_H__

extern DEFINE_PAGE_TABLE(xen_pgtable);

/*
 * On ARM64, all the RAM is currently direct mapped in Xen.
 * Hence return always true.
 */
static inline bool arch_mfns_in_directmap(unsigned long mfn, unsigned long nr)
{
    return true;
}

void arch_setup_page_tables(void);

void update_boot_mapping(bool enable);

#endif /* __ARM_ARM64_MM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
