#ifndef __X86_64_UACCESS_H
#define __X86_64_UACCESS_H

/*
 * With CONFIG_SPECULATIVE_HARDEN_GUEST_ACCESS (apparent) PV guest accesses
 * are prohibited to touch the Xen private VA range.  The compat argument
 * translation area, therefore, can't live within this range.  Domains
 * (potentially) in need of argument translation (32-bit PV, possibly HVM) get
 * a secondary mapping installed, which needs to be used for such accesses in
 * the PV case, and will also be used for HVM to avoid extra conditionals.
 */
#define COMPAT_ARG_XLAT_VIRT_BASE ((void *)ARG_XLAT_START(current) + \
                                   (PERDOMAIN_ALT_VIRT_START - \
                                    PERDOMAIN_VIRT_START))
#define COMPAT_ARG_XLAT_SIZE      (2*PAGE_SIZE)
struct vcpu;
int setup_compat_arg_xlat(struct vcpu *v);
void free_compat_arg_xlat(struct vcpu *v);
#define is_compat_arg_xlat_range(addr, size) ({                               \
    unsigned long __off;                                                      \
    __off = (unsigned long)(addr) - (unsigned long)COMPAT_ARG_XLAT_VIRT_BASE; \
    (__off < COMPAT_ARG_XLAT_SIZE) &&                                         \
    ((__off + (unsigned long)(size)) <= COMPAT_ARG_XLAT_SIZE);                \
})

#define xlat_page_start ((unsigned long)COMPAT_ARG_XLAT_VIRT_BASE)
#define xlat_page_size  COMPAT_ARG_XLAT_SIZE
#define xlat_page_left_size(xlat_page_current) \
    (xlat_page_start + xlat_page_size - (xlat_page_current))

#define xlat_malloc_init(xlat_page_current)    do { \
    (xlat_page_current) = xlat_page_start; \
} while (0)

extern void *xlat_malloc(unsigned long *xlat_page_current, size_t size);

#define xlat_malloc_array(_p, _t, _c) ((_t *) xlat_malloc(&(_p), \
                                                          sizeof(_t) * (_c)))

/*
 * Valid if in +ve half of 48-bit address space, or above Xen-reserved area.
 * This is also valid for range checks (addr, addr+size). As long as the
 * start address is outside the Xen-reserved area, sequential accesses
 * (starting at addr) will hit a non-canonical address (and thus fault)
 * before ever reaching VIRT_START.
 */
#define __addr_ok(addr) \
    (((unsigned long)(addr) < (1UL<<47)) || \
     ((unsigned long)(addr) >= HYPERVISOR_VIRT_END))

#define access_ok(addr, size) \
    (__addr_ok(addr) || is_compat_arg_xlat_range(addr, size))

#define array_access_ok(addr, count, size) \
    (likely(((count) ?: 0UL) < (~0UL / (size))) && \
     access_ok(addr, (count) * (size)))

#define __compat_addr_ok(d, addr) \
    ((unsigned long)(addr) < HYPERVISOR_COMPAT_VIRT_START(d))

#define __compat_access_ok(d, addr, size) \
    __compat_addr_ok(d, (unsigned long)(addr) + ((size) ? (size) - 1 : 0))

#define compat_access_ok(addr, size) \
    __compat_access_ok(current->domain, addr, size)

#define compat_array_access_ok(addr,count,size) \
    (likely((count) < (~0U / (size))) && \
     compat_access_ok(addr, 0 + (count) * (size)))

#endif /* __X86_64_UACCESS_H */
