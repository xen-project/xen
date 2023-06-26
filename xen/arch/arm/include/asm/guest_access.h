#ifndef __ASM_ARM_GUEST_ACCESS_H__
#define __ASM_ARM_GUEST_ACCESS_H__

#include <xen/errno.h>
#include <xen/sched.h>

unsigned long raw_copy_to_guest(void *to, const void *from, unsigned int len);
unsigned long raw_copy_to_guest_flush_dcache(void *to, const void *from,
                                             unsigned int len);
unsigned long raw_copy_from_guest(void *to, const void *from, unsigned int len);
unsigned long raw_clear_guest(void *to, unsigned int len);

/* Copy data to guest physical address, then clean the region. */
unsigned long copy_to_guest_phys_flush_dcache(struct domain *d,
                                              paddr_t gpa,
                                              void *buf,
                                              unsigned int len);

int access_guest_memory_by_gpa(struct domain *d, paddr_t gpa, void *buf,
                               uint32_t size, bool is_write);

#define __raw_copy_to_guest raw_copy_to_guest
#define __raw_copy_from_guest raw_copy_from_guest
#define __raw_clear_guest raw_clear_guest

/*
 * Pre-validate a guest handle.
 * Allows use of faster __copy_* functions.
 */
/* All ARM guests are paging mode external and hence safe */
#define guest_handle_okay(hnd, nr) (1)
#define guest_handle_subrange_okay(hnd, first, last) (1)

#endif /* __ASM_ARM_GUEST_ACCESS_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
