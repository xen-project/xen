#ifndef __XEN_PAGE_SIZE_H__
#define __XEN_PAGE_SIZE_H__

#include <xen/const.h>
#include <asm/page-bits.h>

/*
 * It is important that the masks are signed quantities. This ensures that
 * the compiler sign-extends a 32-bit mask to 64 bits if that is required.
 */
#define PAGE_SIZE           (_AC(1,L) << PAGE_SHIFT)
#define PAGE_MASK           (~(PAGE_SIZE-1))
#define PAGE_OFFSET(ptr)   ((unsigned long)(ptr) & ~PAGE_MASK)

#define PADDR_MASK          ((_AC(1,ULL) << PADDR_BITS) - 1)
#define VADDR_MASK          (~_AC(0,UL) >> (BITS_PER_LONG - VADDR_BITS))

#endif /* __XEN_PAGE_SIZE__ */
