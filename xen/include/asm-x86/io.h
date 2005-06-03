#ifndef _ASM_IO_H
#define _ASM_IO_H

#include <xen/config.h>
#include <asm/page.h>

#define IO_SPACE_LIMIT 0xffff

/**
 *  virt_to_phys    -   map virtual addresses to physical
 *  @address: address to remap
 *
 *  The returned physical address is the physical (CPU) mapping for
 *  the memory address given. It is only valid to use this function on
 *  addresses directly mapped or allocated via xmalloc.
 *
 *  This function does not give bus mappings for DMA transfers. In
 *  almost all conceivable cases a device driver should not be using
 *  this function
 */

static inline unsigned long virt_to_phys(volatile void * address)
{
    return __pa(address);
}

/**
 *  phys_to_virt    -   map physical address to virtual
 *  @address: address to remap
 *
 *  The returned virtual address is a current CPU mapping for
 *  the memory address given. It is only valid to use this function on
 *  addresses that have a kernel mapping
 *
 *  This function does not handle bus mappings for DMA transfers. In
 *  almost all conceivable cases a device driver should not be using
 *  this function
 */

static inline void * phys_to_virt(unsigned long address)
{
    return __va(address);
}

/*
 * Change "struct pfn_info" to physical address.
 */
#ifdef CONFIG_HIGHMEM64G
#define page_to_phys(page)  ((u64)(page - frame_table) << PAGE_SHIFT)
#else
#define page_to_phys(page)  ((page - frame_table) << PAGE_SHIFT)
#endif

#define page_to_pfn(_page)  ((unsigned long)((_page) - frame_table))
#define page_to_virt(_page) phys_to_virt(page_to_phys(_page))

/* We don't need real ioremap() on Xen/x86. */
#define ioremap(x,l) (__va(x))

#define readb(x) (*(volatile char *)(x))
#define readw(x) (*(volatile short *)(x))
#define readl(x) (*(volatile int *)(x))
#define writeb(d,x) (*(volatile char *)(x) = (d))
#define writew(d,x) (*(volatile short *)(x) = (d))
#define writel(d,x) (*(volatile int *)(x) = (d))

/*
 * IO bus memory addresses are also 1:1 with the physical address
 */
#define virt_to_bus virt_to_phys
#define bus_to_virt phys_to_virt
#define page_to_bus page_to_phys

#define __OUT1(s,x) \
static inline void out##s(unsigned x value, unsigned short port) {

#define __OUT2(s,s1,s2) \
__asm__ __volatile__ ("out" #s " %" s1 "0,%" s2 "1"

#define __OUT(s,s1,x) \
__OUT1(s,x) __OUT2(s,s1,"w") : : "a" (value), "Nd" (port)); } \
__OUT1(s##_p,x) __OUT2(s,s1,"w") : : "a" (value), "Nd" (port));} 

#define __IN1(s) \
static inline RETURN_TYPE in##s(unsigned short port) { RETURN_TYPE _v;

#define __IN2(s,s1,s2) \
__asm__ __volatile__ ("in" #s " %" s2 "1,%" s1 "0"

#define __IN(s,s1,i...) \
__IN1(s) __IN2(s,s1,"w") : "=a" (_v) : "Nd" (port) ,##i ); return _v; } \
__IN1(s##_p) __IN2(s,s1,"w") : "=a" (_v) : "Nd" (port) ,##i ); return _v; } 

#define RETURN_TYPE unsigned char
__IN(b,"")
#undef RETURN_TYPE
#define RETURN_TYPE unsigned short
__IN(w,"")
#undef RETURN_TYPE
#define RETURN_TYPE unsigned int
__IN(l,"")
#undef RETURN_TYPE

__OUT(b,"b",char)
__OUT(w,"w",short)
__OUT(l,,int)

#endif
