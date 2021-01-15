#ifndef __ARM_PAGE_SHIFT_H__
#define __ARM_PAGE_SHIFT_H__

#define PAGE_SHIFT              12

#ifdef CONFIG_ARM_64
#define PADDR_BITS              48
#else
#define PADDR_BITS              40
#endif

#endif /* __ARM_PAGE_SHIFT_H__ */
