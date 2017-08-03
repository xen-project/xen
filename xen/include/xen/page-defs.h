#ifndef __XEN_PAGE_DEFS_H__
#define __XEN_PAGE_DEFS_H__

/* Helpers for different page granularities. */
#define PAGE_SIZE_GRAN(gran)        ((paddr_t)1 << PAGE_SHIFT_##gran)
#define PAGE_MASK_GRAN(gran)        (-PAGE_SIZE_GRAN(gran))
#define PAGE_ALIGN_GRAN(gran, addr) ((addr + ~PAGE_MASK_##gran) & PAGE_MASK_##gran)

#define PAGE_SHIFT_4K               12
#define PAGE_SIZE_4K                PAGE_SIZE_GRAN(4K)
#define PAGE_MASK_4K                PAGE_MASK_GRAN(4K)
#define PAGE_ALIGN_4K(addr)         PAGE_ALIGN_GRAN(4K, addr)

#define PAGE_SHIFT_16K              14
#define PAGE_SIZE_16K               PAGE_SIZE_GRAN(16K)
#define PAGE_MASK_16K               PAGE_MASK_GRAN(16K)
#define PAGE_ALIGN_16K(addr)        PAGE_ALIGN_GRAN(16K, addr)

#define PAGE_SHIFT_64K              16
#define PAGE_SIZE_64K               PAGE_SIZE_GRAN(64K)
#define PAGE_MASK_64K               PAGE_MASK_GRAN(64K)
#define PAGE_ALIGN_64K(addr)        PAGE_ALIGN_GRAN(64K, addr)

#endif /* __XEN_PAGE_DEFS_H__ */
