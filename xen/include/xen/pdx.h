#ifndef __XEN_PDX_H__
#define __XEN_PDX_H__

#ifdef HAS_PDX

extern unsigned long max_pdx;
extern unsigned long pfn_pdx_bottom_mask, ma_va_bottom_mask;
extern unsigned int pfn_pdx_hole_shift;
extern unsigned long pfn_hole_mask;
extern unsigned long pfn_top_mask, ma_top_mask;

#define PDX_GROUP_COUNT ((1 << PDX_GROUP_SHIFT) / \
                         (sizeof(*frame_table) & -sizeof(*frame_table)))
extern unsigned long pdx_group_valid[];

extern u64 pdx_init_mask(u64 base_addr);
extern u64 pdx_region_mask(u64 base, u64 len);

extern void set_pdx_range(unsigned long smfn, unsigned long emfn);

#define page_to_pdx(pg)  ((pg) - frame_table)
#define pdx_to_page(pdx) (frame_table + (pdx))

extern int __mfn_valid(unsigned long mfn);

static inline unsigned long pfn_to_pdx(unsigned long pfn)
{
    return (pfn & pfn_pdx_bottom_mask) |
           ((pfn & pfn_top_mask) >> pfn_pdx_hole_shift);
}

static inline unsigned long pdx_to_pfn(unsigned long pdx)
{
    return (pdx & pfn_pdx_bottom_mask) |
           ((pdx << pfn_pdx_hole_shift) & pfn_top_mask);
}

extern void pfn_pdx_hole_setup(unsigned long);

#endif /* HAS_PDX */
#endif /* __XEN_PDX_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
