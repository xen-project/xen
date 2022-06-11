#ifndef __XEN_PMAP_H__
#define __XEN_PMAP_H__

/* Large enough for mapping 5 levels of page tables with some headroom */
#define NUM_FIX_PMAP 8

#ifndef __ASSEMBLY__

#include <xen/mm-frame.h>

void *pmap_map(mfn_t mfn);
void pmap_unmap(const void *p);

#endif /* __ASSEMBLY__ */

#endif /* __XEN_PMAP_H__ */
