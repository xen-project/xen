#ifndef __XEN_PFN_H__
#define __XEN_PFN_H__

#include <asm/page.h>

#define PFN_DOWN(x)   ((x) >> PAGE_SHIFT)
#define PFN_UP(x)     (((x) + PAGE_SIZE-1) >> PAGE_SHIFT)

#define round_pgup(p)    (((p) + (PAGE_SIZE - 1)) & PAGE_MASK)
#define round_pgdown(p)  ((p) & PAGE_MASK)

#endif /* __XEN_PFN_H__ */
