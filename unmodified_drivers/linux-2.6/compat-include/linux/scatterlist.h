#ifndef _LINUX_SCATTERLIST_H
#define _LINUX_SCATTERLIST_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
#error "This version of Linux should not need compat linux/scatterlist.h"
#endif

#include <asm/scatterlist.h>

#endif /* _LINUX_SCATTERLIST_H */
