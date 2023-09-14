/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PPC_IO_H__
#define __ASM_PPC_IO_H__

#include <xen/lib.h>

/* TODO */
#define readb(c)        ({ (void)(c); BUG_ON("unimplemented"); 0; })
#define readw(c)        ({ (void)(c); BUG_ON("unimplemented"); 0; })
#define readl(c)        ({ (void)(c); BUG_ON("unimplemented"); 0; })

#define writeb(v,c)     ({ (void)(v); (void)(c); BUG_ON("unimplemented"); })
#define writew(v,c)     ({ (void)(v); (void)(c); BUG_ON("unimplemented"); })
#define writel(v,c)     ({ (void)(v); (void)(c); BUG_ON("unimplemented"); })

#endif /* __ASM_PPC_IO_H__ */
