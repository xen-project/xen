
#ifndef __XEN_SHADOW_H__
#define __XEN_SHADOW_H__

#include <xen/config.h>

#ifdef CONFIG_SHADOW

#include <asm/shadow.h>

#else

#define shadow_drop_references(d, p)          ((void)0)
#define shadow_sync_and_drop_references(d, p) ((void)0)

#define shadow_mode_translate(d)              (0)

#define guest_physmap_add_page(d, p, m)       ((void)0)
#define guest_physmap_remove_page(d, p, m)    ((void)0)

#endif

#endif /* __XEN_SHADOW_H__ */
