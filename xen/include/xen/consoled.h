#ifndef __XEN_CONSOLED_H__
#define __XEN_CONSOLED_H__

/* SPDX-License-Identifier: GPL-2.0-only */
#include <public/io/console.h>

void consoled_set_ring_addr(struct xencons_interface *ring);
struct xencons_interface *consoled_get_ring_addr(void);
int consoled_guest_rx(void);
int consoled_guest_tx(char c);

#ifdef CONFIG_PV_SHIM

bool consoled_is_enabled(void);

#else

#define consoled_is_enabled()   (false)

#endif /* CONFIG_PV_SHIM */

#endif /* __XEN_CONSOLED_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
