#ifndef __XEN_CONSOLED_H__
#define __XEN_CONSOLED_H__

#include <public/io/console.h>

void consoled_set_ring_addr(struct xencons_interface *ring);
struct xencons_interface *consoled_get_ring_addr(void);
void consoled_guest_rx(void);
void consoled_guest_tx(char c);

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
