#ifndef _XFRD_XEN_DOMAIN_H_
#define _XFRD_XEN_DOMAIN_H_
#include <sys/types.h>
#include <iostream.h>
#include "connection.h"

/** Define to use stubs. Undefine to use Xen ops. */
//#define _XEN_XFR_STUB_

extern int xen_domain_snd(Conn *xend, IOStream *io,
                          uint32_t dom,
                          char *vmconfig, int vmconfig_n,
                          int live, int resource);
extern int xen_domain_rcv(IOStream *io,
                          uint32_t *dom,
                          char **vmconfig, int *vmconfig_n,
                          int *configured);


extern int xen_domain_configure(uint32_t dom, char *vmconfig, int vmconfig_n);
extern int xen_domain_unpause(uint32_t dom);
#endif
