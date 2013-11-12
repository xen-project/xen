#ifndef _XEN_SYMBOLS_H
#define _XEN_SYMBOLS_H

#include <xen/types.h>

#define KSYM_NAME_LEN 127

/* Lookup an address. */
const char *symbols_lookup(unsigned long addr,
                           unsigned long *symbolsize,
                           unsigned long *offset,
                           char *namebuf);

#endif /*_XEN_SYMBOLS_H*/
