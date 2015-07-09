#ifndef _XEN_SYMBOLS_H
#define _XEN_SYMBOLS_H

#include <xen/types.h>

#define KSYM_NAME_LEN 127

/* Lookup an address. */
const char *symbols_lookup(unsigned long addr,
                           unsigned long *symbolsize,
                           unsigned long *offset,
                           char *namebuf);

int xensyms_read(uint32_t *symnum, char *type,
                 uint64_t *address, char *name);

#endif /*_XEN_SYMBOLS_H*/
