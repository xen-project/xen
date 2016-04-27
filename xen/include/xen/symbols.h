#ifndef _XEN_SYMBOLS_H
#define _XEN_SYMBOLS_H

#include <xen/types.h>

#define KSYM_NAME_LEN 127

/*
 * Typedef for the callback functions that symbols_lookup
 * can call if virtual_region_list has an callback for it.
 */
typedef const char *symbols_lookup_t(unsigned long addr,
                                     unsigned long *symbolsize,
                                     unsigned long *offset,
                                     char *namebuf);

/* Lookup an address. */
const char *symbols_lookup(unsigned long addr,
                           unsigned long *symbolsize,
                           unsigned long *offset,
                           char *namebuf);

int xensyms_read(uint32_t *symnum, char *type,
                 unsigned long *address, char *name);

unsigned long symbols_lookup_by_name(const char *symname);

/*
 * A sorted (by symbols) lookup table table to symbols_names (stream)
 * and symbols_address (or offset).
 */
struct symbol_offset {
    uint32_t stream; /* .. in the compressed stream.*/
    uint32_t addr;   /* .. and in the fixed size address array. */
};
#endif /*_XEN_SYMBOLS_H*/
