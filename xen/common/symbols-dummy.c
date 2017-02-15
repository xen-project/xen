/*
 * symbols-dummy.c: dummy symbol-table definitions for the inital partial
 *                  link of the hypervisor image.
 */

#include <xen/types.h>
#include <xen/symbols.h>

#ifdef SYMBOLS_ORIGIN
const unsigned int symbols_offsets[1];
#else
const unsigned long symbols_addresses[1];
#endif
const unsigned int symbols_num_syms;
const u8 symbols_names[1];

#ifdef CONFIG_FAST_SYMBOL_LOOKUP
const struct symbol_offset symbols_sorted_offsets[1];
#endif

const u8 symbols_token_table[1];
const u16 symbols_token_index[1];

const unsigned int symbols_markers[1];
