/*
 * symbols-dummy.c: dummy symbol-table definitions for the inital partial
 *                  link of the hypervisor image.
 */

#include "symbols.h"

#ifdef SYMBOLS_ORIGIN
const unsigned int symbols_offsets[1];
#else
const unsigned long symbols_addresses[1];
#endif
const unsigned int symbols_num_addrs;
const unsigned char symbols_names[1];

#ifdef CONFIG_FAST_SYMBOL_LOOKUP
const unsigned int symbols_num_names;
const struct symbol_offset symbols_sorted_offsets[1];
#endif

const uint8_t symbols_token_table[1];
const uint16_t symbols_token_index[1];

const unsigned int symbols_markers[1];
