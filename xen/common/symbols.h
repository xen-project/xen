/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SYMBOLS_H
#define SYMBOLS_H

#include <xen/stdint.h>
#include <xen/symbols.h>

#ifdef SYMBOLS_ORIGIN
extern const unsigned int symbols_offsets[];
#define symbols_address(n) (SYMBOLS_ORIGIN + symbols_offsets[n])
#else
extern const unsigned long symbols_addresses[];
#define symbols_address(n) symbols_addresses[n]
#endif
extern const unsigned int symbols_num_addrs;
extern const unsigned char symbols_names[];

extern const unsigned int symbols_num_names;
extern const struct symbol_offset symbols_sorted_offsets[];

extern const uint8_t symbols_token_table[];
extern const uint16_t symbols_token_index[];

extern const unsigned int symbols_markers[];

#endif /* SYMBOLS_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
