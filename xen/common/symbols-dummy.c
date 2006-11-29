/*
 * symbols-dummy.c: dummy symbol-table definitions for the inital partial
 *                  link of the hypervisor image.
 */

#include <xen/config.h>
#include <xen/types.h>

unsigned long symbols_addresses[1];
unsigned long symbols_num_syms;
u8 symbols_names[1];

u8 symbols_token_table[1];
u16 symbols_token_index[1];

unsigned long symbols_markers[1];
