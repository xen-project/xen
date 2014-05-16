/*
 * symbols.c: in-kernel printing of symbolic oopses and stack traces.
 *
 * Copyright 2002 Rusty Russell <rusty@rustcorp.com.au> IBM Corporation
 *
 * ChangeLog:
 *
 * (25/Aug/2004) Paulo Marques <pmarques@grupopie.com>
 *      Changed the compression method from stem compression to "table lookup"
 *      compression (see tools/symbols.c for a more complete description)
 */

#include <xen/config.h>
#include <xen/symbols.h>
#include <xen/kernel.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/string.h>
#include <xen/spinlock.h>

#ifdef SYMBOLS_ORIGIN
extern const unsigned int symbols_offsets[1];
#define symbols_address(n) (SYMBOLS_ORIGIN + symbols_offsets[n])
#else
extern const unsigned long symbols_addresses[];
#define symbols_address(n) symbols_addresses[n]
#endif
extern const unsigned int symbols_num_syms;
extern const u8 symbols_names[];

extern const u8 symbols_token_table[];
extern const u16 symbols_token_index[];

extern const unsigned int symbols_markers[];

/* expand a compressed symbol data into the resulting uncompressed string,
   given the offset to where the symbol is in the compressed stream */
static unsigned int symbols_expand_symbol(unsigned int off, char *result)
{
    int len, skipped_first = 0;
    const u8 *tptr, *data;

    /* get the compressed symbol length from the first symbol byte */
    data = &symbols_names[off];
    len = *data;
    data++;

    /* update the offset to return the offset for the next symbol on
     * the compressed stream */
    off += len + 1;

    /* for every byte on the compressed symbol data, copy the table
       entry for that byte */
    while(len) {
        tptr = &symbols_token_table[ symbols_token_index[*data] ];
        data++;
        len--;

        while (*tptr) {
            if(skipped_first) {
                *result = *tptr;
                result++;
            } else
                skipped_first = 1;
            tptr++;
        }
    }

    *result = '\0';

    /* return to offset to the next symbol */
    return off;
}

/* find the offset on the compressed stream given and index in the
 * symbols array */
static unsigned int get_symbol_offset(unsigned long pos)
{
    const u8 *name;
    int i;

    /* use the closest marker we have. We have markers every 256 positions,
     * so that should be close enough */
    name = &symbols_names[ symbols_markers[pos>>8] ];

    /* sequentially scan all the symbols up to the point we're searching for.
     * Every symbol is stored in a [<len>][<len> bytes of data] format, so we
     * just need to add the len to the current pointer for every symbol we
     * wish to skip */
    for(i = 0; i < (pos&0xFF); i++)
        name = name + (*name) + 1;

    return name - symbols_names;
}

bool_t is_active_kernel_text(unsigned long addr)
{
    return (is_kernel_text(addr) ||
            (system_state < SYS_STATE_active && is_kernel_inittext(addr)));
}

const char *symbols_lookup(unsigned long addr,
                           unsigned long *symbolsize,
                           unsigned long *offset,
                           char *namebuf)
{
    unsigned long i, low, high, mid;
    unsigned long symbol_end = 0;

    namebuf[KSYM_NAME_LEN] = 0;
    namebuf[0] = 0;

    if (!is_active_kernel_text(addr))
        return NULL;

        /* do a binary search on the sorted symbols_addresses array */
    low = 0;
    high = symbols_num_syms;

    while (high-low > 1) {
        mid = (low + high) / 2;
        if (symbols_address(mid) <= addr) low = mid;
        else high = mid;
    }

    /* search for the first aliased symbol. Aliased symbols are
           symbols with the same address */
    while (low && symbols_address(low - 1) == symbols_address(low))
        --low;

        /* Grab name */
    symbols_expand_symbol(get_symbol_offset(low), namebuf);

    /* Search for next non-aliased symbol */
    for (i = low + 1; i < symbols_num_syms; i++) {
        if (symbols_address(i) > symbols_address(low)) {
            symbol_end = symbols_address(i);
            break;
        }
    }

    /* if we found no next symbol, we use the end of the section */
    if (!symbol_end)
        symbol_end = is_kernel_inittext(addr) ?
            (unsigned long)_einittext : (unsigned long)_etext;

    *symbolsize = symbol_end - symbols_address(low);
    *offset = addr - symbols_address(low);
    return namebuf;
}
