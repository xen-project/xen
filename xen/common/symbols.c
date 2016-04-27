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
#include <xen/virtual_region.h>
#include <public/platform.h>
#include <xen/guest_access.h>

#ifdef SYMBOLS_ORIGIN
extern const unsigned int symbols_offsets[];
#define symbols_address(n) (SYMBOLS_ORIGIN + symbols_offsets[n])
#else
extern const unsigned long symbols_addresses[];
#define symbols_address(n) symbols_addresses[n]
#endif
extern const unsigned int symbols_num_syms;
extern const u8 symbols_names[];

extern const struct symbol_offset symbols_sorted_offsets[];

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
    return !!find_text_region(addr);
}

const char *symbols_lookup(unsigned long addr,
                           unsigned long *symbolsize,
                           unsigned long *offset,
                           char *namebuf)
{
    unsigned long i, low, high, mid;
    unsigned long symbol_end = 0;
    const struct virtual_region *region;

    namebuf[KSYM_NAME_LEN] = 0;
    namebuf[0] = 0;

    region = find_text_region(addr);
    if (!region)
        return NULL;

    if (region->symbols_lookup)
        return region->symbols_lookup(addr, symbolsize, offset, namebuf);

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

/*
 * Get symbol type information. This is encoded as a single char at the
 * beginning of the symbol name.
 */
static char symbols_get_symbol_type(unsigned int off)
{
    /*
     * Get just the first code, look it up in the token table,
     * and return the first char from this token.
     */
    return symbols_token_table[symbols_token_index[symbols_names[off + 1]]];
}

int xensyms_read(uint32_t *symnum, char *type,
                 unsigned long *address, char *name)
{
    /*
     * Symbols are most likely accessed sequentially so we remember position
     * from previous read. This can help us avoid the extra call to
     * get_symbol_offset().
     */
    static uint64_t next_symbol, next_offset;
    static DEFINE_SPINLOCK(symbols_mutex);

    if ( *symnum > symbols_num_syms )
        return -ERANGE;
    if ( *symnum == symbols_num_syms )
    {
        /* No more symbols */
        name[0] = '\0';
        return 0;
    }

    spin_lock(&symbols_mutex);

    if ( *symnum == 0 )
        next_offset = next_symbol = 0;
    if ( next_symbol != *symnum )
        /* Non-sequential access */
        next_offset = get_symbol_offset(*symnum);

    *type = symbols_get_symbol_type(next_offset);
    next_offset = symbols_expand_symbol(next_offset, name);
    *address = symbols_address(*symnum);

    next_symbol = ++*symnum;

    spin_unlock(&symbols_mutex);

    return 0;
}

unsigned long symbols_lookup_by_name(const char *symname)
{
    char name[KSYM_NAME_LEN + 1];
#ifdef CONFIG_FAST_SYMBOL_LOOKUP
    unsigned long low, high;
#else
    uint32_t symnum = 0;
    char type;
    unsigned long addr;
    int rc;
#endif

    if ( *symname == '\0' )
        return 0;

#ifdef CONFIG_FAST_SYMBOL_LOOKUP
    low = 0;
    high = symbols_num_syms;
    while ( low < high )
    {
        unsigned long mid = low + ((high - low) / 2);
        const struct symbol_offset *s;
        int rc;

        s = &symbols_sorted_offsets[mid];
        (void)symbols_expand_symbol(s->stream, name);
        /* Format is: [filename]#<symbol>. symbols_expand_symbol eats type.*/
        rc = strcmp(symname, name);
        if ( rc < 0 )
            high = mid;
        else if ( rc > 0 )
            low = mid + 1;
        else
            return symbols_address(s->addr);
    }
#else
    do {
        rc = xensyms_read(&symnum, &type, &addr, name);
        if ( rc )
           break;

        if ( !strcmp(name, symname) )
            return addr;

    } while ( name[0] != '\0' );

#endif
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
