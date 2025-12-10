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

#include <xen/kernel.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/string.h>
#include <xen/spinlock.h>
#include <xen/symbols.h>
#include <xen/virtual_region.h>
#include <public/platform.h>
#include <xen/guest_access.h>
#include <xen/errno.h>

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

bool is_active_kernel_text(unsigned long addr)
{
    return !!find_text_region(addr);
}

const char *symbols_lookup(unsigned long addr,
                           unsigned long *symbolsize,
                           unsigned long *offset,
                           char *namebuf)
{
    unsigned int i, low, high, mid;
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
    high = symbols_num_addrs;

    while (high-low > 1) {
        mid = (low + high) / 2;
        if (symbols_address(mid) <= addr) low = mid;
        else high = mid;
    }

    /* If we hit an END symbol, move to the previous (real) one. */
    if (!symbols_names[get_symbol_offset(low)]) {
        ASSERT(low);
        symbol_end = symbols_address(low);
        --low;
    }

    /* search for the first aliased symbol. Aliased symbols are
           symbols with the same address */
    while (low && symbols_address(low - 1) == symbols_address(low))
        --low;

        /* Grab name */
    symbols_expand_symbol(get_symbol_offset(low), namebuf);

    if (!symbol_end) {
        /* Search for next non-aliased symbol */
        for (i = low + 1; i < symbols_num_addrs; i++) {
            if (symbols_address(i) > symbols_address(low)) {
                symbol_end = symbols_address(i);
                break;
            }
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
    static unsigned int next_symbol, next_offset;
    static DEFINE_SPINLOCK(symbols_mutex);

    if ( *symnum > symbols_num_addrs )
        return -ERANGE;
    if ( *symnum == symbols_num_addrs )
    {
    no_symbol:
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

    /*
     * If we're at an END symbol, skip to the next (real) one. This can
     * happen if the caller ignores the *symnum output from an earlier
     * iteration (Linux'es /proc/xen/xensyms handling does as of 6.14-rc).
     */
    if ( !symbols_names[next_offset] )
    {
        ++next_offset;
        if ( ++*symnum == symbols_num_addrs )
        {
            spin_unlock(&symbols_mutex);
            goto no_symbol;
        }
    }

    *type = symbols_get_symbol_type(next_offset);
    next_offset = symbols_expand_symbol(next_offset, name);
    *address = symbols_address(*symnum);

    /* If next one is an END symbol, skip it. */
    if ( !symbols_names[next_offset] )
    {
        ++next_offset;
        /* Make sure not to increment past symbols_num_addrs below. */
        if ( *symnum + 1 < symbols_num_addrs )
            ++*symnum;
    }

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
    high = symbols_num_names;
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

#ifdef CONFIG_SELF_TESTS

static void __init test_lookup(unsigned long addr, const char *expected)
{
    char buf[KSYM_NAME_LEN + 1];
    const char *name, *symname;
    unsigned long size, offs;

    name = symbols_lookup(addr, &size, &offs, buf);
    if ( !name )
        panic("%s: address not found\n", expected);
    if ( offs )
        panic("%s: non-zero offset (%#lx) unexpected\n", expected, offs);

    /* Cope with static symbols, where varying file names/paths may be used. */
    symname = strchr(name, '#');
    symname = symname ? symname + 1 : name;
    if ( strcmp(symname, expected) )
        panic("%s: unexpected symbol name: '%s'\n", expected, symname);

    offs = symbols_lookup_by_name(name);
    if ( offs != addr )
        panic("%s: address %#lx unexpected; wanted %#lx\n",
              expected, offs, addr);
}

static void __init __constructor test_symbols(void)
{
    /* Be sure to only try this for cf_check functions. */
    test_lookup((unsigned long)dump_execstate, "dump_execstate");
    test_lookup((unsigned long)test_symbols, __func__);
}

#endif /* CONFIG_SELF_TESTS */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
