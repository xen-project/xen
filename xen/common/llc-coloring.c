/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Last Level Cache (LLC) coloring common code
 *
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 * Copyright (C) 2024, Minerva Systems SRL
 */
#include <xen/keyhandler.h>
#include <xen/llc-coloring.h>
#include <xen/param.h>
#include <xen/sched.h>
#include <xen/types.h>

#define NR_LLC_COLORS          (1U << CONFIG_LLC_COLORS_ORDER)

/*
 * -1: not specified (disabled unless llc-size and llc-nr-ways present)
 *  0: explicitly disabled through cmdline
 *  1: explicitly enabled through cmdline
 */
static int8_t __initdata opt_llc_coloring = -1;
boolean_param("llc-coloring", opt_llc_coloring);

bool __ro_after_init llc_coloring_enabled;

static unsigned int __initdata llc_size;
size_param("llc-size", llc_size);
static unsigned int __initdata llc_nr_ways;
integer_param("llc-nr-ways", llc_nr_ways);
/* Number of colors available in the LLC */
static unsigned int __ro_after_init max_nr_colors;
/* Default coloring configuration */
static unsigned int __ro_after_init default_colors[NR_LLC_COLORS];

static unsigned int __initdata dom0_colors[NR_LLC_COLORS];
static unsigned int __initdata dom0_num_colors;

/*
 * Parse the coloring configuration given in the buf string, following the
 * syntax below.
 *
 * COLOR_CONFIGURATION ::= COLOR | RANGE,...,COLOR | RANGE
 * RANGE               ::= COLOR-COLOR
 *
 * Example: "0,2-6,15-16" represents the set of colors: 0,2,3,4,5,6,15,16.
 */
static int __init parse_color_config(const char *buf, unsigned int colors[],
                                     unsigned int max_num_colors,
                                     unsigned int *num_colors)
{
    const char *s = buf;

    *num_colors = 0;

    while ( *s != '\0' )
    {
        unsigned int color, start, end;

        start = simple_strtoul(s, &s, 0);

        if ( *s == '-' )    /* Range */
        {
            s++;
            end = simple_strtoul(s, &s, 0);
        }
        else                /* Single value */
            end = start;

        if ( start > end || (end - start) > (UINT_MAX - *num_colors) ||
             (*num_colors + (end - start)) >= max_num_colors )
            return -EINVAL;

        /* Colors are range checked in check_colors() */
        for ( color = start; color <= end; color++ )
            colors[(*num_colors)++] = color;

        if ( *s == ',' )
            s++;
        else if ( *s != '\0' )
            break;
    }

    return *s ? -EINVAL : 0;
}

static int __init parse_dom0_colors(const char *s)
{
    return parse_color_config(s, dom0_colors, ARRAY_SIZE(dom0_colors),
                              &dom0_num_colors);
}
custom_param("dom0-llc-colors", parse_dom0_colors);

static void print_colors(const unsigned int colors[], unsigned int num_colors)
{
    unsigned int i;

    printk("{ ");
    for ( i = 0; i < num_colors; i++ )
    {
        unsigned int start = colors[i], end = start;

        printk("%u", start);

        for ( ; i < num_colors - 1 && end + 1 == colors[i + 1]; i++, end++ )
            ;

        if ( start != end )
            printk("-%u", end);

        if ( i < num_colors - 1 )
            printk(", ");
    }
    printk(" }\n");
}

static bool __init check_colors(const unsigned int colors[],
                                unsigned int num_colors)
{
    unsigned int i;

    for ( i = 0; i < num_colors; i++ )
    {
        if ( colors[i] >= max_nr_colors )
        {
            printk(XENLOG_ERR "LLC color %u >= %u (max allowed)\n", colors[i],
                   max_nr_colors);
            return false;
        }
    }

    return true;
}

void __init llc_coloring_init(void)
{
    unsigned int way_size, i;

    llc_coloring_enabled = (opt_llc_coloring >= 1);
    if ( (opt_llc_coloring != 0) && llc_size && llc_nr_ways )
    {
        llc_coloring_enabled = true;
        way_size = llc_size / llc_nr_ways;
    }
    else if ( !llc_coloring_enabled )
        return;
    else
    {
        way_size = get_llc_way_size();
        if ( !way_size )
            panic("LLC probing failed and 'llc-size' or 'llc-nr-ways' missing\n");
    }

    if ( way_size & ~PAGE_MASK )
        panic("LLC way size must be a multiple of PAGE_SIZE\n");

    /*
     * The maximum number of colors must be a power of 2 in order to correctly
     * map them to bits of an address.
     */
    max_nr_colors = way_size >> PAGE_SHIFT;

    if ( max_nr_colors & (max_nr_colors - 1) )
        panic("Number of LLC colors (%u) isn't a power of 2\n", max_nr_colors);

    if ( max_nr_colors > NR_LLC_COLORS )
    {
        printk(XENLOG_WARNING
               "Number of LLC colors (%u) too big. Using configured max %u\n",
               max_nr_colors, NR_LLC_COLORS);
        max_nr_colors = NR_LLC_COLORS;
    }
    else if ( max_nr_colors < 2 )
        panic("Number of LLC colors %u < 2\n", max_nr_colors);

    for ( i = 0; i < max_nr_colors; i++ )
        default_colors[i] = i;

    arch_llc_coloring_init();
}

void dump_llc_coloring_info(void)
{
    if ( !llc_coloring_enabled )
        return;

    printk("LLC coloring info:\n");
    printk("    Number of LLC colors supported: %u\n", max_nr_colors);
}

void domain_dump_llc_colors(const struct domain *d)
{
    if ( !llc_coloring_enabled )
        return;

    printk("%u LLC colors: ", d->num_llc_colors);
    print_colors(d->llc_colors, d->num_llc_colors);
}

static void __init domain_set_default_colors(struct domain *d)
{
    printk(XENLOG_WARNING
           "LLC color config not found for %pd, using all colors\n", d);

    d->llc_colors = default_colors;
    d->num_llc_colors = max_nr_colors;
}

int __init dom0_set_llc_colors(struct domain *d)
{
    typeof(*dom0_colors) *colors;

    if ( !dom0_num_colors )
    {
        domain_set_default_colors(d);
        return 0;
    }

    if ( (dom0_num_colors > max_nr_colors) ||
         !check_colors(dom0_colors, dom0_num_colors) )
    {
        printk(XENLOG_ERR "%pd:  bad LLC color config\n", d);
        return -EINVAL;
    }

    colors = xmalloc_array(typeof(*dom0_colors), dom0_num_colors);
    if ( !colors )
        return -ENOMEM;

    memcpy(colors, dom0_colors, sizeof(*colors) * dom0_num_colors);
    d->llc_colors = colors;
    d->num_llc_colors = dom0_num_colors;

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
