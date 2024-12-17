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

void __init llc_coloring_init(void)
{
    unsigned int way_size;

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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
