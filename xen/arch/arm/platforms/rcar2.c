/*
 * xen/arch/arm/platforms/rcar2.c
 *
 * Renesas R-Car Gen2 specific settings
 *
 * Iurii Konovalenko <iurii.konovalenko@globallogic.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/mm.h>
#include <xen/vmap.h>
#include <asm/platform.h>
#include <asm/io.h>

#define RCAR2_RAM_ADDR                         0xE63C0000
#define RCAR2_RAM_SIZE                         0x1000
#define RCAR2_SMP_START_OFFSET                 0xFFC

static int __init rcar2_smp_init(void)
{
    void __iomem *pram;

    /* map ICRAM */
    pram = ioremap_nocache(RCAR2_RAM_ADDR, RCAR2_RAM_SIZE);
    if( !pram )
    {
        dprintk( XENLOG_ERR, "Unable to map RCAR2 ICRAM\n");
        return -ENOMEM;
    }

    /* setup reset vectors */
    writel(__pa(init_secondary), pram + RCAR2_SMP_START_OFFSET);
    iounmap(pram);

    sev();

    return 0;
}

static const char *const rcar2_dt_compat[] __initconst =
{
    "renesas,lager",
    NULL
};

PLATFORM_START(rcar2, "Renesas R-Car Gen2")
    .compatible = rcar2_dt_compat,
    .cpu_up = cpu_up_send_sgi,
    .smp_init = rcar2_smp_init,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
