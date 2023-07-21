/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file was derived from Xen 3.2's xen/arch/powerpc/boot_of.c,
 * originally licensed under GPL version 2 or later.
 *
 * Copyright IBM Corp. 2005, 2006, 2007
 * Copyright Raptor Engineering, LLC
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 *          Hollis Blanchard <hollisb@us.ibm.com>
 *          Shawn Anastasio <sanastasio@raptorengineering.com>
 */

#include <xen/init.h>
#include <xen/macros.h>
#include <xen/stdarg.h>
#include <xen/types.h>
#include <asm/boot.h>
#include <asm/byteorder.h>
#include <asm/early_printk.h>

/*
 * The Open Firmware client interface is called in 32-bit mode with the MMU off,
 * so any addresses passed to it must be physical addresses under 4GB.
 *
 * Since the client interface is only used during early boot before the MMU is on
 * and Xen itself was loaded by Open Firmware (and therefore resides below 4GB),
 * we can achieve the desired result with a simple cast to uint32_t.
 */
#define ADDR(x) ((uint32_t)(unsigned long)(x))

/* OF entrypoint*/
static unsigned long __initdata of_vec;

static int __initdata of_out;

static int __init of_call(const char *service, uint32_t nargs, uint32_t nrets,
                          int32_t rets[], ...)
{
    int rc;
    va_list args;
    unsigned int i;
    struct of_service s;

    s.ofs_service = cpu_to_be32(ADDR(service));
    s.ofs_nargs = cpu_to_be32(nargs);
    s.ofs_nrets = cpu_to_be32(nrets);

    /* Copy all the params into the args array */
    va_start(args, rets);

    for ( i = 0; i < nargs; i++ )
        s.ofs_args[i] = cpu_to_be32(va_arg(args, uint32_t));

    va_end(args);

    rc = enter_of(&s, of_vec);

    /* Copy all return values to the output rets array */
    for ( i = 0; i < nrets; i++ )
        rets[i] = be32_to_cpu(s.ofs_args[i + nargs]);

    return rc;
}

static int __init of_finddevice(const char *devspec)
{
    int32_t rets[1] = { OF_FAILURE };

    of_call("finddevice", 1, ARRAY_SIZE(rets), rets, ADDR(devspec));
    return rets[0];
}

static int __init of_getprop(int ph, const char *name, void *buf, uint32_t buflen)
{
    int32_t rets[1] = { OF_FAILURE };

    of_call("getprop", 4, ARRAY_SIZE(rets), rets, ph, ADDR(name), ADDR(buf),
            buflen);
    return rets[0];
}

int __init of_write(int ih, const char *addr, uint32_t len)
{
    int32_t rets[1] = { OF_FAILURE };

    of_call("write", 3, ARRAY_SIZE(rets), rets, ih, ADDR(addr), len);
    return rets[0];
}

static void __init of_putchar(char c)
{
    if ( c == '\n' )
    {
        char buf = '\r';
        of_write(of_out, &buf, 1);
    }
    of_write(of_out, &c, 1);
}

void __init boot_of_init(unsigned long vec)
{
    int bof_chosen;

    of_vec = vec;

    /* Get a handle to the default console */
    bof_chosen = of_finddevice("/chosen");
    of_getprop(bof_chosen, "stdout", &of_out, sizeof(of_out));
    of_out = be32_to_cpu(of_out);

    early_printk_init(of_putchar);
}
