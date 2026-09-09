/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/errno.h>
#include <xen/init.h>
#include <xen/sections.h>
#include <xen/types.h>

#include <asm/cpufeature.h>

static bool __ro_after_init _aia_usable;

bool aia_usable(void)
{
    return _aia_usable;
}

void __init aia_init(void)
{
    if ( !riscv_isa_extension_available(NULL, RISCV_ISA_EXT_ssaia) )
        return;

    _aia_usable = true;
}
