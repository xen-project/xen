/******************************************************************************
 * machine_kexec.c
 *
 * Xen port written by:
 * - Simon 'Horms' Horman <horms@verge.net.au>
 * - Magnus Damm <magnus@valinux.co.jp>
 */

#include <xen/types.h>
#include <xen/kernel.h>
#include <asm/page.h>
#include <public/kexec.h>

int machine_kexec_get_xen(xen_kexec_range_t *range)
{
        range->start = virt_to_maddr(_start);
        range->size = virt_to_maddr(_end) - (unsigned long)range->start;
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
