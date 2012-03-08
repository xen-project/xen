/******************************************************************************
 * xenoprof.c 
 *
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <public/xen.h>
#include <xen/xenoprof.h>
#include <asm/vmx.h>    /* for vmx_user_mode() */

int
xenoprofile_get_mode(const struct vcpu *v, const struct cpu_user_regs *regs)
{
    int mode;

    /*
     * mode
     * 0: user, 1: kernel, 2: xen
     * see linux/driver/oprofile/cpu_buffer.h
     */
#define CPU_MODE_USER           0
#define CPU_MODE_KERNEL         1
#define CPU_MODE_XEN            2
    if (VMX_DOMAIN(v)) {
        if (vmx_user_mode(regs)) {
            switch (ring(regs)) {
            case 3:
                mode = CPU_MODE_USER;
                break;
            case 0:
                mode = CPU_MODE_KERNEL;
                break;
            /* case 0: case 1: */
            default:
                gdprintk(XENLOG_ERR, "%s:%d ring%d in vmx is used!\n",
                         __func__, __LINE__, ring(regs));
                mode = CPU_MODE_KERNEL; /* fall back to kernel mode. */
                break;
            }
        } else {
            mode = CPU_MODE_XEN;
            BUG_ON(ring(regs) != 0);
        }
    } else {
        switch (ring(regs)) {
        case 3:
            mode = CPU_MODE_USER;
            break;
        case CONFIG_CPL0_EMUL:
            mode = CPU_MODE_KERNEL;
            break;
        case 0:
            mode = CPU_MODE_XEN;
            break;
        default:
            gdprintk(XENLOG_ERR, "%s:%d ring%d in pv is used!\n", __func__,
                     __LINE__, 3 - CONFIG_CPL0_EMUL);
            mode = CPU_MODE_KERNEL; /* fall back to kernel mode. */
            break;
        }
    }
    return mode;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
