/*
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
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/init.h>
#include <public/xen.h>
#include <asm/current.h>
#include <asm/papr.h>
#include <asm/hcalls.h>

static void h_put_term_char(struct cpu_user_regs *regs)
{
    char data[(sizeof (u64) * 4) + 1];
    ulong count;
    extern void serial_puts(int handle, const char *s);

    /* XXX what to do with 'channel' in r4? */

    count = regs->gprs[5];
    if (count > 16) {
        regs->gprs[3] = H_Parameter;
        return;
    }

    memcpy(data, &regs->gprs[6], count);
    data[count] = '\0';

    serial_puts(0, data);
    regs->gprs[3] = H_Success;
}

static void h_get_term_char(struct cpu_user_regs *regs)
{
    /* temporary hack to let us use xmon in dom0 */
    extern char serial_getc_nb(int handle);
    char c;

    c = serial_getc_nb(0);
    if (c  > 0)  {
        regs->gprs[4] = 1;
        regs->gprs[5] = (ulong)c << (7 * 8);
        regs->gprs[6] = 0;        /* paranoid */
    } else {
        regs->gprs[4] = 0;
    }

    regs->gprs[3] = H_Success;
}

__init_papr_hcall(H_PUT_TERM_CHAR, h_put_term_char);
__init_papr_hcall(H_GET_TERM_CHAR, h_get_term_char);
