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
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/console.h>
#include <public/xen.h>
#include <xen/version.h>
#include <xen/sched.h>

void show_registers(struct cpu_user_regs *regs)
{
    int i;

    console_start_sync();
    
    printk("----[ Xen-%d.%d%s     ]----\n",
           xen_major_version(), xen_minor_version(), xen_extra_version());
    printk("CPU: %08x   DOMID: %08x\n",
           smp_processor_id(), current->domain->domain_id);
    printk("pc %016lx msr %016lx\n"
           "lr %016lx ctr %016lx\n"
           "srr0 %016lx srr1 %016lx\n",
           regs->pc, regs->msr,
           regs->lr, regs->ctr,
           regs->srr0, regs->srr1);

    /* These come in handy for debugging but are not always saved, so
     * what is "actually" in the register should be good */
    printk("dar %016lx dsisr %08x *** saved\n"
           "dar %016lx dsisr %08x *** actual\n",
           regs->dar, regs->dsisr,
           mfdar(), mfdsisr());

    for (i = 0; i < 32; i += 4) {
        printk("r%02i: %016lx %016lx %016lx %016lx\n", i,
            regs->gprs[i], regs->gprs[i+1], regs->gprs[i+2], regs->gprs[i+3]);
    }
    console_end_sync();
}

