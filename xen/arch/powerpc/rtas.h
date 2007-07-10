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
 * Copyright (C) IBM Corp. 2006
 *
 * Authors: Jimi Xenidis <jimix@us.ibm.com>
 */

#ifndef _ARCH_POWERPC_RTAS_H_
#define _ARCH_POWERPC_RTAS_H_

extern int rtas_entry;
extern unsigned long rtas_msr;
extern unsigned long rtas_base;
extern unsigned long rtas_end;

struct rtas_args {
    int ra_token;
    int ra_nargs;
    int ra_nrets;
    int ra_args[10];
} __attribute__ ((aligned(8)));

struct rtas_token {
    char *name;
    int (*proxy)(int token, struct rtas_args *r);
    int token;
};

extern struct rtas_token rt_power_off;
extern struct rtas_token rt_system_reboot;
extern struct rtas_token rt_nvram_fetch;
extern struct rtas_token rt_nvram_store;
extern struct rtas_token rt_manage_flash;
extern struct rtas_token rt_validate_flash;
extern struct rtas_token rt_update_reboot_flash;

/* RTAS errors */
#define RTAS_HW -1
#define RTAS_BUSY -2
#define RTAS_PARAMETER -3


extern int prom_call(void *arg, unsigned base,
                     unsigned long func, unsigned long msr);
extern int rtas_init(void *);
extern int rtas_halt(void);
extern int rtas_reboot(void);
extern int rtas_proxy_init(void *m);
extern int do_rtas_proxy(ulong arg);
extern void *rtas_remote_addr(ulong addr, ulong length);
extern int rtas_call(void *r);
#endif
