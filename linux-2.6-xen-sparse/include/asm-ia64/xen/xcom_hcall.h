/*
 * Copyright (C) 2006 Tristan Gingold <tristan.gingold@bull.net>, Bull SAS
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#ifndef _LINUX_XENCOMM_HCALL_H_
#define _LINUX_XENCOMM_HCALL_H_

/* These function creates inline descriptor for the parameters and
   calls the corresponding xencomm_arch_hypercall_X.
   Architectures should defines HYPERVISOR_xxx as xencomm_hypercall_xxx unless
   they want to use their own wrapper.  */
extern int xencomm_hypercall_console_io(int cmd, int count, char *str);

extern int xencomm_hypercall_event_channel_op(int cmd, void *op);

extern int xencomm_hypercall_xen_version(int cmd, void *arg);

extern int xencomm_hypercall_physdev_op(int cmd, void *op);

extern int xencomm_hypercall_grant_table_op(unsigned int cmd, void *op,
                                            unsigned int count);

extern int xencomm_hypercall_sched_op(int cmd, void *arg);

extern int xencomm_hypercall_multicall(void *call_list, int nr_calls);

extern int xencomm_hypercall_callback_op(int cmd, void *arg);

extern int xencomm_hypercall_memory_op(unsigned int cmd, void *arg);

extern unsigned long xencomm_hypercall_hvm_op(int cmd, void *arg);

extern int xencomm_hypercall_suspend(unsigned long srec);

extern int xencomm_hypercall_xenoprof_op(int op, void *arg);

extern int xencomm_hypercall_perfmon_op(unsigned long cmd, void* arg,
                                        unsigned long count);

extern long xencomm_hypercall_vcpu_op(int cmd, int cpu, void *arg);

/* Using mini xencomm.  */
extern int xencomm_mini_hypercall_console_io(int cmd, int count, char *str);

extern int xencomm_mini_hypercall_event_channel_op(int cmd, void *op);

extern int xencomm_mini_hypercall_xen_version(int cmd, void *arg);

extern int xencomm_mini_hypercall_physdev_op(int cmd, void *op);

extern int xencomm_mini_hypercall_grant_table_op(unsigned int cmd, void *op,
                                                 unsigned int count);

extern int xencomm_mini_hypercall_sched_op(int cmd, void *arg);

extern int xencomm_mini_hypercall_multicall(void *call_list, int nr_calls);

extern int xencomm_mini_hypercall_callback_op(int cmd, void *arg);

extern int xencomm_mini_hypercall_memory_op(unsigned int cmd, void *arg);

extern unsigned long xencomm_mini_hypercall_hvm_op(int cmd, void *arg);

extern int xencomm_mini_hypercall_xenoprof_op(int op, void *arg);

extern int xencomm_mini_hypercall_perfmon_op(unsigned long cmd, void* arg,
                                             unsigned long count);

/* For privcmd.  Locally declare argument type to avoid include storm.
   Type coherency will be checked within privcmd.c  */
struct privcmd_hypercall;
extern int privcmd_hypercall(struct privcmd_hypercall *hypercall);

#endif /* _LINUX_XENCOMM_HCALL_H_ */
