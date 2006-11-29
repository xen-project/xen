/******************************************************************************
 * xen/xenoprof.h
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

#ifndef __XEN_XENOPROF_H__
#define __XEN_XENOPROF_H__
#ifdef CONFIG_XEN

#include <asm/xenoprof.h>

struct oprofile_operations;
int xenoprofile_init(struct oprofile_operations * ops);
void xenoprofile_exit(void);

struct xenoprof_shared_buffer {
	char					*buffer;
	struct xenoprof_arch_shared_buffer	arch;
};
#else
#define xenoprofile_init(ops)	(-ENOSYS)
#define xenoprofile_exit()	do { } while (0)

#endif /* CONFIG_XEN */
#endif /* __XEN_XENOPROF_H__ */
