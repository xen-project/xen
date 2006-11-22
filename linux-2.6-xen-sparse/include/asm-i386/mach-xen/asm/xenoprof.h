/******************************************************************************
 * asm-i386/mach-xen/asm/xenoprof.h
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
#ifndef __ASM_XENOPROF_H__
#define __ASM_XENOPROF_H__
#ifdef CONFIG_OPROFILE 

struct super_block;
struct dentry;
int xenoprof_create_files(struct super_block * sb, struct dentry * root);

#endif /* CONFIG_OPROFILE */
#endif /* __ASM_XENOPROF_H__ */
