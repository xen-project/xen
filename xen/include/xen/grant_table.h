/******************************************************************************
 * include/xen/grant_table.h
 * 
 * Mechanism for granting foreign access to page frames, and receiving
 * page-ownership transfers.
 * 
 * Copyright (c) 2004 K A Fraser
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
 */

#ifndef __XEN_GRANT_H__
#define __XEN_GRANT_H__

#ifndef __GRANT_TABLE_IMPLEMENTATION__
typedef void grant_table_t;
#endif

/* Start-of-day system initialisation. */
void grant_table_init(void);

/* Create/destroy per-domain grant table context. */
int  grant_table_create(struct domain *d);
void grant_table_destroy(struct domain *d);

#endif /* __XEN_GRANT_H__ */
