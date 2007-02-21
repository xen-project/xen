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

#ifndef NDEBUG
#include <xen/lib.h>
#include <xen/sched.h>

extern void audit_domain(struct domain *d);
extern void audit_domains(void);
extern void audit_domains_key(unsigned char key);

void audit_domain(struct domain *d)
{
    panic("%s unimplemented\n", __func__);
}

void audit_domains(void)
{
    struct domain *d;
    rcu_read_lock(&domlist_read_lock);
    for_each_domain ( d )
        audit_domain(d);
    rcu_read_unlock(&domlist_read_lock);
}

void audit_domains_key(unsigned char key)
{
    audit_domains();
}
#endif
