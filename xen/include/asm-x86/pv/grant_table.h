/*
 * asm-x86/pv/grant_table.h
 *
 * Grant table interfaces for PV guests
 *
 * Copyright (C) 2017 Wei Liu <wei.liu2@citrix.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __X86_PV_GRANT_TABLE_H__
#define __X86_PV_GRANT_TABLE_H__

#ifdef CONFIG_PV

int create_grant_pv_mapping(uint64_t addr, unsigned long frame,
                            unsigned int flags, unsigned int cache_flags);
int replace_grant_pv_mapping(uint64_t addr, unsigned long frame,
                             uint64_t new_addr, unsigned int flags);

#else

#include <public/grant_table.h>

static inline int create_grant_pv_mapping(uint64_t addr, unsigned long frame,
                                          unsigned int flags,
                                          unsigned int cache_flags)
{
    return GNTST_general_error;
}

static inline int replace_grant_pv_mapping(uint64_t addr, unsigned long frame,
                                           uint64_t new_addr, unsigned int flags)
{
    return GNTST_general_error;
}

#endif

#endif /* __X86_PV_GRANT_TABLE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
