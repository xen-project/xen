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
 * Authors: Maria Butrico <butrico@us.ibm.com>
 */

#ifndef _DIV64_H_
#define _DIV64_H_

#include <xen/types.h>

#define do_div(num,base) ({                                             \
        uint32_t _remainder = (uint64_t)(num) %                         \
                                (uint32_t)(base);                       \
        num = (uint64_t)(num) / (uint32_t)(base);                       \
        _remainder;                                                     \
})

#endif  /* #ifndef _DIV64_H_ */
