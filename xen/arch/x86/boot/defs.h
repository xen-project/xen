/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
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
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * max() was copied from xen/xen/include/xen/kernel.h.
 */

#ifndef __BOOT_DEFS_H__
#define __BOOT_DEFS_H__

#define __maybe_unused	__attribute__((__unused__))
#define __packed	__attribute__((__packed__))
#define __stdcall	__attribute__((__stdcall__))

#define ALIGN_UP(arg, align) \
                (((arg) + (align) - 1) & ~((typeof(arg))(align) - 1))

#define min(x,y) ({ \
        const typeof(x) _x = (x);       \
        const typeof(y) _y = (y);       \
        (void) (&_x == &_y);            \
        _x < _y ? _x : _y; })

#define max(x,y) ({ \
        const typeof(x) _x = (x);       \
        const typeof(y) _y = (y);       \
        (void) (&_x == &_y);            \
        _x > _y ? _x : _y; })

#define _p(val)		((void *)(unsigned long)(val))

#define tolower(c)	((c) | 0x20)

#endif /* __BOOT_DEFS_H__ */
