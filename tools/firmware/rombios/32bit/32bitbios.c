/*
 *  32bitbios - jumptable for those function reachable from 16bit area
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

#include "rombios_compat.h"

asm (
    "    .text                       \n"
    "     movzwl %bx,%eax            \n"
    "     jmp *jumptable(,%eax,4)    \n"
    "    .data                       \n"
    "jumptable:                      \n"
#define X(idx, ret, fn, args...) " .long "#fn"\n"
#include "32bitprotos.h"
#undef X
    );
