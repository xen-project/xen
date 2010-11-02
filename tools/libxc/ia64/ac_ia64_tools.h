/*
 * ac_ia64_tools.h
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef AC_IA64_TOOLS_H
#define AC_IA64_TOOLS_H

#define ACPI_MACHINE_WIDTH 64
#define COMPILER_DEPENDENT_UINT64 unsigned long long
#define COMPILER_DEPENDENT_INT64 long long
typedef unsigned long long u64;
typedef long long s64;
typedef unsigned u32;
typedef int s32;
typedef unsigned char u8;
typedef unsigned short u16;
#define __iomem
#define asmlinkage
#define CONFIG_ACPI_BOOT

#endif /* AC_IA64_TOOLS_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
