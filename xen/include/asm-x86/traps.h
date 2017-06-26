/*
 * Copyright (c) 2007, 2008 Advanced Micro Devices, Inc.
 * Author: Christoph Egger <Christoph.Egger@amd.com>
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef ASM_TRAP_H
#define ASM_TRAP_H

void async_exception_cleanup(struct vcpu *);

uint32_t guest_io_read(unsigned int port, unsigned int bytes,
                       struct domain *);
void guest_io_write(unsigned int port, unsigned int bytes, uint32_t data,
                    struct domain *);

const char *trapstr(unsigned int trapnr);

#endif /* ASM_TRAP_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
