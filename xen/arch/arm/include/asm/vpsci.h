/*
 * xen/include/asm-arm/vpsci.h
 *
 * Julien Grall <julien.gral@linaro.org>
 * Copyright (c) 2018 Linaro Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_VPSCI_H__
#define __ASM_VPSCI_H__

#include <asm/psci.h>

/* Number of function implemented by virtual PSCI (only 0.2 or later) */
#define VPSCI_NR_FUNCS  12

/* Functions handle PSCI calls from the guests */
bool do_vpsci_0_1_call(struct cpu_user_regs *regs, uint32_t fid);
bool do_vpsci_0_2_call(struct cpu_user_regs *regs, uint32_t fid);

#endif /* __ASM_VPSCI_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
