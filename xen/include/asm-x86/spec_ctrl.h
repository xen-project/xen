/******************************************************************************
 * include/asm-x86/spec_ctrl.h
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
 *
 * Copyright (c) 2017-2018 Citrix Systems Ltd.
 */

#ifndef __X86_SPEC_CTRL_H__
#define __X86_SPEC_CTRL_H__

#include <asm/current.h>

void init_speculation_mitigations(void);

extern bool_t opt_ibpb;
extern uint8_t default_bti_ist_info;

static inline void init_shadow_spec_ctrl_state(void)
{
    struct cpu_info *info = get_cpu_info();

    info->shadow_spec_ctrl = info->use_shadow_spec_ctrl = 0;
    info->bti_ist_info = default_bti_ist_info;
}

#endif /* !__X86_SPEC_CTRL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
