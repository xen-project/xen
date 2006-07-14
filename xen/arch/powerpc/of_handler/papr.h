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
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#ifndef _OFH_PAPR_H
#define _OFH_PAPR_H

#include <asm/papr.h>

#ifndef __ASSEMBLY__

extern long papr_enter(ulong *retvals, ulong flags, ulong idx, ...);
extern long papr_read(ulong *retvals, ulong flags, ulong idx);
extern long papr_remove(ulong *retvals, ulong flags, ulong pte_index,
        ulong avpn);
extern long papr_clear_mod(ulong *retvals, ulong flags, ulong pte_index);
extern long papr_clear_ref(ulong *retvals, ulong flags, ulong pte_index);
extern long papr_protect(ulong *retvals, ulong flags, ulong pte_index,
        ulong avpn);
extern long papr_get_term_char(ulong *retvals, ulong idx);
extern long papr_put_term_char(ulong *retvals, ulong idx, ulong count, ...);
extern long papr_register_vterm(ulong *retvals, ulong ua, ulong plpid, ulong pua);
extern long papr_vterm_partner_info(ulong *retvals, ulong ua, ulong plpid,
        ulong pua, ulong lpage);
extern long papr_free_vterm(ulong *retvals, ulong uaddr);

extern long papr_cede(ulong *retvals);
extern long papr_page_init(ulong *retvals, ulong flags,
        ulong destination, ulong source);
extern long papr_set_asr(ulong *retvals, ulong value); /* ISTAR only. */
extern long papr_asr_on(ulong *retvals); /* ISTAR only. */
extern long papr_asr_off(ulong *retvals); /* ISTAR only. */
extern long papr_eoi(ulong *retvals, ulong xirr);
extern long papr_cppr(ulong *retvals, ulong cppr);
extern long papr_ipi(ulong *retvals, ulong sn, ulong mfrr);
extern long papr_ipoll(ulong *retvals, ulong sn);
extern long papr_xirr(ulong *retvals);
extern long papr_logical_ci_load_64(ulong *retvals, ulong size,
        ulong addrAndVal);
extern long papr_logical_ci_store_64(ulong *retvals, ulong size,
        ulong addr, ulong value);
extern long papr_logical_cache_load_64(ulong *retvals, ulong size,
        ulong addrAndVal);
extern long papr_logical_cache_store_64(ulong *retvals, ulong size,
        ulong addr, ulong value);
extern long papr_logical_icbi(ulong *retvals, ulong addr);
extern long papr_logical_dcbf(ulong *retvals, ulong addr);
extern long papr_set_dabr(ulong *retvals, ulong dabr);
extern long papr_hypervisor_data(ulong *retvals, u64 control);
extern long papr_real_to_logical(ulong *retvals, ulong raddr);

#endif /* ! __ASSEMBLY__ */
#endif /* ! _OFH_PAPR_H */
