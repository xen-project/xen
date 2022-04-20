/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __X86_GDBX_H__
#define __X86_GDBX_H__

#ifdef CONFIG_GDBSX

struct domain;
struct xen_domctl_gdbsx_memio;

int gdbsx_guest_mem_io(struct domain *d, struct xen_domctl_gdbsx_memio *iop);

void domain_pause_for_debugger(void);

#else

static inline void domain_pause_for_debugger(void) {}

#endif /* CONFIG_GDBSX */
#endif /* __X86_GDBX_H__ */
