/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_STATIC_EVTCHN_H_
#define __ASM_STATIC_EVTCHN_H_

#ifdef CONFIG_STATIC_EVTCHN

void alloc_static_evtchn(void);

#else /* !CONFIG_STATIC_EVTCHN */

static inline void alloc_static_evtchn(void) {};

#endif /* CONFIG_STATIC_EVTCHN */

#endif /* __ASM_STATIC_EVTCHN_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
