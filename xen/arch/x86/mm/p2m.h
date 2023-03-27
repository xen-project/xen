/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/mm/p2m.h
 */

struct p2m_domain *p2m_init_one(struct domain *d);
void p2m_free_one(struct p2m_domain *p2m);

void p2m_pod_init(struct p2m_domain *p2m);

#ifdef CONFIG_HVM
int p2m_init_logdirty(struct p2m_domain *p2m);
void p2m_free_logdirty(struct p2m_domain *p2m);
#else
static inline int p2m_init_logdirty(struct p2m_domain *p2m) { return 0; }
static inline void p2m_free_logdirty(struct p2m_domain *p2m) {}
#endif

int p2m_init_altp2m(struct domain *d);
void p2m_teardown_altp2m(struct domain *d);

void p2m_nestedp2m_init(struct p2m_domain *p2m);
int p2m_init_nestedp2m(struct domain *d);
void p2m_teardown_nestedp2m(struct domain *d);

int ept_p2m_init(struct p2m_domain *p2m);
void ept_p2m_uninit(struct p2m_domain *p2m);
void p2m_init_altp2m_ept(struct domain *d, unsigned int i);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
