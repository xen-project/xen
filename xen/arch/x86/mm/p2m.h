/******************************************************************************
 * arch/x86/mm/p2m.h
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
