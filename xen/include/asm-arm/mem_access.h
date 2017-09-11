/*
 * mem_access.h: architecture specific mem_access handling routines
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _ASM_ARM_MEM_ACCESS_H
#define _ASM_ARM_MEM_ACCESS_H

static inline
bool p2m_mem_access_emulate_check(struct vcpu *v,
                                  const vm_event_response_t *rsp)
{
    /* Not supported on ARM. */
    return false;
}

/* vm_event and mem_access are supported on any ARM guest */
static inline bool p2m_mem_access_sanity_check(struct domain *d)
{
    return true;
}

/*
 * Send mem event based on the access. Boolean return value indicates if trap
 * needs to be injected into guest.
 */
bool p2m_mem_access_check(paddr_t gpa, vaddr_t gla, const struct npfec npfec);

struct page_info*
p2m_mem_access_check_and_get_page(vaddr_t gva, unsigned long flag,
                                  const struct vcpu *v);

#endif /* _ASM_ARM_MEM_ACCESS_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
