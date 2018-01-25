/*
 * include/xen/vpl011.h
 *
 * Virtual PL011 UART
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

#ifndef _VPL011_H_
#define _VPL011_H_

#include <public/domctl.h>
#include <public/io/ring.h>
#include <asm/vreg.h>
#include <xen/mm.h>

/* helper macros */
#define VPL011_LOCK(d,flags) spin_lock_irqsave(&(d)->arch.vpl011.lock, flags)
#define VPL011_UNLOCK(d,flags) spin_unlock_irqrestore(&(d)->arch.vpl011.lock, flags)

#define SBSA_UART_FIFO_SIZE 32

struct vpl011 {
    void *ring_buf;
    struct page_info *ring_page;
    uint32_t    uartfr;         /* Flag register */
    uint32_t    uartcr;         /* Control register */
    uint32_t    uartimsc;       /* Interrupt mask register*/
    uint32_t    uarticr;        /* Interrupt clear register */
    uint32_t    uartris;        /* Raw interrupt status register */
    uint32_t    shadow_uartmis; /* shadow masked interrupt register */
    spinlock_t  lock;
    evtchn_port_t evtchn;
};

struct vpl011_init_info {
    domid_t console_domid;
    gfn_t gfn;
    evtchn_port_t evtchn;
};

#ifdef CONFIG_SBSA_VUART_CONSOLE
int domain_vpl011_init(struct domain *d,
                       struct vpl011_init_info *info);
void domain_vpl011_deinit(struct domain *d);
#else
static inline int domain_vpl011_init(struct domain *d,
                                     struct vpl011_init_info *info)
{
    return -ENOSYS;
}

static inline void domain_vpl011_deinit(struct domain *d) { }
#endif
#endif  /* _VPL011_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
