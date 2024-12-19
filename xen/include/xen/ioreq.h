/*
 * ioreq.h: Hardware virtual machine assist interface definitions.
 *
 * Copyright (c) 2016 Citrix Systems Inc.
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

#ifndef __XEN_IOREQ_H__
#define __XEN_IOREQ_H__

#include <xen/sched.h>

#include <public/hvm/dm_op.h>

struct ioreq_page {
    gfn_t gfn;
    struct page_info *page;
    void *va;
};

struct ioreq_vcpu {
    struct list_head list_entry;
    struct vcpu      *vcpu;
    evtchn_port_t    ioreq_evtchn;
    bool             pending;
};

#define NR_IO_RANGE_TYPES (XEN_DMOP_IO_RANGE_PCI + 1)
#define MAX_NR_IO_RANGES  256

struct ioreq_server {
    struct domain          *target, *emulator;

    /* Lock to serialize toolstack modifications */
    spinlock_t             lock;

    struct ioreq_page      ioreq;
    struct list_head       ioreq_vcpu_list;
    struct ioreq_page      bufioreq;

    /* Lock to serialize access to buffered ioreq ring */
    spinlock_t             bufioreq_lock;
    evtchn_port_t          bufioreq_evtchn;
    struct rangeset        *range[NR_IO_RANGE_TYPES];
    bool                   enabled;
    uint8_t                bufioreq_handling;
};

static inline paddr_t ioreq_mmio_first_byte(const ioreq_t *p)
{
    return unlikely(p->df) ?
           p->addr - (p->count - 1UL) * p->size :
           p->addr;
}

static inline paddr_t ioreq_mmio_last_byte(const ioreq_t *p)
{
    unsigned long size = p->size;

    return unlikely(p->df) ?
           p->addr + size - 1:
           p->addr + (p->count * size) - 1;
}

static inline bool ioreq_needs_completion(const ioreq_t *ioreq)
{
    return ioreq->state == STATE_IOREQ_READY &&
           !ioreq->data_is_ptr &&
           (ioreq->type != IOREQ_TYPE_PIO || ioreq->dir != IOREQ_WRITE);
}

#define HANDLE_BUFIOREQ(s) \
    ((s)->bufioreq_handling != HVM_IOREQSRV_BUFIOREQ_OFF)

bool domain_has_ioreq_server(const struct domain *d);

bool vcpu_ioreq_pending(struct vcpu *v);
bool vcpu_ioreq_handle_completion(struct vcpu *v);
bool is_ioreq_server_page(struct domain *d, const struct page_info *page);

int ioreq_server_get_frame(struct domain *d, ioservid_t id,
                           unsigned int idx, mfn_t *mfn);
int ioreq_server_map_mem_type(struct domain *d, ioservid_t id,
                              uint32_t type, uint32_t flags);

int ioreq_server_add_vcpu_all(struct domain *d, struct vcpu *v);
void ioreq_server_remove_vcpu_all(struct domain *d, struct vcpu *v);
void ioreq_server_destroy_all(struct domain *d);

struct ioreq_server *ioreq_server_select(struct domain *d,
                                         ioreq_t *p);
int ioreq_send(struct ioreq_server *s, ioreq_t *proto_p,
               bool buffered);
unsigned int ioreq_broadcast(ioreq_t *p, bool buffered);
void ioreq_request_mapcache_invalidate(const struct domain *d);
void ioreq_signal_mapcache_invalidate(void);

void ioreq_domain_init(struct domain *d);

int ioreq_server_dm_op(struct xen_dm_op *op, struct domain *d, bool *const_op);

bool arch_ioreq_complete_mmio(void);

#ifdef CONFIG_ARCH_VCPU_IOREQ_COMPLETION
bool arch_vcpu_ioreq_completion(enum vio_completion completion);
#else
static inline bool arch_vcpu_ioreq_completion(enum vio_completion completion)
{
    ASSERT_UNREACHABLE();
    return true;
}
#endif

int arch_ioreq_server_map_pages(struct ioreq_server *s);
void arch_ioreq_server_unmap_pages(struct ioreq_server *s);
void arch_ioreq_server_enable(struct ioreq_server *s);
void arch_ioreq_server_disable(struct ioreq_server *s);
void arch_ioreq_server_destroy(struct ioreq_server *s);
int arch_ioreq_server_map_mem_type(struct domain *d,
                                   struct ioreq_server *s,
                                   uint32_t flags);
void arch_ioreq_server_map_mem_type_completed(struct domain *d,
                                              struct ioreq_server *s,
                                              uint32_t flags);
bool arch_ioreq_server_destroy_all(struct domain *d);
bool arch_ioreq_server_get_type_addr(const struct domain *d, const ioreq_t *p,
                                     uint8_t *type, uint64_t *addr);
void arch_ioreq_domain_init(struct domain *d);

#endif /* __XEN_IOREQ_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
