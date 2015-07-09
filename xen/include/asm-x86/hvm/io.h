/*
 * io.h: HVM IO support
 *
 * Copyright (c) 2004, Intel Corporation.
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#ifndef __ASM_X86_HVM_IO_H__
#define __ASM_X86_HVM_IO_H__

#include <asm/hvm/vpic.h>
#include <asm/hvm/vioapic.h>
#include <public/hvm/ioreq.h>
#include <public/event_channel.h>

#define NR_IO_HANDLERS 32

typedef int (*hvm_mmio_read_t)(struct vcpu *v,
                               unsigned long addr,
                               unsigned int length,
                               unsigned long *val);
typedef int (*hvm_mmio_write_t)(struct vcpu *v,
                                unsigned long addr,
                                unsigned int length,
                                unsigned long val);
typedef int (*hvm_mmio_check_t)(struct vcpu *v, unsigned long addr);

struct hvm_mmio_ops {
    hvm_mmio_check_t check;
    hvm_mmio_read_t  read;
    hvm_mmio_write_t write;
};

typedef int (*portio_action_t)(
    int dir, unsigned int port, unsigned int bytes, uint32_t *val);

struct hvm_io_handler {
    union {
        struct {
            const struct hvm_mmio_ops *ops;
        } mmio;
        struct {
            unsigned int port, size;
            portio_action_t action;
        } portio;
    };
    uint8_t type;
};

typedef int (*hvm_io_read_t)(const struct hvm_io_handler *,
                             uint64_t addr,
                             uint32_t size,
                             uint64_t *data);
typedef int (*hvm_io_write_t)(const struct hvm_io_handler *,
                              uint64_t addr,
                              uint32_t size,
                              uint64_t data);
typedef bool_t (*hvm_io_accept_t)(const struct hvm_io_handler *,
                                  const ioreq_t *p);
struct hvm_io_ops {
    hvm_io_accept_t accept;
    hvm_io_read_t   read;
    hvm_io_write_t  write;
};

int hvm_process_io_intercept(const struct hvm_io_handler *handler,
                             ioreq_t *p);

const struct hvm_io_handler *hvm_find_io_handler(ioreq_t *p);

int hvm_io_intercept(ioreq_t *p);

struct hvm_io_handler *hvm_next_io_handler(struct domain *d);

bool_t hvm_mmio_internal(paddr_t gpa);

void register_mmio_handler(struct domain *d,
                           const struct hvm_mmio_ops *ops);

void register_portio_handler(
    struct domain *d, unsigned int port, unsigned int size,
    portio_action_t action);

void relocate_portio_handler(
    struct domain *d, unsigned int old_port, unsigned int new_port,
    unsigned int size);

int hvm_buffered_io_send(ioreq_t *p);
void send_timeoffset_req(unsigned long timeoff);
void send_invalidate_req(void);
int handle_mmio(void);
int handle_mmio_with_translation(unsigned long gva, unsigned long gpfn,
                                 struct npfec);
int handle_pio(uint16_t port, unsigned int size, int dir);
void hvm_interrupt_post(struct vcpu *v, int vector, int type);
void hvm_io_assist(ioreq_t *p);
void hvm_dpci_eoi(struct domain *d, unsigned int guest_irq,
                  const union vioapic_redir_entry *ent);
void msix_write_completion(struct vcpu *);
void msixtbl_init(struct domain *d);

struct hvm_hw_stdvga {
    uint8_t sr_index;
    uint8_t sr[8];
    uint8_t gr_index;
    uint8_t gr[9];
    bool_t stdvga;
    bool_t cache;
    uint32_t latch;
    struct page_info *vram_page[64];  /* shadow of 0xa0000-0xaffff */
    spinlock_t lock;
};

void stdvga_init(struct domain *d);
int stdvga_intercept_mmio(ioreq_t *p);
void stdvga_deinit(struct domain *d);

extern void hvm_dpci_msi_eoi(struct domain *d, int vector);
#endif /* __ASM_X86_HVM_IO_H__ */


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
