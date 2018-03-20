/*
 * hvm.h: Hardware virtual machine assist interface definitions.
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

#ifndef __ASM_X86_HVM_IOREQ_H__
#define __ASM_X86_HVM_IOREQ_H__

bool hvm_io_pending(struct vcpu *v);
bool handle_hvm_io_completion(struct vcpu *v);
bool is_ioreq_server_page(struct domain *d, const struct page_info *page);

int hvm_create_ioreq_server(struct domain *d, bool is_default,
                            int bufioreq_handling, ioservid_t *id);
int hvm_destroy_ioreq_server(struct domain *d, ioservid_t id);
int hvm_get_ioreq_server_info(struct domain *d, ioservid_t id,
                              unsigned long *ioreq_gfn,
                              unsigned long *bufioreq_gfn,
                              evtchn_port_t *bufioreq_port);
int hvm_map_io_range_to_ioreq_server(struct domain *d, ioservid_t id,
                                     uint32_t type, uint64_t start,
                                     uint64_t end);
int hvm_unmap_io_range_from_ioreq_server(struct domain *d, ioservid_t id,
                                         uint32_t type, uint64_t start,
                                         uint64_t end);
int hvm_map_mem_type_to_ioreq_server(struct domain *d, ioservid_t id,
                                     uint32_t type, uint32_t flags);
int hvm_set_ioreq_server_state(struct domain *d, ioservid_t id,
                               bool enabled);

int hvm_all_ioreq_servers_add_vcpu(struct domain *d, struct vcpu *v);
void hvm_all_ioreq_servers_remove_vcpu(struct domain *d, struct vcpu *v);
void hvm_destroy_all_ioreq_servers(struct domain *d);

struct hvm_ioreq_server *hvm_select_ioreq_server(struct domain *d,
                                                 ioreq_t *p);
int hvm_send_ioreq(struct hvm_ioreq_server *s, ioreq_t *proto_p,
                   bool buffered);
unsigned int hvm_broadcast_ioreq(ioreq_t *p, bool buffered);

void hvm_ioreq_init(struct domain *d);

#endif /* __ASM_X86_HVM_IOREQ_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
