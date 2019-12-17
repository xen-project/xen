/* Copyright (c) 2018 Citrix Systems Inc. */

#ifndef X86_HVM_VIRIDIAN_PRIVATE_H
#define X86_HVM_VIRIDIAN_PRIVATE_H

#include <asm/hvm/save.h>

int viridian_synic_wrmsr(struct vcpu *v, uint32_t idx, uint64_t val);
int viridian_synic_rdmsr(const struct vcpu *v, uint32_t idx, uint64_t *val);

bool viridian_synic_deliver_timer_msg(struct vcpu *v, unsigned int sintx,
                                      unsigned int index,
                                      uint64_t expiration,
                                      uint64_t delivery);

int viridian_synic_vcpu_init(const struct vcpu *v);
int viridian_synic_domain_init(const struct domain *d);

void viridian_synic_vcpu_deinit(const struct vcpu *v);
void viridian_synic_domain_deinit(const struct domain *d);

void viridian_synic_save_vcpu_ctxt(const struct vcpu *v,
                                   struct hvm_viridian_vcpu_context *ctxt);
void viridian_synic_load_vcpu_ctxt(
    struct vcpu *v, const struct hvm_viridian_vcpu_context *ctxt);

void viridian_synic_save_domain_ctxt(
    const struct domain *d, struct hvm_viridian_domain_context *ctxt);
void viridian_synic_load_domain_ctxt(
    struct domain *d, const struct hvm_viridian_domain_context *ctxt);

int viridian_time_wrmsr(struct vcpu *v, uint32_t idx, uint64_t val);
int viridian_time_rdmsr(const struct vcpu *v, uint32_t idx, uint64_t *val);

void viridian_time_poll_timers(struct vcpu *v);

int viridian_time_vcpu_init(struct vcpu *v);
int viridian_time_domain_init(const struct domain *d);

void viridian_time_vcpu_deinit(const struct vcpu *v);
void viridian_time_domain_deinit(const struct domain *d);

void viridian_time_save_vcpu_ctxt(
    const struct vcpu *v, struct hvm_viridian_vcpu_context *ctxt);
void viridian_time_load_vcpu_ctxt(
    struct vcpu *v, const struct hvm_viridian_vcpu_context *ctxt);

void viridian_time_save_domain_ctxt(
    const struct domain *d, struct hvm_viridian_domain_context *ctxt);
void viridian_time_load_domain_ctxt(
    struct domain *d, const struct hvm_viridian_domain_context *ctxt);

void viridian_dump_guest_page(const struct vcpu *v, const char *name,
                              const struct viridian_page *vp);
void viridian_map_guest_page(struct domain *d, struct viridian_page *vp);
void viridian_unmap_guest_page(struct viridian_page *vp);

#endif /* X86_HVM_VIRIDIAN_PRIVATE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
