/******************************************************************************
 * hvm/emulate.h
 * 
 * HVM instruction emulation. Used for MMIO and VMX real mode.
 * 
 * Copyright (c) 2008 Citrix Systems, Inc.
 * 
 * Authors:
 *    Keir Fraser <keir@xen.org>
 */

#ifndef __ASM_X86_HVM_EMULATE_H__
#define __ASM_X86_HVM_EMULATE_H__

#include <xen/err.h>
#include <asm/hvm/hvm.h>
#include <asm/x86_emulate.h>

typedef bool hvm_emulate_validate_t(const struct x86_emulate_state *state,
                                    const struct x86_emulate_ctxt *ctxt);

struct hvm_emulate_ctxt {
    struct x86_emulate_ctxt ctxt;

    /*
     * validate: Post-decode, pre-emulate hook to allow caller controlled
     * filtering.
     */
    hvm_emulate_validate_t *validate;

    /* Cache of 16 bytes of instruction. */
    uint8_t insn_buf[16];
    unsigned long insn_buf_eip;
    unsigned int insn_buf_bytes;

    struct segment_register seg_reg[10];
    unsigned long seg_reg_accessed;
    unsigned long seg_reg_dirty;

    /*
     * MFNs behind temporary mappings in the write callback.  The length is
     * arbitrary, and can be increased if writes longer than PAGE_SIZE+1 are
     * needed.
     */
    mfn_t mfn[2];

    uint32_t intr_shadow;

    bool_t set_context;
};

enum emul_kind {
    EMUL_KIND_NORMAL,
    EMUL_KIND_NOWRITE,
    EMUL_KIND_SET_CONTEXT_DATA,
    EMUL_KIND_SET_CONTEXT_INSN
};

bool __nonnull(1, 2) hvm_emulate_one_insn(
    hvm_emulate_validate_t *validate,
    const char *descr);
int hvm_emulate_one(
    struct hvm_emulate_ctxt *hvmemul_ctxt);
void hvm_emulate_one_vm_event(enum emul_kind kind,
    unsigned int trapnr,
    unsigned int errcode);
/* Must be called once to set up hvmemul state. */
void hvm_emulate_init_once(
    struct hvm_emulate_ctxt *hvmemul_ctxt,
    hvm_emulate_validate_t *validate,
    struct cpu_user_regs *regs);
/* Must be called once before each instruction emulated. */
void hvm_emulate_init_per_insn(
    struct hvm_emulate_ctxt *hvmemul_ctxt,
    const unsigned char *insn_buf,
    unsigned int insn_bytes);
void hvm_emulate_writeback(
    struct hvm_emulate_ctxt *hvmemul_ctxt);
int hvmemul_cpuid(uint32_t leaf, uint32_t subleaf,
                  struct cpuid_leaf *res, struct x86_emulate_ctxt *ctxt);
struct segment_register *hvmemul_get_seg_reg(
    enum x86_segment seg,
    struct hvm_emulate_ctxt *hvmemul_ctxt);
int hvm_emulate_one_mmio(unsigned long mfn, unsigned long gla);

static inline bool handle_mmio(void)
{
    return hvm_emulate_one_insn(x86_insn_is_mem_access, "MMIO");
}

int hvmemul_insn_fetch(enum x86_segment seg,
                       unsigned long offset,
                       void *p_data,
                       unsigned int bytes,
                       struct x86_emulate_ctxt *ctxt);
int hvmemul_do_pio_buffer(uint16_t port,
                          unsigned int size,
                          uint8_t dir,
                          void *buffer);

void hvm_dump_emulation_state(const char *loglvl, const char *prefix,
                              struct hvm_emulate_ctxt *hvmemul_ctxt, int rc);

#endif /* __ASM_X86_HVM_EMULATE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
