
/*
 * vvmx.h: Support virtual VMX for nested virtualization.
 *
 * Copyright (c) 2010, Intel Corporation.
 * Author: Qing He <qing.he@intel.com>
 *         Eddie Dong <eddie.dong@intel.com>
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
 *
 */
#ifndef __ASM_X86_HVM_VVMX_H__
#define __ASM_X86_HVM_VVMX_H__

struct vvmcs_list {
    unsigned long vvmcs_mfn;
    struct list_head node;
};

struct nestedvmx {
    paddr_t    vmxon_region_pa;
    void       *iobitmap[2];		/* map (va) of L1 guest I/O bitmap */
    void       *msrbitmap;		/* map (va) of L1 guest MSR bitmap */
    /* deferred nested interrupt */
    struct {
        unsigned long intr_info;
        u32           error_code;
        u8            source;
    } intr;
    struct {
        bool_t   enabled;
        uint32_t exit_reason;
        uint32_t exit_qual;
    } ept;
    uint32_t guest_vpid;
    struct list_head launched_list;
};

#define vcpu_2_nvmx(v)	(vcpu_nestedhvm(v).u.nvmx)

/* bit 1, 2, 4 must be 1 */
#define VMX_PINBASED_CTLS_DEFAULT1	0x16
/* bit 1, 4-6,8,13-16,26 must be 1 */
#define VMX_PROCBASED_CTLS_DEFAULT1	0x401e172
/* bit 0-8, 10,11,13,14,16,17 must be 1 */
#define VMX_EXIT_CTLS_DEFAULT1		0x36dff
/* bit 0-8, and 12 must be 1 */
#define VMX_ENTRY_CTLS_DEFAULT1		0x11ff

/*
 * Encode of VMX instructions base on Table 24-11 & 24-12 of SDM 3B
 */

enum vmx_regs_enc {
    VMX_REG_RAX,
    VMX_REG_RCX,
    VMX_REG_RDX,
    VMX_REG_RBX,
    VMX_REG_RSP,
    VMX_REG_RBP,
    VMX_REG_RSI,
    VMX_REG_RDI,
    VMX_REG_R8,
    VMX_REG_R9,
    VMX_REG_R10,
    VMX_REG_R11,
    VMX_REG_R12,
    VMX_REG_R13,
    VMX_REG_R14,
    VMX_REG_R15,
};

enum vmx_sregs_enc {
    VMX_SREG_ES,
    VMX_SREG_CS,
    VMX_SREG_SS,
    VMX_SREG_DS,
    VMX_SREG_FS,
    VMX_SREG_GS,
};

union vmx_inst_info {
    struct {
        unsigned int scaling           :2; /* bit 0-1 */
        unsigned int __rsvd0           :1; /* bit 2 */
        unsigned int reg1              :4; /* bit 3-6 */
        unsigned int addr_size         :3; /* bit 7-9 */
        unsigned int memreg            :1; /* bit 10 */
        unsigned int __rsvd1           :4; /* bit 11-14 */
        unsigned int segment           :3; /* bit 15-17 */
        unsigned int index_reg         :4; /* bit 18-21 */
        unsigned int index_reg_invalid :1; /* bit 22 */
        unsigned int base_reg          :4; /* bit 23-26 */
        unsigned int base_reg_invalid  :1; /* bit 27 */
        unsigned int reg2              :4; /* bit 28-31 */
    } fields;
    u32 word;
};

int nvmx_vcpu_initialise(struct vcpu *v);
void nvmx_vcpu_destroy(struct vcpu *v);
int nvmx_vcpu_reset(struct vcpu *v);
uint64_t nvmx_vcpu_eptp_base(struct vcpu *v);
enum hvm_intblk nvmx_intr_blocked(struct vcpu *v);
bool_t nvmx_intercepts_exception(struct vcpu *v, unsigned int trap,
                                 int error_code);
void nvmx_domain_relinquish_resources(struct domain *d);

bool_t nvmx_ept_enabled(struct vcpu *v);

int nvmx_handle_vmxon(struct cpu_user_regs *regs);
int nvmx_handle_vmxoff(struct cpu_user_regs *regs);

#define EPT_TRANSLATE_SUCCEED       0
#define EPT_TRANSLATE_VIOLATION     1
#define EPT_TRANSLATE_MISCONFIG     2
#define EPT_TRANSLATE_RETRY         3

int
nvmx_hap_walk_L1_p2m(struct vcpu *v, paddr_t L2_gpa, paddr_t *L1_gpa,
                     unsigned int *page_order, uint8_t *p2m_acc,
                     bool_t access_r, bool_t access_w, bool_t access_x);
/*
 * Virtual VMCS layout
 *
 * Since physical VMCS layout is unknown, a custom layout is used
 * for virtual VMCS seen by guest. It occupies a 4k page, and the
 * field is offset by an 9-bit offset into u64[], The offset is as
 * follow, which means every <width, type> pair has a max of 32
 * fields available.
 *
 *             9       7      5               0
 *             --------------------------------
 *     offset: | width | type |     index     |
 *             --------------------------------
 *
 * Also, since the lower range <width=0, type={0,1}> has only one
 * field: VPID, it is moved to a higher offset (63), and leaves the
 * lower range to non-indexed field like VMCS revision.
 *
 */

struct vvmcs_header {
    u32 revision;
    u32 abort;
};

union vmcs_encoding {
    struct {
        u32 access_type : 1;
        u32 index : 9;
        u32 type : 2;
        u32 rsv1 : 1;
        u32 width : 2;
        u32 rsv2 : 17;
    };
    u32 word;
};

enum vvmcs_encoding_width {
    VVMCS_WIDTH_16 = 0,
    VVMCS_WIDTH_64,
    VVMCS_WIDTH_32,
    VVMCS_WIDTH_NATURAL,
};

enum vvmcs_encoding_type {
    VVMCS_TYPE_CONTROL = 0,
    VVMCS_TYPE_RO,
    VVMCS_TYPE_GSTATE,
    VVMCS_TYPE_HSTATE,
};

u64 get_vvmcs_virtual(void *vvmcs, u32 encoding);
u64 get_vvmcs_real(const struct vcpu *, u32 encoding);
void set_vvmcs_virtual(void *vvmcs, u32 encoding, u64 val);
void set_vvmcs_real(const struct vcpu *, u32 encoding, u64 val);

#define get_vvmcs(vcpu, encoding) \
  (cpu_has_vmx_vmcs_shadowing ? \
   get_vvmcs_real(vcpu, encoding) : \
   get_vvmcs_virtual(vcpu_nestedhvm(vcpu).nv_vvmcx, encoding))

#define set_vvmcs(vcpu, encoding, val) \
  (cpu_has_vmx_vmcs_shadowing ? \
   set_vvmcs_real(vcpu, encoding, val) : \
   set_vvmcs_virtual(vcpu_nestedhvm(vcpu).nv_vvmcx, encoding, val))

uint64_t get_shadow_eptp(struct vcpu *v);

void nvmx_destroy_vmcs(struct vcpu *v);
int nvmx_handle_vmptrld(struct cpu_user_regs *regs);
int nvmx_handle_vmptrst(struct cpu_user_regs *regs);
int nvmx_handle_vmclear(struct cpu_user_regs *regs);
int nvmx_handle_vmread(struct cpu_user_regs *regs);
int nvmx_handle_vmwrite(struct cpu_user_regs *regs);
int nvmx_handle_vmresume(struct cpu_user_regs *regs);
int nvmx_handle_vmlaunch(struct cpu_user_regs *regs);
int nvmx_handle_invept(struct cpu_user_regs *regs);
int nvmx_handle_invvpid(struct cpu_user_regs *regs);
int nvmx_msr_read_intercept(unsigned int msr,
                                u64 *msr_content);
int nvmx_msr_write_intercept(unsigned int msr,
                                 u64 msr_content);

void nvmx_update_exec_control(struct vcpu *v, u32 value);
void nvmx_update_secondary_exec_control(struct vcpu *v,
                                        unsigned long value);
void nvmx_update_exception_bitmap(struct vcpu *v, unsigned long value);
void nvmx_switch_guest(void);
void nvmx_idtv_handling(void);
u64 nvmx_get_tsc_offset(struct vcpu *v);
int nvmx_n2_vmexit_handler(struct cpu_user_regs *regs,
                          unsigned int exit_reason);
void nvmx_set_cr_read_shadow(struct vcpu *v, unsigned int cr);

uint64_t nept_get_ept_vpid_cap(void);

int nept_translate_l2ga(struct vcpu *v, paddr_t l2ga,
                        unsigned int *page_order, uint32_t rwx_acc,
                        unsigned long *l1gfn, uint8_t *p2m_acc,
                        uint64_t *exit_qual, uint32_t *exit_reason);
int nvmx_cpu_up_prepare(unsigned int cpu);
void nvmx_cpu_dead(unsigned int cpu);
#endif /* __ASM_X86_HVM_VVMX_H__ */

