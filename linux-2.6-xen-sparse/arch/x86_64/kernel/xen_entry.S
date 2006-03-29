/*
 * Copied from arch/xen/i386/kernel/entry.S
 */                        
/* Offsets into shared_info_t. */                
#define evtchn_upcall_pending		/* 0 */
#define evtchn_upcall_mask		1

#define sizeof_vcpu_shift		6

#ifdef CONFIG_SMP
//#define preempt_disable(reg)	incl threadinfo_preempt_count(reg)
//#define preempt_enable(reg)	decl threadinfo_preempt_count(reg)
#define preempt_disable(reg)
#define preempt_enable(reg)
#define XEN_GET_VCPU_INFO(reg)	preempt_disable(%rbp)			; \
				movq %gs:pda_cpunumber,reg		; \
				shl  $32, reg				; \
				shr  $32-sizeof_vcpu_shift,reg		; \
				addq HYPERVISOR_shared_info,reg
#define XEN_PUT_VCPU_INFO(reg)	preempt_enable(%rbp)			; \
#define XEN_PUT_VCPU_INFO_fixup .byte 0xff,0xff,0xff
#else
#define XEN_GET_VCPU_INFO(reg)	movq HYPERVISOR_shared_info,reg
#define XEN_PUT_VCPU_INFO(reg)
#define XEN_PUT_VCPU_INFO_fixup
#endif

#define XEN_LOCKED_BLOCK_EVENTS(reg)	movb $1,evtchn_upcall_mask(reg)
#define XEN_LOCKED_UNBLOCK_EVENTS(reg)	movb $0,evtchn_upcall_mask(reg)
#define XEN_BLOCK_EVENTS(reg)	XEN_GET_VCPU_INFO(reg)			; \
				XEN_LOCKED_BLOCK_EVENTS(reg)		; \
    				XEN_PUT_VCPU_INFO(reg)
#define XEN_UNBLOCK_EVENTS(reg)	XEN_GET_VCPU_INFO(reg)			; \
				XEN_LOCKED_UNBLOCK_EVENTS(reg)		; \
    				XEN_PUT_VCPU_INFO(reg)
#define XEN_TEST_PENDING(reg)	testb $0xFF,evtchn_upcall_pending(reg)

VGCF_IN_SYSCALL = (1<<8)
        
	
