#ifndef __ASM_ARM_MULTICALL_H__
#define __ASM_ARM_MULTICALL_H__

extern enum mc_disposition {
    mc_continue,
    mc_exit,
    mc_preempt,
} do_multicall_call(struct multicall_entry *call);

#endif /* __ASM_ARM_MULTICALL_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
