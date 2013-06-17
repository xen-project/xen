#ifndef _ASM_VFP_H
#define _ASM_VFP_H

#include <xen/sched.h>

#if defined(CONFIG_ARM_32)
# include <asm/arm32/vfp.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/vfp.h>
#else
# error "Unknown ARM variant"
#endif

void vfp_save_state(struct vcpu *v);
void vfp_restore_state(struct vcpu *v);

#endif /* _ASM_VFP_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
