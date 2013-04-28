#ifndef __ASM_ARM_PLATFORMS_VEXPRESS_H
#define __ASM_ARM_PLATFORMS_VEXPRESS_H

/* V2M */
#define V2M_SYS_MMIO_BASE     (0x1c010000)
#define V2M_SYS_FLAGSSET      (0x30)
#define V2M_SYS_FLAGSCLR      (0x34)

#define V2M_SYS_CFGDATA       (0x00A0)
#define V2M_SYS_CFGCTRL       (0x00A4)
#define V2M_SYS_CFGSTAT       (0x00A8)

#define V2M_SYS_CFG_START     (1<<31)
#define V2M_SYS_CFG_WRITE     (1<<30)
#define V2M_SYS_CFG_ERROR     (1<<1)
#define V2M_SYS_CFG_COMPLETE  (1<<0)

#define V2M_SYS_CFG_OSC_FUNC  1
#define V2M_SYS_CFG_OSC0      0
#define V2M_SYS_CFG_OSC1      1
#define V2M_SYS_CFG_OSC2      2
#define V2M_SYS_CFG_OSC3      3
#define V2M_SYS_CFG_OSC4      4
#define V2M_SYS_CFG_OSC5      5

/* Board-specific: base address of system controller */
#define SP810_ADDRESS 0x1C020000

#ifndef __ASSEMBLY__
#include <xen/inttypes.h>

int vexpress_syscfg(int write, int function, int device, uint32_t *data);
#endif

#endif /* __ASM_ARM_PLATFORMS_VEXPRESS_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
