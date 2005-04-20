#ifndef _HYPERVISOR_IFS_H_
#define _HYPERVISOR_IFS_H_

#define s8  int8_t
#define s16 int16_t
#define s32 int32_t
#define s64 int64_t

#define u8  uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

#define CONFIG_XEN_BLKDEV_GRANT
#include <machine/xen-public/xen.h>
#include <machine/xen-public/io/domain_controller.h>
#include <machine/xen-public/io/netif.h>
#include <machine/xen-public/io/blkif.h>
#include <machine/xen-public/dom0_ops.h>
#include <machine/xen-public/event_channel.h>
#include <machine/xen-public/sched_ctl.h>
#include <machine/xen-public/physdev.h>
#include <machine/xen-public/grant_table.h>
#undef  blkif_sector_t			/* XXX pre-processor didn't do the */
#define blkif_sector_t uint64_t		/* right thing */

#undef s8  
#undef s16 
#undef s32 
#undef s64 

#undef u8  
#undef u16 
#undef u32 
#undef u64 


#endif
