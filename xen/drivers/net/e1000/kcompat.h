/*******************************************************************************

  
  Copyright(c) 1999 - 2003 Intel Corporation. All rights reserved.
  
  This program is free software; you can redistribute it and/or modify it 
  under the terms of the GNU General Public License as published by the Free 
  Software Foundation; either version 2 of the License, or (at your option) 
  any later version.
  
  This program is distributed in the hope that it will be useful, but WITHOUT 
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
  more details.
  
  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc., 59 
  Temple Place - Suite 330, Boston, MA  02111-1307, USA.
  
  The full GNU General Public License is included in this distribution in the
  file called LICENSE.
  
  Contact Information:
  Linux NICS <linux.nics@intel.com>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#include <xen/version.h>
#include <xen/types.h>
#include <xen/errno.h>
#include <xen/module.h>
#include <xen/pci.h>
#include <xen/netdevice.h>
#include <xen/ioport.h>
#include <xen/slab.h>
//#include <xen/pagemap.h>
#include <xen/list.h>
#include <xen/sched.h>
#include <asm/io.h>

#ifndef IRQ_HANDLED
#define irqreturn_t void
#define IRQ_HANDLED
#define IRQ_NONE
#endif

#ifndef SET_NETDEV_DEV
#define SET_NETDEV_DEV(net, pdev)
#endif

/*****************************************************************************/
#ifndef unlikely
#define unlikely(_x) _x
#define likely(_x) _x
#endif
/*****************************************************************************/

/*****************************************************************************/
/* Installations with ethtool version without eeprom, adapter id, or statistics
 * support */
#ifndef ETHTOOL_GSTATS
#define ETHTOOL_GSTATS 0x1d
#undef ethtool_drvinfo
#define ethtool_drvinfo k_ethtool_drvinfo
struct k_ethtool_drvinfo {
	uint32_t cmd;
	char	 driver[32];
	char	 version[32];
	char	 fw_version[32];
	char	 bus_info[32];
	char	 reserved1[32];
	char	 reserved2[16];
	uint32_t n_stats;
	uint32_t testinfo_len;
	uint32_t eedump_len;
	uint32_t regdump_len;
};

struct ethtool_stats {
	uint32_t cmd;
	uint32_t n_stats;
	uint64_t data[0];
};

#ifndef ETHTOOL_PHYS_ID
#define ETHTOOL_PHYS_ID 0x1c
#ifndef ETHTOOL_GSTRINGS
#define ETHTOOL_GSTRINGS 0x1b
enum ethtool_stringset {
	ETH_SS_TEST             = 0,
	ETH_SS_STATS,
};
struct ethtool_gstrings {
	u32     cmd;            /* ETHTOOL_GSTRINGS */
	u32     string_set;     /* string set id e.c. ETH_SS_TEST, etc*/
	u32     len;            /* number of strings in the string set */
	u8      data[0];
};
#ifndef ETHTOOL_TEST
#define ETHTOOL_TEST 0x1a
enum ethtool_test_flags {
	ETH_TEST_FL_OFFLINE	= (1 << 0),
	ETH_TEST_FL_FAILED	= (1 << 1),
};
struct ethtool_test {
	uint32_t cmd;
	uint32_t flags;
	uint32_t reserved;
	uint32_t len;
	uint64_t data[0];
};
#ifndef ETHTOOL_GEEPROM
#define ETHTOOL_GEEPROM 0xb
#undef ETHTOOL_GREGS
struct ethtool_eeprom {
	uint32_t cmd;
	uint32_t magic;
	uint32_t offset;
	uint32_t len;
	uint8_t	 data[0];
};

struct ethtool_value {
	uint32_t cmd;
	uint32_t data;
};

#ifndef ETHTOOL_GLINK
#define ETHTOOL_GLINK 0xa
#endif /* Ethtool version without link support */
#endif /* Ethtool version without eeprom support */
#endif /* Ethtool version without test support */
#endif /* Ethtool version without strings support */
#endif /* Ethtool version wihtout adapter id support */
#endif /* Ethtool version without statistics support */

/*****************************************************************************/
/* 2.4.3 => 2.4.0 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,3) )

/**************************************/
/* PCI DRIVER API */

#ifndef pci_set_dma_mask
#define pci_set_dma_mask _kc_pci_set_dma_mask
extern int _kc_pci_set_dma_mask(struct pci_dev *dev, dma_addr_t mask);
#endif

#ifndef pci_request_regions
#define pci_request_regions _kc_pci_request_regions
extern int _kc_pci_request_regions(struct pci_dev *pdev, char *res_name);
#endif

#ifndef pci_release_regions
#define pci_release_regions _kc_pci_release_regions
extern void _kc_pci_release_regions(struct pci_dev *pdev);
#endif

/**************************************/
/* NETWORK DRIVER API */

#ifndef alloc_etherdev
#define alloc_etherdev _kc_alloc_etherdev
extern struct net_device * _kc_alloc_etherdev(int sizeof_priv);
#endif

#ifndef is_valid_ether_addr
#define is_valid_ether_addr _kc_is_valid_ether_addr
extern int _kc_is_valid_ether_addr(u8 *addr);
#endif

/**************************************/
/* MISCELLANEOUS */

#ifndef INIT_TQUEUE
#define INIT_TQUEUE(_tq, _routine, _data)		\
	do {						\
		INIT_LIST_HEAD(&(_tq)->list);		\
		(_tq)->sync = 0;			\
		(_tq)->routine = _routine;		\
		(_tq)->data = _data;			\
	} while(0)
#endif

#endif /* 2.4.3 => 2.4.0 */

/*****************************************************************************/
/* 2.4.6 => 2.4.3 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,6) )

#ifndef pci_set_power_state
#define pci_set_power_state _kc_pci_set_power_state
extern int _kc_pci_set_power_state(struct pci_dev *dev, int state);
#endif

#ifndef pci_save_state
#define pci_save_state _kc_pci_save_state
extern int _kc_pci_save_state(struct pci_dev *dev, u32 *buffer);
#endif

#ifndef pci_restore_state
#define pci_restore_state _kc_pci_restore_state
extern int _kc_pci_restore_state(struct pci_dev *pdev, u32 *buffer);
#endif

#ifndef pci_enable_wake
#define pci_enable_wake _kc_pci_enable_wake
extern int _kc_pci_enable_wake(struct pci_dev *pdev, u32 state, int enable);
#endif

/* PCI PM entry point syntax changed, so don't support suspend/resume */
#undef CONFIG_PM

#endif /* 2.4.6 => 2.4.3 */

/*****************************************************************************/
/* 2.4.10 => 2.4.6 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,10) )

/**************************************/
/* MODULE API */

#ifndef MODULE_LICENSE
	#define MODULE_LICENSE(X)
#endif

/**************************************/
/* OTHER */

#undef min
#define min(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })

#undef max
#define max(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })

#endif /* 2.4.10 -> 2.4.6 */


/*****************************************************************************/
/* 2.4.13 => 2.4.10 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,13) )

/**************************************/
/* PCI DMA MAPPING */

#ifndef virt_to_page
	#define virt_to_page(v) (mem_map + (virt_to_phys(v) >> PAGE_SHIFT))
#endif

#ifndef pci_map_page
#define pci_map_page _kc_pci_map_page
extern u64 _kc_pci_map_page(struct pci_dev *dev, struct page *page, unsigned long offset, size_t size, int direction);
#endif

#ifndef pci_unmap_page
#define pci_unmap_page _kc_pci_unmap_page
extern void _kc_pci_unmap_page(struct pci_dev *dev, u64 dma_addr, size_t size, int direction);
#endif

/* pci_set_dma_mask takes dma_addr_t, which is only 32-bits prior to 2.4.13 */

#undef PCI_DMA_32BIT
#define PCI_DMA_32BIT	0xffffffff
#undef PCI_DMA_64BIT
#define PCI_DMA_64BIT	0xffffffff

#endif /* 2.4.13 => 2.4.10 */

/*****************************************************************************/
/* 2.4.17 => 2.4.12 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,17) )

#ifndef __devexit_p
	#define __devexit_p(x) &(x)
#endif

#endif /* 2.4.17 => 2.4.13 */

/*****************************************************************************/
/* 2.5.28 => 2.4.17 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,5,28) )

static inline void _kc_synchronize_irq() { synchronize_irq(); }
#undef synchronize_irq
#define synchronize_irq(X) _kc_synchronize_irq()

#include <xen/tqueue.h>
#define work_struct tq_struct
#define INIT_WORK INIT_TQUEUE
#define schedule_work schedule_task

#endif /* 2.5.28 => 2.4.17 */

#endif /* _KCOMPAT_H_ */

