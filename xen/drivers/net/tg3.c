/*
 * tg3.c: Broadcom Tigon3 ethernet driver.
 *
 * Copyright (C) 2001, 2002 David S. Miller (davem@redhat.com)
 * Copyright (C) 2001, 2002 Jeff Garzik (jgarzik@pobox.com)
 */

#include <linux/config.h>

#include <linux/module.h>

#include <linux/lib.h>
#include <linux/types.h>
#include <linux/tqueue.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/if_vlan.h>

#include <asm/system.h>
#include <asm/io.h>
#include <asm/byteorder.h>
#include <asm/uaccess.h>

#ifndef PCI_DMA_BUS_IS_PHYS
#define PCI_DMA_BUS_IS_PHYS 1
#endif

#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
#define TG3_VLAN_TAG_USED 1
#else
#define TG3_VLAN_TAG_USED 0
#endif

#ifdef NETIF_F_TSO
/* XXX some bug in tso firmware hangs tx cpu, disabled until fixed */
#define TG3_DO_TSO	0
#else
#define TG3_DO_TSO	0
#endif

#include "tg3.h"

#define DRV_MODULE_NAME		"tg3"
#define PFX DRV_MODULE_NAME	": "
#define DRV_MODULE_VERSION	"1.4c"
#define DRV_MODULE_RELDATE	"Feb 18, 2003"

#define TG3_DEF_MAC_MODE	0
#define TG3_DEF_RX_MODE		0
#define TG3_DEF_TX_MODE		0
#define TG3_DEF_MSG_ENABLE	  \
	(NETIF_MSG_DRV		| \
	 NETIF_MSG_PROBE	| \
	 NETIF_MSG_LINK		| \
	 NETIF_MSG_TIMER	| \
	 NETIF_MSG_IFDOWN	| \
	 NETIF_MSG_IFUP		| \
	 NETIF_MSG_RX_ERR	| \
	 NETIF_MSG_TX_ERR)

/* length of time before we decide the hardware is borked,
 * and dev->tx_timeout() should be called to fix the problem
 */
#define TG3_TX_TIMEOUT			(5 * HZ)

/* hardware minimum and maximum for a single frame's data payload */
#define TG3_MIN_MTU			60
#define TG3_MAX_MTU			9000

/* These numbers seem to be hard coded in the NIC firmware somehow.
 * You can't change the ring sizes, but you can change where you place
 * them in the NIC onboard memory.
 */
#define TG3_RX_RING_SIZE		512
#define TG3_DEF_RX_RING_PENDING		200
#define TG3_RX_JUMBO_RING_SIZE		256
#define TG3_DEF_RX_JUMBO_RING_PENDING	100
#define TG3_RX_RCB_RING_SIZE		1024
#define TG3_TX_RING_SIZE		512
#define TG3_DEF_TX_RING_PENDING		(TG3_TX_RING_SIZE - 1)

#define TG3_RX_RING_BYTES	(sizeof(struct tg3_rx_buffer_desc) * \
				 TG3_RX_RING_SIZE)
#define TG3_RX_JUMBO_RING_BYTES	(sizeof(struct tg3_rx_buffer_desc) * \
			         TG3_RX_JUMBO_RING_SIZE)
#define TG3_RX_RCB_RING_BYTES	(sizeof(struct tg3_rx_buffer_desc) * \
			         TG3_RX_RCB_RING_SIZE)
#define TG3_TX_RING_BYTES	(sizeof(struct tg3_tx_buffer_desc) * \
				 TG3_TX_RING_SIZE)
#define TX_RING_GAP(TP)	\
	(TG3_TX_RING_SIZE - (TP)->tx_pending)
#define TX_BUFFS_AVAIL(TP)						\
	(((TP)->tx_cons <= (TP)->tx_prod) ?				\
	  (TP)->tx_cons + (TP)->tx_pending - (TP)->tx_prod :		\
	  (TP)->tx_cons - (TP)->tx_prod - TX_RING_GAP(TP))
#define NEXT_TX(N)		(((N) + 1) & (TG3_TX_RING_SIZE - 1))

#define RX_PKT_BUF_SZ		(1536 + tp->rx_offset + 64)
#define RX_JUMBO_PKT_BUF_SZ	(9046 + tp->rx_offset + 64)

/* minimum number of free TX descriptors required to wake up TX process */
#define TG3_TX_WAKEUP_THRESH		(TG3_TX_RING_SIZE / 4)

static char version[] __devinitdata =
	DRV_MODULE_NAME ".c:v" DRV_MODULE_VERSION " (" DRV_MODULE_RELDATE ")\n";

MODULE_AUTHOR("David S. Miller (davem@redhat.com) and Jeff Garzik (jgarzik@pobox.com)");
MODULE_DESCRIPTION("Broadcom Tigon3 ethernet driver");
MODULE_LICENSE("GPL");
MODULE_PARM(tg3_debug, "i");
MODULE_PARM_DESC(tg3_debug, "Tigon3 bitmapped debugging message enable value");

static int tg3_debug = -1;	/* -1 == use TG3_DEF_MSG_ENABLE as value */

static struct pci_device_id tg3_pci_tbl[] __devinitdata = {
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5700,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0UL },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5701,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0UL },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5702,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0UL },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5703,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0UL },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5704,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0UL },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5702FE,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0UL },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5702X,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0UL },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5703X,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0UL },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5704S,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0UL },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5702A3,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0UL },
	{ PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5703A3,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0UL },
	{ PCI_VENDOR_ID_SYSKONNECT, 0x4400,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0UL },
	{ PCI_VENDOR_ID_ALTIMA, PCI_DEVICE_ID_ALTIMA_AC1000,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0UL },
	{ PCI_VENDOR_ID_ALTIMA, PCI_DEVICE_ID_ALTIMA_AC9100,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0UL },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, tg3_pci_tbl);

static void tg3_write_indirect_reg32(struct tg3 *tp, u32 off, u32 val)
{
	if ((tp->tg3_flags & TG3_FLAG_PCIX_TARGET_HWBUG) != 0) {
		unsigned long flags;

		spin_lock_irqsave(&tp->indirect_lock, flags);
		pci_write_config_dword(tp->pdev, TG3PCI_REG_BASE_ADDR, off);
		pci_write_config_dword(tp->pdev, TG3PCI_REG_DATA, val);
		spin_unlock_irqrestore(&tp->indirect_lock, flags);
	} else {
		writel(val, tp->regs + off);
		if ((tp->tg3_flags & TG3_FLAG_5701_REG_WRITE_BUG) != 0)
			readl(tp->regs + off);
	}
}

#define tw32(reg,val)		tg3_write_indirect_reg32(tp,(reg),(val))
#define tw32_mailbox(reg, val)	writel(((val) & 0xffffffff), tp->regs + (reg))
#define tw16(reg,val)		writew(((val) & 0xffff), tp->regs + (reg))
#define tw8(reg,val)		writeb(((val) & 0xff), tp->regs + (reg))
#define tr32(reg)		readl(tp->regs + (reg))
#define tr16(reg)		readw(tp->regs + (reg))
#define tr8(reg)		readb(tp->regs + (reg))

static void tg3_write_mem(struct tg3 *tp, u32 off, u32 val)
{
	unsigned long flags;

	spin_lock_irqsave(&tp->indirect_lock, flags);
	pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR, off);
	pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_DATA, val);

	/* Always leave this as zero. */
	pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR, 0);
	spin_unlock_irqrestore(&tp->indirect_lock, flags);
}

static void tg3_read_mem(struct tg3 *tp, u32 off, u32 *val)
{
	unsigned long flags;

	spin_lock_irqsave(&tp->indirect_lock, flags);
	pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR, off);
	pci_read_config_dword(tp->pdev, TG3PCI_MEM_WIN_DATA, val);

	/* Always leave this as zero. */
	pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR, 0);
	spin_unlock_irqrestore(&tp->indirect_lock, flags);
}

static void tg3_disable_ints(struct tg3 *tp)
{
	tw32(TG3PCI_MISC_HOST_CTRL,
	     (tp->misc_host_ctrl | MISC_HOST_CTRL_MASK_PCI_INT));
	tw32_mailbox(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW, 0x00000001);
	tr32(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW);
}

static inline void tg3_cond_int(struct tg3 *tp)
{
	if (tp->hw_status->status & SD_STATUS_UPDATED)
		tw32(GRC_LOCAL_CTRL, tp->grc_local_ctrl | GRC_LCLCTRL_SETINT);
}

static void tg3_enable_ints(struct tg3 *tp)
{
	tw32(TG3PCI_MISC_HOST_CTRL,
	     (tp->misc_host_ctrl & ~MISC_HOST_CTRL_MASK_PCI_INT));
	tw32_mailbox(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW, 0x00000000);
	tr32(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW);

	tg3_cond_int(tp);
}

#ifdef NAPI
/* these netif_xxx funcs should be moved into generic net layer */
static void netif_poll_disable(struct net_device *dev)
{
	while (test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state)) {
		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(1);
	}
}

static inline void netif_poll_enable(struct net_device *dev)
{
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

/* same as netif_rx_complete, except that local_irq_save(flags)
 * has already been issued
 */
static inline void __netif_rx_complete(struct net_device *dev)
{
	if (!test_bit(__LINK_STATE_RX_SCHED, &dev->state)) BUG();
	list_del(&dev->poll_list);
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
}
#endif

static inline void netif_tx_disable(struct net_device *dev)
{
	spin_lock_bh(&dev->xmit_lock);
	netif_stop_queue(dev);
	spin_unlock_bh(&dev->xmit_lock);
}

static inline void tg3_netif_stop(struct tg3 *tp)
{
#ifdef NAPI
	netif_poll_disable(tp->dev);
#endif
	netif_tx_disable(tp->dev);
}

static inline void tg3_netif_start(struct tg3 *tp)
{
	netif_wake_queue(tp->dev);
	/* NOTE: unconditional netif_wake_queue is only appropriate
	 * so long as all callers are assured to have free tx slots
	 * (such as after tg3_init_hw)
	 */
#ifdef NAPI
	netif_poll_enable(tp->dev);
#endif
	tg3_cond_int(tp);
}

static void tg3_switch_clocks(struct tg3 *tp)
{
	if (tr32(TG3PCI_CLOCK_CTRL) & CLOCK_CTRL_44MHZ_CORE) {
		tw32(TG3PCI_CLOCK_CTRL,
		     (CLOCK_CTRL_44MHZ_CORE | CLOCK_CTRL_ALTCLK));
		tr32(TG3PCI_CLOCK_CTRL);
		udelay(40);
		tw32(TG3PCI_CLOCK_CTRL,
		     (CLOCK_CTRL_ALTCLK));
		tr32(TG3PCI_CLOCK_CTRL);
		udelay(40);
	}
	tw32(TG3PCI_CLOCK_CTRL, 0);
	tr32(TG3PCI_CLOCK_CTRL);
	udelay(40);
}

#define PHY_BUSY_LOOPS	5000

static int tg3_readphy(struct tg3 *tp, int reg, u32 *val)
{
	u32 frame_val;
	int loops, ret;

	if ((tp->mi_mode & MAC_MI_MODE_AUTO_POLL) != 0) {
		tw32(MAC_MI_MODE,
		     (tp->mi_mode & ~MAC_MI_MODE_AUTO_POLL));
		tr32(MAC_MI_MODE);
		udelay(40);
	}

	*val = 0xffffffff;

	frame_val  = ((PHY_ADDR << MI_COM_PHY_ADDR_SHIFT) &
		      MI_COM_PHY_ADDR_MASK);
	frame_val |= ((reg << MI_COM_REG_ADDR_SHIFT) &
		      MI_COM_REG_ADDR_MASK);
	frame_val |= (MI_COM_CMD_READ | MI_COM_START);
	
	tw32(MAC_MI_COM, frame_val);
	tr32(MAC_MI_COM);

	loops = PHY_BUSY_LOOPS;
	while (loops-- > 0) {
		udelay(10);
		frame_val = tr32(MAC_MI_COM);

		if ((frame_val & MI_COM_BUSY) == 0) {
			udelay(5);
			frame_val = tr32(MAC_MI_COM);
			break;
		}
	}

	ret = -EBUSY;
	if (loops > 0) {
		*val = frame_val & MI_COM_DATA_MASK;
		ret = 0;
	}

	if ((tp->mi_mode & MAC_MI_MODE_AUTO_POLL) != 0) {
		tw32(MAC_MI_MODE, tp->mi_mode);
		tr32(MAC_MI_MODE);
		udelay(40);
	}

	return ret;
}

static int tg3_writephy(struct tg3 *tp, int reg, u32 val)
{
	u32 frame_val;
	int loops, ret;

	if ((tp->mi_mode & MAC_MI_MODE_AUTO_POLL) != 0) {
		tw32(MAC_MI_MODE,
		     (tp->mi_mode & ~MAC_MI_MODE_AUTO_POLL));
		tr32(MAC_MI_MODE);
		udelay(40);
	}

	frame_val  = ((PHY_ADDR << MI_COM_PHY_ADDR_SHIFT) &
		      MI_COM_PHY_ADDR_MASK);
	frame_val |= ((reg << MI_COM_REG_ADDR_SHIFT) &
		      MI_COM_REG_ADDR_MASK);
	frame_val |= (val & MI_COM_DATA_MASK);
	frame_val |= (MI_COM_CMD_WRITE | MI_COM_START);
	
	tw32(MAC_MI_COM, frame_val);
	tr32(MAC_MI_COM);

	loops = PHY_BUSY_LOOPS;
	while (loops-- > 0) {
		udelay(10);
		frame_val = tr32(MAC_MI_COM);
		if ((frame_val & MI_COM_BUSY) == 0) {
			udelay(5);
			frame_val = tr32(MAC_MI_COM);
			break;
		}
	}

	ret = -EBUSY;
	if (loops > 0)
		ret = 0;

	if ((tp->mi_mode & MAC_MI_MODE_AUTO_POLL) != 0) {
		tw32(MAC_MI_MODE, tp->mi_mode);
		tr32(MAC_MI_MODE);
		udelay(40);
	}

	return ret;
}

/* This will reset the tigon3 PHY if there is no valid
 * link unless the FORCE argument is non-zero.
 */
static int tg3_phy_reset(struct tg3 *tp, int force)
{
	u32 phy_status, phy_control;
	int err, limit;

	err  = tg3_readphy(tp, MII_BMSR, &phy_status);
	err |= tg3_readphy(tp, MII_BMSR, &phy_status);
	if (err != 0)
		return -EBUSY;

	/* If we have link, and not forcing a reset, then nothing
	 * to do.
	 */
	if ((phy_status & BMSR_LSTATUS) != 0 && (force == 0))
		return 0;

	/* OK, reset it, and poll the BMCR_RESET bit until it
	 * clears or we time out.
	 */
	phy_control = BMCR_RESET;
	err = tg3_writephy(tp, MII_BMCR, phy_control);
	if (err != 0)
		return -EBUSY;

	limit = 5000;
	while (limit--) {
		err = tg3_readphy(tp, MII_BMCR, &phy_control);
		if (err != 0)
			return -EBUSY;

		if ((phy_control & BMCR_RESET) == 0) {
			udelay(40);
			return 0;
		}
		udelay(10);
	}

	return -EBUSY;
}

static int tg3_setup_phy(struct tg3 *);

static int tg3_set_power_state(struct tg3 *tp, int state)
{
	u32 misc_host_ctrl;
	u16 power_control, power_caps;
	int pm = tp->pm_cap;

	/* Make sure register accesses (indirect or otherwise)
	 * will function correctly.
	 */
	pci_write_config_dword(tp->pdev,
			       TG3PCI_MISC_HOST_CTRL,
			       tp->misc_host_ctrl);

	pci_read_config_word(tp->pdev,
			     pm + PCI_PM_CTRL,
			     &power_control);
	power_control |= PCI_PM_CTRL_PME_STATUS;
	power_control &= ~(PCI_PM_CTRL_STATE_MASK);
	switch (state) {
	case 0:
		power_control |= 0;
		pci_write_config_word(tp->pdev,
				      pm + PCI_PM_CTRL,
				      power_control);
		tw32(GRC_LOCAL_CTRL, tp->grc_local_ctrl);
		tr32(GRC_LOCAL_CTRL);
		udelay(100);

		return 0;

	case 1:
		power_control |= 1;
		break;

	case 2:
		power_control |= 2;
		break;

	case 3:
		power_control |= 3;
		break;

	default:
		printk(KERN_WARNING PFX "%s: Invalid power state (%d) "
		       "requested.\n",
		       tp->dev->name, state);
		return -EINVAL;
	};

	power_control |= PCI_PM_CTRL_PME_ENABLE;

	misc_host_ctrl = tr32(TG3PCI_MISC_HOST_CTRL);
	tw32(TG3PCI_MISC_HOST_CTRL,
	     misc_host_ctrl | MISC_HOST_CTRL_MASK_PCI_INT);

	if (tp->link_config.phy_is_low_power == 0) {
		tp->link_config.phy_is_low_power = 1;
		tp->link_config.orig_speed = tp->link_config.speed;
		tp->link_config.orig_duplex = tp->link_config.duplex;
		tp->link_config.orig_autoneg = tp->link_config.autoneg;
	}

	if (tp->phy_id != PHY_ID_SERDES) {
		tp->link_config.speed = SPEED_10;
		tp->link_config.duplex = DUPLEX_HALF;
		tp->link_config.autoneg = AUTONEG_ENABLE;
		tg3_setup_phy(tp);
	}

	pci_read_config_word(tp->pdev, pm + PCI_PM_PMC, &power_caps);

	if (tp->tg3_flags & TG3_FLAG_WOL_ENABLE) {
		u32 mac_mode;

		if (tp->phy_id != PHY_ID_SERDES) {
			tg3_writephy(tp, MII_TG3_AUX_CTRL, 0x5a);
			udelay(40);

			mac_mode = MAC_MODE_PORT_MODE_MII;

			if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5700 ||
			    !(tp->tg3_flags & TG3_FLAG_WOL_SPEED_100MB))
				mac_mode |= MAC_MODE_LINK_POLARITY;
		} else {
			mac_mode = MAC_MODE_PORT_MODE_TBI;
		}


		if (((power_caps & PCI_PM_CAP_PME_D3cold) &&
		     (tp->tg3_flags & TG3_FLAG_WOL_ENABLE)))
			mac_mode |= MAC_MODE_MAGIC_PKT_ENABLE;

		tw32(MAC_MODE, mac_mode);
		tr32(MAC_MODE);
		udelay(100);

		tw32(MAC_RX_MODE, RX_MODE_ENABLE);
		tr32(MAC_RX_MODE);
		udelay(10);
	}

	if (tp->tg3_flags & TG3_FLAG_WOL_SPEED_100MB) {
		u32 base_val;

		base_val = 0;
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700 ||
		    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5701)
			base_val |= (CLOCK_CTRL_RXCLK_DISABLE |
				     CLOCK_CTRL_TXCLK_DISABLE);

		tw32(TG3PCI_CLOCK_CTRL, base_val |
		     CLOCK_CTRL_ALTCLK);
		tr32(TG3PCI_CLOCK_CTRL);
		udelay(40);

		tw32(TG3PCI_CLOCK_CTRL, base_val |
		     CLOCK_CTRL_ALTCLK |
		     CLOCK_CTRL_44MHZ_CORE);
		tr32(TG3PCI_CLOCK_CTRL);
		udelay(40);

		tw32(TG3PCI_CLOCK_CTRL, base_val |
		     CLOCK_CTRL_44MHZ_CORE);
		tr32(TG3PCI_CLOCK_CTRL);
		udelay(40);
	} else {
		u32 base_val;

		base_val = 0;
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700 ||
		    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5701)
			base_val |= (CLOCK_CTRL_RXCLK_DISABLE |
				     CLOCK_CTRL_TXCLK_DISABLE);

		tw32(TG3PCI_CLOCK_CTRL, base_val |
		     CLOCK_CTRL_ALTCLK |
		     CLOCK_CTRL_PWRDOWN_PLL133);
		tr32(TG3PCI_CLOCK_CTRL);
		udelay(40);
	}

	if (!(tp->tg3_flags & TG3_FLAG_EEPROM_WRITE_PROT) &&
	    (tp->tg3_flags & TG3_FLAG_WOL_ENABLE)) {
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700 ||
		    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5701) {
			tw32(GRC_LOCAL_CTRL,
			     (GRC_LCLCTRL_GPIO_OE0 |
			      GRC_LCLCTRL_GPIO_OE1 |
			      GRC_LCLCTRL_GPIO_OE2 |
			      GRC_LCLCTRL_GPIO_OUTPUT0 |
			      GRC_LCLCTRL_GPIO_OUTPUT1));
			tr32(GRC_LOCAL_CTRL);
			udelay(100);
		} else {
			tw32(GRC_LOCAL_CTRL,
			     (GRC_LCLCTRL_GPIO_OE0 |
			      GRC_LCLCTRL_GPIO_OE1 |
			      GRC_LCLCTRL_GPIO_OE2 |
			      GRC_LCLCTRL_GPIO_OUTPUT1 |
			      GRC_LCLCTRL_GPIO_OUTPUT2));
			tr32(GRC_LOCAL_CTRL);
			udelay(100);

			tw32(GRC_LOCAL_CTRL,
			     (GRC_LCLCTRL_GPIO_OE0 |
			      GRC_LCLCTRL_GPIO_OE1 |
			      GRC_LCLCTRL_GPIO_OE2 |
			      GRC_LCLCTRL_GPIO_OUTPUT0 |
			      GRC_LCLCTRL_GPIO_OUTPUT1 |
			      GRC_LCLCTRL_GPIO_OUTPUT2));
			tr32(GRC_LOCAL_CTRL);
			udelay(100);

			tw32(GRC_LOCAL_CTRL,
			     (GRC_LCLCTRL_GPIO_OE0 |
			      GRC_LCLCTRL_GPIO_OE1 |
			      GRC_LCLCTRL_GPIO_OE2 |
			      GRC_LCLCTRL_GPIO_OUTPUT0 |
			      GRC_LCLCTRL_GPIO_OUTPUT1));
			tr32(GRC_LOCAL_CTRL);
			udelay(100);
		}
	}

	/* Finally, set the new power state. */
	pci_write_config_word(tp->pdev, pm + PCI_PM_CTRL, power_control);

	return 0;
}

static void tg3_link_report(struct tg3 *tp)
{
	if (!netif_carrier_ok(tp->dev)) {
		printk(KERN_INFO PFX "%s: Link is down.\n", tp->dev->name);
	} else {
		printk(KERN_INFO PFX "%s: Link is up at %d Mbps, %s duplex.\n",
		       tp->dev->name,
		       (tp->link_config.active_speed == SPEED_1000 ?
			1000 :
			(tp->link_config.active_speed == SPEED_100 ?
			 100 : 10)),
		       (tp->link_config.active_duplex == DUPLEX_FULL ?
			"full" : "half"));

		printk(KERN_INFO PFX "%s: Flow control is %s for TX and "
		       "%s for RX.\n",
		       tp->dev->name,
		       (tp->tg3_flags & TG3_FLAG_TX_PAUSE) ? "on" : "off",
		       (tp->tg3_flags & TG3_FLAG_RX_PAUSE) ? "on" : "off");
	}
}

static void tg3_setup_flow_control(struct tg3 *tp, u32 local_adv, u32 remote_adv)
{
	u32 new_tg3_flags = 0;

	if (local_adv & ADVERTISE_PAUSE_CAP) {
		if (local_adv & ADVERTISE_PAUSE_ASYM) {
			if (remote_adv & LPA_PAUSE_CAP)
				new_tg3_flags |=
					(TG3_FLAG_RX_PAUSE |
					 TG3_FLAG_TX_PAUSE);
			else if (remote_adv & LPA_PAUSE_ASYM)
				new_tg3_flags |=
					(TG3_FLAG_RX_PAUSE);
		} else {
			if (remote_adv & LPA_PAUSE_CAP)
				new_tg3_flags |=
					(TG3_FLAG_RX_PAUSE |
					 TG3_FLAG_TX_PAUSE);
		}
	} else if (local_adv & ADVERTISE_PAUSE_ASYM) {
		if ((remote_adv & LPA_PAUSE_CAP) &&
		    (remote_adv & LPA_PAUSE_ASYM))
			new_tg3_flags |= TG3_FLAG_TX_PAUSE;
	}

	tp->tg3_flags &= ~(TG3_FLAG_RX_PAUSE | TG3_FLAG_TX_PAUSE);
	tp->tg3_flags |= new_tg3_flags;

	if (new_tg3_flags & TG3_FLAG_RX_PAUSE)
		tp->rx_mode |= RX_MODE_FLOW_CTRL_ENABLE;
	else
		tp->rx_mode &= ~RX_MODE_FLOW_CTRL_ENABLE;

	if (new_tg3_flags & TG3_FLAG_TX_PAUSE)
		tp->tx_mode |= TX_MODE_FLOW_CTRL_ENABLE;
	else
		tp->tx_mode &= ~TX_MODE_FLOW_CTRL_ENABLE;
}

static void tg3_aux_stat_to_speed_duplex(struct tg3 *tp, u32 val, u16 *speed, u8 *duplex)
{
	switch (val & MII_TG3_AUX_STAT_SPDMASK) {
	case MII_TG3_AUX_STAT_10HALF:
		*speed = SPEED_10;
		*duplex = DUPLEX_HALF;
		break;

	case MII_TG3_AUX_STAT_10FULL:
		*speed = SPEED_10;
		*duplex = DUPLEX_FULL;
		break;

	case MII_TG3_AUX_STAT_100HALF:
		*speed = SPEED_100;
		*duplex = DUPLEX_HALF;
		break;

	case MII_TG3_AUX_STAT_100FULL:
		*speed = SPEED_100;
		*duplex = DUPLEX_FULL;
		break;

	case MII_TG3_AUX_STAT_1000HALF:
		*speed = SPEED_1000;
		*duplex = DUPLEX_HALF;
		break;

	case MII_TG3_AUX_STAT_1000FULL:
		*speed = SPEED_1000;
		*duplex = DUPLEX_FULL;
		break;

	default:
		*speed = SPEED_INVALID;
		*duplex = DUPLEX_INVALID;
		break;
	};
}

static int tg3_phy_copper_begin(struct tg3 *tp, int wait_for_link)
{
	u32 new_adv;
	int i;

	if (tp->link_config.phy_is_low_power) {
		/* Entering low power mode.  Disable gigabit and
		 * 100baseT advertisements.
		 */
		tg3_writephy(tp, MII_TG3_CTRL, 0);

		new_adv = (ADVERTISE_10HALF | ADVERTISE_10FULL |
			   ADVERTISE_CSMA | ADVERTISE_PAUSE_CAP);
		if (tp->tg3_flags & TG3_FLAG_WOL_SPEED_100MB)
			new_adv |= (ADVERTISE_100HALF | ADVERTISE_100FULL);

		tg3_writephy(tp, MII_ADVERTISE, new_adv);
	} else if (tp->link_config.speed == SPEED_INVALID) {
		tp->link_config.advertising =
			(ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full |
			 ADVERTISED_100baseT_Half | ADVERTISED_100baseT_Full |
			 ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full |
			 ADVERTISED_Autoneg | ADVERTISED_MII);

		if (tp->tg3_flags & TG3_FLAG_10_100_ONLY)
			tp->link_config.advertising &=
				~(ADVERTISED_1000baseT_Half |
				  ADVERTISED_1000baseT_Full);

		new_adv = (ADVERTISE_CSMA | ADVERTISE_PAUSE_CAP);
		if (tp->link_config.advertising & ADVERTISED_10baseT_Half)
			new_adv |= ADVERTISE_10HALF;
		if (tp->link_config.advertising & ADVERTISED_10baseT_Full)
			new_adv |= ADVERTISE_10FULL;
		if (tp->link_config.advertising & ADVERTISED_100baseT_Half)
			new_adv |= ADVERTISE_100HALF;
		if (tp->link_config.advertising & ADVERTISED_100baseT_Full)
			new_adv |= ADVERTISE_100FULL;
		tg3_writephy(tp, MII_ADVERTISE, new_adv);

		if (tp->link_config.advertising &
		    (ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full)) {
			new_adv = 0;
			if (tp->link_config.advertising & ADVERTISED_1000baseT_Half)
				new_adv |= MII_TG3_CTRL_ADV_1000_HALF;
			if (tp->link_config.advertising & ADVERTISED_1000baseT_Full)
				new_adv |= MII_TG3_CTRL_ADV_1000_FULL;
			if (!(tp->tg3_flags & TG3_FLAG_10_100_ONLY) &&
			    (tp->pci_chip_rev_id == CHIPREV_ID_5701_A0 ||
			     tp->pci_chip_rev_id == CHIPREV_ID_5701_B0))
				new_adv |= (MII_TG3_CTRL_AS_MASTER |
					    MII_TG3_CTRL_ENABLE_AS_MASTER);
			tg3_writephy(tp, MII_TG3_CTRL, new_adv);
		} else {
			tg3_writephy(tp, MII_TG3_CTRL, 0);
		}
	} else {
		/* Asking for a specific link mode. */
		if (tp->link_config.speed == SPEED_1000) {
			new_adv = ADVERTISE_CSMA | ADVERTISE_PAUSE_CAP;
			tg3_writephy(tp, MII_ADVERTISE, new_adv);

			if (tp->link_config.duplex == DUPLEX_FULL)
				new_adv = MII_TG3_CTRL_ADV_1000_FULL;
			else
				new_adv = MII_TG3_CTRL_ADV_1000_HALF;
			if (tp->pci_chip_rev_id == CHIPREV_ID_5701_A0 ||
			    tp->pci_chip_rev_id == CHIPREV_ID_5701_B0)
				new_adv |= (MII_TG3_CTRL_AS_MASTER |
					    MII_TG3_CTRL_ENABLE_AS_MASTER);
			tg3_writephy(tp, MII_TG3_CTRL, new_adv);
		} else {
			tg3_writephy(tp, MII_TG3_CTRL, 0);

			new_adv = ADVERTISE_CSMA | ADVERTISE_PAUSE_CAP;
			if (tp->link_config.speed == SPEED_100) {
				if (tp->link_config.duplex == DUPLEX_FULL)
					new_adv |= ADVERTISE_100FULL;
				else
					new_adv |= ADVERTISE_100HALF;
			} else {
				if (tp->link_config.duplex == DUPLEX_FULL)
					new_adv |= ADVERTISE_10FULL;
				else
					new_adv |= ADVERTISE_10HALF;
			}
			tg3_writephy(tp, MII_ADVERTISE, new_adv);
		}
	}

	if (tp->link_config.autoneg == AUTONEG_DISABLE &&
	    tp->link_config.speed != SPEED_INVALID) {
		u32 bmcr, orig_bmcr;

		tp->link_config.active_speed = tp->link_config.speed;
		tp->link_config.active_duplex = tp->link_config.duplex;

		bmcr = 0;
		switch (tp->link_config.speed) {
		default:
		case SPEED_10:
			break;

		case SPEED_100:
			bmcr |= BMCR_SPEED100;
			break;

		case SPEED_1000:
			bmcr |= TG3_BMCR_SPEED1000;
			break;
		};

		if (tp->link_config.duplex == DUPLEX_FULL)
			bmcr |= BMCR_FULLDPLX;

		tg3_readphy(tp, MII_BMCR, &orig_bmcr);
		if (bmcr != orig_bmcr) {
			tg3_writephy(tp, MII_BMCR, BMCR_LOOPBACK);
			for (i = 0; i < 15000; i++) {
				u32 tmp;

				udelay(10);
				tg3_readphy(tp, MII_BMSR, &tmp);
				tg3_readphy(tp, MII_BMSR, &tmp);
				if (!(tmp & BMSR_LSTATUS)) {
					udelay(40);
					break;
				}
			}
			tg3_writephy(tp, MII_BMCR, bmcr);
			udelay(40);
		}
	} else {
		tg3_writephy(tp, MII_BMCR,
			     BMCR_ANENABLE | BMCR_ANRESTART);
	}

	if (wait_for_link) {
		tp->link_config.active_speed = SPEED_INVALID;
		tp->link_config.active_duplex = DUPLEX_INVALID;
		for (i = 0; i < 300000; i++) {
			u32 tmp;

			udelay(10);
			tg3_readphy(tp, MII_BMSR, &tmp);
			tg3_readphy(tp, MII_BMSR, &tmp);
			if (!(tmp & BMSR_LSTATUS))
				continue;

			tg3_readphy(tp, MII_TG3_AUX_STAT, &tmp);
			tg3_aux_stat_to_speed_duplex(tp, tmp,
						     &tp->link_config.active_speed,
						     &tp->link_config.active_duplex);
		}
		if (tp->link_config.active_speed == SPEED_INVALID)
			return -EINVAL;
	}

	return 0;
}

static int tg3_init_5401phy_dsp(struct tg3 *tp)
{
	int err;

	/* Turn off tap power management. */
	err  = tg3_writephy(tp, MII_TG3_AUX_CTRL, 0x0c20);

	err |= tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x0012);
	err |= tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x1804);

	err |= tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x0013);
	err |= tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x1204);

	err |= tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x8006);
	err |= tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x0132);

	err |= tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x8006);
	err |= tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x0232);

	err |= tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x201f);
	err |= tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x0a20);

	udelay(40);

	return err;
}

static int tg3_setup_copper_phy(struct tg3 *tp)
{
	int current_link_up;
	u32 bmsr, dummy;
	u16 current_speed;
	u8 current_duplex;
	int i, err;

	tw32(MAC_STATUS,
	     (MAC_STATUS_SYNC_CHANGED |
	      MAC_STATUS_CFG_CHANGED));
	tr32(MAC_STATUS);
	udelay(40);

	tp->mi_mode = MAC_MI_MODE_BASE;
	tw32(MAC_MI_MODE, tp->mi_mode);
	tr32(MAC_MI_MODE);
	udelay(40);

	tg3_writephy(tp, MII_TG3_AUX_CTRL, 0x02);

	/* Some third-party PHYs need to be reset on link going
	 * down.
	 *
	 * XXX 5705 note: This workaround also applies to 5705_a0
	 */
	if ((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703 ||
	     GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704) &&
	    netif_carrier_ok(tp->dev)) {
		tg3_readphy(tp, MII_BMSR, &bmsr);
		tg3_readphy(tp, MII_BMSR, &bmsr);
		if (!(bmsr & BMSR_LSTATUS))
			tg3_phy_reset(tp, 1);
	}

	if ((tp->phy_id & PHY_ID_MASK) == PHY_ID_BCM5401) {
		tg3_readphy(tp, MII_BMSR, &bmsr);
		tg3_readphy(tp, MII_BMSR, &bmsr);

		if (!(tp->tg3_flags & TG3_FLAG_INIT_COMPLETE))
			bmsr = 0;

		if (!(bmsr & BMSR_LSTATUS)) {
			err = tg3_init_5401phy_dsp(tp);
			if (err)
				return err;

			tg3_readphy(tp, MII_BMSR, &bmsr);
			for (i = 0; i < 1000; i++) {
				udelay(10);
				tg3_readphy(tp, MII_BMSR, &bmsr);
				if (bmsr & BMSR_LSTATUS) {
					udelay(40);
					break;
				}
			}

			if ((tp->phy_id & PHY_ID_REV_MASK) == PHY_REV_BCM5401_B0 &&
			    !(bmsr & BMSR_LSTATUS) &&
			    tp->link_config.active_speed == SPEED_1000) {
				err = tg3_phy_reset(tp, 1);
				if (!err)
					err = tg3_init_5401phy_dsp(tp);
				if (err)
					return err;
			}
		}
	} else if (tp->pci_chip_rev_id == CHIPREV_ID_5701_A0 ||
		   tp->pci_chip_rev_id == CHIPREV_ID_5701_B0) {
		/* 5701 {A0,B0} CRC bug workaround */
		tg3_writephy(tp, 0x15, 0x0a75);
		tg3_writephy(tp, 0x1c, 0x8c68);
		tg3_writephy(tp, 0x1c, 0x8d68);
		tg3_writephy(tp, 0x1c, 0x8c68);
	}

	/* Clear pending interrupts... */
	tg3_readphy(tp, MII_TG3_ISTAT, &dummy);
	tg3_readphy(tp, MII_TG3_ISTAT, &dummy);

	if (tp->tg3_flags & TG3_FLAG_USE_MI_INTERRUPT)
		tg3_writephy(tp, MII_TG3_IMASK, ~MII_TG3_INT_LINKCHG);
	else
		tg3_writephy(tp, MII_TG3_IMASK, ~0);

	if (tp->led_mode == led_mode_three_link)
		tg3_writephy(tp, MII_TG3_EXT_CTRL,
			     MII_TG3_EXT_CTRL_LNK3_LED_MODE);
	else
		tg3_writephy(tp, MII_TG3_EXT_CTRL, 0);

	current_link_up = 0;
	current_speed = SPEED_INVALID;
	current_duplex = DUPLEX_INVALID;

	tg3_readphy(tp, MII_BMSR, &bmsr);
	tg3_readphy(tp, MII_BMSR, &bmsr);

	if (bmsr & BMSR_LSTATUS) {
		u32 aux_stat, bmcr;

		tg3_readphy(tp, MII_TG3_AUX_STAT, &aux_stat);
		for (i = 0; i < 2000; i++) {
			udelay(10);
			tg3_readphy(tp, MII_TG3_AUX_STAT, &aux_stat);
			if (aux_stat)
				break;
		}

		tg3_aux_stat_to_speed_duplex(tp, aux_stat,
					     &current_speed,
					     &current_duplex);
		tg3_readphy(tp, MII_BMCR, &bmcr);
		tg3_readphy(tp, MII_BMCR, &bmcr);
		if (tp->link_config.autoneg == AUTONEG_ENABLE) {
			if (bmcr & BMCR_ANENABLE) {
				u32 gig_ctrl;

				current_link_up = 1;

				/* Force autoneg restart if we are exiting
				 * low power mode.
				 */
				tg3_readphy(tp, MII_TG3_CTRL, &gig_ctrl);
				if (!(gig_ctrl & (MII_TG3_CTRL_ADV_1000_HALF |
						  MII_TG3_CTRL_ADV_1000_FULL))) {
					current_link_up = 0;
				}
			} else {
				current_link_up = 0;
			}
		} else {
			if (!(bmcr & BMCR_ANENABLE) &&
			    tp->link_config.speed == current_speed &&
			    tp->link_config.duplex == current_duplex) {
				current_link_up = 1;
			} else {
				current_link_up = 0;
			}
		}

		tp->link_config.active_speed = current_speed;
		tp->link_config.active_duplex = current_duplex;
	}

	if (current_link_up == 1 &&
	    (tp->link_config.active_duplex == DUPLEX_FULL) &&
	    (tp->link_config.autoneg == AUTONEG_ENABLE)) {
		u32 local_adv, remote_adv;

		tg3_readphy(tp, MII_ADVERTISE, &local_adv);
		local_adv &= (ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM);

		tg3_readphy(tp, MII_LPA, &remote_adv);
		remote_adv &= (LPA_PAUSE_CAP | LPA_PAUSE_ASYM);

		/* If we are not advertising full pause capability,
		 * something is wrong.  Bring the link down and reconfigure.
		 */
		if (local_adv != ADVERTISE_PAUSE_CAP) {
			current_link_up = 0;
		} else {
			tg3_setup_flow_control(tp, local_adv, remote_adv);
		}
	}

	if (current_link_up == 0) {
		u32 tmp;

		tg3_phy_copper_begin(tp, 0);

		tg3_readphy(tp, MII_BMSR, &tmp);
		tg3_readphy(tp, MII_BMSR, &tmp);
		if (tmp & BMSR_LSTATUS)
			current_link_up = 1;
	}

	tp->mac_mode &= ~MAC_MODE_PORT_MODE_MASK;
	if (current_link_up == 1) {
		if (tp->link_config.active_speed == SPEED_100 ||
		    tp->link_config.active_speed == SPEED_10)
			tp->mac_mode |= MAC_MODE_PORT_MODE_MII;
		else
			tp->mac_mode |= MAC_MODE_PORT_MODE_GMII;
	} else
		tp->mac_mode |= MAC_MODE_PORT_MODE_GMII;

	tp->mac_mode &= ~MAC_MODE_HALF_DUPLEX;
	if (tp->link_config.active_duplex == DUPLEX_HALF)
		tp->mac_mode |= MAC_MODE_HALF_DUPLEX;

	tp->mac_mode &= ~MAC_MODE_LINK_POLARITY;
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700) {
		if ((tp->led_mode == led_mode_link10) ||
		    (current_link_up == 1 &&
		     tp->link_config.active_speed == SPEED_10))
			tp->mac_mode |= MAC_MODE_LINK_POLARITY;
	} else {
		if (current_link_up == 1)
			tp->mac_mode |= MAC_MODE_LINK_POLARITY;
		tw32(MAC_LED_CTRL, LED_CTRL_PHY_MODE_1);
	}

	/* ??? Without this setting Netgear GA302T PHY does not
	 * ??? send/receive packets...
	 */
	if ((tp->phy_id & PHY_ID_MASK) == PHY_ID_BCM5411 &&
	    tp->pci_chip_rev_id == CHIPREV_ID_5700_ALTIMA) {
		tp->mi_mode |= MAC_MI_MODE_AUTO_POLL;
		tw32(MAC_MI_MODE, tp->mi_mode);
		tr32(MAC_MI_MODE);
		udelay(40);
	}

	tw32(MAC_MODE, tp->mac_mode);
	tr32(MAC_MODE);
	udelay(40);

	if (tp->tg3_flags &
	    (TG3_FLAG_USE_LINKCHG_REG |
	     TG3_FLAG_POLL_SERDES)) {
		/* Polled via timer. */
		tw32(MAC_EVENT, 0);
	} else {
		tw32(MAC_EVENT, MAC_EVENT_LNKSTATE_CHANGED);
	}
	tr32(MAC_EVENT);
	udelay(40);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700 &&
	    current_link_up == 1 &&
	    tp->link_config.active_speed == SPEED_1000 &&
	    ((tp->tg3_flags & TG3_FLAG_PCIX_MODE) ||
	     (tp->tg3_flags & TG3_FLAG_PCI_HIGH_SPEED))) {
		udelay(120);
		tw32(MAC_STATUS,
		     (MAC_STATUS_SYNC_CHANGED |
		      MAC_STATUS_CFG_CHANGED));
		tr32(MAC_STATUS);
		udelay(40);
		tg3_write_mem(tp,
			      NIC_SRAM_FIRMWARE_MBOX,
			      NIC_SRAM_FIRMWARE_MBOX_MAGIC2);
	}

	if (current_link_up != netif_carrier_ok(tp->dev)) {
		if (current_link_up)
			netif_carrier_on(tp->dev);
		else
			netif_carrier_off(tp->dev);
		tg3_link_report(tp);
	}

	return 0;
}

struct tg3_fiber_aneginfo {
	int state;
#define ANEG_STATE_UNKNOWN		0
#define ANEG_STATE_AN_ENABLE		1
#define ANEG_STATE_RESTART_INIT		2
#define ANEG_STATE_RESTART		3
#define ANEG_STATE_DISABLE_LINK_OK	4
#define ANEG_STATE_ABILITY_DETECT_INIT	5
#define ANEG_STATE_ABILITY_DETECT	6
#define ANEG_STATE_ACK_DETECT_INIT	7
#define ANEG_STATE_ACK_DETECT		8
#define ANEG_STATE_COMPLETE_ACK_INIT	9
#define ANEG_STATE_COMPLETE_ACK		10
#define ANEG_STATE_IDLE_DETECT_INIT	11
#define ANEG_STATE_IDLE_DETECT		12
#define ANEG_STATE_LINK_OK		13
#define ANEG_STATE_NEXT_PAGE_WAIT_INIT	14
#define ANEG_STATE_NEXT_PAGE_WAIT	15

	u32 flags;
#define MR_AN_ENABLE		0x00000001
#define MR_RESTART_AN		0x00000002
#define MR_AN_COMPLETE		0x00000004
#define MR_PAGE_RX		0x00000008
#define MR_NP_LOADED		0x00000010
#define MR_TOGGLE_TX		0x00000020
#define MR_LP_ADV_FULL_DUPLEX	0x00000040
#define MR_LP_ADV_HALF_DUPLEX	0x00000080
#define MR_LP_ADV_SYM_PAUSE	0x00000100
#define MR_LP_ADV_ASYM_PAUSE	0x00000200
#define MR_LP_ADV_REMOTE_FAULT1	0x00000400
#define MR_LP_ADV_REMOTE_FAULT2	0x00000800
#define MR_LP_ADV_NEXT_PAGE	0x00001000
#define MR_TOGGLE_RX		0x00002000
#define MR_NP_RX		0x00004000

#define MR_LINK_OK		0x80000000

	unsigned long link_time, cur_time;

	u32 ability_match_cfg;
	int ability_match_count;

	char ability_match, idle_match, ack_match;

	u32 txconfig, rxconfig;
#define ANEG_CFG_NP		0x00000080
#define ANEG_CFG_ACK		0x00000040
#define ANEG_CFG_RF2		0x00000020
#define ANEG_CFG_RF1		0x00000010
#define ANEG_CFG_PS2		0x00000001
#define ANEG_CFG_PS1		0x00008000
#define ANEG_CFG_HD		0x00004000
#define ANEG_CFG_FD		0x00002000
#define ANEG_CFG_INVAL		0x00001f06

};
#define ANEG_OK		0
#define ANEG_DONE	1
#define ANEG_TIMER_ENAB	2
#define ANEG_FAILED	-1

#define ANEG_STATE_SETTLE_TIME	10000

static int tg3_fiber_aneg_smachine(struct tg3 *tp,
				   struct tg3_fiber_aneginfo *ap)
{
	unsigned long delta;
	u32 rx_cfg_reg;
	int ret;

	if (ap->state == ANEG_STATE_UNKNOWN) {
		ap->rxconfig = 0;
		ap->link_time = 0;
		ap->cur_time = 0;
		ap->ability_match_cfg = 0;
		ap->ability_match_count = 0;
		ap->ability_match = 0;
		ap->idle_match = 0;
		ap->ack_match = 0;
	}
	ap->cur_time++;

	if (tr32(MAC_STATUS) & MAC_STATUS_RCVD_CFG) {
		rx_cfg_reg = tr32(MAC_RX_AUTO_NEG);

		if (rx_cfg_reg != ap->ability_match_cfg) {
			ap->ability_match_cfg = rx_cfg_reg;
			ap->ability_match = 0;
			ap->ability_match_count = 0;
		} else {
			if (++ap->ability_match_count > 1) {
				ap->ability_match = 1;
				ap->ability_match_cfg = rx_cfg_reg;
			}
		}
		if (rx_cfg_reg & ANEG_CFG_ACK)
			ap->ack_match = 1;
		else
			ap->ack_match = 0;

		ap->idle_match = 0;
	} else {
		ap->idle_match = 1;
		ap->ability_match_cfg = 0;
		ap->ability_match_count = 0;
		ap->ability_match = 0;
		ap->ack_match = 0;

		rx_cfg_reg = 0;
	}

	ap->rxconfig = rx_cfg_reg;
	ret = ANEG_OK;

	switch(ap->state) {
	case ANEG_STATE_UNKNOWN:
		if (ap->flags & (MR_AN_ENABLE | MR_RESTART_AN))
			ap->state = ANEG_STATE_AN_ENABLE;

		/* fallthru */
	case ANEG_STATE_AN_ENABLE:
		ap->flags &= ~(MR_AN_COMPLETE | MR_PAGE_RX);
		if (ap->flags & MR_AN_ENABLE) {
			ap->link_time = 0;
			ap->cur_time = 0;
			ap->ability_match_cfg = 0;
			ap->ability_match_count = 0;
			ap->ability_match = 0;
			ap->idle_match = 0;
			ap->ack_match = 0;

			ap->state = ANEG_STATE_RESTART_INIT;
		} else {
			ap->state = ANEG_STATE_DISABLE_LINK_OK;
		}
		break;

	case ANEG_STATE_RESTART_INIT:
		ap->link_time = ap->cur_time;
		ap->flags &= ~(MR_NP_LOADED);
		ap->txconfig = 0;
		tw32(MAC_TX_AUTO_NEG, 0);
		tp->mac_mode |= MAC_MODE_SEND_CONFIGS;
		tw32(MAC_MODE, tp->mac_mode);
		tr32(MAC_MODE);
		udelay(40);

		ret = ANEG_TIMER_ENAB;
		ap->state = ANEG_STATE_RESTART;

		/* fallthru */
	case ANEG_STATE_RESTART:
		delta = ap->cur_time - ap->link_time;
		if (delta > ANEG_STATE_SETTLE_TIME) {
			ap->state = ANEG_STATE_ABILITY_DETECT_INIT;
		} else {
			ret = ANEG_TIMER_ENAB;
		}
		break;

	case ANEG_STATE_DISABLE_LINK_OK:
		ret = ANEG_DONE;
		break;

	case ANEG_STATE_ABILITY_DETECT_INIT:
		ap->flags &= ~(MR_TOGGLE_TX);
		ap->txconfig = (ANEG_CFG_FD | ANEG_CFG_PS1);
		tw32(MAC_TX_AUTO_NEG, ap->txconfig);
		tp->mac_mode |= MAC_MODE_SEND_CONFIGS;
		tw32(MAC_MODE, tp->mac_mode);
		tr32(MAC_MODE);
		udelay(40);

		ap->state = ANEG_STATE_ABILITY_DETECT;
		break;

	case ANEG_STATE_ABILITY_DETECT:
		if (ap->ability_match != 0 && ap->rxconfig != 0) {
			ap->state = ANEG_STATE_ACK_DETECT_INIT;
		}
		break;

	case ANEG_STATE_ACK_DETECT_INIT:
		ap->txconfig |= ANEG_CFG_ACK;
		tw32(MAC_TX_AUTO_NEG, ap->txconfig);
		tp->mac_mode |= MAC_MODE_SEND_CONFIGS;
		tw32(MAC_MODE, tp->mac_mode);
		tr32(MAC_MODE);
		udelay(40);

		ap->state = ANEG_STATE_ACK_DETECT;

		/* fallthru */
	case ANEG_STATE_ACK_DETECT:
		if (ap->ack_match != 0) {
			if ((ap->rxconfig & ~ANEG_CFG_ACK) ==
			    (ap->ability_match_cfg & ~ANEG_CFG_ACK)) {
				ap->state = ANEG_STATE_COMPLETE_ACK_INIT;
			} else {
				ap->state = ANEG_STATE_AN_ENABLE;
			}
		} else if (ap->ability_match != 0 &&
			   ap->rxconfig == 0) {
			ap->state = ANEG_STATE_AN_ENABLE;
		}
		break;

	case ANEG_STATE_COMPLETE_ACK_INIT:
		if (ap->rxconfig & ANEG_CFG_INVAL) {
			ret = ANEG_FAILED;
			break;
		}
		ap->flags &= ~(MR_LP_ADV_FULL_DUPLEX |
			       MR_LP_ADV_HALF_DUPLEX |
			       MR_LP_ADV_SYM_PAUSE |
			       MR_LP_ADV_ASYM_PAUSE |
			       MR_LP_ADV_REMOTE_FAULT1 |
			       MR_LP_ADV_REMOTE_FAULT2 |
			       MR_LP_ADV_NEXT_PAGE |
			       MR_TOGGLE_RX |
			       MR_NP_RX);
		if (ap->rxconfig & ANEG_CFG_FD)
			ap->flags |= MR_LP_ADV_FULL_DUPLEX;
		if (ap->rxconfig & ANEG_CFG_HD)
			ap->flags |= MR_LP_ADV_HALF_DUPLEX;
		if (ap->rxconfig & ANEG_CFG_PS1)
			ap->flags |= MR_LP_ADV_SYM_PAUSE;
		if (ap->rxconfig & ANEG_CFG_PS2)
			ap->flags |= MR_LP_ADV_ASYM_PAUSE;
		if (ap->rxconfig & ANEG_CFG_RF1)
			ap->flags |= MR_LP_ADV_REMOTE_FAULT1;
		if (ap->rxconfig & ANEG_CFG_RF2)
			ap->flags |= MR_LP_ADV_REMOTE_FAULT2;
		if (ap->rxconfig & ANEG_CFG_NP)
			ap->flags |= MR_LP_ADV_NEXT_PAGE;

		ap->link_time = ap->cur_time;

		ap->flags ^= (MR_TOGGLE_TX);
		if (ap->rxconfig & 0x0008)
			ap->flags |= MR_TOGGLE_RX;
		if (ap->rxconfig & ANEG_CFG_NP)
			ap->flags |= MR_NP_RX;
		ap->flags |= MR_PAGE_RX;

		ap->state = ANEG_STATE_COMPLETE_ACK;
		ret = ANEG_TIMER_ENAB;
		break;

	case ANEG_STATE_COMPLETE_ACK:
		if (ap->ability_match != 0 &&
		    ap->rxconfig == 0) {
			ap->state = ANEG_STATE_AN_ENABLE;
			break;
		}
		delta = ap->cur_time - ap->link_time;
		if (delta > ANEG_STATE_SETTLE_TIME) {
			if (!(ap->flags & (MR_LP_ADV_NEXT_PAGE))) {
				ap->state = ANEG_STATE_IDLE_DETECT_INIT;
			} else {
				if ((ap->txconfig & ANEG_CFG_NP) == 0 &&
				    !(ap->flags & MR_NP_RX)) {
					ap->state = ANEG_STATE_IDLE_DETECT_INIT;
				} else {
					ret = ANEG_FAILED;
				}
			}
		}
		break;

	case ANEG_STATE_IDLE_DETECT_INIT:
		ap->link_time = ap->cur_time;
		tp->mac_mode &= ~MAC_MODE_SEND_CONFIGS;
		tw32(MAC_MODE, tp->mac_mode);
		tr32(MAC_MODE);
		udelay(40);

		ap->state = ANEG_STATE_IDLE_DETECT;
		ret = ANEG_TIMER_ENAB;
		break;

	case ANEG_STATE_IDLE_DETECT:
		if (ap->ability_match != 0 &&
		    ap->rxconfig == 0) {
			ap->state = ANEG_STATE_AN_ENABLE;
			break;
		}
		delta = ap->cur_time - ap->link_time;
		if (delta > ANEG_STATE_SETTLE_TIME) {
			/* XXX another gem from the Broadcom driver :( */
			ap->state = ANEG_STATE_LINK_OK;
		}
		break;

	case ANEG_STATE_LINK_OK:
		ap->flags |= (MR_AN_COMPLETE | MR_LINK_OK);
		ret = ANEG_DONE;
		break;

	case ANEG_STATE_NEXT_PAGE_WAIT_INIT:
		/* ??? unimplemented */
		break;

	case ANEG_STATE_NEXT_PAGE_WAIT:
		/* ??? unimplemented */
		break;

	default:
		ret = ANEG_FAILED;
		break;
	};

	return ret;
}

static int tg3_setup_fiber_phy(struct tg3 *tp)
{
	u32 orig_pause_cfg;
	u16 orig_active_speed;
	u8 orig_active_duplex;
	int current_link_up;
	int i;

	orig_pause_cfg =
		(tp->tg3_flags & (TG3_FLAG_RX_PAUSE |
				  TG3_FLAG_TX_PAUSE));
	orig_active_speed = tp->link_config.active_speed;
	orig_active_duplex = tp->link_config.active_duplex;

	tp->mac_mode &= ~(MAC_MODE_PORT_MODE_MASK | MAC_MODE_HALF_DUPLEX);
	tp->mac_mode |= MAC_MODE_PORT_MODE_TBI;
	tw32(MAC_MODE, tp->mac_mode);
	tr32(MAC_MODE);
	udelay(40);

	/* Reset when initting first time or we have a link. */
	if (!(tp->tg3_flags & TG3_FLAG_INIT_COMPLETE) ||
	    (tr32(MAC_STATUS) & MAC_STATUS_PCS_SYNCED)) {
		/* Set PLL lock range. */
		tg3_writephy(tp, 0x16, 0x8007);

		/* SW reset */
		tg3_writephy(tp, MII_BMCR, BMCR_RESET);

		/* Wait for reset to complete. */
		/* XXX schedule_timeout() ... */
		for (i = 0; i < 500; i++)
			udelay(10);

		/* Config mode; select PMA/Ch 1 regs. */
		tg3_writephy(tp, 0x10, 0x8411);

		/* Enable auto-lock and comdet, select txclk for tx. */
		tg3_writephy(tp, 0x11, 0x0a10);

		tg3_writephy(tp, 0x18, 0x00a0);
		tg3_writephy(tp, 0x16, 0x41ff);

		/* Assert and deassert POR. */
		tg3_writephy(tp, 0x13, 0x0400);
		udelay(40);
		tg3_writephy(tp, 0x13, 0x0000);

		tg3_writephy(tp, 0x11, 0x0a50);
		udelay(40);
		tg3_writephy(tp, 0x11, 0x0a10);

		/* Wait for signal to stabilize */
		/* XXX schedule_timeout() ... */
		for (i = 0; i < 15000; i++)
			udelay(10);

		/* Deselect the channel register so we can read the PHYID
		 * later.
		 */
		tg3_writephy(tp, 0x10, 0x8011);
	}

	/* Enable link change interrupt unless serdes polling.  */
	if (!(tp->tg3_flags & TG3_FLAG_POLL_SERDES))
		tw32(MAC_EVENT, MAC_EVENT_LNKSTATE_CHANGED);
	else
		tw32(MAC_EVENT, 0);
	tr32(MAC_EVENT);
	udelay(40);

	current_link_up = 0;
	if (tr32(MAC_STATUS) & MAC_STATUS_PCS_SYNCED) {
		if (tp->link_config.autoneg == AUTONEG_ENABLE &&
		    !(tp->tg3_flags & TG3_FLAG_GOT_SERDES_FLOWCTL)) {
			struct tg3_fiber_aneginfo aninfo;
			int status = ANEG_FAILED;
			unsigned int tick;
			u32 tmp;

			memset(&aninfo, 0, sizeof(aninfo));
			aninfo.flags |= (MR_AN_ENABLE);

			tw32(MAC_TX_AUTO_NEG, 0);

			tmp = tp->mac_mode & ~MAC_MODE_PORT_MODE_MASK;
			tw32(MAC_MODE, tmp | MAC_MODE_PORT_MODE_GMII);
			tr32(MAC_MODE);
			udelay(40);

			tw32(MAC_MODE, tp->mac_mode | MAC_MODE_SEND_CONFIGS);
			tr32(MAC_MODE);
			udelay(40);

			aninfo.state = ANEG_STATE_UNKNOWN;
			aninfo.cur_time = 0;
			tick = 0;
			while (++tick < 195000) {
				status = tg3_fiber_aneg_smachine(tp, &aninfo);
				if (status == ANEG_DONE ||
				    status == ANEG_FAILED)
					break;

				udelay(1);
			}

			tp->mac_mode &= ~MAC_MODE_SEND_CONFIGS;
			tw32(MAC_MODE, tp->mac_mode);
			tr32(MAC_MODE);
			udelay(40);

			if (status == ANEG_DONE &&
			    (aninfo.flags &
			     (MR_AN_COMPLETE | MR_LINK_OK |
			      MR_LP_ADV_FULL_DUPLEX))) {
				u32 local_adv, remote_adv;

				local_adv = ADVERTISE_PAUSE_CAP;
				remote_adv = 0;
				if (aninfo.flags & MR_LP_ADV_SYM_PAUSE)
					remote_adv |= LPA_PAUSE_CAP;
				if (aninfo.flags & MR_LP_ADV_ASYM_PAUSE)
					remote_adv |= LPA_PAUSE_ASYM;

				tg3_setup_flow_control(tp, local_adv, remote_adv);

				tp->tg3_flags |=
					TG3_FLAG_GOT_SERDES_FLOWCTL;
				current_link_up = 1;
			}
			for (i = 0; i < 60; i++) {
				udelay(20);
				tw32(MAC_STATUS,
				     (MAC_STATUS_SYNC_CHANGED |
				      MAC_STATUS_CFG_CHANGED));
				tr32(MAC_STATUS);
				udelay(40);
				if ((tr32(MAC_STATUS) &
				     (MAC_STATUS_SYNC_CHANGED |
				      MAC_STATUS_CFG_CHANGED)) == 0)
					break;
			}
			if (current_link_up == 0 &&
			    (tr32(MAC_STATUS) & MAC_STATUS_PCS_SYNCED)) {
				current_link_up = 1;
			}
		} else {
			/* Forcing 1000FD link up. */
			current_link_up = 1;
		}
	}

	tp->mac_mode &= ~MAC_MODE_LINK_POLARITY;
	tw32(MAC_MODE, tp->mac_mode);
	tr32(MAC_MODE);
	udelay(40);

	tp->hw_status->status =
		(SD_STATUS_UPDATED |
		 (tp->hw_status->status & ~SD_STATUS_LINK_CHG));

	for (i = 0; i < 100; i++) {
		udelay(20);
		tw32(MAC_STATUS,
		     (MAC_STATUS_SYNC_CHANGED |
		      MAC_STATUS_CFG_CHANGED));
		tr32(MAC_STATUS);
		udelay(40);
		if ((tr32(MAC_STATUS) &
		     (MAC_STATUS_SYNC_CHANGED |
		      MAC_STATUS_CFG_CHANGED)) == 0)
			break;
	}

	if ((tr32(MAC_STATUS) & MAC_STATUS_PCS_SYNCED) == 0)
		current_link_up = 0;

	if (current_link_up == 1) {
		tp->link_config.active_speed = SPEED_1000;
		tp->link_config.active_duplex = DUPLEX_FULL;
	} else {
		tp->link_config.active_speed = SPEED_INVALID;
		tp->link_config.active_duplex = DUPLEX_INVALID;
	}

	if (current_link_up != netif_carrier_ok(tp->dev)) {
		if (current_link_up)
			netif_carrier_on(tp->dev);
		else
			netif_carrier_off(tp->dev);
		tg3_link_report(tp);
	} else {
		u32 now_pause_cfg =
			tp->tg3_flags & (TG3_FLAG_RX_PAUSE |
					 TG3_FLAG_TX_PAUSE);
		if (orig_pause_cfg != now_pause_cfg ||
		    orig_active_speed != tp->link_config.active_speed ||
		    orig_active_duplex != tp->link_config.active_duplex)
			tg3_link_report(tp);
	}

	if ((tr32(MAC_STATUS) & MAC_STATUS_PCS_SYNCED) == 0) {
		tw32(MAC_MODE, tp->mac_mode | MAC_MODE_LINK_POLARITY);
		tr32(MAC_MODE);
		udelay(40);
		if (tp->tg3_flags & TG3_FLAG_INIT_COMPLETE) {
			tw32(MAC_MODE, tp->mac_mode);
			tr32(MAC_MODE);
			udelay(40);
		}
	}

	return 0;
}

static int tg3_setup_phy(struct tg3 *tp)
{
	int err;

	if (tp->phy_id == PHY_ID_SERDES) {
		err = tg3_setup_fiber_phy(tp);
	} else {
		err = tg3_setup_copper_phy(tp);
	}

	if (tp->link_config.active_speed == SPEED_1000 &&
	    tp->link_config.active_duplex == DUPLEX_HALF)
		tw32(MAC_TX_LENGTHS,
		     ((2 << TX_LENGTHS_IPG_CRS_SHIFT) |
		      (6 << TX_LENGTHS_IPG_SHIFT) |
		      (0xff << TX_LENGTHS_SLOT_TIME_SHIFT)));
	else
		tw32(MAC_TX_LENGTHS,
		     ((2 << TX_LENGTHS_IPG_CRS_SHIFT) |
		      (6 << TX_LENGTHS_IPG_SHIFT) |
		      (32 << TX_LENGTHS_SLOT_TIME_SHIFT)));

	return err;
}

/* Tigon3 never reports partial packet sends.  So we do not
 * need special logic to handle SKBs that have not had all
 * of their frags sent yet, like SunGEM does.
 */
static void tg3_tx(struct tg3 *tp)
{
	u32 hw_idx = tp->hw_status->idx[0].tx_consumer;
	u32 sw_idx = tp->tx_cons;

	while (sw_idx != hw_idx) {
		struct tx_ring_info *ri = &tp->tx_buffers[sw_idx];
		struct sk_buff *skb = ri->skb;
		int i;

		if (unlikely(skb == NULL))
			BUG();

		pci_unmap_single(tp->pdev,
				 pci_unmap_addr(ri, mapping),
				 (skb->len - skb->data_len),
				 PCI_DMA_TODEVICE);

		ri->skb = NULL;

		sw_idx = NEXT_TX(sw_idx);

		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
			if (unlikely(sw_idx == hw_idx))
				BUG();

			ri = &tp->tx_buffers[sw_idx];
			if (unlikely(ri->skb != NULL))
				BUG();

			pci_unmap_page(tp->pdev,
				       pci_unmap_addr(ri, mapping),
				       skb_shinfo(skb)->frags[i].size,
				       PCI_DMA_TODEVICE);

			sw_idx = NEXT_TX(sw_idx);
		}

		dev_kfree_skb_irq(skb);
	}

	tp->tx_cons = sw_idx;

	if (netif_queue_stopped(tp->dev) &&
	    (TX_BUFFS_AVAIL(tp) > TG3_TX_WAKEUP_THRESH))
		netif_wake_queue(tp->dev);
}

/* Returns size of skb allocated or < 0 on error.
 *
 * We only need to fill in the address because the other members
 * of the RX descriptor are invariant, see tg3_init_rings.
 *
 * Note the purposeful assymetry of cpu vs. chip accesses.  For
 * posting buffers we only dirty the first cache line of the RX
 * descriptor (containing the address).  Whereas for the RX status
 * buffers the cpu only reads the last cacheline of the RX descriptor
 * (to fetch the error flags, vlan tag, checksum, and opaque cookie).
 */
static int tg3_alloc_rx_skb(struct tg3 *tp, u32 opaque_key,
			    int src_idx, u32 dest_idx_unmasked)
{
	struct tg3_rx_buffer_desc *desc;
	struct ring_info *map, *src_map;
	struct sk_buff *skb;
	dma_addr_t mapping;
	int skb_size, dest_idx;

	src_map = NULL;
	switch (opaque_key) {
	case RXD_OPAQUE_RING_STD:
		dest_idx = dest_idx_unmasked % TG3_RX_RING_SIZE;
		desc = &tp->rx_std[dest_idx];
		map = &tp->rx_std_buffers[dest_idx];
		if (src_idx >= 0)
			src_map = &tp->rx_std_buffers[src_idx];
		skb_size = RX_PKT_BUF_SZ;
		break;

	case RXD_OPAQUE_RING_JUMBO:
		dest_idx = dest_idx_unmasked % TG3_RX_JUMBO_RING_SIZE;
		desc = &tp->rx_jumbo[dest_idx];
		map = &tp->rx_jumbo_buffers[dest_idx];
		if (src_idx >= 0)
			src_map = &tp->rx_jumbo_buffers[src_idx];
		skb_size = RX_JUMBO_PKT_BUF_SZ;
		break;

	default:
		return -EINVAL;
	};

	/* Do not overwrite any of the map or rp information
	 * until we are sure we can commit to a new buffer.
	 *
	 * Callers depend upon this behavior and assume that
	 * we leave everything unchanged if we fail.
	 */
	skb = dev_alloc_skb(skb_size);
	if (skb == NULL)
		return -ENOMEM;

	skb->dev = tp->dev;
	skb_reserve(skb, tp->rx_offset);

	mapping = pci_map_single(tp->pdev, skb->data,
				 skb_size - tp->rx_offset,
				 PCI_DMA_FROMDEVICE);

	map->skb = skb;
	pci_unmap_addr_set(map, mapping, mapping);

	if (src_map != NULL)
		src_map->skb = NULL;

	desc->addr_hi = ((u64)mapping >> 32);
	desc->addr_lo = ((u64)mapping & 0xffffffff);

	return skb_size;
}

/* We only need to move over in the address because the other
 * members of the RX descriptor are invariant.  See notes above
 * tg3_alloc_rx_skb for full details.
 */
static void tg3_recycle_rx(struct tg3 *tp, u32 opaque_key,
			   int src_idx, u32 dest_idx_unmasked)
{
	struct tg3_rx_buffer_desc *src_desc, *dest_desc;
	struct ring_info *src_map, *dest_map;
	int dest_idx;

	switch (opaque_key) {
	case RXD_OPAQUE_RING_STD:
		dest_idx = dest_idx_unmasked % TG3_RX_RING_SIZE;
		dest_desc = &tp->rx_std[dest_idx];
		dest_map = &tp->rx_std_buffers[dest_idx];
		src_desc = &tp->rx_std[src_idx];
		src_map = &tp->rx_std_buffers[src_idx];
		break;

	case RXD_OPAQUE_RING_JUMBO:
		dest_idx = dest_idx_unmasked % TG3_RX_JUMBO_RING_SIZE;
		dest_desc = &tp->rx_jumbo[dest_idx];
		dest_map = &tp->rx_jumbo_buffers[dest_idx];
		src_desc = &tp->rx_jumbo[src_idx];
		src_map = &tp->rx_jumbo_buffers[src_idx];
		break;

	default:
		return;
	};

	dest_map->skb = src_map->skb;
	pci_unmap_addr_set(dest_map, mapping,
			   pci_unmap_addr(src_map, mapping));
	dest_desc->addr_hi = src_desc->addr_hi;
	dest_desc->addr_lo = src_desc->addr_lo;

	src_map->skb = NULL;
}

#if TG3_VLAN_TAG_USED
static int tg3_vlan_rx(struct tg3 *tp, struct sk_buff *skb, u16 vlan_tag)
{
	return vlan_hwaccel_receive_skb(skb, tp->vlgrp, vlan_tag);
}
#endif

/* The RX ring scheme is composed of multiple rings which post fresh
 * buffers to the chip, and one special ring the chip uses to report
 * status back to the host.
 *
 * The special ring reports the status of received packets to the
 * host.  The chip does not write into the original descriptor the
 * RX buffer was obtained from.  The chip simply takes the original
 * descriptor as provided by the host, updates the status and length
 * field, then writes this into the next status ring entry.
 *
 * Each ring the host uses to post buffers to the chip is described
 * by a TG3_BDINFO entry in the chips SRAM area.  When a packet arrives,
 * it is first placed into the on-chip ram.  When the packet's length
 * is known, it walks down the TG3_BDINFO entries to select the ring.
 * Each TG3_BDINFO specifies a MAXLEN field and the first TG3_BDINFO
 * which is within the range of the new packet's length is chosen.
 *
 * The "seperate ring for rx status" scheme may sound queer, but it makes
 * sense from a cache coherency perspective.  If only the host writes
 * to the buffer post rings, and only the chip writes to the rx status
 * rings, then cache lines never move beyond shared-modified state.
 * If both the host and chip were to write into the same ring, cache line
 * eviction could occur since both entities want it in an exclusive state.
 */
static int tg3_rx(struct tg3 *tp, int budget)
{
	u32 work_mask;
	u32 rx_rcb_ptr = tp->rx_rcb_ptr;
	u16 hw_idx, sw_idx;
	int received;

	hw_idx = tp->hw_status->idx[0].rx_producer;
	sw_idx = rx_rcb_ptr % TG3_RX_RCB_RING_SIZE;
	work_mask = 0;
	received = 0;
	while (sw_idx != hw_idx && budget > 0) {
		struct tg3_rx_buffer_desc *desc = &tp->rx_rcb[sw_idx];
		unsigned int len;
		struct sk_buff *skb;
		dma_addr_t dma_addr;
		u32 opaque_key, desc_idx, *post_ptr;

		desc_idx = desc->opaque & RXD_OPAQUE_INDEX_MASK;
		opaque_key = desc->opaque & RXD_OPAQUE_RING_MASK;
		if (opaque_key == RXD_OPAQUE_RING_STD) {
			dma_addr = pci_unmap_addr(&tp->rx_std_buffers[desc_idx],
						  mapping);
			skb = tp->rx_std_buffers[desc_idx].skb;
			post_ptr = &tp->rx_std_ptr;
		} else if (opaque_key == RXD_OPAQUE_RING_JUMBO) {
			dma_addr = pci_unmap_addr(&tp->rx_jumbo_buffers[desc_idx],
						  mapping);
			skb = tp->rx_jumbo_buffers[desc_idx].skb;
			post_ptr = &tp->rx_jumbo_ptr;
		}
		else {
			goto next_pkt_nopost;
		}

		work_mask |= opaque_key;

		if ((desc->err_vlan & RXD_ERR_MASK) != 0 &&
		    (desc->err_vlan != RXD_ERR_ODD_NIBBLE_RCVD_MII)) {
		drop_it:
			tg3_recycle_rx(tp, opaque_key,
				       desc_idx, *post_ptr);
		drop_it_no_recycle:
			/* Other statistics kept track of by card. */
			tp->net_stats.rx_dropped++;
			goto next_pkt;
		}

		len = ((desc->idx_len & RXD_LEN_MASK) >> RXD_LEN_SHIFT) - 4; /* omit crc */

		if (len > RX_COPY_THRESHOLD) {
			int skb_size;

			skb_size = tg3_alloc_rx_skb(tp, opaque_key,
						    desc_idx, *post_ptr);
			if (skb_size < 0)
				goto drop_it;

			pci_unmap_single(tp->pdev, dma_addr,
					 skb_size - tp->rx_offset,
					 PCI_DMA_FROMDEVICE);

			skb_put(skb, len);
		} else {
			struct sk_buff *copy_skb;

			tg3_recycle_rx(tp, opaque_key,
				       desc_idx, *post_ptr);

			copy_skb = dev_alloc_skb(len + 2);
			if (copy_skb == NULL)
				goto drop_it_no_recycle;

			copy_skb->dev = tp->dev;
			skb_reserve(copy_skb, 2);
			skb_put(copy_skb, len);
			pci_dma_sync_single(tp->pdev, dma_addr, len, PCI_DMA_FROMDEVICE);
			memcpy(copy_skb->data, skb->data, len);

			/* We'll reuse the original ring buffer. */
			skb = copy_skb;
		}

		if ((tp->tg3_flags & TG3_FLAG_RX_CHECKSUMS) &&
		    (desc->type_flags & RXD_FLAG_TCPUDP_CSUM) &&
		    (((desc->ip_tcp_csum & RXD_TCPCSUM_MASK)
		      >> RXD_TCPCSUM_SHIFT) == 0xffff))
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		else
			skb->ip_summed = CHECKSUM_NONE;

		skb->protocol = eth_type_trans(skb, tp->dev);
#if TG3_VLAN_TAG_USED
		if (tp->vlgrp != NULL &&
		    desc->type_flags & RXD_FLAG_VLAN) {
			tg3_vlan_rx(tp, skb,
				    desc->err_vlan & RXD_VLAN_MASK);
		} else
#endif
#ifdef NAPI
			netif_receive_skb(skb);
#else
			netif_rx(skb);
#endif
		tp->dev->last_rx = jiffies;
		received++;
		budget--;

next_pkt:
		(*post_ptr)++;
next_pkt_nopost:
		rx_rcb_ptr++;
		sw_idx = rx_rcb_ptr % TG3_RX_RCB_RING_SIZE;
	}

	/* ACK the status ring. */
	tp->rx_rcb_ptr = rx_rcb_ptr;
	tw32_mailbox(MAILBOX_RCVRET_CON_IDX_0 + TG3_64BIT_REG_LOW,
		     (rx_rcb_ptr % TG3_RX_RCB_RING_SIZE));
	if (tp->tg3_flags & TG3_FLAG_MBOX_WRITE_REORDER)
		tr32(MAILBOX_RCVRET_CON_IDX_0 + TG3_64BIT_REG_LOW);

	/* Refill RX ring(s). */
	if (work_mask & RXD_OPAQUE_RING_STD) {
		sw_idx = tp->rx_std_ptr % TG3_RX_RING_SIZE;
		tw32_mailbox(MAILBOX_RCV_STD_PROD_IDX + TG3_64BIT_REG_LOW,
			     sw_idx);
		if (tp->tg3_flags & TG3_FLAG_MBOX_WRITE_REORDER)
			tr32(MAILBOX_RCV_STD_PROD_IDX + TG3_64BIT_REG_LOW);
	}
	if (work_mask & RXD_OPAQUE_RING_JUMBO) {
		sw_idx = tp->rx_jumbo_ptr % TG3_RX_JUMBO_RING_SIZE;
		tw32_mailbox(MAILBOX_RCV_JUMBO_PROD_IDX + TG3_64BIT_REG_LOW,
			     sw_idx);
		if (tp->tg3_flags & TG3_FLAG_MBOX_WRITE_REORDER)
			tr32(MAILBOX_RCV_JUMBO_PROD_IDX + TG3_64BIT_REG_LOW);
	}

	return received;
}

static int tg3_poll(struct net_device *netdev, int *budget)
{
	struct tg3 *tp = netdev->priv;
	struct tg3_hw_status *sblk = tp->hw_status;
	unsigned long flags;
	int done;

	spin_lock_irqsave(&tp->lock, flags);

	/* handle link change and other phy events */
	if (!(tp->tg3_flags &
	      (TG3_FLAG_USE_LINKCHG_REG |
	       TG3_FLAG_POLL_SERDES))) {
		if (sblk->status & SD_STATUS_LINK_CHG) {
			sblk->status = SD_STATUS_UPDATED |
				(sblk->status & ~SD_STATUS_LINK_CHG);
			tg3_setup_phy(tp);
		}
	}

	/* run TX completion thread */
	if (sblk->idx[0].tx_consumer != tp->tx_cons) {
		spin_lock(&tp->tx_lock);
		tg3_tx(tp);
		spin_unlock(&tp->tx_lock);
	}

	spin_unlock_irqrestore(&tp->lock, flags);

	/* run RX thread, within the bounds set by NAPI.
	 * All RX "locking" is done by ensuring outside
	 * code synchronizes with dev->poll()
	 */
	done = 1;
	if (sblk->idx[0].rx_producer != tp->rx_rcb_ptr) {
		int work_done;
#ifdef NAPI
		int orig_budget = *budget;

		if (orig_budget > netdev->quota)
			orig_budget = netdev->quota;

		work_done = tg3_rx(tp, orig_budget);

		*budget -= work_done;
		netdev->quota -= work_done;

		if (work_done >= orig_budget)
			done = 0;
#else
		work_done = tg3_rx(tp, 1000);
#endif
	}
#ifdef NAPI
	/* if no more work, tell net stack and NIC we're done */
	if (done) {
		spin_lock_irqsave(&tp->lock, flags);
		__netif_rx_complete(netdev);
		tg3_enable_ints(tp);
		spin_unlock_irqrestore(&tp->lock, flags);
	}
#endif
	return (done ? 0 : 1);
}

static inline unsigned int tg3_has_work(struct net_device *dev, struct tg3 *tp)
{
	struct tg3_hw_status *sblk = tp->hw_status;
	unsigned int work_exists = 0;

	/* check for phy events */
	if (!(tp->tg3_flags &
	      (TG3_FLAG_USE_LINKCHG_REG |
	       TG3_FLAG_POLL_SERDES))) {
		if (sblk->status & SD_STATUS_LINK_CHG)
			work_exists = 1;
	}
	/* check for RX/TX work to do */
	if (sblk->idx[0].tx_consumer != tp->tx_cons ||
	    sblk->idx[0].rx_producer != tp->rx_rcb_ptr)
		work_exists = 1;

	return work_exists;
}

static void tg3_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	struct net_device *dev = dev_id;
	struct tg3 *tp = dev->priv;
#ifdef NAPI
	struct tg3_hw_status *sblk = tp->hw_status;
#endif
	unsigned long flags;

	spin_lock_irqsave(&tp->lock, flags);
#ifdef NAPI
	if (sblk->status & SD_STATUS_UPDATED) {
		/*
		 * writing any value to intr-mbox-0 clears PCI INTA# and
		 * chip-internal interrupt pending events.
		 * writing non-zero to intr-mbox-0 additional tells the
		 * NIC to stop sending us irqs, engaging "in-intr-handler"
		 * event coalescing.
		 */
		tw32_mailbox(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW,
			     0x00000001);
		/*
		 * Flush PCI write.  This also guarantees that our
		 * status block has been flushed to host memory.
		 */
		tr32(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW);
		sblk->status &= ~SD_STATUS_UPDATED;

		if (likely(tg3_has_work(dev, tp)))
			netif_rx_schedule(dev);		/* schedule NAPI poll */
		else {
			/* no work, shared interrupt perhaps?  re-enable
			 * interrupts, and flush that PCI write
			 */
			tw32_mailbox(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW,
			     	0x00000000);
			tr32(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW);
		}
	}
#else
	{
		int budget = 1000;
		tg3_poll( dev, &budget );

		tw32_mailbox(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW,
		       0x00000000);
		tr32(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW);
	}
#endif
	spin_unlock_irqrestore(&tp->lock, flags);
}

static void tg3_init_rings(struct tg3 *);
static int tg3_init_hw(struct tg3 *);
static int tg3_halt(struct tg3 *);

static void tg3_reset_task(void *_data)
{
	struct tg3 *tp = _data;
	unsigned int restart_timer;

	tg3_netif_stop(tp);

	spin_lock_irq(&tp->lock);
	spin_lock(&tp->tx_lock);

	restart_timer = tp->tg3_flags2 & TG3_FLG2_RESTART_TIMER;
	tp->tg3_flags2 &= ~TG3_FLG2_RESTART_TIMER;

	tg3_halt(tp);
	tg3_init_rings(tp);
	tg3_init_hw(tp);

	spin_unlock(&tp->tx_lock);
	spin_unlock_irq(&tp->lock);

	tg3_netif_start(tp);

	if (restart_timer)
		mod_timer(&tp->timer, jiffies + 1);
}

static void tg3_tx_timeout(struct net_device *dev)
{
        struct tg3 *tp = dev->priv;

        printk(KERN_ERR PFX "%s: transmit timed out, resetting\n",
               dev->name);

        spin_lock_irq(&tp->lock);
        spin_lock(&tp->tx_lock);

        tg3_halt(tp);
        tg3_init_rings(tp);
        tg3_init_hw(tp);

        spin_unlock(&tp->tx_lock);
        spin_unlock_irq(&tp->lock);

        netif_wake_queue(dev);
}

#if !PCI_DMA_BUS_IS_PHYS
static void tg3_set_txd_addr(struct tg3 *tp, int entry, dma_addr_t mapping)
{
	if (tp->tg3_flags & TG3_FLAG_HOST_TXDS) {
		struct tg3_tx_buffer_desc *txd = &tp->tx_ring[entry];

		txd->addr_hi = ((u64) mapping >> 32);
		txd->addr_lo = ((u64) mapping & 0xffffffff);
	} else {
		unsigned long txd;

		txd = (tp->regs +
		       NIC_SRAM_WIN_BASE +
		       NIC_SRAM_TX_BUFFER_DESC);
		txd += (entry * TXD_SIZE);

		if (sizeof(dma_addr_t) != sizeof(u32))
			writel(((u64) mapping >> 32),
			       txd + TXD_ADDR + TG3_64BIT_REG_HIGH);

		writel(((u64) mapping & 0xffffffff),
		       txd + TXD_ADDR + TG3_64BIT_REG_LOW);
	}
}
#endif

static void tg3_set_txd(struct tg3 *, int, dma_addr_t, int, u32, u32);

static int tigon3_4gb_hwbug_workaround(struct tg3 *tp, struct sk_buff *skb,
				       u32 guilty_entry, int guilty_len,
				       u32 last_plus_one, u32 *start, u32 mss)
{
	dma_addr_t new_addr;
	u32 entry = *start;
	int i;

#if !PCI_DMA_BUS_IS_PHYS
	/* IOMMU, just map the guilty area again which is guarenteed to
	 * use different addresses.
	 */

	i = 0;
	while (entry != guilty_entry) {
		entry = NEXT_TX(entry);
		i++;
	}
	if (i == 0) {
		new_addr = pci_map_single(tp->pdev, skb->data, guilty_len,
					  PCI_DMA_TODEVICE);
	} else {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i - 1];

		new_addr = pci_map_page(tp->pdev,
					frag->page, frag->page_offset,
					guilty_len, PCI_DMA_TODEVICE);
	}
	pci_unmap_single(tp->pdev, pci_unmap_addr(&tp->tx_buffers[guilty_entry],
						  mapping),
			 guilty_len, PCI_DMA_TODEVICE);
	tg3_set_txd_addr(tp, guilty_entry, new_addr);
	pci_unmap_addr_set(&tp->tx_buffers[guilty_entry], mapping,
			   new_addr);
	*start = last_plus_one;
#else
	/* Oh well, no IOMMU, have to allocate a whole new SKB. */
	struct sk_buff *new_skb = skb_copy(skb, GFP_ATOMIC);

	if (!new_skb) {
		dev_kfree_skb(skb);
		return -1;
	}

	/* New SKB is guarenteed to be linear. */
	entry = *start;
	new_addr = pci_map_single(tp->pdev, new_skb->data, new_skb->len,
				  PCI_DMA_TODEVICE);
	tg3_set_txd(tp, entry, new_addr, new_skb->len,
		    (skb->ip_summed == CHECKSUM_HW) ?
		    TXD_FLAG_TCPUDP_CSUM : 0, 1 | (mss << 1));
	*start = NEXT_TX(entry);

	/* Now clean up the sw ring entries. */
	i = 0;
	while (entry != last_plus_one) {
		int len;

		if (i == 0)
			len = skb->len - skb->data_len;
		else
			len = skb_shinfo(skb)->frags[i-1].size;
		pci_unmap_single(tp->pdev,
				 pci_unmap_addr(&tp->tx_buffers[entry], mapping),
				 len, PCI_DMA_TODEVICE);
		if (i == 0) {
			tp->tx_buffers[entry].skb = new_skb;
			pci_unmap_addr_set(&tp->tx_buffers[entry], mapping, new_addr);
		} else {
			tp->tx_buffers[entry].skb = NULL;
		}
		entry = NEXT_TX(entry);
	}

	dev_kfree_skb(skb);
#endif

	return 0;
}

static void tg3_set_txd(struct tg3 *tp, int entry,
			dma_addr_t mapping, int len, u32 flags,
			u32 mss_and_is_end)
{
	int is_end = (mss_and_is_end & 0x1);
	u32 mss = (mss_and_is_end >> 1);
	u32 vlan_tag = 0;

	if (is_end)
		flags |= TXD_FLAG_END;
	if (flags & TXD_FLAG_VLAN) {
		vlan_tag = flags >> 16;
		flags &= 0xffff;
	}
	vlan_tag |= (mss << TXD_MSS_SHIFT);
	if (tp->tg3_flags & TG3_FLAG_HOST_TXDS) {
		struct tg3_tx_buffer_desc *txd = &tp->tx_ring[entry];

		txd->addr_hi = ((u64) mapping >> 32);
		txd->addr_lo = ((u64) mapping & 0xffffffff);
		txd->len_flags = (len << TXD_LEN_SHIFT) | flags;
		txd->vlan_tag = vlan_tag << TXD_VLAN_TAG_SHIFT;
	} else {
		struct tx_ring_info *txr = &tp->tx_buffers[entry];
		unsigned long txd;

		txd = (tp->regs +
		       NIC_SRAM_WIN_BASE +
		       NIC_SRAM_TX_BUFFER_DESC);
		txd += (entry * TXD_SIZE);

		/* Save some PIOs */
		if (sizeof(dma_addr_t) != sizeof(u32))
			writel(((u64) mapping >> 32),
			       txd + TXD_ADDR + TG3_64BIT_REG_HIGH);

		writel(((u64) mapping & 0xffffffff),
		       txd + TXD_ADDR + TG3_64BIT_REG_LOW);
		writel(len << TXD_LEN_SHIFT | flags, txd + TXD_LEN_FLAGS);
		if (txr->prev_vlan_tag != vlan_tag) {
			writel(vlan_tag << TXD_VLAN_TAG_SHIFT, txd + TXD_VLAN_TAG);
			txr->prev_vlan_tag = vlan_tag;
		}
	}
}

static inline int tg3_4g_overflow_test(dma_addr_t mapping, int len)
{
	u32 base = (u32) mapping & 0xffffffff;

	return ((base > 0xffffdcc0) &&
		((u64) mapping >> 32) == 0 &&
		(base + len + 8 < base));
}

static int tg3_start_xmit_4gbug(struct sk_buff *skb, struct net_device *dev)
{
	struct tg3 *tp = dev->priv;
	dma_addr_t mapping;
	unsigned int i;
	u32 len, entry, base_flags, mss;
	int would_hit_hwbug;
	unsigned long flags;

	len = (skb->len - skb->data_len);

	/* No BH disabling for tx_lock here.  We are running in BH disabled
	 * context and TX reclaim runs via tp->poll inside of a software
	 * interrupt.  Rejoice!
	 *
	 * Actually, things are not so simple.  If we are to take a hw
	 * IRQ here, we can deadlock, consider:
	 *
	 *       CPU1		CPU2
	 *   tg3_start_xmit
	 *   take tp->tx_lock
	 *			tg3_timer
	 *			take tp->lock
	 *   tg3_interrupt
	 *   spin on tp->lock
	 *			spin on tp->tx_lock
	 *
	 * So we really do need to disable interrupts when taking
	 * tx_lock here.
	 */
	spin_lock_irqsave(&tp->tx_lock, flags);

	/* This is a hard error, log it. */
	if (unlikely(TX_BUFFS_AVAIL(tp) <= (skb_shinfo(skb)->nr_frags + 1))) {
		netif_stop_queue(dev);
		spin_unlock_irqrestore(&tp->tx_lock, flags);
		printk(KERN_ERR PFX "%s: BUG! Tx Ring full when queue awake!\n",
		       dev->name);
		return 1;
	}

	entry = tp->tx_prod;
	base_flags = 0;
	if (skb->ip_summed == CHECKSUM_HW)
		base_flags |= TXD_FLAG_TCPUDP_CSUM;
#if TG3_DO_TSO != 0
	if ((mss = skb_shinfo(skb)->tso_size) != 0)
		base_flags |= (TXD_FLAG_CPU_PRE_DMA |
			       TXD_FLAG_CPU_POST_DMA);
#else
	mss = 0;
#endif
#if TG3_VLAN_TAG_USED
	if (tp->vlgrp != NULL && vlan_tx_tag_present(skb))
		base_flags |= (TXD_FLAG_VLAN |
			       (vlan_tx_tag_get(skb) << 16));
#endif

	/* Queue skb data, a.k.a. the main skb fragment. */
	mapping = pci_map_single(tp->pdev, skb->data, len, PCI_DMA_TODEVICE);

	tp->tx_buffers[entry].skb = skb;
	pci_unmap_addr_set(&tp->tx_buffers[entry], mapping, mapping);

	would_hit_hwbug = 0;

	if (tg3_4g_overflow_test(mapping, len))
		would_hit_hwbug = entry + 1;

	tg3_set_txd(tp, entry, mapping, len, base_flags,
		    (skb_shinfo(skb)->nr_frags == 0) | (mss << 1));

	entry = NEXT_TX(entry);

	/* Now loop through additional data fragments, and queue them. */
	if (skb_shinfo(skb)->nr_frags > 0) {
		unsigned int i, last;

		last = skb_shinfo(skb)->nr_frags - 1;
		for (i = 0; i <= last; i++) {
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

			len = frag->size;
			mapping = pci_map_page(tp->pdev,
					       frag->page,
					       frag->page_offset,
					       len, PCI_DMA_TODEVICE);

			tp->tx_buffers[entry].skb = NULL;
			pci_unmap_addr_set(&tp->tx_buffers[entry], mapping, mapping);

			if (tg3_4g_overflow_test(mapping, len)) {
				/* Only one should match. */
				if (would_hit_hwbug)
					BUG();
				would_hit_hwbug = entry + 1;
			}

			tg3_set_txd(tp, entry, mapping, len,
				    base_flags, (i == last) | (mss << 1));

			entry = NEXT_TX(entry);
		}
	}

	if (would_hit_hwbug) {
		u32 last_plus_one = entry;
		u32 start;
		unsigned int len = 0;

		would_hit_hwbug -= 1;
		entry = entry - 1 - skb_shinfo(skb)->nr_frags;
		entry &= (TG3_TX_RING_SIZE - 1);
		start = entry;
		i = 0;
		while (entry != last_plus_one) {
			if (i == 0)
				len = skb->len - skb->data_len;
			else
				len = skb_shinfo(skb)->frags[i-1].size;

			if (entry == would_hit_hwbug)
				break;

			i++;
			entry = NEXT_TX(entry);

		}

		/* If the workaround fails due to memory/mapping
		 * failure, silently drop this packet.
		 */
		if (tigon3_4gb_hwbug_workaround(tp, skb,
						entry, len,
						last_plus_one,
						&start, mss))
			goto out_unlock;

		entry = start;
	}

	/* Packets are ready, update Tx producer idx local and on card. */
	if (tp->tg3_flags & TG3_FLAG_HOST_TXDS) {
		tw32_mailbox((MAILBOX_SNDHOST_PROD_IDX_0 +
			      TG3_64BIT_REG_LOW), entry);
		if (tp->tg3_flags & TG3_FLAG_TXD_MBOX_HWBUG)
			tw32_mailbox((MAILBOX_SNDHOST_PROD_IDX_0 +
				      TG3_64BIT_REG_LOW), entry);
		if (tp->tg3_flags & TG3_FLAG_MBOX_WRITE_REORDER)
			tr32(MAILBOX_SNDHOST_PROD_IDX_0 +
			     TG3_64BIT_REG_LOW);
	} else {
		/* First, make sure tg3 sees last descriptor fully
		 * in SRAM.
		 */
		if (tp->tg3_flags & TG3_FLAG_MBOX_WRITE_REORDER)
			tr32(MAILBOX_SNDNIC_PROD_IDX_0 +
			     TG3_64BIT_REG_LOW);

		tw32_mailbox((MAILBOX_SNDNIC_PROD_IDX_0 +
			      TG3_64BIT_REG_LOW), entry);
		if (tp->tg3_flags & TG3_FLAG_TXD_MBOX_HWBUG)
			tw32_mailbox((MAILBOX_SNDNIC_PROD_IDX_0 +
				      TG3_64BIT_REG_LOW), entry);

		/* Now post the mailbox write itself.  */
		if (tp->tg3_flags & TG3_FLAG_MBOX_WRITE_REORDER)
			tr32(MAILBOX_SNDNIC_PROD_IDX_0 +
			     TG3_64BIT_REG_LOW);
	}

	tp->tx_prod = entry;
	if (TX_BUFFS_AVAIL(tp) <= (MAX_SKB_FRAGS + 1))
		netif_stop_queue(dev);

out_unlock:
	spin_unlock_irqrestore(&tp->tx_lock, flags);

	dev->trans_start = jiffies;

	return 0;
}

static int tg3_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct tg3 *tp = dev->priv;
	dma_addr_t mapping;
	u32 len, entry, base_flags, mss;
	unsigned long flags;

	len = (skb->len - skb->data_len);

	/* No BH disabling for tx_lock here.  We are running in BH disabled
	 * context and TX reclaim runs via tp->poll inside of a software
	 * interrupt.  Rejoice!
	 *
	 * Actually, things are not so simple.  If we are to take a hw
	 * IRQ here, we can deadlock, consider:
	 *
	 *       CPU1		CPU2
	 *   tg3_start_xmit
	 *   take tp->tx_lock
	 *			tg3_timer
	 *			take tp->lock
	 *   tg3_interrupt
	 *   spin on tp->lock
	 *			spin on tp->tx_lock
	 *
	 * So we really do need to disable interrupts when taking
	 * tx_lock here.
	 */
	spin_lock_irqsave(&tp->tx_lock, flags);

	/* This is a hard error, log it. */
	if (unlikely(TX_BUFFS_AVAIL(tp) <= (skb_shinfo(skb)->nr_frags + 1))) {
		netif_stop_queue(dev);
		spin_unlock_irqrestore(&tp->tx_lock, flags);
		printk(KERN_ERR PFX "%s: BUG! Tx Ring full when queue awake!\n",
		       dev->name);
		return 1;
	}

	entry = tp->tx_prod;
	base_flags = 0;
	if (skb->ip_summed == CHECKSUM_HW)
		base_flags |= TXD_FLAG_TCPUDP_CSUM;
#if TG3_DO_TSO != 0
	if ((mss = skb_shinfo(skb)->tso_size) != 0)
		base_flags |= (TXD_FLAG_CPU_PRE_DMA |
			       TXD_FLAG_CPU_POST_DMA);
#else
	mss = 0;
#endif
#if TG3_VLAN_TAG_USED
	if (tp->vlgrp != NULL && vlan_tx_tag_present(skb))
		base_flags |= (TXD_FLAG_VLAN |
			       (vlan_tx_tag_get(skb) << 16));
#endif

	/* Queue skb data, a.k.a. the main skb fragment. */
	mapping = pci_map_single(tp->pdev, skb->data, len, PCI_DMA_TODEVICE);

	tp->tx_buffers[entry].skb = skb;
	pci_unmap_addr_set(&tp->tx_buffers[entry], mapping, mapping);

	tg3_set_txd(tp, entry, mapping, len, base_flags,
		    (skb_shinfo(skb)->nr_frags == 0) | (mss << 1));

	entry = NEXT_TX(entry);

	/* Now loop through additional data fragments, and queue them. */
	if (skb_shinfo(skb)->nr_frags > 0) {
		unsigned int i, last;

		last = skb_shinfo(skb)->nr_frags - 1;
		for (i = 0; i <= last; i++) {
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];


			len = frag->size;
			mapping = pci_map_page(tp->pdev,
					       frag->page,
					       frag->page_offset,
					       len, PCI_DMA_TODEVICE);

			tp->tx_buffers[entry].skb = NULL;
			pci_unmap_addr_set(&tp->tx_buffers[entry], mapping, mapping);

			tg3_set_txd(tp, entry, mapping, len,
				    base_flags, (i == last) | (mss << 1));

			entry = NEXT_TX(entry);
		}
	}

	/* Packets are ready, update Tx producer idx local and on card.
	 * We know this is not a 5700 (by virtue of not being a chip
	 * requiring the 4GB overflow workaround) so we can safely omit
	 * the double-write bug tests.
	 */
	if (tp->tg3_flags & TG3_FLAG_HOST_TXDS) {
		tw32_mailbox((MAILBOX_SNDHOST_PROD_IDX_0 +
			      TG3_64BIT_REG_LOW), entry);
		if (tp->tg3_flags & TG3_FLAG_MBOX_WRITE_REORDER)
			tr32(MAILBOX_SNDHOST_PROD_IDX_0 +
			     TG3_64BIT_REG_LOW);
	} else {
		/* First, make sure tg3 sees last descriptor fully
		 * in SRAM.
		 */
		if (tp->tg3_flags & TG3_FLAG_MBOX_WRITE_REORDER)
			tr32(MAILBOX_SNDNIC_PROD_IDX_0 +
			     TG3_64BIT_REG_LOW);

		tw32_mailbox((MAILBOX_SNDNIC_PROD_IDX_0 +
			      TG3_64BIT_REG_LOW), entry);

		/* Now post the mailbox write itself.  */
		if (tp->tg3_flags & TG3_FLAG_MBOX_WRITE_REORDER)
			tr32(MAILBOX_SNDNIC_PROD_IDX_0 +
			     TG3_64BIT_REG_LOW);
	}

	tp->tx_prod = entry;
	if (TX_BUFFS_AVAIL(tp) <= (MAX_SKB_FRAGS + 1))
		netif_stop_queue(dev);

	spin_unlock_irqrestore(&tp->tx_lock, flags);

	dev->trans_start = jiffies;

	return 0;
}

static inline void tg3_set_mtu(struct net_device *dev, struct tg3 *tp,
			       int new_mtu)
{
	dev->mtu = new_mtu;

	if (new_mtu > ETH_DATA_LEN)
		tp->tg3_flags |= TG3_FLAG_JUMBO_ENABLE;
	else
		tp->tg3_flags &= ~TG3_FLAG_JUMBO_ENABLE;
}

static int tg3_change_mtu(struct net_device *dev, int new_mtu)
{
	struct tg3 *tp = dev->priv;

	if (new_mtu < TG3_MIN_MTU || new_mtu > TG3_MAX_MTU)
		return -EINVAL;

	if (!netif_running(dev)) {
		/* We'll just catch it later when the
		 * device is up'd.
		 */
		tg3_set_mtu(dev, tp, new_mtu);
		return 0;
	}

	tg3_netif_stop(tp);
	spin_lock_irq(&tp->lock);
	spin_lock(&tp->tx_lock);

	tg3_halt(tp);

	tg3_set_mtu(dev, tp, new_mtu);

	tg3_init_rings(tp);
	tg3_init_hw(tp);

	spin_unlock(&tp->tx_lock);
	spin_unlock_irq(&tp->lock);
	tg3_netif_start(tp);

	return 0;
}

/* Free up pending packets in all rx/tx rings.
 *
 * The chip has been shut down and the driver detached from
 * the networking, so no interrupts or new tx packets will
 * end up in the driver.  tp->{tx,}lock is not held and we are not
 * in an interrupt context and thus may sleep.
 */
static void tg3_free_rings(struct tg3 *tp)
{
	struct ring_info *rxp;
	int i;

	for (i = 0; i < TG3_RX_RING_SIZE; i++) {
		rxp = &tp->rx_std_buffers[i];

		if (rxp->skb == NULL)
			continue;
		pci_unmap_single(tp->pdev,
				 pci_unmap_addr(rxp, mapping),
				 RX_PKT_BUF_SZ - tp->rx_offset,
				 PCI_DMA_FROMDEVICE);
		dev_kfree_skb_any(rxp->skb);
		rxp->skb = NULL;
	}

	for (i = 0; i < TG3_RX_JUMBO_RING_SIZE; i++) {
		rxp = &tp->rx_jumbo_buffers[i];

		if (rxp->skb == NULL)
			continue;
		pci_unmap_single(tp->pdev,
				 pci_unmap_addr(rxp, mapping),
				 RX_JUMBO_PKT_BUF_SZ - tp->rx_offset,
				 PCI_DMA_FROMDEVICE);
		dev_kfree_skb_any(rxp->skb);
		rxp->skb = NULL;
	}

	for (i = 0; i < TG3_TX_RING_SIZE; ) {
		struct tx_ring_info *txp;
		struct sk_buff *skb;
		int j;

		txp = &tp->tx_buffers[i];
		skb = txp->skb;

		if (skb == NULL) {
			i++;
			continue;
		}

		pci_unmap_single(tp->pdev,
				 pci_unmap_addr(txp, mapping),
				 (skb->len - skb->data_len),
				 PCI_DMA_TODEVICE);
		txp->skb = NULL;

		i++;

		for (j = 0; j < skb_shinfo(skb)->nr_frags; j++) {
			txp = &tp->tx_buffers[i & (TG3_TX_RING_SIZE - 1)];
			pci_unmap_page(tp->pdev,
				       pci_unmap_addr(txp, mapping),
				       skb_shinfo(skb)->frags[j].size,
				       PCI_DMA_TODEVICE);
			i++;
		}

		dev_kfree_skb_any(skb);
	}
}

/* Initialize tx/rx rings for packet processing.
 *
 * The chip has been shut down and the driver detached from
 * the networking, so no interrupts or new tx packets will
 * end up in the driver.  tp->{tx,}lock is not held and we are not
 * in an interrupt context and thus may sleep.
 */
static void tg3_init_rings(struct tg3 *tp)
{
	unsigned long start, end;
	u32 i;

	/* Free up all the SKBs. */
	tg3_free_rings(tp);

	/* Zero out all descriptors. */
	memset(tp->rx_std, 0, TG3_RX_RING_BYTES);
	memset(tp->rx_jumbo, 0, TG3_RX_JUMBO_RING_BYTES);
	memset(tp->rx_rcb, 0, TG3_RX_RCB_RING_BYTES);

	if (tp->tg3_flags & TG3_FLAG_HOST_TXDS) {
		memset(tp->tx_ring, 0, TG3_TX_RING_BYTES);
	} else {
		start = (tp->regs +
			 NIC_SRAM_WIN_BASE +
			 NIC_SRAM_TX_BUFFER_DESC);
		end = start + TG3_TX_RING_BYTES;
		while (start < end) {
			writel(0, start);
			start += 4;
		}
		for (i = 0; i < TG3_TX_RING_SIZE; i++)
			tp->tx_buffers[i].prev_vlan_tag = 0;
	}

	/* Initialize invariants of the rings, we only set this
	 * stuff once.  This works because the card does not
	 * write into the rx buffer posting rings.
	 */
	for (i = 0; i < TG3_RX_RING_SIZE; i++) {
		struct tg3_rx_buffer_desc *rxd;

		rxd = &tp->rx_std[i];
		rxd->idx_len = (RX_PKT_BUF_SZ - tp->rx_offset - 64)
			<< RXD_LEN_SHIFT;
		rxd->type_flags = (RXD_FLAG_END << RXD_FLAGS_SHIFT);
		rxd->opaque = (RXD_OPAQUE_RING_STD |
			       (i << RXD_OPAQUE_INDEX_SHIFT));
	}

	if (tp->tg3_flags & TG3_FLAG_JUMBO_ENABLE) {
		for (i = 0; i < TG3_RX_JUMBO_RING_SIZE; i++) {
			struct tg3_rx_buffer_desc *rxd;

			rxd = &tp->rx_jumbo[i];
			rxd->idx_len = (RX_JUMBO_PKT_BUF_SZ - tp->rx_offset - 64)
				<< RXD_LEN_SHIFT;
			rxd->type_flags = (RXD_FLAG_END << RXD_FLAGS_SHIFT) |
				RXD_FLAG_JUMBO;
			rxd->opaque = (RXD_OPAQUE_RING_JUMBO |
			       (i << RXD_OPAQUE_INDEX_SHIFT));
		}
	}

	/* Now allocate fresh SKBs for each rx ring. */
	for (i = 0; i < tp->rx_pending; i++) {
		if (tg3_alloc_rx_skb(tp, RXD_OPAQUE_RING_STD,
				     -1, i) < 0)
			break;
	}

	if (tp->tg3_flags & TG3_FLAG_JUMBO_ENABLE) {
		for (i = 0; i < tp->rx_jumbo_pending; i++) {
			if (tg3_alloc_rx_skb(tp, RXD_OPAQUE_RING_JUMBO,
					     -1, i) < 0)
				break;
		}
	}
}

/*
 * Must not be invoked with interrupt sources disabled and
 * the hardware shutdown down.
 */
static void tg3_free_consistent(struct tg3 *tp)
{
	if (tp->rx_std_buffers) {
		kfree(tp->rx_std_buffers);
		tp->rx_std_buffers = NULL;
	}
	if (tp->rx_std) {
		pci_free_consistent(tp->pdev, TG3_RX_RING_BYTES,
				    tp->rx_std, tp->rx_std_mapping);
		tp->rx_std = NULL;
	}
	if (tp->rx_jumbo) {
		pci_free_consistent(tp->pdev, TG3_RX_JUMBO_RING_BYTES,
				    tp->rx_jumbo, tp->rx_jumbo_mapping);
		tp->rx_jumbo = NULL;
	}
	if (tp->rx_rcb) {
		pci_free_consistent(tp->pdev, TG3_RX_RCB_RING_BYTES,
				    tp->rx_rcb, tp->rx_rcb_mapping);
		tp->rx_rcb = NULL;
	}
	if (tp->tx_ring) {
		pci_free_consistent(tp->pdev, TG3_TX_RING_BYTES,
			tp->tx_ring, tp->tx_desc_mapping);
		tp->tx_ring = NULL;
	}
	if (tp->hw_status) {
		pci_free_consistent(tp->pdev, TG3_HW_STATUS_SIZE,
				    tp->hw_status, tp->status_mapping);
		tp->hw_status = NULL;
	}
	if (tp->hw_stats) {
		pci_free_consistent(tp->pdev, sizeof(struct tg3_hw_stats),
				    tp->hw_stats, tp->stats_mapping);
		tp->hw_stats = NULL;
	}
}

/*
 * Must not be invoked with interrupt sources disabled and
 * the hardware shutdown down.  Can sleep.
 */
static int tg3_alloc_consistent(struct tg3 *tp)
{
	tp->rx_std_buffers = kmalloc((sizeof(struct ring_info) *
				      (TG3_RX_RING_SIZE +
				       TG3_RX_JUMBO_RING_SIZE)) +
				     (sizeof(struct tx_ring_info) *
				      TG3_TX_RING_SIZE),
				     GFP_KERNEL);
	if (!tp->rx_std_buffers)
		return -ENOMEM;

	memset(tp->rx_std_buffers, 0,
	       (sizeof(struct ring_info) *
		(TG3_RX_RING_SIZE +
		 TG3_RX_JUMBO_RING_SIZE)) +
	       (sizeof(struct tx_ring_info) *
		TG3_TX_RING_SIZE));

	tp->rx_jumbo_buffers = &tp->rx_std_buffers[TG3_RX_RING_SIZE];
	tp->tx_buffers = (struct tx_ring_info *)
		&tp->rx_jumbo_buffers[TG3_RX_JUMBO_RING_SIZE];

	tp->rx_std = pci_alloc_consistent(tp->pdev, TG3_RX_RING_BYTES,
					  &tp->rx_std_mapping);
	if (!tp->rx_std)
		goto err_out;

	tp->rx_jumbo = pci_alloc_consistent(tp->pdev, TG3_RX_JUMBO_RING_BYTES,
					    &tp->rx_jumbo_mapping);

	if (!tp->rx_jumbo)
		goto err_out;

	tp->rx_rcb = pci_alloc_consistent(tp->pdev, TG3_RX_RCB_RING_BYTES,
					  &tp->rx_rcb_mapping);
	if (!tp->rx_rcb)
		goto err_out;

	if (tp->tg3_flags & TG3_FLAG_HOST_TXDS) {
		tp->tx_ring = pci_alloc_consistent(tp->pdev, TG3_TX_RING_BYTES,
						   &tp->tx_desc_mapping);
		if (!tp->tx_ring)
			goto err_out;
	} else {
		tp->tx_ring = NULL;
		tp->tx_desc_mapping = 0;
	}

	tp->hw_status = pci_alloc_consistent(tp->pdev,
					     TG3_HW_STATUS_SIZE,
					     &tp->status_mapping);
	if (!tp->hw_status)
		goto err_out;

	tp->hw_stats = pci_alloc_consistent(tp->pdev,
					    sizeof(struct tg3_hw_stats),
					    &tp->stats_mapping);
	if (!tp->hw_stats)
		goto err_out;

	memset(tp->hw_status, 0, TG3_HW_STATUS_SIZE);
	memset(tp->hw_stats, 0, sizeof(struct tg3_hw_stats));

	return 0;

err_out:
	tg3_free_consistent(tp);
	return -ENOMEM;
}

#define MAX_WAIT_CNT 1000

/* To stop a block, clear the enable bit and poll till it
 * clears.  tp->lock is held.
 */
static int tg3_stop_block(struct tg3 *tp, unsigned long ofs, u32 enable_bit)
{
	unsigned int i;
	u32 val;

	val = tr32(ofs);
	val &= ~enable_bit;
	tw32(ofs, val);
	tr32(ofs);

	for (i = 0; i < MAX_WAIT_CNT; i++) {
		udelay(100);
		val = tr32(ofs);
		if ((val & enable_bit) == 0)
			break;
	}

	if (i == MAX_WAIT_CNT) {
		printk(KERN_ERR PFX "tg3_stop_block timed out, "
		       "ofs=%lx enable_bit=%x\n",
		       ofs, enable_bit);
		return -ENODEV;
	}

	return 0;
}

/* tp->lock is held. */
static int tg3_abort_hw(struct tg3 *tp)
{
	int i, err;

	tg3_disable_ints(tp);

	tp->rx_mode &= ~RX_MODE_ENABLE;
	tw32(MAC_RX_MODE, tp->rx_mode);
	tr32(MAC_RX_MODE);
	udelay(10);

	err  = tg3_stop_block(tp, RCVBDI_MODE, RCVBDI_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVLPC_MODE, RCVLPC_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVLSC_MODE, RCVLSC_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVDBDI_MODE, RCVDBDI_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVDCC_MODE, RCVDCC_MODE_ENABLE);
	err |= tg3_stop_block(tp, RCVCC_MODE, RCVCC_MODE_ENABLE);

	err |= tg3_stop_block(tp, SNDBDS_MODE, SNDBDS_MODE_ENABLE);
	err |= tg3_stop_block(tp, SNDBDI_MODE, SNDBDI_MODE_ENABLE);
	err |= tg3_stop_block(tp, SNDDATAI_MODE, SNDDATAI_MODE_ENABLE);
	err |= tg3_stop_block(tp, RDMAC_MODE, RDMAC_MODE_ENABLE);
	err |= tg3_stop_block(tp, SNDDATAC_MODE, SNDDATAC_MODE_ENABLE);
	err |= tg3_stop_block(tp, SNDBDC_MODE, SNDBDC_MODE_ENABLE);
	if (err)
		goto out;

	tp->mac_mode &= ~MAC_MODE_TDE_ENABLE;
	tw32(MAC_MODE, tp->mac_mode);
	tr32(MAC_MODE);
	udelay(40);

	tp->tx_mode &= ~TX_MODE_ENABLE;
	tw32(MAC_TX_MODE, tp->tx_mode);
	tr32(MAC_TX_MODE);

	for (i = 0; i < MAX_WAIT_CNT; i++) {
		udelay(100);
		if (!(tr32(MAC_TX_MODE) & TX_MODE_ENABLE))
			break;
	}
	if (i >= MAX_WAIT_CNT) {
		printk(KERN_ERR PFX "tg3_abort_hw timed out for %s, "
		       "TX_MODE_ENABLE will not clear MAC_TX_MODE=%08x\n",
		       tp->dev->name, tr32(MAC_TX_MODE));
		return -ENODEV;
	}

	err  = tg3_stop_block(tp, HOSTCC_MODE, HOSTCC_MODE_ENABLE);
	err |= tg3_stop_block(tp, WDMAC_MODE, WDMAC_MODE_ENABLE);
	err |= tg3_stop_block(tp, MBFREE_MODE, MBFREE_MODE_ENABLE);

	tw32(FTQ_RESET, 0xffffffff);
	tw32(FTQ_RESET, 0x00000000);

	err |= tg3_stop_block(tp, BUFMGR_MODE, BUFMGR_MODE_ENABLE);
	err |= tg3_stop_block(tp, MEMARB_MODE, MEMARB_MODE_ENABLE);
	if (err)
		goto out;

	memset(tp->hw_status, 0, TG3_HW_STATUS_SIZE);

out:
	return err;
}

/* tp->lock is held. */
static void tg3_chip_reset(struct tg3 *tp)
{
	u32 val;
	u32 flags_save;

	/* Force NVRAM to settle.
	 * This deals with a chip bug which can result in EEPROM
	 * corruption.
	 */
	if (tp->tg3_flags & TG3_FLAG_NVRAM) {
		int i;

		tw32(NVRAM_SWARB, SWARB_REQ_SET1);
		for (i = 0; i < 100000; i++) {
			if (tr32(NVRAM_SWARB) & SWARB_GNT1)
				break;
			udelay(10);
		}
	}

	/*
	 * We must avoid the readl() that normally takes place.
	 * It locks machines, causes machine checks, and other
	 * fun things.  So, temporarily disable the 5701
	 * hardware workaround, while we do the reset.
	 */
	flags_save = tp->tg3_flags;
	tp->tg3_flags &= ~TG3_FLAG_5701_REG_WRITE_BUG;

	/* do the reset */
	tw32(GRC_MISC_CFG, GRC_MISC_CFG_CORECLK_RESET);

	/* restore 5701 hardware bug workaround flag */
	tp->tg3_flags = flags_save;

	/* Flush PCI posted writes.  The normal MMIO registers
	 * are inaccessible at this time so this is the only
	 * way to make this reliably.  I tried to use indirect
	 * register read/write but this upset some 5701 variants.
	 */
	pci_read_config_dword(tp->pdev, PCI_COMMAND, &val);

	udelay(40);
	udelay(40);
	udelay(40);

	/* Re-enable indirect register accesses. */
	pci_write_config_dword(tp->pdev, TG3PCI_MISC_HOST_CTRL,
			       tp->misc_host_ctrl);

	/* Set MAX PCI retry to zero. */
	val = (PCISTATE_ROM_ENABLE | PCISTATE_ROM_RETRY_ENABLE);
	if (tp->pci_chip_rev_id == CHIPREV_ID_5704_A0 &&
	    (tp->tg3_flags & TG3_FLAG_PCIX_MODE))
		val |= PCISTATE_RETRY_SAME_DMA;
	pci_write_config_dword(tp->pdev, TG3PCI_PCISTATE, val);

	pci_restore_state(tp->pdev, tp->pci_cfg_state);

	/* Make sure PCI-X relaxed ordering bit is clear. */
	pci_read_config_dword(tp->pdev, TG3PCI_X_CAPS, &val);
	val &= ~PCIX_CAPS_RELAXED_ORDERING;
	pci_write_config_dword(tp->pdev, TG3PCI_X_CAPS, val);

	tw32(MEMARB_MODE, MEMARB_MODE_ENABLE);

	tw32(TG3PCI_MISC_HOST_CTRL, tp->misc_host_ctrl);
}

/* tp->lock is held. */
static void tg3_stop_fw(struct tg3 *tp)
{
	if (tp->tg3_flags & TG3_FLAG_ENABLE_ASF) {
		u32 val;
		int i;

		tg3_write_mem(tp, NIC_SRAM_FW_CMD_MBOX, FWCMD_NICDRV_PAUSE_FW);
		val = tr32(GRC_RX_CPU_EVENT);
		val |= (1 << 14);
		tw32(GRC_RX_CPU_EVENT, val);

		/* Wait for RX cpu to ACK the event.  */
		for (i = 0; i < 100; i++) {
			if (!(tr32(GRC_RX_CPU_EVENT) & (1 << 14)))
				break;
			udelay(1);
		}
	}
}

/* tp->lock is held. */
static int tg3_halt(struct tg3 *tp)
{
	u32 val;
	int i;

	tg3_stop_fw(tp);
	tg3_abort_hw(tp);
	tg3_chip_reset(tp);
	tg3_write_mem(tp,
		      NIC_SRAM_FIRMWARE_MBOX,
		      NIC_SRAM_FIRMWARE_MBOX_MAGIC1);
	for (i = 0; i < 100000; i++) {
		tg3_read_mem(tp, NIC_SRAM_FIRMWARE_MBOX, &val);
		if (val == ~NIC_SRAM_FIRMWARE_MBOX_MAGIC1)
			break;
		udelay(10);
	}

	if (i >= 100000) {
		printk(KERN_ERR PFX "tg3_halt timed out for %s, "
		       "firmware will not restart magic=%08x\n",
		       tp->dev->name, val);
		return -ENODEV;
	}

	if (tp->tg3_flags & TG3_FLAG_ENABLE_ASF) {
		if (tp->tg3_flags & TG3_FLAG_WOL_ENABLE)
			tg3_write_mem(tp, NIC_SRAM_FW_DRV_STATE_MBOX,
				      DRV_STATE_WOL);
		else
			tg3_write_mem(tp, NIC_SRAM_FW_DRV_STATE_MBOX,
				      DRV_STATE_UNLOAD);
	} else
		tg3_write_mem(tp, NIC_SRAM_FW_DRV_STATE_MBOX,
			      DRV_STATE_SUSPEND);

	return 0;
}

#define TG3_FW_RELEASE_MAJOR	0x0
#define TG3_FW_RELASE_MINOR	0x0
#define TG3_FW_RELEASE_FIX	0x0
#define TG3_FW_START_ADDR	0x08000000
#define TG3_FW_TEXT_ADDR	0x08000000
#define TG3_FW_TEXT_LEN		0x9c0
#define TG3_FW_RODATA_ADDR	0x080009c0
#define TG3_FW_RODATA_LEN	0x60
#define TG3_FW_DATA_ADDR	0x08000a40
#define TG3_FW_DATA_LEN		0x20
#define TG3_FW_SBSS_ADDR	0x08000a60
#define TG3_FW_SBSS_LEN		0xc
#define TG3_FW_BSS_ADDR		0x08000a70
#define TG3_FW_BSS_LEN		0x10

static u32 tg3FwText[(TG3_FW_TEXT_LEN / sizeof(u32)) + 1] = {
	0x00000000, 0x10000003, 0x00000000, 0x0000000d, 0x0000000d, 0x3c1d0800,
	0x37bd3ffc, 0x03a0f021, 0x3c100800, 0x26100000, 0x0e000018, 0x00000000,
	0x0000000d, 0x3c1d0800, 0x37bd3ffc, 0x03a0f021, 0x3c100800, 0x26100034,
	0x0e00021c, 0x00000000, 0x0000000d, 0x00000000, 0x00000000, 0x00000000,
	0x27bdffe0, 0x3c1cc000, 0xafbf0018, 0xaf80680c, 0x0e00004c, 0x241b2105,
	0x97850000, 0x97870002, 0x9782002c, 0x9783002e, 0x3c040800, 0x248409c0,
	0xafa00014, 0x00021400, 0x00621825, 0x00052c00, 0xafa30010, 0x8f860010,
	0x00e52825, 0x0e000060, 0x24070102, 0x3c02ac00, 0x34420100, 0x3c03ac01,
	0x34630100, 0xaf820490, 0x3c02ffff, 0xaf820494, 0xaf830498, 0xaf82049c,
	0x24020001, 0xaf825ce0, 0x0e00003f, 0xaf825d00, 0x0e000140, 0x00000000,
	0x8fbf0018, 0x03e00008, 0x27bd0020, 0x2402ffff, 0xaf825404, 0x8f835400,
	0x34630400, 0xaf835400, 0xaf825404, 0x3c020800, 0x24420034, 0xaf82541c,
	0x03e00008, 0xaf805400, 0x00000000, 0x00000000, 0x3c020800, 0x34423000,
	0x3c030800, 0x34633000, 0x3c040800, 0x348437ff, 0x3c010800, 0xac220a64,
	0x24020040, 0x3c010800, 0xac220a68, 0x3c010800, 0xac200a60, 0xac600000,
	0x24630004, 0x0083102b, 0x5040fffd, 0xac600000, 0x03e00008, 0x00000000,
	0x00804821, 0x8faa0010, 0x3c020800, 0x8c420a60, 0x3c040800, 0x8c840a68,
	0x8fab0014, 0x24430001, 0x0044102b, 0x3c010800, 0xac230a60, 0x14400003,
	0x00004021, 0x3c010800, 0xac200a60, 0x3c020800, 0x8c420a60, 0x3c030800,
	0x8c630a64, 0x91240000, 0x00021140, 0x00431021, 0x00481021, 0x25080001,
	0xa0440000, 0x29020008, 0x1440fff4, 0x25290001, 0x3c020800, 0x8c420a60,
	0x3c030800, 0x8c630a64, 0x8f84680c, 0x00021140, 0x00431021, 0xac440008,
	0xac45000c, 0xac460010, 0xac470014, 0xac4a0018, 0x03e00008, 0xac4b001c,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0,
	0x02000008, 0x00000000, 0x0a0001e3, 0x3c0a0001, 0x0a0001e3, 0x3c0a0002,
	0x0a0001e3, 0x00000000, 0x0a0001e3, 0x00000000, 0x0a0001e3, 0x00000000,
	0x0a0001e3, 0x00000000, 0x0a0001e3, 0x00000000, 0x0a0001e3, 0x00000000,
	0x0a0001e3, 0x00000000, 0x0a0001e3, 0x00000000, 0x0a0001e3, 0x00000000,
	0x0a0001e3, 0x3c0a0007, 0x0a0001e3, 0x3c0a0008, 0x0a0001e3, 0x3c0a0009,
	0x0a0001e3, 0x00000000, 0x0a0001e3, 0x00000000, 0x0a0001e3, 0x3c0a000b,
	0x0a0001e3, 0x3c0a000c, 0x0a0001e3, 0x3c0a000d, 0x0a0001e3, 0x00000000,
	0x0a0001e3, 0x00000000, 0x0a0001e3, 0x3c0a000e, 0x0a0001e3, 0x00000000,
	0x0a0001e3, 0x00000000, 0x0a0001e3, 0x00000000, 0x0a0001e3, 0x00000000,
	0x0a0001e3, 0x00000000, 0x0a0001e3, 0x00000000, 0x0a0001e3, 0x00000000,
	0x0a0001e3, 0x00000000, 0x0a0001e3, 0x3c0a0013, 0x0a0001e3, 0x3c0a0014,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0x27bdffe0, 0x00001821, 0x00001021, 0xafbf0018, 0xafb10014, 0xafb00010,
	0x3c010800, 0x00220821, 0xac200a70, 0x3c010800, 0x00220821, 0xac200a74,
	0x3c010800, 0x00220821, 0xac200a78, 0x24630001, 0x1860fff5, 0x2442000c,
	0x24110001, 0x8f906810, 0x32020004, 0x14400005, 0x24040001, 0x3c020800,
	0x8c420a78, 0x18400003, 0x00002021, 0x0e000182, 0x00000000, 0x32020001,
	0x10400003, 0x00000000, 0x0e000169, 0x00000000, 0x0a000153, 0xaf915028,
	0x8fbf0018, 0x8fb10014, 0x8fb00010, 0x03e00008, 0x27bd0020, 0x3c050800,
	0x8ca50a70, 0x3c060800, 0x8cc60a80, 0x3c070800, 0x8ce70a78, 0x27bdffe0,
	0x3c040800, 0x248409d0, 0xafbf0018, 0xafa00010, 0x0e000060, 0xafa00014,
	0x0e00017b, 0x00002021, 0x8fbf0018, 0x03e00008, 0x27bd0020, 0x24020001,
	0x8f836810, 0x00821004, 0x00021027, 0x00621824, 0x03e00008, 0xaf836810,
	0x27bdffd8, 0xafbf0024, 0x1080002e, 0xafb00020, 0x8f825cec, 0xafa20018,
	0x8f825cec, 0x3c100800, 0x26100a78, 0xafa2001c, 0x34028000, 0xaf825cec,
	0x8e020000, 0x18400016, 0x00000000, 0x3c020800, 0x94420a74, 0x8fa3001c,
	0x000221c0, 0xac830004, 0x8fa2001c, 0x3c010800, 0x0e000201, 0xac220a74,
	0x10400005, 0x00000000, 0x8e020000, 0x24420001, 0x0a0001df, 0xae020000,
	0x3c020800, 0x8c420a70, 0x00021c02, 0x000321c0, 0x0a0001c5, 0xafa2001c,
	0x0e000201, 0x00000000, 0x1040001f, 0x00000000, 0x8e020000, 0x8fa3001c,
	0x24420001, 0x3c010800, 0xac230a70, 0x3c010800, 0xac230a74, 0x0a0001df,
	0xae020000, 0x3c100800, 0x26100a78, 0x8e020000, 0x18400028, 0x00000000,
	0x0e000201, 0x00000000, 0x14400024, 0x00000000, 0x8e020000, 0x3c030800,
	0x8c630a70, 0x2442ffff, 0xafa3001c, 0x18400006, 0xae020000, 0x00031402,
	0x000221c0, 0x8c820004, 0x3c010800, 0xac220a70, 0x97a2001e, 0x2442ff00,
	0x2c420300, 0x1440000b, 0x24024000, 0x3c040800, 0x248409dc, 0xafa00010,
	0xafa00014, 0x8fa6001c, 0x24050008, 0x0e000060, 0x00003821, 0x0a0001df,
	0x00000000, 0xaf825cf8, 0x3c020800, 0x8c420a40, 0x8fa3001c, 0x24420001,
	0xaf835cf8, 0x3c010800, 0xac220a40, 0x8fbf0024, 0x8fb00020, 0x03e00008,
	0x27bd0028, 0x27bdffe0, 0x3c040800, 0x248409e8, 0x00002821, 0x00003021,
	0x00003821, 0xafbf0018, 0xafa00010, 0x0e000060, 0xafa00014, 0x8fbf0018,
	0x03e00008, 0x27bd0020, 0x8f82680c, 0x8f85680c, 0x00021827, 0x0003182b,
	0x00031823, 0x00431024, 0x00441021, 0x00a2282b, 0x10a00006, 0x00000000,
	0x00401821, 0x8f82680c, 0x0043102b, 0x1440fffd, 0x00000000, 0x03e00008,
	0x00000000, 0x3c040800, 0x8c840000, 0x3c030800, 0x8c630a40, 0x0064102b,
	0x54400002, 0x00831023, 0x00641023, 0x2c420008, 0x03e00008, 0x38420001,
	0x27bdffe0, 0x00802821, 0x3c040800, 0x24840a00, 0x00003021, 0x00003821,
	0xafbf0018, 0xafa00010, 0x0e000060, 0xafa00014, 0x0a000216, 0x00000000,
	0x8fbf0018, 0x03e00008, 0x27bd0020, 0x00000000, 0x27bdffe0, 0x3c1cc000,
	0xafbf0018, 0x0e00004c, 0xaf80680c, 0x3c040800, 0x24840a10, 0x03802821,
	0x00003021, 0x00003821, 0xafa00010, 0x0e000060, 0xafa00014, 0x2402ffff,
	0xaf825404, 0x3c0200aa, 0x0e000234, 0xaf825434, 0x8fbf0018, 0x03e00008,
	0x27bd0020, 0x00000000, 0x00000000, 0x00000000, 0x27bdffe8, 0xafb00010,
	0x24100001, 0xafbf0014, 0x3c01c003, 0xac200000, 0x8f826810, 0x30422000,
	0x10400003, 0x00000000, 0x0e000246, 0x00000000, 0x0a00023a, 0xaf905428,
	0x8fbf0014, 0x8fb00010, 0x03e00008, 0x27bd0018, 0x27bdfff8, 0x8f845d0c,
	0x3c0200ff, 0x3c030800, 0x8c630a50, 0x3442fff8, 0x00821024, 0x1043001e,
	0x3c0500ff, 0x34a5fff8, 0x3c06c003, 0x3c074000, 0x00851824, 0x8c620010,
	0x3c010800, 0xac230a50, 0x30420008, 0x10400005, 0x00871025, 0x8cc20000,
	0x24420001, 0xacc20000, 0x00871025, 0xaf825d0c, 0x8fa20000, 0x24420001,
	0xafa20000, 0x8fa20000, 0x8fa20000, 0x24420001, 0xafa20000, 0x8fa20000,
	0x8f845d0c, 0x3c030800, 0x8c630a50, 0x00851024, 0x1443ffe8, 0x00851824,
	0x27bd0008, 0x03e00008, 0x00000000, 0x00000000, 0x00000000
};

static u32 tg3FwRodata[(TG3_FW_RODATA_LEN / sizeof(u32)) + 1] = {
	0x35373031, 0x726c7341, 0x00000000, 0x00000000, 0x53774576, 0x656e7430,
	0x00000000, 0x726c7045, 0x76656e74, 0x31000000, 0x556e6b6e, 0x45766e74,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x66617461, 0x6c457272,
	0x00000000, 0x00000000, 0x4d61696e, 0x43707542, 0x00000000, 0x00000000,
	0x00000000
};

#if 0 /* All zeros, dont eat up space with it. */
u32 tg3FwData[(TG3_FW_DATA_LEN / sizeof(u32)) + 1] = {
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000
};
#endif

#define RX_CPU_SCRATCH_BASE	0x30000
#define RX_CPU_SCRATCH_SIZE	0x04000
#define TX_CPU_SCRATCH_BASE	0x34000
#define TX_CPU_SCRATCH_SIZE	0x04000

/* tp->lock is held. */
static int tg3_reset_cpu(struct tg3 *tp, u32 offset)
{
	int i;

	tw32(offset + CPU_STATE, 0xffffffff);
	tw32(offset + CPU_MODE,  CPU_MODE_RESET);
	if (offset == RX_CPU_BASE) {
		for (i = 0; i < 10000; i++)
			if (!(tr32(offset + CPU_MODE) & CPU_MODE_RESET))
				break;
		tw32(offset + CPU_STATE, 0xffffffff);
		tw32(offset + CPU_MODE,  CPU_MODE_RESET);
		tr32(offset + CPU_MODE);
		udelay(10);
	} else {
		for (i = 0; i < 10000; i++) {
			if (!(tr32(offset + CPU_MODE) & CPU_MODE_RESET))
				break;
			tw32(offset + CPU_STATE, 0xffffffff);
			tw32(offset + CPU_MODE,  CPU_MODE_RESET);
			tr32(offset + CPU_MODE);
			udelay(10);
		}
	}

	if (i >= 10000) {
		printk(KERN_ERR PFX "tg3_reset_cpu timed out for %s, "
		       "and %s CPU\n",
		       tp->dev->name,
		       (offset == RX_CPU_BASE ? "RX" : "TX"));
		return -ENODEV;
	}
	return 0;
}

struct fw_info {
	unsigned int text_base;
	unsigned int text_len;
	u32 *text_data;
	unsigned int rodata_base;
	unsigned int rodata_len;
	u32 *rodata_data;
	unsigned int data_base;
	unsigned int data_len;
	u32 *data_data;
};

/* tp->lock is held. */
static int tg3_load_firmware_cpu(struct tg3 *tp, u32 cpu_base, u32 cpu_scratch_base,
				 int cpu_scratch_size, struct fw_info *info)
{
	int err, i;
	u32 orig_tg3_flags = tp->tg3_flags;

	/* Force use of PCI config space for indirect register
	 * write calls.
	 */
	tp->tg3_flags |= TG3_FLAG_PCIX_TARGET_HWBUG;

	err = tg3_reset_cpu(tp, cpu_base);
	if (err)
		goto out;

	for (i = 0; i < cpu_scratch_size; i += sizeof(u32))
		tg3_write_indirect_reg32(tp, cpu_scratch_base + i, 0);
	tw32(cpu_base + CPU_STATE, 0xffffffff);
	tw32(cpu_base + CPU_MODE, tr32(cpu_base+CPU_MODE)|CPU_MODE_HALT);
	for (i = 0; i < (info->text_len / sizeof(u32)); i++)
		tg3_write_indirect_reg32(tp, (cpu_scratch_base +
					      (info->text_base & 0xffff) +
					      (i * sizeof(u32))),
					 (info->text_data ?
					  info->text_data[i] : 0));
	for (i = 0; i < (info->rodata_len / sizeof(u32)); i++)
		tg3_write_indirect_reg32(tp, (cpu_scratch_base +
					      (info->rodata_base & 0xffff) +
					      (i * sizeof(u32))),
					 (info->rodata_data ?
					  info->rodata_data[i] : 0));
	for (i = 0; i < (info->data_len / sizeof(u32)); i++)
		tg3_write_indirect_reg32(tp, (cpu_scratch_base +
					      (info->data_base & 0xffff) +
					      (i * sizeof(u32))),
					 (info->data_data ?
					  info->data_data[i] : 0));

	err = 0;

out:
	tp->tg3_flags = orig_tg3_flags;
	return err;
}

/* tp->lock is held. */
static int tg3_load_5701_a0_firmware_fix(struct tg3 *tp)
{
	struct fw_info info;
	int err, i;

	info.text_base = TG3_FW_TEXT_ADDR;
	info.text_len = TG3_FW_TEXT_LEN;
	info.text_data = &tg3FwText[0];
	info.rodata_base = TG3_FW_RODATA_ADDR;
	info.rodata_len = TG3_FW_RODATA_LEN;
	info.rodata_data = &tg3FwRodata[0];
	info.data_base = TG3_FW_DATA_ADDR;
	info.data_len = TG3_FW_DATA_LEN;
	info.data_data = NULL;

	err = tg3_load_firmware_cpu(tp, RX_CPU_BASE,
				    RX_CPU_SCRATCH_BASE, RX_CPU_SCRATCH_SIZE,
				    &info);
	if (err)
		return err;

	err = tg3_load_firmware_cpu(tp, TX_CPU_BASE,
				    TX_CPU_SCRATCH_BASE, TX_CPU_SCRATCH_SIZE,
				    &info);
	if (err)
		return err;

	/* Now startup only the RX cpu. */
	tw32(RX_CPU_BASE + CPU_STATE, 0xffffffff);
	tw32(RX_CPU_BASE + CPU_PC,    TG3_FW_TEXT_ADDR);

	/* Flush posted writes. */
	tr32(RX_CPU_BASE + CPU_PC);
	for (i = 0; i < 5; i++) {
		if (tr32(RX_CPU_BASE + CPU_PC) == TG3_FW_TEXT_ADDR)
			break;
		tw32(RX_CPU_BASE + CPU_STATE, 0xffffffff);
		tw32(RX_CPU_BASE + CPU_MODE,  CPU_MODE_HALT);
		tw32(RX_CPU_BASE + CPU_PC,    TG3_FW_TEXT_ADDR);

		/* Flush posted writes. */
		tr32(RX_CPU_BASE + CPU_PC);

		udelay(1000);
	}
	if (i >= 5) {
		printk(KERN_ERR PFX "tg3_load_firmware fails for %s "
		       "to set RX CPU PC, is %08x should be %08x\n",
		       tp->dev->name, tr32(RX_CPU_BASE + CPU_PC),
		       TG3_FW_TEXT_ADDR);
		return -ENODEV;
	}
	tw32(RX_CPU_BASE + CPU_STATE, 0xffffffff);
	tw32(RX_CPU_BASE + CPU_MODE,  0x00000000);

	/* Flush posted writes. */
	tr32(RX_CPU_BASE + CPU_MODE);

	return 0;
}

#if TG3_DO_TSO != 0

#define TG3_TSO_FW_RELEASE_MAJOR	0x1
#define TG3_TSO_FW_RELASE_MINOR		0x8
#define TG3_TSO_FW_RELEASE_FIX		0x0
#define TG3_TSO_FW_START_ADDR		0x08000000
#define TG3_TSO_FW_TEXT_ADDR		0x08000000
#define TG3_TSO_FW_TEXT_LEN		0x1650
#define TG3_TSO_FW_RODATA_ADDR		0x08001650
#define TG3_TSO_FW_RODATA_LEN		0x30
#define TG3_TSO_FW_DATA_ADDR		0x080016a0
#define TG3_TSO_FW_DATA_LEN		0x20
#define TG3_TSO_FW_SBSS_ADDR		0x080016c0
#define TG3_TSO_FW_SBSS_LEN		0x14
#define TG3_TSO_FW_BSS_ADDR		0x080016e0
#define TG3_TSO_FW_BSS_LEN		0x8fc

static u32 tg3TsoFwText[] = {
	0x00000000, 0x10000003, 0x00000000, 0x0000000d, 0x0000000d, 0x3c1d0800,
	0x37bd4000, 0x03a0f021, 0x3c100800, 0x26100000, 0x0e000010, 0x00000000,
	0x0000000d, 0x00000000, 0x00000000, 0x00000000, 0x27bdffe0, 0x3c1bc000,
	0xafbf0018, 0x0e000058, 0xaf60680c, 0x3c040800, 0x24841650, 0x03602821,
	0x24060001, 0x24070004, 0xafa00010, 0x0e00006c, 0xafa00014, 0x8f625c50,
	0x34420001, 0xaf625c50, 0x8f625c90, 0x34420001, 0xaf625c90, 0x2402ffff,
	0x0e000098, 0xaf625404, 0x8fbf0018, 0x03e00008, 0x27bd0020, 0x00000000,
	0x00000000, 0x00000000, 0x24030b60, 0x24050fff, 0xac000b50, 0x00002021,
	0xac640000, 0x24630004, 0x0065102b, 0x1440fffc, 0x24840001, 0x24030b60,
	0x0065102b, 0x10400011, 0x00002021, 0x24090b54, 0x3c06dead, 0x34c6beef,
	0x24080b58, 0x24070b5c, 0x8c620000, 0x50440006, 0x24630004, 0xad260000,
	0x8c620000, 0xace40000, 0xad020000, 0x24630004, 0x0065102b, 0x1440fff6,
	0x24840001, 0x03e00008, 0x00000000, 0x27bdfff8, 0x18800009, 0x00002821,
	0x8f63680c, 0x8f62680c, 0x1043fffe, 0x00000000, 0x24a50001, 0x00a4102a,
	0x1440fff9, 0x00000000, 0x03e00008, 0x27bd0008, 0x3c020800, 0x34423000,
	0x3c030800, 0x34633000, 0x3c040800, 0x348437ff, 0x3c010800, 0xac2216c4,
	0x24020040, 0x3c010800, 0xac2216c8, 0x3c010800, 0xac2016c0, 0xac600000,
	0x24630004, 0x0083102b, 0x5040fffd, 0xac600000, 0x03e00008, 0x00000000,
	0x00804821, 0x8faa0010, 0x3c020800, 0x8c4216c0, 0x3c040800, 0x8c8416c8,
	0x8fab0014, 0x24430001, 0x0044102b, 0x3c010800, 0xac2316c0, 0x14400003,
	0x00004021, 0x3c010800, 0xac2016c0, 0x3c020800, 0x8c4216c0, 0x3c030800,
	0x8c6316c4, 0x91240000, 0x00021140, 0x00431021, 0x00481021, 0x25080001,
	0xa0440000, 0x29020008, 0x1440fff4, 0x25290001, 0x3c020800, 0x8c4216c0,
	0x3c030800, 0x8c6316c4, 0x8f64680c, 0x00021140, 0x00431021, 0xac440008,
	0xac45000c, 0xac460010, 0xac470014, 0xac4a0018, 0x03e00008, 0xac4b001c,
	0x00000000, 0x00000000, 0x27bdffe0, 0xafbf0018, 0xafb10014, 0x0e0000b6,
	0xafb00010, 0x24110001, 0x8f706820, 0x32020100, 0x10400003, 0x00000000,
	0x0e000127, 0x00000000, 0x8f706820, 0x32022000, 0x10400004, 0x32020001,
	0x0e00025a, 0x24040001, 0x32020001, 0x10400003, 0x00000000, 0x0e0000e6,
	0x00000000, 0x0a00009e, 0xaf715028, 0x8fbf0018, 0x8fb10014, 0x8fb00010,
	0x03e00008, 0x27bd0020, 0x27bdffe0, 0x3c040800, 0x24841660, 0x00002821,
	0x00003021, 0x00003821, 0xafbf0018, 0xafa00010, 0x0e00006c, 0xafa00014,
	0x3c010800, 0xa4201fb8, 0x3c010800, 0xa02016f8, 0x3c010800, 0xac2016fc,
	0x3c010800, 0xac201700, 0x3c010800, 0xac201704, 0x3c010800, 0xac20170c,
	0x3c010800, 0xac201718, 0x3c010800, 0xac20171c, 0x8f624434, 0x3c010800,
	0xac2216e8, 0x8f624438, 0x3c010800, 0xac2216ec, 0x8f624410, 0x3c010800,
	0xac2016e0, 0x3c010800, 0xac2016e4, 0x3c010800, 0xac201fc0, 0x3c010800,
	0xac201f68, 0x3c010800, 0xac201f6c, 0x3c010800, 0xac2216f0, 0x8fbf0018,
	0x03e00008, 0x27bd0020, 0x27bdffe0, 0x3c040800, 0x2484166c, 0x00002821,
	0x00003021, 0x00003821, 0xafbf0018, 0xafa00010, 0x0e00006c, 0xafa00014,
	0x3c040800, 0x24841660, 0x00002821, 0x00003021, 0x00003821, 0xafa00010,
	0x0e00006c, 0xafa00014, 0x3c010800, 0xa4201fb8, 0x3c010800, 0xa02016f8,
	0x3c010800, 0xac2016fc, 0x3c010800, 0xac201700, 0x3c010800, 0xac201704,
	0x3c010800, 0xac20170c, 0x3c010800, 0xac201718, 0x3c010800, 0xac20171c,
	0x8f624434, 0x3c010800, 0xac2216e8, 0x8f624438, 0x3c010800, 0xac2216ec,
	0x8f624410, 0x3c010800, 0xac2016e0, 0x3c010800, 0xac2016e4, 0x3c010800,
	0xac201fc0, 0x3c010800, 0xac201f68, 0x3c010800, 0xac201f6c, 0x3c010800,
	0xac2216f0, 0x0e000120, 0x00002021, 0x8fbf0018, 0x03e00008, 0x27bd0020,
	0x24020001, 0x8f636820, 0x00821004, 0x00021027, 0x00621824, 0x03e00008,
	0xaf636820, 0x27bdffd0, 0x3c0300ff, 0xafbf002c, 0xafb60028, 0xafb50024,
	0xafb40020, 0xafb3001c, 0xafb20018, 0xafb10014, 0xafb00010, 0x8f665c5c,
	0x3c040800, 0x2484171c, 0x8c820000, 0x3463fff8, 0x14460005, 0x00c38824,
	0x3c020800, 0x904216f8, 0x14400115, 0x00000000, 0x00111902, 0x306300ff,
	0x30c20003, 0x000211c0, 0x00623825, 0x00e02821, 0x00061602, 0xac860000,
	0x3c030800, 0x906316f8, 0x3044000f, 0x1460002b, 0x00804021, 0x24020001,
	0x3c010800, 0xa02216f8, 0x00071100, 0x00821025, 0x3c010800, 0xac2016fc,
	0x3c010800, 0xac201700, 0x3c010800, 0xac201704, 0x3c010800, 0xac20170c,
	0x3c010800, 0xac201718, 0x3c010800, 0xac201710, 0x3c010800, 0xac201714,
	0x3c010800, 0xa4221fb8, 0x9623000c, 0x30628000, 0x10400008, 0x30627fff,
	0x2442003e, 0x3c010800, 0xa42216f6, 0x24020001, 0x3c010800, 0x0a00016e,
	0xac221fd4, 0x24620036, 0x3c010800, 0xa42216f6, 0x3c010800, 0xac201fd4,
	0x3c010800, 0xac201fd0, 0x3c010800, 0x0a000176, 0xac201fd8, 0x9622000c,
	0x3c010800, 0xa4221fcc, 0x3c040800, 0x248416fc, 0x8c820000, 0x00021100,
	0x3c010800, 0x00220821, 0xac311728, 0x8c820000, 0x00021100, 0x3c010800,
	0x00220821, 0xac26172c, 0x8c820000, 0x24a30001, 0x306701ff, 0x00021100,
	0x3c010800, 0x00220821, 0xac271730, 0x8c820000, 0x00021100, 0x3c010800,
	0x00220821, 0xac281734, 0x96230008, 0x3c020800, 0x8c42170c, 0x00432821,
	0x3c010800, 0xac25170c, 0x9622000a, 0x30420004, 0x14400019, 0x00071100,
	0x3c02c000, 0x00c21825, 0xaf635c5c, 0x8f625c50, 0x30420002, 0x1440fffc,
	0x00000000, 0x8f630c14, 0x3063000f, 0x2c620002, 0x1440001e, 0x00000000,
	0x8f630c14, 0x3c020800, 0x8c4216b4, 0x3063000f, 0x24420001, 0x3c010800,
	0xac2216b4, 0x2c620002, 0x1040fff7, 0x00000000, 0x0a0001c1, 0x00000000,
	0x3c030800, 0x8c6316e0, 0x3c040800, 0x948416f4, 0x01021025, 0x3c010800,
	0xa4221fba, 0x24020001, 0x3c010800, 0xac221718, 0x24630001, 0x0085202a,
	0x3c010800, 0x10800003, 0xac2316e0, 0x3c010800, 0xa42516f4, 0x3c030800,
	0x246316fc, 0x8c620000, 0x24420001, 0xac620000, 0x28420080, 0x14400005,
	0x24020001, 0x0e0002df, 0x24040002, 0x0a000250, 0x00000000, 0x3c030800,
	0x906316f8, 0x1462007c, 0x24020003, 0x3c160800, 0x96d616f6, 0x3c050800,
	0x8ca5170c, 0x32c4ffff, 0x00a4102a, 0x14400078, 0x00000000, 0x3c020800,
	0x8c421718, 0x10400005, 0x32c2ffff, 0x14a40003, 0x00000000, 0x3c010800,
	0xac231fd0, 0x10400062, 0x00009021, 0x0040a021, 0x3c150800, 0x26b51700,
	0x26b30010, 0x8ea20000, 0x00028100, 0x3c110800, 0x02308821, 0x0e0002e1,
	0x8e311728, 0x00403021, 0x10c00059, 0x00000000, 0x9628000a, 0x31020040,
	0x10400004, 0x2407180c, 0x8e22000c, 0x2407188c, 0xacc20018, 0x31021000,
	0x10400004, 0x34e32000, 0x00081040, 0x3042c000, 0x00623825, 0x3c030800,
	0x00701821, 0x8c631730, 0x3c020800, 0x00501021, 0x8c421734, 0x00031d00,
	0x00021400, 0x00621825, 0xacc30014, 0x8ea30004, 0x96220008, 0x00432023,
	0x3242ffff, 0x3083ffff, 0x00431021, 0x0282102a, 0x14400002, 0x02d22823,
	0x00802821, 0x8e620000, 0x30a4ffff, 0x00441021, 0xae620000, 0x8e220000,
	0xacc20000, 0x8e220004, 0x8e63fff4, 0x00431021, 0xacc20004, 0xa4c5000e,
	0x8e62fff4, 0x00441021, 0xae62fff4, 0x96230008, 0x0043102a, 0x14400005,
	0x02459021, 0x8e62fff0, 0xae60fff4, 0x24420001, 0xae62fff0, 0xacc00008,
	0x3242ffff, 0x14540008, 0x24020305, 0x31020080, 0x54400001, 0x34e70010,
	0x24020905, 0xa4c2000c, 0x0a000233, 0x34e70020, 0xa4c2000c, 0x30e2ffff,
	0xacc20010, 0x3c020800, 0x8c421fd0, 0x10400003, 0x3c024b65, 0x0a00023d,
	0x34427654, 0x3c02b49a, 0x344289ab, 0xacc2001c, 0x0e000560, 0x00c02021,
	0x3242ffff, 0x0054102b, 0x1440ffa4, 0x00000000, 0x24020002, 0x3c010800,
	0x0a000250, 0xa02216f8, 0x8ea208bc, 0x24420001, 0x0a000250, 0xaea208bc,
	0x14620003, 0x00000000, 0x0e000450, 0x00000000, 0x8fbf002c, 0x8fb60028,
	0x8fb50024, 0x8fb40020, 0x8fb3001c, 0x8fb20018, 0x8fb10014, 0x8fb00010,
	0x03e00008, 0x27bd0030, 0x27bdffd8, 0xafb3001c, 0x00809821, 0xafbf0020,
	0xafb20018, 0xafb10014, 0xafb00010, 0x8f725c9c, 0x3c0200ff, 0x3442fff8,
	0x3c040800, 0x24841714, 0x02428824, 0x9623000e, 0x8c820000, 0x00431021,
	0xac820000, 0x8e220010, 0x30420020, 0x14400011, 0x00000000, 0x0e0002f7,
	0x02202021, 0x3c02c000, 0x02421825, 0xaf635c9c, 0x8f625c90, 0x30420002,
	0x10400061, 0x00000000, 0xaf635c9c, 0x8f625c90, 0x30420002, 0x1040005c,
	0x00000000, 0x0a000278, 0x00000000, 0x8e220008, 0x00021c02, 0x000321c0,
	0x3042ffff, 0x3c030800, 0x906316f8, 0x000229c0, 0x24020002, 0x14620003,
	0x3c034b65, 0x0a000290, 0x00008021, 0x8e22001c, 0x34637654, 0x10430002,
	0x24100002, 0x24100001, 0x0e000300, 0x02003021, 0x24020003, 0x3c010800,
	0xa02216f8, 0x24020002, 0x1202000a, 0x24020001, 0x3c030800, 0x8c631fd0,
	0x10620006, 0x00000000, 0x3c020800, 0x94421fb8, 0x00021400, 0x0a0002cd,
	0xae220014, 0x3c040800, 0x24841fba, 0x94820000, 0x00021400, 0xae220014,
	0x3c020800, 0x8c42171c, 0x3c03c000, 0x3c010800, 0xa02016f8, 0x00431025,
	0xaf625c5c, 0x8f625c50, 0x30420002, 0x10400009, 0x00000000, 0x2484f762,
	0x8c820000, 0x00431025, 0xaf625c5c, 0x8f625c50, 0x30420002, 0x1440fffa,
	0x00000000, 0x3c020800, 0x244216e4, 0x8c430000, 0x24630001, 0xac430000,
	0x8f630c14, 0x3063000f, 0x2c620002, 0x1440000b, 0x00009821, 0x8f630c14,
	0x3c020800, 0x8c4216b4, 0x3063000f, 0x24420001, 0x3c010800, 0xac2216b4,
	0x2c620002, 0x1040fff7, 0x00009821, 0x3c024000, 0x02421825, 0xaf635c9c,
	0x8f625c90, 0x30420002, 0x1440fffc, 0x00000000, 0x12600003, 0x00000000,
	0x0e000450, 0x00000000, 0x8fbf0020, 0x8fb3001c, 0x8fb20018, 0x8fb10014,
	0x8fb00010, 0x03e00008, 0x27bd0028, 0x0a0002df, 0x00000000, 0x8f634450,
	0x3c040800, 0x248416e8, 0x8c820000, 0x00031c02, 0x0043102b, 0x14400007,
	0x3c038000, 0x8c840004, 0x8f624450, 0x00021c02, 0x0083102b, 0x1040fffc,
	0x3c038000, 0xaf634444, 0x8f624444, 0x00431024, 0x1440fffd, 0x00000000,
	0x8f624448, 0x03e00008, 0x3042ffff, 0x3c024000, 0x00822025, 0xaf645c38,
	0x8f625c30, 0x30420002, 0x1440fffc, 0x00000000, 0x03e00008, 0x00000000,
	0x27bdffe0, 0x00805021, 0x14c00017, 0x254c0008, 0x3c020800, 0x8c421fd4,
	0x1040000a, 0x2402003e, 0x3c010800, 0xa4221fb0, 0x24020016, 0x3c010800,
	0xa4221fb2, 0x2402002a, 0x3c010800, 0x0a00031a, 0xa4221fb4, 0x95420014,
	0x3c010800, 0xa4221fb0, 0x8d430010, 0x00031402, 0x3c010800, 0xa4221fb2,
	0x3c010800, 0xa4231fb4, 0x3c040800, 0x94841fb4, 0x3c030800, 0x94631fb2,
	0x958d0006, 0x3c020800, 0x94421fb0, 0x00832023, 0x01a27023, 0x3065ffff,
	0x24a20028, 0x01824021, 0x3082ffff, 0x14c0001a, 0x01025821, 0x9562000c,
	0x3042003f, 0x3c010800, 0xa4221fb6, 0x95620004, 0x95630006, 0x3c010800,
	0xac201fc4, 0x3c010800, 0xac201fc8, 0x00021400, 0x00431025, 0x3c010800,
	0xac221720, 0x95020004, 0x3c010800, 0xa4221724, 0x95030002, 0x01a51023,
	0x0043102a, 0x10400010, 0x24020001, 0x3c010800, 0x0a00034e, 0xac221fd8,
	0x3c030800, 0x8c631fc8, 0x3c020800, 0x94421724, 0x00431021, 0xa5020004,
	0x3c020800, 0x94421720, 0xa5620004, 0x3c020800, 0x8c421720, 0xa5620006,
	0x3c020800, 0x8c421fd0, 0x3c070800, 0x8ce71fc4, 0x3c050800, 0x144000c7,
	0x8ca51fc8, 0x3c020800, 0x94421724, 0x00451821, 0x3063ffff, 0x0062182b,
	0x24020002, 0x10c2000d, 0x00a32823, 0x3c020800, 0x94421fb6, 0x30420009,
	0x10400008, 0x00000000, 0x9562000c, 0x3042fff6, 0xa562000c, 0x3c020800,
	0x94421fb6, 0x30420009, 0x00e23823, 0x3c020800, 0x8c421fd8, 0x1040004b,
	0x24020002, 0x01003021, 0x3c020800, 0x94421fb2, 0x00003821, 0xa500000a,
	0x01a21023, 0xa5020002, 0x3082ffff, 0x00021042, 0x18400008, 0x00002821,
	0x00401821, 0x94c20000, 0x24e70001, 0x00a22821, 0x00e3102a, 0x1440fffb,
	0x24c60002, 0x00051c02, 0x30a2ffff, 0x00622821, 0x00051402, 0x00a22821,
	0x00a04821, 0x00051027, 0xa502000a, 0x00002821, 0x2506000c, 0x00003821,
	0x94c20000, 0x24e70001, 0x00a22821, 0x2ce20004, 0x1440fffb, 0x24c60002,
	0x95020002, 0x00003821, 0x91030009, 0x00442023, 0x01603021, 0x3082ffff,
	0xa4c00010, 0x00621821, 0x00021042, 0x18400010, 0x00a32821, 0x00404021,
	0x94c20000, 0x24c60002, 0x00a22821, 0x30c2007f, 0x14400006, 0x24e70001,
	0x8d430000, 0x3c02007f, 0x3442ff80, 0x00625024, 0x25460008, 0x00e8102a,
	0x1440fff3, 0x00000000, 0x30820001, 0x10400005, 0x00051c02, 0xa0c00001,
	0x94c20000, 0x00a22821, 0x00051c02, 0x30a2ffff, 0x00622821, 0x00051402,
	0x00a22821, 0x0a000415, 0x30a5ffff, 0x14c20063, 0x00000000, 0x3c090800,
	0x95291fb2, 0x95030002, 0x01a91023, 0x1062005d, 0x01003021, 0x00003821,
	0x00002821, 0x01a91023, 0xa5020002, 0x3082ffff, 0x00021042, 0x18400008,
	0xa500000a, 0x00401821, 0x94c20000, 0x24e70001, 0x00a22821, 0x00e3102a,
	0x1440fffb, 0x24c60002, 0x00051c02, 0x30a2ffff, 0x00622821, 0x00051402,
	0x00a22821, 0x00a04821, 0x00051027, 0xa502000a, 0x00002821, 0x2506000c,
	0x00003821, 0x94c20000, 0x24e70001, 0x00a22821, 0x2ce20004, 0x1440fffb,
	0x24c60002, 0x95020002, 0x00003821, 0x91030009, 0x00442023, 0x01603021,
	0x3082ffff, 0xa4c00010, 0x3c040800, 0x94841fb4, 0x00621821, 0x00a32821,
	0x00051c02, 0x30a2ffff, 0x00622821, 0x00051c02, 0x3c020800, 0x94421fb0,
	0x00a34021, 0x00441023, 0x00021fc2, 0x00431021, 0x00021043, 0x18400010,
	0x00002821, 0x00402021, 0x94c20000, 0x24c60002, 0x00a22821, 0x30c2007f,
	0x14400006, 0x24e70001, 0x8d430000, 0x3c02007f, 0x3442ff80, 0x00625024,
	0x25460008, 0x00e4102a, 0x1440fff3, 0x00000000, 0x3c020800, 0x94421fcc,
	0x00a22821, 0x00051c02, 0x30a2ffff, 0x00622821, 0x00051402, 0x00a22821,
	0x3102ffff, 0x00a22821, 0x00051c02, 0x30a2ffff, 0x00622821, 0x00051402,
	0x00a22821, 0x00a02021, 0x00051027, 0xa5620010, 0xad800014, 0x0a000435,
	0xad800000, 0x8d830010, 0x00602021, 0x10a00007, 0x00034c02, 0x01252821,
	0x00051402, 0x30a3ffff, 0x00432821, 0x00051402, 0x00a24821, 0x00091027,
	0xa502000a, 0x3c030800, 0x94631fb4, 0x3082ffff, 0x01a21021, 0x00432823,
	0x00a72821, 0x00051c02, 0x30a2ffff, 0x00622821, 0x00051402, 0x00a22821,
	0x00a02021, 0x00051027, 0xa5620010, 0x3082ffff, 0x00091c00, 0x00431025,
	0xad820010, 0x3c020800, 0x8c421fd4, 0x10400002, 0x25a2fff2, 0xa5820034,
	0x3c020800, 0x8c421fc8, 0x3c030800, 0x8c631720, 0x24420001, 0x3c010800,
	0xac221fc8, 0x3c020800, 0x8c421fc4, 0x31c4ffff, 0x00641821, 0x3c010800,
	0xac231720, 0x00441021, 0x3c010800, 0xac221fc4, 0x03e00008, 0x27bd0020,
	0x27bdffc8, 0x3c040800, 0x248416f8, 0xafbf0034, 0xafbe0030, 0xafb7002c,
	0xafb60028, 0xafb50024, 0xafb40020, 0xafb3001c, 0xafb20018, 0xafb10014,
	0xafb00010, 0x90830000, 0x24020003, 0x146200f4, 0x00000000, 0x3c020800,
	0x8c421710, 0x3c030800, 0x8c63170c, 0x3c1e0800, 0x97de16f6, 0x0043102a,
	0x104000eb, 0x3c168000, 0x249708c4, 0x33d5ffff, 0x24920018, 0x3c020800,
	0x8c421718, 0x104000e4, 0x00000000, 0x3c140800, 0x96941fb0, 0x3282ffff,
	0x104000d6, 0x00008021, 0x00409821, 0x00008821, 0x8f634450, 0x3c020800,
	0x8c4216e8, 0x00031c02, 0x0043102b, 0x14400008, 0x00000000, 0x3c040800,
	0x8c8416ec, 0x8f624450, 0x00021c02, 0x0083102b, 0x1040fffc, 0x00000000,
	0xaf764444, 0x8f624444, 0x00561024, 0x10400006, 0x00000000, 0x3c038000,
	0x8f624444, 0x00431024, 0x1440fffd, 0x00000000, 0x8f624448, 0x3046ffff,
	0x10c0005f, 0x00000000, 0x3c090800, 0x01314821, 0x8d291728, 0x9528000a,
	0x31020040, 0x10400004, 0x2407180c, 0x8d22000c, 0x2407188c, 0xacc20018,
	0x31021000, 0x10400004, 0x34e32000, 0x00081040, 0x3042c000, 0x00623825,
	0x31020080, 0x54400001, 0x34e70010, 0x3c020800, 0x00511021, 0x8c421730,
	0x3c030800, 0x00711821, 0x8c631734, 0x00021500, 0x00031c00, 0x00431025,
	0xacc20014, 0x95240008, 0x3202ffff, 0x00821021, 0x0262102a, 0x14400002,
	0x02902823, 0x00802821, 0x8d220000, 0x02058021, 0xacc20000, 0x8d220004,
	0x00c02021, 0x26310010, 0xac820004, 0x30e2ffff, 0xac800008, 0xa485000e,
	0xac820010, 0x24020305, 0x0e000560, 0xa482000c, 0x3202ffff, 0x0053102b,
	0x1440ffaf, 0x3202ffff, 0x0a00054c, 0x00000000, 0x8e420000, 0x8e43fffc,
	0x0043102a, 0x10400084, 0x00000000, 0x8e45fff0, 0x8f644450, 0x3c030800,
	0x8c6316e8, 0x00051100, 0x3c090800, 0x01224821, 0x8d291728, 0x00041402,
	0x0062182b, 0x14600008, 0x00000000, 0x3c030800, 0x8c6316ec, 0x8f624450,
	0x00021402, 0x0062102b, 0x1040fffc, 0x00000000, 0xaf764444, 0x8f624444,
	0x00561024, 0x10400006, 0x00000000, 0x3c038000, 0x8f624444, 0x00431024,
	0x1440fffd, 0x00000000, 0x8f624448, 0x3046ffff, 0x14c00005, 0x00000000,
	0x8ee20000, 0x24420001, 0x0a000554, 0xaee20000, 0x9528000a, 0x31020040,
	0x10400004, 0x2407180c, 0x8d22000c, 0x2407188c, 0xacc20018, 0x31021000,
	0x10400004, 0x34e32000, 0x00081040, 0x3042c000, 0x00623825, 0x00051900,
	0x3c020800, 0x00431021, 0x8c421730, 0x3c010800, 0x00230821, 0x8c231734,
	0x00021500, 0x00031c00, 0x00431025, 0xacc20014, 0x3c030800, 0x8c631704,
	0x95220008, 0x00432023, 0x3202ffff, 0x3083ffff, 0x00431021, 0x02a2102a,
	0x14400002, 0x03d02823, 0x00802821, 0x8e420000, 0x30a4ffff, 0x00441021,
	0xae420000, 0xa4c5000e, 0x8d220000, 0xacc20000, 0x8d220004, 0x8e43fff4,
	0x00431021, 0xacc20004, 0x8e43fff4, 0x95220008, 0x00641821, 0x0062102a,
	0x14400006, 0x02058021, 0x8e42fff0, 0xae40fff4, 0x24420001, 0x0a000530,
	0xae42fff0, 0xae43fff4, 0xacc00008, 0x3202ffff, 0x10550003, 0x31020004,
	0x10400006, 0x24020305, 0x31020080, 0x54400001, 0x34e70010, 0x34e70020,
	0x24020905, 0xa4c2000c, 0x30e2ffff, 0xacc20010, 0x3c030800, 0x8c63170c,
	0x3c020800, 0x8c421710, 0x54620004, 0x3c02b49a, 0x3c024b65, 0x0a000548,
	0x34427654, 0x344289ab, 0xacc2001c, 0x0e000560, 0x00c02021, 0x3202ffff,
	0x0055102b, 0x1440ff7e, 0x00000000, 0x8e420000, 0x8e43fffc, 0x0043102a,
	0x1440ff1a, 0x00000000, 0x8fbf0034, 0x8fbe0030, 0x8fb7002c, 0x8fb60028,
	0x8fb50024, 0x8fb40020, 0x8fb3001c, 0x8fb20018, 0x8fb10014, 0x8fb00010,
	0x03e00008, 0x27bd0038, 0x27bdffe8, 0xafbf0014, 0xafb00010, 0x8f624450,
	0x8f634410, 0x0a00056f, 0x00808021, 0x8f626820, 0x30422000, 0x10400003,
	0x00000000, 0x0e00025a, 0x00002021, 0x8f624450, 0x8f634410, 0x3042ffff,
	0x0043102b, 0x1440fff5, 0x00000000, 0x8f630c14, 0x3063000f, 0x2c620002,
	0x1440000b, 0x00000000, 0x8f630c14, 0x3c020800, 0x8c4216b4, 0x3063000f,
	0x24420001, 0x3c010800, 0xac2216b4, 0x2c620002, 0x1040fff7, 0x00000000,
	0xaf705c18, 0x8f625c10, 0x30420002, 0x10400009, 0x00000000, 0x8f626820,
	0x30422000, 0x1040fff8, 0x00000000, 0x0e00025a, 0x00002021, 0x0a000582,
	0x00000000, 0x8fbf0014, 0x8fb00010, 0x03e00008, 0x27bd0018, 0x00000000,
	0x00000000
};

u32 tg3TsoFwRodata[] = {
	0x4d61696e, 0x43707542, 0x00000000, 0x00000000, 0x74637073, 0x6567496e,
	0x00000000, 0x53774576, 0x656e7430, 0x00000000, 0x00000000, 0x00000000,
	0x00000000
};

#if 0 /* All zeros, dont eat up space with it. */
u32 tg3TsoFwData[] = {
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000
};
#endif

/* tp->lock is held. */
static int tg3_load_tso_firmware(struct tg3 *tp)
{
	struct fw_info info;
	int err, i;

	info.text_base = TG3_TSO_FW_TEXT_ADDR;
	info.text_len = TG3_TSO_FW_TEXT_LEN;
	info.text_data = &tg3TsoFwText[0];
	info.rodata_base = TG3_TSO_FW_RODATA_ADDR;
	info.rodata_len = TG3_TSO_FW_RODATA_LEN;
	info.rodata_data = &tg3TsoFwRodata[0];
	info.data_base = TG3_TSO_FW_DATA_ADDR;
	info.data_len = TG3_TSO_FW_DATA_LEN;
	info.data_data = NULL;

	err = tg3_load_firmware_cpu(tp, TX_CPU_BASE,
				    TX_CPU_SCRATCH_BASE, TX_CPU_SCRATCH_SIZE,
				    &info);
	if (err)
		return err;

	/* Now startup only the TX cpu. */
	tw32(TX_CPU_BASE + CPU_STATE, 0xffffffff);
	tw32(TX_CPU_BASE + CPU_PC,    TG3_TSO_FW_TEXT_ADDR);

	/* Flush posted writes. */
	tr32(TX_CPU_BASE + CPU_PC);
	for (i = 0; i < 5; i++) {
		if (tr32(TX_CPU_BASE + CPU_PC) == TG3_TSO_FW_TEXT_ADDR)
			break;
		tw32(TX_CPU_BASE + CPU_STATE, 0xffffffff);
		tw32(TX_CPU_BASE + CPU_MODE,  CPU_MODE_HALT);
		tw32(TX_CPU_BASE + CPU_PC,    TG3_TSO_FW_TEXT_ADDR);

		/* Flush posted writes. */
		tr32(TX_CPU_BASE + CPU_PC);

		udelay(1000);
	}
	if (i >= 5) {
		printk(KERN_ERR PFX "tg3_load_tso_firmware fails for %s "
		       "to set TX CPU PC, is %08x should be %08x\n",
		       tp->dev->name, tr32(TX_CPU_BASE + CPU_PC),
		       TG3_TSO_FW_TEXT_ADDR);
		return -ENODEV;
	}
	tw32(TX_CPU_BASE + CPU_STATE, 0xffffffff);
	tw32(TX_CPU_BASE + CPU_MODE,  0x00000000);

	/* Flush posted writes. */
	tr32(TX_CPU_BASE + CPU_MODE);

	return 0;
}

#endif /* TG3_DO_TSO != 0 */

/* tp->lock is held. */
static void __tg3_set_mac_addr(struct tg3 *tp)
{
	u32 addr_high, addr_low;
	int i;

	addr_high = ((tp->dev->dev_addr[0] << 8) |
		     tp->dev->dev_addr[1]);
	addr_low = ((tp->dev->dev_addr[2] << 24) |
		    (tp->dev->dev_addr[3] << 16) |
		    (tp->dev->dev_addr[4] <<  8) |
		    (tp->dev->dev_addr[5] <<  0));
	for (i = 0; i < 4; i++) {
		tw32(MAC_ADDR_0_HIGH + (i * 8), addr_high);
		tw32(MAC_ADDR_0_LOW + (i * 8), addr_low);
	}

	addr_high = (tp->dev->dev_addr[0] +
		     tp->dev->dev_addr[1] +
		     tp->dev->dev_addr[2] +
		     tp->dev->dev_addr[3] +
		     tp->dev->dev_addr[4] +
		     tp->dev->dev_addr[5]) &
		TX_BACKOFF_SEED_MASK;
	tw32(MAC_TX_BACKOFF_SEED, addr_high);
}

static int tg3_set_mac_addr(struct net_device *dev, void *p)
{
	struct tg3 *tp = dev->priv;
	struct sockaddr *addr = p;

	if (netif_running(dev))
		return -EBUSY;

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

	spin_lock_irq(&tp->lock);
	__tg3_set_mac_addr(tp);
	spin_unlock_irq(&tp->lock);

	return 0;
}

/* tp->lock is held. */
static void tg3_set_bdinfo(struct tg3 *tp, u32 bdinfo_addr,
			   dma_addr_t mapping, u32 maxlen_flags,
			   u32 nic_addr)
{
	tg3_write_mem(tp,
		      (bdinfo_addr +
		       TG3_BDINFO_HOST_ADDR +
		       TG3_64BIT_REG_HIGH),
		      ((u64) mapping >> 32));
	tg3_write_mem(tp,
		      (bdinfo_addr +
		       TG3_BDINFO_HOST_ADDR +
		       TG3_64BIT_REG_LOW),
		      ((u64) mapping & 0xffffffff));
	tg3_write_mem(tp,
		      (bdinfo_addr +
		       TG3_BDINFO_MAXLEN_FLAGS),
		       maxlen_flags);
	tg3_write_mem(tp,
		      (bdinfo_addr +
		       TG3_BDINFO_NIC_ADDR),
		      nic_addr);
}

static void __tg3_set_rx_mode(struct net_device *);

/* tp->lock is held. */
static int tg3_reset_hw(struct tg3 *tp)
{
	u32 val;
	int i, err;

	tg3_disable_ints(tp);

	tg3_stop_fw(tp);

	if (tp->tg3_flags & TG3_FLAG_INIT_COMPLETE) {
		err = tg3_abort_hw(tp);
		if (err)
			return err;
	}

	tg3_chip_reset(tp);

	tw32(GRC_MODE, tp->grc_mode);
	tg3_write_mem(tp,
		      NIC_SRAM_FIRMWARE_MBOX,
		      NIC_SRAM_FIRMWARE_MBOX_MAGIC1);
	if (tp->phy_id == PHY_ID_SERDES) {
		tp->mac_mode = MAC_MODE_PORT_MODE_TBI;
		tw32(MAC_MODE, tp->mac_mode);
	} else
		tw32(MAC_MODE, 0);
	tr32(MAC_MODE);
	udelay(40);

	/* Wait for firmware initialization to complete. */
	for (i = 0; i < 100000; i++) {
		tg3_read_mem(tp, NIC_SRAM_FIRMWARE_MBOX, &val);
		if (val == ~NIC_SRAM_FIRMWARE_MBOX_MAGIC1)
			break;
		udelay(10);
	}
	if (i >= 100000) {
		printk(KERN_ERR PFX "tg3_reset_hw timed out for %s, "
		       "firmware will not restart magic=%08x\n",
		       tp->dev->name, val);
		return -ENODEV;
	}

	if (tp->tg3_flags & TG3_FLAG_ENABLE_ASF)
		tg3_write_mem(tp, NIC_SRAM_FW_DRV_STATE_MBOX,
			      DRV_STATE_START);
	else
		tg3_write_mem(tp, NIC_SRAM_FW_DRV_STATE_MBOX,
			      DRV_STATE_SUSPEND);

	/* This works around an issue with Athlon chipsets on
	 * B3 tigon3 silicon.  This bit has no effect on any
	 * other revision.
	 */
	val = tr32(TG3PCI_CLOCK_CTRL);
	val |= CLOCK_CTRL_DELAY_PCI_GRANT;
	tw32(TG3PCI_CLOCK_CTRL, val);
	tr32(TG3PCI_CLOCK_CTRL);

	if (tp->pci_chip_rev_id == CHIPREV_ID_5704_A0 &&
	    (tp->tg3_flags & TG3_FLAG_PCIX_MODE)) {
		val = tr32(TG3PCI_PCISTATE);
		val |= PCISTATE_RETRY_SAME_DMA;
		tw32(TG3PCI_PCISTATE, val);
	}

	/* Clear statistics/status block in chip, and status block in ram. */
	for (i = NIC_SRAM_STATS_BLK;
	     i < NIC_SRAM_STATUS_BLK + TG3_HW_STATUS_SIZE;
	     i += sizeof(u32)) {
		tg3_write_mem(tp, i, 0);
		udelay(40);
	}
	memset(tp->hw_status, 0, TG3_HW_STATUS_SIZE);

	/* This value is determined during the probe time DMA
	 * engine test, tg3_test_dma.
	 */
	tw32(TG3PCI_DMA_RW_CTRL, tp->dma_rwctrl);

	tp->grc_mode &= ~(GRC_MODE_HOST_SENDBDS |
			  GRC_MODE_4X_NIC_SEND_RINGS |
			  GRC_MODE_NO_TX_PHDR_CSUM |
			  GRC_MODE_NO_RX_PHDR_CSUM);
	if (tp->tg3_flags & TG3_FLAG_HOST_TXDS)
		tp->grc_mode |= GRC_MODE_HOST_SENDBDS;
	else
		tp->grc_mode |= GRC_MODE_4X_NIC_SEND_RINGS;
	if (tp->tg3_flags & TG3_FLAG_NO_TX_PSEUDO_CSUM)
		tp->grc_mode |= GRC_MODE_NO_TX_PHDR_CSUM;
	if (tp->tg3_flags & TG3_FLAG_NO_RX_PSEUDO_CSUM)
		tp->grc_mode |= GRC_MODE_NO_RX_PHDR_CSUM;

	tw32(GRC_MODE,
	     tp->grc_mode |
	     (GRC_MODE_IRQ_ON_MAC_ATTN | GRC_MODE_HOST_STACKUP));

	/* Setup the timer prescalar register.  Clock is always 66Mhz. */
	tw32(GRC_MISC_CFG,
	     (65 << GRC_MISC_CFG_PRESCALAR_SHIFT));

	/* Initialize MBUF/DESC pool. */
	tw32(BUFMGR_MB_POOL_ADDR, NIC_SRAM_MBUF_POOL_BASE);
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704)
		tw32(BUFMGR_MB_POOL_SIZE, NIC_SRAM_MBUF_POOL_SIZE64);
	else
		tw32(BUFMGR_MB_POOL_SIZE, NIC_SRAM_MBUF_POOL_SIZE96);
	tw32(BUFMGR_DMA_DESC_POOL_ADDR, NIC_SRAM_DMA_DESC_POOL_BASE);
	tw32(BUFMGR_DMA_DESC_POOL_SIZE, NIC_SRAM_DMA_DESC_POOL_SIZE);

	if (!(tp->tg3_flags & TG3_FLAG_JUMBO_ENABLE)) {
		tw32(BUFMGR_MB_RDMA_LOW_WATER,
		     tp->bufmgr_config.mbuf_read_dma_low_water);
		tw32(BUFMGR_MB_MACRX_LOW_WATER,
		     tp->bufmgr_config.mbuf_mac_rx_low_water);
		tw32(BUFMGR_MB_HIGH_WATER,
		     tp->bufmgr_config.mbuf_high_water);
	} else {
		tw32(BUFMGR_MB_RDMA_LOW_WATER,
		     tp->bufmgr_config.mbuf_read_dma_low_water_jumbo);
		tw32(BUFMGR_MB_MACRX_LOW_WATER,
		     tp->bufmgr_config.mbuf_mac_rx_low_water_jumbo);
		tw32(BUFMGR_MB_HIGH_WATER,
		     tp->bufmgr_config.mbuf_high_water_jumbo);
	}
	tw32(BUFMGR_DMA_LOW_WATER,
	     tp->bufmgr_config.dma_low_water);
	tw32(BUFMGR_DMA_HIGH_WATER,
	     tp->bufmgr_config.dma_high_water);

	tw32(BUFMGR_MODE, BUFMGR_MODE_ENABLE | BUFMGR_MODE_ATTN_ENABLE);
	for (i = 0; i < 2000; i++) {
		if (tr32(BUFMGR_MODE) & BUFMGR_MODE_ENABLE)
			break;
		udelay(10);
	}
	if (i >= 2000) {
		printk(KERN_ERR PFX "tg3_reset_hw cannot enable BUFMGR for %s.\n",
		       tp->dev->name);
		return -ENODEV;
	}

	tw32(FTQ_RESET, 0xffffffff);
	tw32(FTQ_RESET, 0x00000000);
	for (i = 0; i < 2000; i++) {
		if (tr32(FTQ_RESET) == 0x00000000)
			break;
		udelay(10);
	}
	if (i >= 2000) {
		printk(KERN_ERR PFX "tg3_reset_hw cannot reset FTQ for %s.\n",
		       tp->dev->name);
		return -ENODEV;
	}

	/* Initialize TG3_BDINFO's at:
	 *  RCVDBDI_STD_BD:	standard eth size rx ring
	 *  RCVDBDI_JUMBO_BD:	jumbo frame rx ring
	 *  RCVDBDI_MINI_BD:	small frame rx ring (??? does not work)
	 *
	 * like so:
	 *  TG3_BDINFO_HOST_ADDR:	high/low parts of DMA address of ring
	 *  TG3_BDINFO_MAXLEN_FLAGS:	(rx max buffer size << 16) |
	 *                              ring attribute flags
	 *  TG3_BDINFO_NIC_ADDR:	location of descriptors in nic SRAM
	 *
	 * Standard receive ring @ NIC_SRAM_RX_BUFFER_DESC, 512 entries.
	 * Jumbo receive ring @ NIC_SRAM_RX_JUMBO_BUFFER_DESC, 256 entries.
	 *
	 * The size of each ring is fixed in the firmware, but the location is
	 * configurable.
	 */
	tw32(RCVDBDI_STD_BD + TG3_BDINFO_HOST_ADDR + TG3_64BIT_REG_HIGH,
	     ((u64) tp->rx_std_mapping >> 32));
	tw32(RCVDBDI_STD_BD + TG3_BDINFO_HOST_ADDR + TG3_64BIT_REG_LOW,
	     ((u64) tp->rx_std_mapping & 0xffffffff));
	tw32(RCVDBDI_STD_BD + TG3_BDINFO_MAXLEN_FLAGS,
	     RX_STD_MAX_SIZE << BDINFO_FLAGS_MAXLEN_SHIFT);
	tw32(RCVDBDI_STD_BD + TG3_BDINFO_NIC_ADDR,
	     NIC_SRAM_RX_BUFFER_DESC);

	tw32(RCVDBDI_MINI_BD + TG3_BDINFO_MAXLEN_FLAGS,
	     BDINFO_FLAGS_DISABLED);

	if (tp->tg3_flags & TG3_FLAG_JUMBO_ENABLE) {
		tw32(RCVDBDI_JUMBO_BD + TG3_BDINFO_HOST_ADDR + TG3_64BIT_REG_HIGH,
		     ((u64) tp->rx_jumbo_mapping >> 32));
		tw32(RCVDBDI_JUMBO_BD + TG3_BDINFO_HOST_ADDR + TG3_64BIT_REG_LOW,
		     ((u64) tp->rx_jumbo_mapping & 0xffffffff));
		tw32(RCVDBDI_JUMBO_BD + TG3_BDINFO_MAXLEN_FLAGS,
		     RX_JUMBO_MAX_SIZE << BDINFO_FLAGS_MAXLEN_SHIFT);
		tw32(RCVDBDI_JUMBO_BD + TG3_BDINFO_NIC_ADDR,
		     NIC_SRAM_RX_JUMBO_BUFFER_DESC);
	} else {
		tw32(RCVDBDI_JUMBO_BD + TG3_BDINFO_MAXLEN_FLAGS,
		     BDINFO_FLAGS_DISABLED);
	}

	/* Setup replenish thresholds. */
	tw32(RCVBDI_STD_THRESH, tp->rx_pending / 8);
	tw32(RCVBDI_JUMBO_THRESH, tp->rx_jumbo_pending / 8);

	/* Clear out send RCB ring in SRAM. */
	for (i = NIC_SRAM_SEND_RCB; i < NIC_SRAM_RCV_RET_RCB; i += TG3_BDINFO_SIZE)
		tg3_write_mem(tp, i + TG3_BDINFO_MAXLEN_FLAGS, BDINFO_FLAGS_DISABLED);

	tp->tx_prod = 0;
	tp->tx_cons = 0;
	tw32_mailbox(MAILBOX_SNDHOST_PROD_IDX_0 + TG3_64BIT_REG_LOW, 0);
	tw32_mailbox(MAILBOX_SNDNIC_PROD_IDX_0 + TG3_64BIT_REG_LOW, 0);
	if (tp->tg3_flags & TG3_FLAG_MBOX_WRITE_REORDER)
		tr32(MAILBOX_SNDNIC_PROD_IDX_0 + TG3_64BIT_REG_LOW);

	if (tp->tg3_flags & TG3_FLAG_HOST_TXDS) {
		tg3_set_bdinfo(tp, NIC_SRAM_SEND_RCB,
			       tp->tx_desc_mapping,
			       (TG3_TX_RING_SIZE <<
				BDINFO_FLAGS_MAXLEN_SHIFT),
			       NIC_SRAM_TX_BUFFER_DESC);
	} else {
		tg3_set_bdinfo(tp, NIC_SRAM_SEND_RCB,
			       0,
			       BDINFO_FLAGS_DISABLED,
			       NIC_SRAM_TX_BUFFER_DESC);
	}

	for (i = NIC_SRAM_RCV_RET_RCB; i < NIC_SRAM_STATS_BLK; i += TG3_BDINFO_SIZE) {
		tg3_write_mem(tp, i + TG3_BDINFO_MAXLEN_FLAGS,
			      BDINFO_FLAGS_DISABLED);
	}

	tp->rx_rcb_ptr = 0;
	tw32_mailbox(MAILBOX_RCVRET_CON_IDX_0 + TG3_64BIT_REG_LOW, 0);
	if (tp->tg3_flags & TG3_FLAG_MBOX_WRITE_REORDER)
		tr32(MAILBOX_RCVRET_CON_IDX_0 + TG3_64BIT_REG_LOW);

	tg3_set_bdinfo(tp, NIC_SRAM_RCV_RET_RCB,
		       tp->rx_rcb_mapping,
		       (TG3_RX_RCB_RING_SIZE <<
			BDINFO_FLAGS_MAXLEN_SHIFT),
		       0);

	tp->rx_std_ptr = tp->rx_pending;
	tw32_mailbox(MAILBOX_RCV_STD_PROD_IDX + TG3_64BIT_REG_LOW,
		     tp->rx_std_ptr);
	if (tp->tg3_flags & TG3_FLAG_MBOX_WRITE_REORDER)
		tr32(MAILBOX_RCV_STD_PROD_IDX + TG3_64BIT_REG_LOW);

	if (tp->tg3_flags & TG3_FLAG_JUMBO_ENABLE)
		tp->rx_jumbo_ptr = tp->rx_jumbo_pending;
	else
		tp->rx_jumbo_ptr = 0;
	tw32_mailbox(MAILBOX_RCV_JUMBO_PROD_IDX + TG3_64BIT_REG_LOW,
		     tp->rx_jumbo_ptr);
	if (tp->tg3_flags & TG3_FLAG_MBOX_WRITE_REORDER)
		tr32(MAILBOX_RCV_JUMBO_PROD_IDX + TG3_64BIT_REG_LOW);

	/* Initialize MAC address and backoff seed. */
	__tg3_set_mac_addr(tp);

	/* MTU + ethernet header + FCS + optional VLAN tag */
	tw32(MAC_RX_MTU_SIZE, tp->dev->mtu + ETH_HLEN + 8);

	/* The slot time is changed by tg3_setup_phy if we
	 * run at gigabit with half duplex.
	 */
	tw32(MAC_TX_LENGTHS,
	     (2 << TX_LENGTHS_IPG_CRS_SHIFT) |
	     (6 << TX_LENGTHS_IPG_SHIFT) |
	     (32 << TX_LENGTHS_SLOT_TIME_SHIFT));

	/* Receive rules. */
	tw32(MAC_RCV_RULE_CFG, RCV_RULE_CFG_DEFAULT_CLASS);
	tw32(RCVLPC_CONFIG, 0x0181);

	/* Receive/send statistics. */
	tw32(RCVLPC_STATS_ENABLE, 0xffffff);
	tw32(RCVLPC_STATSCTRL, RCVLPC_STATSCTRL_ENABLE);
	tw32(SNDDATAI_STATSENAB, 0xffffff);
	tw32(SNDDATAI_STATSCTRL,
	     (SNDDATAI_SCTRL_ENABLE |
	      SNDDATAI_SCTRL_FASTUPD));

	/* Setup host coalescing engine. */
	tw32(HOSTCC_MODE, 0);
	for (i = 0; i < 2000; i++) {
		if (!(tr32(HOSTCC_MODE) & HOSTCC_MODE_ENABLE))
			break;
		udelay(10);
	}

#ifdef NAPI
	tw32(HOSTCC_RXCOL_TICKS, 0);
	tw32(HOSTCC_RXMAX_FRAMES, 1);
	tw32(HOSTCC_RXCOAL_TICK_INT, 0);
	tw32(HOSTCC_RXCOAL_MAXF_INT, 1);
	tw32(HOSTCC_TXCOL_TICKS, LOW_TXCOL_TICKS);
	tw32(HOSTCC_TXMAX_FRAMES, LOW_RXMAX_FRAMES);
	tw32(HOSTCC_TXCOAL_TICK_INT, 0);
	tw32(HOSTCC_TXCOAL_MAXF_INT, 0);
	tw32(HOSTCC_STAT_COAL_TICKS,
	     DEFAULT_STAT_COAL_TICKS);
#else
	tw32(HOSTCC_RXCOL_TICKS, DEFAULT_RXCOL_TICKS);
	tw32(HOSTCC_RXMAX_FRAMES, DEFAULT_RXMAX_FRAMES);
	tw32(HOSTCC_RXCOAL_TICK_INT, DEFAULT_RXCOAL_TICK_INT);
	tw32(HOSTCC_RXCOAL_MAXF_INT, DEFAULT_RXCOAL_MAXF_INT);
	tw32(HOSTCC_TXCOL_TICKS, DEFAULT_TXCOL_TICKS);
	tw32(HOSTCC_TXMAX_FRAMES, DEFAULT_TXMAX_FRAMES);
	tw32(HOSTCC_TXCOAL_TICK_INT, DEFAULT_TXCOAL_TICK_INT);
	tw32(HOSTCC_TXCOAL_MAXF_INT, DEFAULT_TXCOAL_MAXF_INT);
	tw32(HOSTCC_STAT_COAL_TICKS,
	     DEFAULT_STAT_COAL_TICKS);
#endif

	/* Status/statistics block address. */
	tw32(HOSTCC_STATS_BLK_HOST_ADDR + TG3_64BIT_REG_HIGH,
	     ((u64) tp->stats_mapping >> 32));
	tw32(HOSTCC_STATS_BLK_HOST_ADDR + TG3_64BIT_REG_LOW,
	     ((u64) tp->stats_mapping & 0xffffffff));
	tw32(HOSTCC_STATUS_BLK_HOST_ADDR + TG3_64BIT_REG_HIGH,
	     ((u64) tp->status_mapping >> 32));
	tw32(HOSTCC_STATUS_BLK_HOST_ADDR + TG3_64BIT_REG_LOW,
	     ((u64) tp->status_mapping & 0xffffffff));
	tw32(HOSTCC_STATS_BLK_NIC_ADDR, NIC_SRAM_STATS_BLK);
	tw32(HOSTCC_STATUS_BLK_NIC_ADDR, NIC_SRAM_STATUS_BLK);

	tw32(HOSTCC_MODE, HOSTCC_MODE_ENABLE | tp->coalesce_mode);

	tw32(RCVCC_MODE, RCVCC_MODE_ENABLE | RCVCC_MODE_ATTN_ENABLE);
	tw32(RCVLPC_MODE, RCVLPC_MODE_ENABLE);
	tw32(RCVLSC_MODE, RCVLSC_MODE_ENABLE | RCVLSC_MODE_ATTN_ENABLE);

	tp->mac_mode = MAC_MODE_TXSTAT_ENABLE | MAC_MODE_RXSTAT_ENABLE |
		MAC_MODE_TDE_ENABLE | MAC_MODE_RDE_ENABLE | MAC_MODE_FHDE_ENABLE;
	tw32(MAC_MODE, tp->mac_mode | MAC_MODE_RXSTAT_CLEAR | MAC_MODE_TXSTAT_CLEAR);
	tr32(MAC_MODE);
	udelay(40);

	tp->grc_local_ctrl = GRC_LCLCTRL_INT_ON_ATTN | GRC_LCLCTRL_AUTO_SEEPROM;
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700)
		tp->grc_local_ctrl |= (GRC_LCLCTRL_GPIO_OE1 |
				       GRC_LCLCTRL_GPIO_OUTPUT1);
	tw32(GRC_LOCAL_CTRL, tp->grc_local_ctrl);
	tr32(GRC_LOCAL_CTRL);
	udelay(100);

	tw32_mailbox(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW, 0);
	tr32(MAILBOX_INTERRUPT_0);

	tw32(DMAC_MODE, DMAC_MODE_ENABLE);
	tr32(DMAC_MODE);
	udelay(40);

	tw32(WDMAC_MODE, (WDMAC_MODE_ENABLE | WDMAC_MODE_TGTABORT_ENAB |
			  WDMAC_MODE_MSTABORT_ENAB | WDMAC_MODE_PARITYERR_ENAB |
			  WDMAC_MODE_ADDROFLOW_ENAB | WDMAC_MODE_FIFOOFLOW_ENAB |
			  WDMAC_MODE_FIFOURUN_ENAB | WDMAC_MODE_FIFOOREAD_ENAB |
			  WDMAC_MODE_LNGREAD_ENAB));
	tr32(WDMAC_MODE);
	udelay(40);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704 &&
	    (tp->tg3_flags & TG3_FLAG_PCIX_MODE)) {
		val = tr32(TG3PCI_X_CAPS);
		val &= ~(PCIX_CAPS_SPLIT_MASK | PCIX_CAPS_BURST_MASK);
		val |= (PCIX_CAPS_MAX_BURST_5704 << PCIX_CAPS_BURST_SHIFT);
		if (tp->tg3_flags & TG3_FLAG_SPLIT_MODE)
			val |= (tp->split_mode_max_reqs <<
				PCIX_CAPS_SPLIT_SHIFT);
		tw32(TG3PCI_X_CAPS, val);
	}

	val = (RDMAC_MODE_ENABLE | RDMAC_MODE_TGTABORT_ENAB |
	       RDMAC_MODE_MSTABORT_ENAB | RDMAC_MODE_PARITYERR_ENAB |
	       RDMAC_MODE_ADDROFLOW_ENAB | RDMAC_MODE_FIFOOFLOW_ENAB |
	       RDMAC_MODE_FIFOURUN_ENAB | RDMAC_MODE_FIFOOREAD_ENAB |
	       RDMAC_MODE_LNGREAD_ENAB);
	if (tp->tg3_flags & TG3_FLAG_SPLIT_MODE)
		val |= RDMAC_MODE_SPLIT_ENABLE;
	tw32(RDMAC_MODE, val);
	tr32(RDMAC_MODE);
	udelay(40);

	tw32(RCVDCC_MODE, RCVDCC_MODE_ENABLE | RCVDCC_MODE_ATTN_ENABLE);
	tw32(MBFREE_MODE, MBFREE_MODE_ENABLE);
	tw32(SNDDATAC_MODE, SNDDATAC_MODE_ENABLE);
	tw32(SNDBDC_MODE, SNDBDC_MODE_ENABLE | SNDBDC_MODE_ATTN_ENABLE);
	tw32(RCVBDI_MODE, RCVBDI_MODE_ENABLE | RCVBDI_MODE_RCB_ATTN_ENAB);
	tw32(RCVDBDI_MODE, RCVDBDI_MODE_ENABLE | RCVDBDI_MODE_INV_RING_SZ);
	tw32(SNDDATAI_MODE, SNDDATAI_MODE_ENABLE);
	tw32(SNDBDI_MODE, SNDBDI_MODE_ENABLE | SNDBDI_MODE_ATTN_ENABLE);
	tw32(SNDBDS_MODE, SNDBDS_MODE_ENABLE | SNDBDS_MODE_ATTN_ENABLE);

	if (tp->pci_chip_rev_id == CHIPREV_ID_5701_A0) {
		err = tg3_load_5701_a0_firmware_fix(tp);
		if (err)
			return err;
	}

#if TG3_DO_TSO != 0
	err = tg3_load_tso_firmware(tp);
	if (err)
		return err;
#endif

	tp->tx_mode = TX_MODE_ENABLE;
	tw32(MAC_TX_MODE, tp->tx_mode);
	tr32(MAC_TX_MODE);
	udelay(100);

	tp->rx_mode = RX_MODE_ENABLE;
	tw32(MAC_RX_MODE, tp->rx_mode);
	tr32(MAC_RX_MODE);
	udelay(10);

	if (tp->link_config.phy_is_low_power) {
		tp->link_config.phy_is_low_power = 0;
		tp->link_config.speed = tp->link_config.orig_speed;
		tp->link_config.duplex = tp->link_config.orig_duplex;
		tp->link_config.autoneg = tp->link_config.orig_autoneg;
	}

	tp->mi_mode = MAC_MI_MODE_BASE;
	tw32(MAC_MI_MODE, tp->mi_mode);
	tr32(MAC_MI_MODE);
	udelay(40);

	tw32(MAC_LED_CTRL, 0);
	tw32(MAC_MI_STAT, MAC_MI_STAT_LNKSTAT_ATTN_ENAB);
	tw32(MAC_RX_MODE, RX_MODE_RESET);
	tr32(MAC_RX_MODE);
	udelay(10);
	tw32(MAC_RX_MODE, tp->rx_mode);
	tr32(MAC_RX_MODE);
	udelay(10);

	if (tp->pci_chip_rev_id == CHIPREV_ID_5703_A1)
		tw32(MAC_SERDES_CFG, 0x616000);

	/* Prevent chip from dropping frames when flow control
	 * is enabled.
	 */
	tw32(MAC_LOW_WMARK_MAX_RX_FRAME, 2);
	tr32(MAC_LOW_WMARK_MAX_RX_FRAME);

	err = tg3_setup_phy(tp);
	if (err)
		return err;

	if (tp->phy_id != PHY_ID_SERDES) {
		u32 tmp;

		/* Clear CRC stats. */
		tg3_readphy(tp, 0x1e, &tmp);
		tg3_writephy(tp, 0x1e, tmp | 0x8000);
		tg3_readphy(tp, 0x14, &tmp);
	}

	__tg3_set_rx_mode(tp->dev);

	/* Initialize receive rules. */
	tw32(MAC_RCV_RULE_0,  0xc2000000 & RCV_RULE_DISABLE_MASK);
	tw32(MAC_RCV_VALUE_0, 0xffffffff & RCV_RULE_DISABLE_MASK);
	tw32(MAC_RCV_RULE_1,  0x86000004 & RCV_RULE_DISABLE_MASK);
	tw32(MAC_RCV_VALUE_1, 0xffffffff & RCV_RULE_DISABLE_MASK);
#if 0
	tw32(MAC_RCV_RULE_2,  0); tw32(MAC_RCV_VALUE_2,  0);
	tw32(MAC_RCV_RULE_3,  0); tw32(MAC_RCV_VALUE_3,  0);
#endif
	tw32(MAC_RCV_RULE_4,  0); tw32(MAC_RCV_VALUE_4,  0);
	tw32(MAC_RCV_RULE_5,  0); tw32(MAC_RCV_VALUE_5,  0);
	tw32(MAC_RCV_RULE_6,  0); tw32(MAC_RCV_VALUE_6,  0);
	tw32(MAC_RCV_RULE_7,  0); tw32(MAC_RCV_VALUE_7,  0);
	tw32(MAC_RCV_RULE_8,  0); tw32(MAC_RCV_VALUE_8,  0);
	tw32(MAC_RCV_RULE_9,  0); tw32(MAC_RCV_VALUE_9,  0);
	tw32(MAC_RCV_RULE_10,  0); tw32(MAC_RCV_VALUE_10,  0);
	tw32(MAC_RCV_RULE_11,  0); tw32(MAC_RCV_VALUE_11,  0);
	tw32(MAC_RCV_RULE_12,  0); tw32(MAC_RCV_VALUE_12,  0);
	tw32(MAC_RCV_RULE_13,  0); tw32(MAC_RCV_VALUE_13,  0);
	tw32(MAC_RCV_RULE_14,  0); tw32(MAC_RCV_VALUE_14,  0);
	tw32(MAC_RCV_RULE_15,  0); tw32(MAC_RCV_VALUE_15,  0);

	if (tp->tg3_flags & TG3_FLAG_INIT_COMPLETE)
		tg3_enable_ints(tp);

	return 0;
}

/* Called at device open time to get the chip ready for
 * packet processing.  Invoked with tp->lock held.
 */
static int tg3_init_hw(struct tg3 *tp)
{
	int err;

	/* Force the chip into D0. */
	err = tg3_set_power_state(tp, 0);
	if (err)
		goto out;

	tg3_switch_clocks(tp);

	tw32(TG3PCI_MEM_WIN_BASE_ADDR, 0);

	err = tg3_reset_hw(tp);

out:
	return err;
}

static void tg3_timer(unsigned long __opaque)
{
	struct tg3 *tp = (struct tg3 *) __opaque;
	unsigned long flags;

	spin_lock_irqsave(&tp->lock, flags);
	spin_lock(&tp->tx_lock);

	/* All of this garbage is because when using non-tagged
	 * IRQ status the mailbox/status_block protocol the chip
	 * uses with the cpu is race prone.
	 */
	if (tp->hw_status->status & SD_STATUS_UPDATED) {
		tw32(GRC_LOCAL_CTRL,
		     tp->grc_local_ctrl | GRC_LCLCTRL_SETINT);
	} else {
		tw32(HOSTCC_MODE, tp->coalesce_mode |
		     (HOSTCC_MODE_ENABLE | HOSTCC_MODE_NOW));
	}

	if (!(tr32(WDMAC_MODE) & WDMAC_MODE_ENABLE)) {
		tp->tg3_flags2 |= TG3_FLG2_RESTART_TIMER;
		spin_unlock(&tp->tx_lock);
		spin_unlock_irqrestore(&tp->lock, flags);
#if 0
		schedule_task(&tp->reset_task);
#else
                tg3_halt(tp);
                tg3_init_rings(tp);
                tg3_init_hw(tp);
#endif
		return;
	}

	/* This part only runs once per second. */
	if (!--tp->timer_counter) {
		if (tp->tg3_flags & TG3_FLAG_USE_LINKCHG_REG) {
			u32 mac_stat;
			int phy_event;

			mac_stat = tr32(MAC_STATUS);

			phy_event = 0;
			if (tp->tg3_flags & TG3_FLAG_USE_MI_INTERRUPT) {
				if (mac_stat & MAC_STATUS_MI_INTERRUPT)
					phy_event = 1;
			} else if (mac_stat & MAC_STATUS_LNKSTATE_CHANGED)
				phy_event = 1;

			if (phy_event)
				tg3_setup_phy(tp);
		} else if (tp->tg3_flags & TG3_FLAG_POLL_SERDES) {
			u32 mac_stat = tr32(MAC_STATUS);
			int need_setup = 0;

			if (netif_carrier_ok(tp->dev) &&
			    (mac_stat & MAC_STATUS_LNKSTATE_CHANGED)) {
				need_setup = 1;
			}
			if (! netif_carrier_ok(tp->dev) &&
			    (mac_stat & MAC_STATUS_PCS_SYNCED)) {
				need_setup = 1;
			}
			if (need_setup) {
				tw32(MAC_MODE,
				     (tp->mac_mode &
				      ~MAC_MODE_PORT_MODE_MASK));
				tr32(MAC_MODE);
				udelay(40);
				tw32(MAC_MODE, tp->mac_mode);
				tr32(MAC_MODE);
				udelay(40);
				tg3_setup_phy(tp);
			}
		}

		tp->timer_counter = tp->timer_multiplier;
	}

	/* Heartbeat is only sent once every 120 seconds.  */
	if (!--tp->asf_counter) {
		if (tp->tg3_flags & TG3_FLAG_ENABLE_ASF) {
			u32 val;

			tg3_write_mem(tp, NIC_SRAM_FW_CMD_MBOX, FWCMD_NICDRV_ALIVE);
			tg3_write_mem(tp, NIC_SRAM_FW_CMD_LEN_MBOX, 4);
			tg3_write_mem(tp, NIC_SRAM_FW_CMD_DATA_MBOX, 3);
			val = tr32(GRC_RX_CPU_EVENT);
			val |= (1 << 14);
			tw32(GRC_RX_CPU_EVENT, val);
		}
		tp->asf_counter = tp->asf_multiplier;
	}

	spin_unlock(&tp->tx_lock);
	spin_unlock_irqrestore(&tp->lock, flags);

	tp->timer.expires = jiffies + tp->timer_offset;
	add_timer(&tp->timer);
}

static int tg3_open(struct net_device *dev)
{
	struct tg3 *tp = dev->priv;
	int err;

	spin_lock_irq(&tp->lock);
	spin_lock(&tp->tx_lock);

	tg3_disable_ints(tp);
	tp->tg3_flags &= ~TG3_FLAG_INIT_COMPLETE;

	spin_unlock(&tp->tx_lock);
	spin_unlock_irq(&tp->lock);

	/* If you move this call, make sure TG3_FLAG_HOST_TXDS in
	 * tp->tg3_flags is accurate at that new place.
	 */
	err = tg3_alloc_consistent(tp);
	if (err)
		return err;

	err = request_irq(dev->irq, tg3_interrupt,
			  SA_SHIRQ, dev->name, dev);

	if (err) {
		tg3_free_consistent(tp);
		return err;
	}

	spin_lock_irq(&tp->lock);
	spin_lock(&tp->tx_lock);

	tg3_init_rings(tp);

	err = tg3_init_hw(tp);
	if (err) {
		tg3_halt(tp);
		tg3_free_rings(tp);
	} else {
		tp->timer_offset = HZ / 10;
		tp->timer_counter = tp->timer_multiplier = 10;
		tp->asf_counter = tp->asf_multiplier = (10 * 120);

		init_timer(&tp->timer);
		tp->timer.expires = jiffies + tp->timer_offset;
		tp->timer.data = (unsigned long) tp;
		tp->timer.function = tg3_timer;
		add_timer(&tp->timer);

		tp->tg3_flags |= TG3_FLAG_INIT_COMPLETE;
	}

	spin_unlock(&tp->tx_lock);
	spin_unlock_irq(&tp->lock);

	if (err) {
		free_irq(dev->irq, dev);
		tg3_free_consistent(tp);
		return err;
	}

	spin_lock_irq(&tp->lock);
	spin_lock(&tp->tx_lock);

	tg3_enable_ints(tp);

	spin_unlock(&tp->tx_lock);
	spin_unlock_irq(&tp->lock);

	netif_start_queue(dev);

	return 0;
}

#if 0
/*static*/ void tg3_dump_state(struct tg3 *tp)
{
	u32 val32, val32_2, val32_3, val32_4, val32_5;
	u16 val16;
	int i;

	pci_read_config_word(tp->pdev, PCI_STATUS, &val16);
	pci_read_config_dword(tp->pdev, TG3PCI_PCISTATE, &val32);
	printk("DEBUG: PCI status [%04x] TG3PCI state[%08x]\n",
	       val16, val32);

	/* MAC block */
	printk("DEBUG: MAC_MODE[%08x] MAC_STATUS[%08x]\n",
	       tr32(MAC_MODE), tr32(MAC_STATUS));
	printk("       MAC_EVENT[%08x] MAC_LED_CTRL[%08x]\n",
	       tr32(MAC_EVENT), tr32(MAC_LED_CTRL));
	printk("DEBUG: MAC_TX_MODE[%08x] MAC_TX_STATUS[%08x]\n",
	       tr32(MAC_TX_MODE), tr32(MAC_TX_STATUS));
	printk("       MAC_RX_MODE[%08x] MAC_RX_STATUS[%08x]\n",
	       tr32(MAC_RX_MODE), tr32(MAC_RX_STATUS));

	/* Send data initiator control block */
	printk("DEBUG: SNDDATAI_MODE[%08x] SNDDATAI_STATUS[%08x]\n",
	       tr32(SNDDATAI_MODE), tr32(SNDDATAI_STATUS));
	printk("       SNDDATAI_STATSCTRL[%08x]\n",
	       tr32(SNDDATAI_STATSCTRL));

	/* Send data completion control block */
	printk("DEBUG: SNDDATAC_MODE[%08x]\n", tr32(SNDDATAC_MODE));

	/* Send BD ring selector block */
	printk("DEBUG: SNDBDS_MODE[%08x] SNDBDS_STATUS[%08x]\n",
	       tr32(SNDBDS_MODE), tr32(SNDBDS_STATUS));

	/* Send BD initiator control block */
	printk("DEBUG: SNDBDI_MODE[%08x] SNDBDI_STATUS[%08x]\n",
	       tr32(SNDBDI_MODE), tr32(SNDBDI_STATUS));

	/* Send BD completion control block */
	printk("DEBUG: SNDBDC_MODE[%08x]\n", tr32(SNDBDC_MODE));

	/* Receive list placement control block */
	printk("DEBUG: RCVLPC_MODE[%08x] RCVLPC_STATUS[%08x]\n",
	       tr32(RCVLPC_MODE), tr32(RCVLPC_STATUS));
	printk("       RCVLPC_STATSCTRL[%08x]\n",
	       tr32(RCVLPC_STATSCTRL));

	/* Receive data and receive BD initiator control block */
	printk("DEBUG: RCVDBDI_MODE[%08x] RCVDBDI_STATUS[%08x]\n",
	       tr32(RCVDBDI_MODE), tr32(RCVDBDI_STATUS));

	/* Receive data completion control block */
	printk("DEBUG: RCVDCC_MODE[%08x]\n",
	       tr32(RCVDCC_MODE));

	/* Receive BD initiator control block */
	printk("DEBUG: RCVBDI_MODE[%08x] RCVBDI_STATUS[%08x]\n",
	       tr32(RCVBDI_MODE), tr32(RCVBDI_STATUS));

	/* Receive BD completion control block */
	printk("DEBUG: RCVCC_MODE[%08x] RCVCC_STATUS[%08x]\n",
	       tr32(RCVCC_MODE), tr32(RCVCC_STATUS));

	/* Receive list selector control block */
	printk("DEBUG: RCVLSC_MODE[%08x] RCVLSC_STATUS[%08x]\n",
	       tr32(RCVLSC_MODE), tr32(RCVLSC_STATUS));

	/* Mbuf cluster free block */
	printk("DEBUG: MBFREE_MODE[%08x] MBFREE_STATUS[%08x]\n",
	       tr32(MBFREE_MODE), tr32(MBFREE_STATUS));

	/* Host coalescing control block */
	printk("DEBUG: HOSTCC_MODE[%08x] HOSTCC_STATUS[%08x]\n",
	       tr32(HOSTCC_MODE), tr32(HOSTCC_STATUS));
	printk("DEBUG: HOSTCC_STATS_BLK_HOST_ADDR[%08x%08x]\n",
	       tr32(HOSTCC_STATS_BLK_HOST_ADDR + TG3_64BIT_REG_HIGH),
	       tr32(HOSTCC_STATS_BLK_HOST_ADDR + TG3_64BIT_REG_LOW));
	printk("DEBUG: HOSTCC_STATUS_BLK_HOST_ADDR[%08x%08x]\n",
	       tr32(HOSTCC_STATUS_BLK_HOST_ADDR + TG3_64BIT_REG_HIGH),
	       tr32(HOSTCC_STATUS_BLK_HOST_ADDR + TG3_64BIT_REG_LOW));
	printk("DEBUG: HOSTCC_STATS_BLK_NIC_ADDR[%08x]\n",
	       tr32(HOSTCC_STATS_BLK_NIC_ADDR));
	printk("DEBUG: HOSTCC_STATUS_BLK_NIC_ADDR[%08x]\n",
	       tr32(HOSTCC_STATUS_BLK_NIC_ADDR));

	/* Memory arbiter control block */
	printk("DEBUG: MEMARB_MODE[%08x] MEMARB_STATUS[%08x]\n",
	       tr32(MEMARB_MODE), tr32(MEMARB_STATUS));

	/* Buffer manager control block */
	printk("DEBUG: BUFMGR_MODE[%08x] BUFMGR_STATUS[%08x]\n",
	       tr32(BUFMGR_MODE), tr32(BUFMGR_STATUS));
	printk("DEBUG: BUFMGR_MB_POOL_ADDR[%08x] BUFMGR_MB_POOL_SIZE[%08x]\n",
	       tr32(BUFMGR_MB_POOL_ADDR), tr32(BUFMGR_MB_POOL_SIZE));
	printk("DEBUG: BUFMGR_DMA_DESC_POOL_ADDR[%08x] "
	       "BUFMGR_DMA_DESC_POOL_SIZE[%08x]\n",
	       tr32(BUFMGR_DMA_DESC_POOL_ADDR),
	       tr32(BUFMGR_DMA_DESC_POOL_SIZE));

	/* Read DMA control block */
	printk("DEBUG: RDMAC_MODE[%08x] RDMAC_STATUS[%08x]\n",
	       tr32(RDMAC_MODE), tr32(RDMAC_STATUS));

	/* Write DMA control block */
	printk("DEBUG: WDMAC_MODE[%08x] WDMAC_STATUS[%08x]\n",
	       tr32(WDMAC_MODE), tr32(WDMAC_STATUS));

	/* DMA completion block */
	printk("DEBUG: DMAC_MODE[%08x]\n",
	       tr32(DMAC_MODE));

	/* GRC block */
	printk("DEBUG: GRC_MODE[%08x] GRC_MISC_CFG[%08x]\n",
	       tr32(GRC_MODE), tr32(GRC_MISC_CFG));
	printk("DEBUG: GRC_LOCAL_CTRL[%08x]\n",
	       tr32(GRC_LOCAL_CTRL));

	/* TG3_BDINFOs */
	printk("DEBUG: RCVDBDI_JUMBO_BD[%08x%08x:%08x:%08x]\n",
	       tr32(RCVDBDI_JUMBO_BD + 0x0),
	       tr32(RCVDBDI_JUMBO_BD + 0x4),
	       tr32(RCVDBDI_JUMBO_BD + 0x8),
	       tr32(RCVDBDI_JUMBO_BD + 0xc));
	printk("DEBUG: RCVDBDI_STD_BD[%08x%08x:%08x:%08x]\n",
	       tr32(RCVDBDI_STD_BD + 0x0),
	       tr32(RCVDBDI_STD_BD + 0x4),
	       tr32(RCVDBDI_STD_BD + 0x8),
	       tr32(RCVDBDI_STD_BD + 0xc));
	printk("DEBUG: RCVDBDI_MINI_BD[%08x%08x:%08x:%08x]\n",
	       tr32(RCVDBDI_MINI_BD + 0x0),
	       tr32(RCVDBDI_MINI_BD + 0x4),
	       tr32(RCVDBDI_MINI_BD + 0x8),
	       tr32(RCVDBDI_MINI_BD + 0xc));

	tg3_read_mem(tp, NIC_SRAM_SEND_RCB + 0x0, &val32);
	tg3_read_mem(tp, NIC_SRAM_SEND_RCB + 0x4, &val32_2);
	tg3_read_mem(tp, NIC_SRAM_SEND_RCB + 0x8, &val32_3);
	tg3_read_mem(tp, NIC_SRAM_SEND_RCB + 0xc, &val32_4);
	printk("DEBUG: SRAM_SEND_RCB_0[%08x%08x:%08x:%08x]\n",
	       val32, val32_2, val32_3, val32_4);

	tg3_read_mem(tp, NIC_SRAM_RCV_RET_RCB + 0x0, &val32);
	tg3_read_mem(tp, NIC_SRAM_RCV_RET_RCB + 0x4, &val32_2);
	tg3_read_mem(tp, NIC_SRAM_RCV_RET_RCB + 0x8, &val32_3);
	tg3_read_mem(tp, NIC_SRAM_RCV_RET_RCB + 0xc, &val32_4);
	printk("DEBUG: SRAM_RCV_RET_RCB_0[%08x%08x:%08x:%08x]\n",
	       val32, val32_2, val32_3, val32_4);

	tg3_read_mem(tp, NIC_SRAM_STATUS_BLK + 0x0, &val32);
	tg3_read_mem(tp, NIC_SRAM_STATUS_BLK + 0x4, &val32_2);
	tg3_read_mem(tp, NIC_SRAM_STATUS_BLK + 0x8, &val32_3);
	tg3_read_mem(tp, NIC_SRAM_STATUS_BLK + 0xc, &val32_4);
	tg3_read_mem(tp, NIC_SRAM_STATUS_BLK + 0x10, &val32_5);
	printk("DEBUG: SRAM_STATUS_BLK[%08x:%08x:%08x:%08x:%08x]\n",
	       val32, val32_2, val32_3, val32_4, val32_5);

	/* SW status block */
	printk("DEBUG: Host status block [%08x:%08x:(%04x:%04x:%04x):(%04x:%04x)]\n",
	       tp->hw_status->status,
	       tp->hw_status->status_tag,
	       tp->hw_status->rx_jumbo_consumer,
	       tp->hw_status->rx_consumer,
	       tp->hw_status->rx_mini_consumer,
	       tp->hw_status->idx[0].rx_producer,
	       tp->hw_status->idx[0].tx_consumer);

	/* SW statistics block */
	printk("DEBUG: Host statistics block [%08x:%08x:%08x:%08x]\n",
	       ((u32 *)tp->hw_stats)[0],
	       ((u32 *)tp->hw_stats)[1],
	       ((u32 *)tp->hw_stats)[2],
	       ((u32 *)tp->hw_stats)[3]);

	/* Mailboxes */
	printk("DEBUG: SNDHOST_PROD[%08x%08x] SNDNIC_PROD[%08x%08x]\n",
	       tr32(MAILBOX_SNDHOST_PROD_IDX_0 + 0x0),
	       tr32(MAILBOX_SNDHOST_PROD_IDX_0 + 0x4),
	       tr32(MAILBOX_SNDNIC_PROD_IDX_0 + 0x0),
	       tr32(MAILBOX_SNDNIC_PROD_IDX_0 + 0x4));

	/* NIC side send descriptors. */
	for (i = 0; i < 6; i++) {
		unsigned long txd;

		txd = tp->regs + NIC_SRAM_WIN_BASE + NIC_SRAM_TX_BUFFER_DESC
			+ (i * sizeof(struct tg3_tx_buffer_desc));
		printk("DEBUG: NIC TXD(%d)[%08x:%08x:%08x:%08x]\n",
		       i,
		       readl(txd + 0x0), readl(txd + 0x4),
		       readl(txd + 0x8), readl(txd + 0xc));
	}

	/* NIC side RX descriptors. */
	for (i = 0; i < 6; i++) {
		unsigned long rxd;

		rxd = tp->regs + NIC_SRAM_WIN_BASE + NIC_SRAM_RX_BUFFER_DESC
			+ (i * sizeof(struct tg3_rx_buffer_desc));
		printk("DEBUG: NIC RXD_STD(%d)[0][%08x:%08x:%08x:%08x]\n",
		       i,
		       readl(rxd + 0x0), readl(rxd + 0x4),
		       readl(rxd + 0x8), readl(rxd + 0xc));
		rxd += (4 * sizeof(u32));
		printk("DEBUG: NIC RXD_STD(%d)[1][%08x:%08x:%08x:%08x]\n",
		       i,
		       readl(rxd + 0x0), readl(rxd + 0x4),
		       readl(rxd + 0x8), readl(rxd + 0xc));
	}

	for (i = 0; i < 6; i++) {
		unsigned long rxd;

		rxd = tp->regs + NIC_SRAM_WIN_BASE + NIC_SRAM_RX_JUMBO_BUFFER_DESC
			+ (i * sizeof(struct tg3_rx_buffer_desc));
		printk("DEBUG: NIC RXD_JUMBO(%d)[0][%08x:%08x:%08x:%08x]\n",
		       i,
		       readl(rxd + 0x0), readl(rxd + 0x4),
		       readl(rxd + 0x8), readl(rxd + 0xc));
		rxd += (4 * sizeof(u32));
		printk("DEBUG: NIC RXD_JUMBO(%d)[1][%08x:%08x:%08x:%08x]\n",
		       i,
		       readl(rxd + 0x0), readl(rxd + 0x4),
		       readl(rxd + 0x8), readl(rxd + 0xc));
	}
}
#endif

static struct net_device_stats *tg3_get_stats(struct net_device *);

static int tg3_close(struct net_device *dev)
{
	struct tg3 *tp = dev->priv;

	netif_stop_queue(dev);

	del_timer_sync(&tp->timer);

	spin_lock_irq(&tp->lock);
	spin_lock(&tp->tx_lock);
#if 0
	tg3_dump_state(tp);
#endif

	tg3_disable_ints(tp);

	tg3_halt(tp);
	tg3_free_rings(tp);
	tp->tg3_flags &=
		~(TG3_FLAG_INIT_COMPLETE |
		  TG3_FLAG_GOT_SERDES_FLOWCTL);
	netif_carrier_off(tp->dev);

	spin_unlock(&tp->tx_lock);
	spin_unlock_irq(&tp->lock);

	free_irq(dev->irq, dev);

	memcpy(&tp->net_stats_prev, tg3_get_stats(tp->dev),
	       sizeof(tp->net_stats_prev));

	tg3_free_consistent(tp);

	return 0;
}

static inline unsigned long get_stat64(tg3_stat64_t *val)
{
	unsigned long ret;

#if (BITS_PER_LONG == 32)
	ret = val->low;
#else
	ret = ((u64)val->high << 32) | ((u64)val->low);
#endif
	return ret;
}

static unsigned long calc_crc_errors(struct tg3 *tp)
{
	struct tg3_hw_stats *hw_stats = tp->hw_stats;

	if (tp->phy_id != PHY_ID_SERDES &&
	    (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700 ||
	     GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5701)) {
		unsigned long flags;
		u32 val;

		spin_lock_irqsave(&tp->lock, flags);
		tg3_readphy(tp, 0x1e, &val);
		tg3_writephy(tp, 0x1e, val | 0x8000);
		tg3_readphy(tp, 0x14, &val);
		spin_unlock_irqrestore(&tp->lock, flags);

		tp->phy_crc_errors += val;

		return tp->phy_crc_errors;
	}

	return get_stat64(&hw_stats->rx_fcs_errors);
}

static struct net_device_stats *tg3_get_stats(struct net_device *dev)
{
	struct tg3 *tp = dev->priv;
	struct net_device_stats *stats = &tp->net_stats;
	struct net_device_stats *old_stats = &tp->net_stats_prev;
	struct tg3_hw_stats *hw_stats = tp->hw_stats;

	if (!hw_stats)
		return old_stats;

	stats->rx_packets = old_stats->rx_packets +
		get_stat64(&hw_stats->rx_ucast_packets) +
		get_stat64(&hw_stats->rx_mcast_packets) +
		get_stat64(&hw_stats->rx_bcast_packets);
		
	stats->tx_packets = old_stats->tx_packets +
		get_stat64(&hw_stats->COS_out_packets[0]);

	stats->rx_bytes = old_stats->rx_bytes +
		get_stat64(&hw_stats->rx_octets);
	stats->tx_bytes = old_stats->tx_bytes +
		get_stat64(&hw_stats->tx_octets);

	stats->rx_errors = old_stats->rx_errors +
		get_stat64(&hw_stats->rx_errors);
	stats->tx_errors = old_stats->tx_errors +
		get_stat64(&hw_stats->tx_errors) +
		get_stat64(&hw_stats->tx_mac_errors) +
		get_stat64(&hw_stats->tx_carrier_sense_errors) +
		get_stat64(&hw_stats->tx_discards);

	stats->multicast = old_stats->multicast +
		get_stat64(&hw_stats->rx_mcast_packets);
	stats->collisions = old_stats->collisions +
		get_stat64(&hw_stats->tx_collisions);

	stats->rx_length_errors = old_stats->rx_length_errors +
		get_stat64(&hw_stats->rx_frame_too_long_errors) +
		get_stat64(&hw_stats->rx_undersize_packets);

	stats->rx_over_errors = old_stats->rx_over_errors +
		get_stat64(&hw_stats->rxbds_empty);
	stats->rx_frame_errors = old_stats->rx_frame_errors +
		get_stat64(&hw_stats->rx_align_errors);
	stats->tx_aborted_errors = old_stats->tx_aborted_errors +
		get_stat64(&hw_stats->tx_discards);
	stats->tx_carrier_errors = old_stats->tx_carrier_errors +
		get_stat64(&hw_stats->tx_carrier_sense_errors);

	stats->rx_crc_errors = old_stats->rx_crc_errors +
		calc_crc_errors(tp);

	return stats;
}

static inline u32 calc_crc(unsigned char *buf, int len)
{
	u32 reg;
	u32 tmp;
	int j, k;

	reg = 0xffffffff;

	for (j = 0; j < len; j++) {
		reg ^= buf[j];

		for (k = 0; k < 8; k++) {
			tmp = reg & 0x01;

			reg >>= 1;

			if (tmp) {
				reg ^= 0xedb88320;
			}
		}
	}

	return ~reg;
}

static void tg3_set_multi(struct tg3 *tp, unsigned int accept_all)
{
	/* accept or reject all multicast frames */
	tw32(MAC_HASH_REG_0, accept_all ? 0xffffffff : 0);
	tw32(MAC_HASH_REG_1, accept_all ? 0xffffffff : 0);
	tw32(MAC_HASH_REG_2, accept_all ? 0xffffffff : 0);
	tw32(MAC_HASH_REG_3, accept_all ? 0xffffffff : 0);
}

static void __tg3_set_rx_mode(struct net_device *dev)
{
	struct tg3 *tp = dev->priv;
	u32 rx_mode;

	rx_mode = tp->rx_mode & ~(RX_MODE_PROMISC |
				  RX_MODE_KEEP_VLAN_TAG);
#if TG3_VLAN_TAG_USED
	if (!tp->vlgrp)
		rx_mode |= RX_MODE_KEEP_VLAN_TAG;
#else
	/* By definition, VLAN is disabled always in this
	 * case.
	 */
	rx_mode |= RX_MODE_KEEP_VLAN_TAG;
#endif

	if (dev->flags & IFF_PROMISC) {
		/* Promiscuous mode. */
		rx_mode |= RX_MODE_PROMISC;
	} else if (dev->flags & IFF_ALLMULTI) {
		/* Accept all multicast. */
		tg3_set_multi (tp, 1);
	} else if (dev->mc_count < 1) {
		/* Reject all multicast. */
		tg3_set_multi (tp, 0);
	} else {
		/* Accept one or more multicast(s). */
		struct dev_mc_list *mclist;
		unsigned int i;
		u32 mc_filter[4] = { 0, };
		u32 regidx;
		u32 bit;
		u32 crc;

		for (i = 0, mclist = dev->mc_list; mclist && i < dev->mc_count;
		     i++, mclist = mclist->next) {

			crc = calc_crc (mclist->dmi_addr, ETH_ALEN);
			bit = ~crc & 0x7f;
			regidx = (bit & 0x60) >> 5;
			bit &= 0x1f;
			mc_filter[regidx] |= (1 << bit);
		}

		tw32(MAC_HASH_REG_0, mc_filter[0]);
		tw32(MAC_HASH_REG_1, mc_filter[1]);
		tw32(MAC_HASH_REG_2, mc_filter[2]);
		tw32(MAC_HASH_REG_3, mc_filter[3]);
	}

	if (rx_mode != tp->rx_mode) {
		tp->rx_mode = rx_mode;
		tw32(MAC_RX_MODE, rx_mode);
		tr32(MAC_RX_MODE);
		udelay(10);
	}
}

static void tg3_set_rx_mode(struct net_device *dev)
{
	struct tg3 *tp = dev->priv;

	spin_lock_irq(&tp->lock);
	__tg3_set_rx_mode(dev);
	spin_unlock_irq(&tp->lock);
}

#define TG3_REGDUMP_LEN		(32 * 1024)

static u8 *tg3_get_regs(struct tg3 *tp)
{
	u8 *orig_p = kmalloc(TG3_REGDUMP_LEN, GFP_KERNEL);
	u8 *p;
	int i;

	if (orig_p == NULL)
		return NULL;

	memset(orig_p, 0, TG3_REGDUMP_LEN);

	spin_lock_irq(&tp->lock);
	spin_lock(&tp->tx_lock);

#define __GET_REG32(reg)	(*((u32 *)(p))++ = tr32(reg))
#define GET_REG32_LOOP(base,len)		\
do {	p = orig_p + (base);			\
	for (i = 0; i < len; i += 4)		\
		__GET_REG32((base) + i);	\
} while (0)
#define GET_REG32_1(reg)	\
do {	p = orig_p + (reg);	\
	__GET_REG32((reg));	\
} while (0)

	GET_REG32_LOOP(TG3PCI_VENDOR, 0xb0);
	GET_REG32_LOOP(MAILBOX_INTERRUPT_0, 0x200);
	GET_REG32_LOOP(MAC_MODE, 0x4f0);
	GET_REG32_LOOP(SNDDATAI_MODE, 0xe0);
	GET_REG32_1(SNDDATAC_MODE);
	GET_REG32_LOOP(SNDBDS_MODE, 0x80);
	GET_REG32_LOOP(SNDBDI_MODE, 0x48);
	GET_REG32_1(SNDBDC_MODE);
	GET_REG32_LOOP(RCVLPC_MODE, 0x20);
	GET_REG32_LOOP(RCVLPC_SELLST_BASE, 0x15c);
	GET_REG32_LOOP(RCVDBDI_MODE, 0x0c);
	GET_REG32_LOOP(RCVDBDI_JUMBO_BD, 0x3c);
	GET_REG32_LOOP(RCVDBDI_BD_PROD_IDX_0, 0x44);
	GET_REG32_1(RCVDCC_MODE);
	GET_REG32_LOOP(RCVBDI_MODE, 0x20);
	GET_REG32_LOOP(RCVCC_MODE, 0x14);
	GET_REG32_LOOP(RCVLSC_MODE, 0x08);
	GET_REG32_1(MBFREE_MODE);
	GET_REG32_LOOP(HOSTCC_MODE, 0x100);
	GET_REG32_LOOP(MEMARB_MODE, 0x10);
	GET_REG32_LOOP(BUFMGR_MODE, 0x58);
	GET_REG32_LOOP(RDMAC_MODE, 0x08);
	GET_REG32_LOOP(WDMAC_MODE, 0x08);
	GET_REG32_LOOP(RX_CPU_BASE, 0x280);
	GET_REG32_LOOP(TX_CPU_BASE, 0x280);
	GET_REG32_LOOP(GRCMBOX_INTERRUPT_0, 0x110);
	GET_REG32_LOOP(FTQ_RESET, 0x120);
	GET_REG32_LOOP(MSGINT_MODE, 0x0c);
	GET_REG32_1(DMAC_MODE);
	GET_REG32_LOOP(GRC_MODE, 0x4c);
	GET_REG32_LOOP(NVRAM_CMD, 0x24);

#undef __GET_REG32
#undef GET_REG32_LOOP
#undef GET_REG32_1

	spin_unlock(&tp->tx_lock);
	spin_unlock_irq(&tp->lock);

	return orig_p;
}

static int tg3_ethtool_ioctl (struct net_device *dev, void *useraddr)
{
	struct tg3 *tp = dev->priv;
	struct pci_dev *pci_dev = tp->pdev;
	u32 ethcmd;

	if (copy_from_user (&ethcmd, useraddr, sizeof (ethcmd)))
		return -EFAULT;

	switch (ethcmd) {
	case ETHTOOL_GDRVINFO:{
		struct ethtool_drvinfo info = { ETHTOOL_GDRVINFO };
		strcpy (info.driver, DRV_MODULE_NAME);
		strcpy (info.version, DRV_MODULE_VERSION);
		memset(&info.fw_version, 0, sizeof(info.fw_version));
		strcpy (info.bus_info, pci_dev->slot_name);
		info.eedump_len = 0;
		info.regdump_len = TG3_REGDUMP_LEN;
		if (copy_to_user (useraddr, &info, sizeof (info)))
			return -EFAULT;
		return 0;
	}

	case ETHTOOL_GSET: {
		struct ethtool_cmd cmd = { ETHTOOL_GSET };

		if (!(tp->tg3_flags & TG3_FLAG_INIT_COMPLETE) ||
		    tp->link_config.phy_is_low_power)
			return -EAGAIN;
		cmd.supported = (SUPPORTED_Autoneg);

		if (!(tp->tg3_flags & TG3_FLAG_10_100_ONLY))
			cmd.supported |= (SUPPORTED_1000baseT_Half |
					  SUPPORTED_1000baseT_Full);

		if (tp->phy_id != PHY_ID_SERDES)
			cmd.supported |= (SUPPORTED_100baseT_Half |
					  SUPPORTED_100baseT_Full |
					  SUPPORTED_10baseT_Half |
					  SUPPORTED_10baseT_Full |
					  SUPPORTED_MII);
		else
			cmd.supported |= SUPPORTED_FIBRE;

		cmd.advertising = tp->link_config.advertising;
		cmd.speed = tp->link_config.active_speed;
		cmd.duplex = tp->link_config.active_duplex;
		cmd.port = 0;
		cmd.phy_address = PHY_ADDR;
		cmd.transceiver = 0;
		cmd.autoneg = tp->link_config.autoneg;
		cmd.maxtxpkt = 0;
		cmd.maxrxpkt = 0;
		if (copy_to_user(useraddr, &cmd, sizeof(cmd)))
			return -EFAULT;
		return 0;
	}
	case ETHTOOL_SSET: {
		struct ethtool_cmd cmd;

		if (!(tp->tg3_flags & TG3_FLAG_INIT_COMPLETE) ||
		    tp->link_config.phy_is_low_power)
			return -EAGAIN;

		if (copy_from_user(&cmd, useraddr, sizeof(cmd)))
			return -EFAULT;

		/* Fiber PHY only supports 1000 full/half */
		if (cmd.autoneg == AUTONEG_ENABLE) {
			if (tp->phy_id == PHY_ID_SERDES &&
			    (cmd.advertising &
			     (ADVERTISED_10baseT_Half |
			      ADVERTISED_10baseT_Full |
			      ADVERTISED_100baseT_Half |
			      ADVERTISED_100baseT_Full)))
				return -EINVAL;
			if ((tp->tg3_flags & TG3_FLAG_10_100_ONLY) &&
			    (cmd.advertising &
			     (ADVERTISED_1000baseT_Half |
			      ADVERTISED_1000baseT_Full)))
				return -EINVAL;
		} else {
			if (tp->phy_id == PHY_ID_SERDES &&
			    (cmd.speed == SPEED_10 ||
			     cmd.speed == SPEED_100))
				return -EINVAL;
			if ((tp->tg3_flags & TG3_FLAG_10_100_ONLY) &&
			    (cmd.speed == SPEED_10 ||
			     cmd.speed == SPEED_100))
				return -EINVAL;
		}

		spin_lock_irq(&tp->lock);
		spin_lock(&tp->tx_lock);

		tp->link_config.autoneg = cmd.autoneg;
		if (cmd.autoneg == AUTONEG_ENABLE) {
			tp->link_config.advertising = cmd.advertising;
			tp->link_config.speed = SPEED_INVALID;
			tp->link_config.duplex = DUPLEX_INVALID;
		} else {
			tp->link_config.speed = cmd.speed;
			tp->link_config.duplex = cmd.duplex;
		}

		tg3_setup_phy(tp);
		spin_unlock(&tp->tx_lock);
		spin_unlock_irq(&tp->lock);

		return 0;
	}

	case ETHTOOL_GREGS: {
		struct ethtool_regs regs;
		u8 *regbuf;
		int ret;

		if (copy_from_user(&regs, useraddr, sizeof(regs)))
			return -EFAULT;
		if (regs.len > TG3_REGDUMP_LEN)
			regs.len = TG3_REGDUMP_LEN;
		regs.version = 0;
		if (copy_to_user(useraddr, &regs, sizeof(regs)))
			return -EFAULT;

		regbuf = tg3_get_regs(tp);
		if (!regbuf)
			return -ENOMEM;

		useraddr += offsetof(struct ethtool_regs, data);
		ret = 0;
		if (copy_to_user(useraddr, regbuf, regs.len))
			ret = -EFAULT;
		kfree(regbuf);
		return ret;
	}
	case ETHTOOL_GWOL: {
		struct ethtool_wolinfo wol = { ETHTOOL_GWOL };

		wol.supported = WAKE_MAGIC;
		wol.wolopts = 0;
		if (tp->tg3_flags & TG3_FLAG_WOL_ENABLE)
			wol.wolopts = WAKE_MAGIC;
		memset(&wol.sopass, 0, sizeof(wol.sopass));
		if (copy_to_user(useraddr, &wol, sizeof(wol)))
			return -EFAULT;
		return 0;
	}
	case ETHTOOL_SWOL: {
		struct ethtool_wolinfo wol;

		if (copy_from_user(&wol, useraddr, sizeof(wol)))
			return -EFAULT;
		if (wol.wolopts & ~WAKE_MAGIC)
			return -EINVAL;
		if ((wol.wolopts & WAKE_MAGIC) &&
		    tp->phy_id == PHY_ID_SERDES &&
		    !(tp->tg3_flags & TG3_FLAG_SERDES_WOL_CAP))
			return -EINVAL;

		spin_lock_irq(&tp->lock);
		if (wol.wolopts & WAKE_MAGIC)
			tp->tg3_flags |= TG3_FLAG_WOL_ENABLE;
		else
			tp->tg3_flags &= ~TG3_FLAG_WOL_ENABLE;
		spin_unlock_irq(&tp->lock);

		return 0;
	}
	case ETHTOOL_GMSGLVL: {
		struct ethtool_value edata = { ETHTOOL_GMSGLVL };
		edata.data = tp->msg_enable;
		if (copy_to_user(useraddr, &edata, sizeof(edata)))
			return -EFAULT;
		return 0;
	}
	case ETHTOOL_SMSGLVL: {
		struct ethtool_value edata;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		tp->msg_enable = edata.data;
		return 0;
	}
	case ETHTOOL_NWAY_RST: {
		u32 bmcr;
		int r;

		spin_lock_irq(&tp->lock);
		tg3_readphy(tp, MII_BMCR, &bmcr);
		tg3_readphy(tp, MII_BMCR, &bmcr);
		r = -EINVAL;
		if (bmcr & BMCR_ANENABLE) {
			tg3_writephy(tp, MII_BMCR,
				     bmcr | BMCR_ANRESTART);
			r = 0;
		}
		spin_unlock_irq(&tp->lock);

		return r;
	}
	case ETHTOOL_GLINK: {
		struct ethtool_value edata = { ETHTOOL_GLINK };
		edata.data = netif_carrier_ok(tp->dev) ? 1 : 0;
		if (copy_to_user(useraddr, &edata, sizeof(edata)))
			return -EFAULT;
		return 0;
	}
	case ETHTOOL_GRINGPARAM: {
		struct ethtool_ringparam ering = { ETHTOOL_GRINGPARAM };

		ering.rx_max_pending = TG3_RX_RING_SIZE - 1;
		ering.rx_mini_max_pending = 0;
		ering.rx_jumbo_max_pending = TG3_RX_JUMBO_RING_SIZE - 1;

		ering.rx_pending = tp->rx_pending;
		ering.rx_mini_pending = 0;
		ering.rx_jumbo_pending = tp->rx_jumbo_pending;
		ering.tx_pending = tp->tx_pending;

		if (copy_to_user(useraddr, &ering, sizeof(ering)))
			return -EFAULT;
		return 0;
	}
	case ETHTOOL_SRINGPARAM: {
		struct ethtool_ringparam ering;

		if (copy_from_user(&ering, useraddr, sizeof(ering)))
			return -EFAULT;

		if ((ering.rx_pending > TG3_RX_RING_SIZE - 1) ||
		    (ering.rx_jumbo_pending > TG3_RX_JUMBO_RING_SIZE - 1) ||
		    (ering.tx_pending > TG3_TX_RING_SIZE - 1))
			return -EINVAL;

		tg3_netif_stop(tp);
		spin_lock_irq(&tp->lock);
		spin_lock(&tp->tx_lock);

		tp->rx_pending = ering.rx_pending;
		tp->rx_jumbo_pending = ering.rx_jumbo_pending;
		tp->tx_pending = ering.tx_pending;

		tg3_halt(tp);
		tg3_init_rings(tp);
		tg3_init_hw(tp);
		netif_wake_queue(tp->dev);
		spin_unlock(&tp->tx_lock);
		spin_unlock_irq(&tp->lock);
		tg3_netif_start(tp);

		return 0;
	}
	case ETHTOOL_GPAUSEPARAM: {
		struct ethtool_pauseparam epause = { ETHTOOL_GPAUSEPARAM };

		epause.autoneg =
			(tp->tg3_flags & TG3_FLAG_PAUSE_AUTONEG) != 0;
		epause.rx_pause =
			(tp->tg3_flags & TG3_FLAG_PAUSE_RX) != 0;
		epause.tx_pause =
			(tp->tg3_flags & TG3_FLAG_PAUSE_TX) != 0;
		if (copy_to_user(useraddr, &epause, sizeof(epause)))
			return -EFAULT;
		return 0;
	}
	case ETHTOOL_SPAUSEPARAM: {
		struct ethtool_pauseparam epause;

		if (copy_from_user(&epause, useraddr, sizeof(epause)))
			return -EFAULT;

		tg3_netif_stop(tp);
		spin_lock_irq(&tp->lock);
		spin_lock(&tp->tx_lock);
		if (epause.autoneg)
			tp->tg3_flags |= TG3_FLAG_PAUSE_AUTONEG;
		else
			tp->tg3_flags &= ~TG3_FLAG_PAUSE_AUTONEG;
		if (epause.rx_pause)
			tp->tg3_flags |= TG3_FLAG_PAUSE_RX;
		else
			tp->tg3_flags &= ~TG3_FLAG_PAUSE_RX;
		if (epause.tx_pause)
			tp->tg3_flags |= TG3_FLAG_PAUSE_TX;
		else
			tp->tg3_flags &= ~TG3_FLAG_PAUSE_TX;
		tg3_halt(tp);
		tg3_init_rings(tp);
		tg3_init_hw(tp);
		spin_unlock(&tp->tx_lock);
		spin_unlock_irq(&tp->lock);
		tg3_netif_start(tp);

		return 0;
	}
	case ETHTOOL_GRXCSUM: {
		struct ethtool_value edata = { ETHTOOL_GRXCSUM };

		edata.data =
			(tp->tg3_flags & TG3_FLAG_RX_CHECKSUMS) != 0;
		if (copy_to_user(useraddr, &edata, sizeof(edata)))
			return -EFAULT;
		return 0;
	}
	case ETHTOOL_SRXCSUM: {
		struct ethtool_value edata;

		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;

		if (tp->tg3_flags & TG3_FLAG_BROKEN_CHECKSUMS) {
			if (edata.data != 0)
				return -EINVAL;
			return 0;
		}

		spin_lock_irq(&tp->lock);
		if (edata.data)
			tp->tg3_flags |= TG3_FLAG_RX_CHECKSUMS;
		else
			tp->tg3_flags &= ~TG3_FLAG_RX_CHECKSUMS;
		spin_unlock_irq(&tp->lock);

		return 0;
	}
	case ETHTOOL_GTXCSUM: {
		struct ethtool_value edata = { ETHTOOL_GTXCSUM };

		edata.data =
			(tp->dev->features & NETIF_F_IP_CSUM) != 0;
		if (copy_to_user(useraddr, &edata, sizeof(edata)))
			return -EFAULT;
		return 0;
	}
	case ETHTOOL_STXCSUM: {
		struct ethtool_value edata;

		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;

		if (tp->tg3_flags & TG3_FLAG_BROKEN_CHECKSUMS) {
			if (edata.data != 0)
				return -EINVAL;
			return 0;
		}

		if (edata.data)
			tp->dev->features |= NETIF_F_IP_CSUM;
		else
			tp->dev->features &= ~NETIF_F_IP_CSUM;

		return 0;
	}
	case ETHTOOL_GSG: {
		struct ethtool_value edata = { ETHTOOL_GSG };

		edata.data =
			(tp->dev->features & NETIF_F_SG) != 0;
		if (copy_to_user(useraddr, &edata, sizeof(edata)))
			return -EFAULT;
		return 0;
	}
	case ETHTOOL_SSG: {
		struct ethtool_value edata;

		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;

		if (edata.data)
			tp->dev->features |= NETIF_F_SG;
		else
			tp->dev->features &= ~NETIF_F_SG;

		return 0;
	}
	};

	return -EOPNOTSUPP;
}

static int tg3_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct mii_ioctl_data *data = (struct mii_ioctl_data *)&ifr->ifr_data;
	struct tg3 *tp = dev->priv;
	int err;

	switch(cmd) {
	case SIOCETHTOOL:
		return tg3_ethtool_ioctl(dev, (void *) ifr->ifr_data);
	case SIOCGMIIPHY:
		data->phy_id = PHY_ADDR;

		/* fallthru */
	case SIOCGMIIREG: {
		u32 mii_regval;

		spin_lock_irq(&tp->lock);
		err = tg3_readphy(tp, data->reg_num & 0x1f, &mii_regval);
		spin_unlock_irq(&tp->lock);

		data->val_out = mii_regval;

		return err;
	}

	case SIOCSMIIREG:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;

		spin_lock_irq(&tp->lock);
		err = tg3_writephy(tp, data->reg_num & 0x1f, data->val_in);
		spin_unlock_irq(&tp->lock);

		return err;

	default:
		/* do nothing */
		break;
	}
	return -EOPNOTSUPP;
}

#if TG3_VLAN_TAG_USED
static void tg3_vlan_rx_register(struct net_device *dev, struct vlan_group *grp)
{
	struct tg3 *tp = dev->priv;

	spin_lock_irq(&tp->lock);
	spin_lock(&tp->tx_lock);

	tp->vlgrp = grp;

	/* Update RX_MODE_KEEP_VLAN_TAG bit in RX_MODE register. */
	__tg3_set_rx_mode(dev);

	spin_unlock(&tp->tx_lock);
	spin_unlock_irq(&tp->lock);
}

static void tg3_vlan_rx_kill_vid(struct net_device *dev, unsigned short vid)
{
	struct tg3 *tp = dev->priv;

	spin_lock_irq(&tp->lock);
	spin_lock(&tp->tx_lock);
	if (tp->vlgrp)
		tp->vlgrp->vlan_devices[vid] = NULL;
	spin_unlock(&tp->tx_lock);
	spin_unlock_irq(&tp->lock);
}
#endif

/* Chips other than 5700/5701 use the NVRAM for fetching info. */
static void __devinit tg3_nvram_init(struct tg3 *tp)
{
	int j;

	tw32(GRC_EEPROM_ADDR,
	     (EEPROM_ADDR_FSM_RESET |
	      (EEPROM_DEFAULT_CLOCK_PERIOD <<
	       EEPROM_ADDR_CLKPERD_SHIFT)));

	/* XXX schedule_timeout() ... */
	for (j = 0; j < 100; j++)
		udelay(10);

	/* Enable seeprom accesses. */
	tw32(GRC_LOCAL_CTRL,
	     tr32(GRC_LOCAL_CTRL) | GRC_LCLCTRL_AUTO_SEEPROM);
	tr32(GRC_LOCAL_CTRL);
	udelay(100);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5700 &&
	    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5701) {
		u32 nvcfg1 = tr32(NVRAM_CFG1);

		tp->tg3_flags |= TG3_FLAG_NVRAM;
		if (nvcfg1 & NVRAM_CFG1_FLASHIF_ENAB) {
			if (nvcfg1 & NVRAM_CFG1_BUFFERED_MODE)
				tp->tg3_flags |= TG3_FLAG_NVRAM_BUFFERED;
		} else {
			nvcfg1 &= ~NVRAM_CFG1_COMPAT_BYPASS;
			tw32(NVRAM_CFG1, nvcfg1);
		}

	} else {
		tp->tg3_flags &= ~(TG3_FLAG_NVRAM | TG3_FLAG_NVRAM_BUFFERED);
	}
}

static int __devinit tg3_nvram_read_using_eeprom(struct tg3 *tp,
						 u32 offset, u32 *val)
{
	u32 tmp;
	int i;

	if (offset > EEPROM_ADDR_ADDR_MASK ||
	    (offset % 4) != 0)
		return -EINVAL;

	tmp = tr32(GRC_EEPROM_ADDR) & ~(EEPROM_ADDR_ADDR_MASK |
					EEPROM_ADDR_DEVID_MASK |
					EEPROM_ADDR_READ);
	tw32(GRC_EEPROM_ADDR,
	     tmp |
	     (0 << EEPROM_ADDR_DEVID_SHIFT) |
	     ((offset << EEPROM_ADDR_ADDR_SHIFT) &
	      EEPROM_ADDR_ADDR_MASK) |
	     EEPROM_ADDR_READ | EEPROM_ADDR_START);

	for (i = 0; i < 10000; i++) {
		tmp = tr32(GRC_EEPROM_ADDR);

		if (tmp & EEPROM_ADDR_COMPLETE)
			break;
		udelay(100);
	}
	if (!(tmp & EEPROM_ADDR_COMPLETE))
		return -EBUSY;

	*val = tr32(GRC_EEPROM_DATA);
	return 0;
}

static int __devinit tg3_nvram_read(struct tg3 *tp,
				    u32 offset, u32 *val)
{
	int i, saw_done_clear;

	if (!(tp->tg3_flags & TG3_FLAG_NVRAM))
		return tg3_nvram_read_using_eeprom(tp, offset, val);

	if (tp->tg3_flags & TG3_FLAG_NVRAM_BUFFERED)
		offset = ((offset / NVRAM_BUFFERED_PAGE_SIZE) <<
			  NVRAM_BUFFERED_PAGE_POS) +
			(offset % NVRAM_BUFFERED_PAGE_SIZE);

	if (offset > NVRAM_ADDR_MSK)
		return -EINVAL;

	tw32(NVRAM_SWARB, SWARB_REQ_SET1);
	for (i = 0; i < 1000; i++) {
		if (tr32(NVRAM_SWARB) & SWARB_GNT1)
			break;
		udelay(20);
	}

	tw32(NVRAM_ADDR, offset);
	tw32(NVRAM_CMD,
	     NVRAM_CMD_RD | NVRAM_CMD_GO |
	     NVRAM_CMD_FIRST | NVRAM_CMD_LAST | NVRAM_CMD_DONE);

	/* Wait for done bit to clear then set again. */
	saw_done_clear = 0;
	for (i = 0; i < 1000; i++) {
		udelay(10);
		if (!saw_done_clear &&
		    !(tr32(NVRAM_CMD) & NVRAM_CMD_DONE))
			saw_done_clear = 1;
		else if (saw_done_clear &&
			 (tr32(NVRAM_CMD) & NVRAM_CMD_DONE))
			break;
	}
	if (i >= 1000) {
		tw32(NVRAM_SWARB, SWARB_REQ_CLR1);
		return -EBUSY;
	}

	*val = swab32(tr32(NVRAM_RDDATA));
	tw32(NVRAM_SWARB, 0x20);

	return 0;
}

struct subsys_tbl_ent {
	u16 subsys_vendor, subsys_devid;
	u32 phy_id;
};

static struct subsys_tbl_ent subsys_id_to_phy_id[] = {
	/* Broadcom boards. */
	{ 0x14e4, 0x1644, PHY_ID_BCM5401 }, /* BCM95700A6 */
	{ 0x14e4, 0x0001, PHY_ID_BCM5701 }, /* BCM95701A5 */
	{ 0x14e4, 0x0002, PHY_ID_BCM8002 }, /* BCM95700T6 */
	{ 0x14e4, 0x0003, PHY_ID_SERDES  }, /* BCM95700A9 */
	{ 0x14e4, 0x0005, PHY_ID_BCM5701 }, /* BCM95701T1 */
	{ 0x14e4, 0x0006, PHY_ID_BCM5701 }, /* BCM95701T8 */
	{ 0x14e4, 0x0007, PHY_ID_SERDES  }, /* BCM95701A7 */
	{ 0x14e4, 0x0008, PHY_ID_BCM5701 }, /* BCM95701A10 */
	{ 0x14e4, 0x8008, PHY_ID_BCM5701 }, /* BCM95701A12 */
	{ 0x14e4, 0x0009, PHY_ID_BCM5701 }, /* BCM95703Ax1 */
	{ 0x14e4, 0x8009, PHY_ID_BCM5701 }, /* BCM95703Ax2 */

	/* 3com boards. */
	{ PCI_VENDOR_ID_3COM, 0x1000, PHY_ID_BCM5401 }, /* 3C996T */
	{ PCI_VENDOR_ID_3COM, 0x1006, PHY_ID_BCM5701 }, /* 3C996BT */
	/* { PCI_VENDOR_ID_3COM, 0x1002, PHY_ID_XXX },     3C996CT */
	/* { PCI_VENDOR_ID_3COM, 0x1003, PHY_ID_XXX },     3C997T */
	{ PCI_VENDOR_ID_3COM, 0x1004, PHY_ID_SERDES  }, /* 3C996SX */
	/* { PCI_VENDOR_ID_3COM, 0x1005, PHY_ID_XXX },     3C997SZ */
	{ PCI_VENDOR_ID_3COM, 0x1007, PHY_ID_BCM5701 }, /* 3C1000T */
	{ PCI_VENDOR_ID_3COM, 0x1008, PHY_ID_BCM5701 }, /* 3C940BR01 */

	/* DELL boards. */
	{ PCI_VENDOR_ID_DELL, 0x00d1, PHY_ID_BCM5401 }, /* VIPER */
	{ PCI_VENDOR_ID_DELL, 0x0106, PHY_ID_BCM5401 }, /* JAGUAR */
	{ PCI_VENDOR_ID_DELL, 0x0109, PHY_ID_BCM5411 }, /* MERLOT */
	{ PCI_VENDOR_ID_DELL, 0x010a, PHY_ID_BCM5411 }, /* SLIM_MERLOT */

	/* Compaq boards. */
	{ PCI_VENDOR_ID_COMPAQ, 0x007c, PHY_ID_BCM5701 }, /* BANSHEE */
	{ PCI_VENDOR_ID_COMPAQ, 0x009a, PHY_ID_BCM5701 }, /* BANSHEE_2 */
	{ PCI_VENDOR_ID_COMPAQ, 0x007d, PHY_ID_SERDES  }, /* CHANGELING */
	{ PCI_VENDOR_ID_COMPAQ, 0x0085, PHY_ID_BCM5701 }, /* NC7780 */
	{ PCI_VENDOR_ID_COMPAQ, 0x0099, PHY_ID_BCM5701 }  /* NC7780_2 */
};

static int __devinit tg3_phy_probe(struct tg3 *tp)
{
	u32 eeprom_phy_id, hw_phy_id_1, hw_phy_id_2;
	u32 hw_phy_id, hw_phy_id_masked;
	enum phy_led_mode eeprom_led_mode;
	u32 val;
	int i, eeprom_signature_found, err;

	tp->phy_id = PHY_ID_INVALID;
	for (i = 0; i < ARRAY_SIZE(subsys_id_to_phy_id); i++) {
		if ((subsys_id_to_phy_id[i].subsys_vendor ==
		     tp->pdev->subsystem_vendor) &&
		    (subsys_id_to_phy_id[i].subsys_devid ==
		     tp->pdev->subsystem_device)) {
			tp->phy_id = subsys_id_to_phy_id[i].phy_id;
			break;
		}
	}

	eeprom_phy_id = PHY_ID_INVALID;
	eeprom_led_mode = led_mode_auto;
	eeprom_signature_found = 0;
	tg3_read_mem(tp, NIC_SRAM_DATA_SIG, &val);
	if (val == NIC_SRAM_DATA_SIG_MAGIC) {
		u32 nic_cfg;

		tg3_read_mem(tp, NIC_SRAM_DATA_CFG, &nic_cfg);

		eeprom_signature_found = 1;

		if ((nic_cfg & NIC_SRAM_DATA_CFG_PHY_TYPE_MASK) ==
		    NIC_SRAM_DATA_CFG_PHY_TYPE_FIBER) {
			eeprom_phy_id = PHY_ID_SERDES;
		} else {
			u32 nic_phy_id;

			tg3_read_mem(tp, NIC_SRAM_DATA_PHY_ID, &nic_phy_id);
			if (nic_phy_id != 0) {
				u32 id1 = nic_phy_id & NIC_SRAM_DATA_PHY_ID1_MASK;
				u32 id2 = nic_phy_id & NIC_SRAM_DATA_PHY_ID2_MASK;

				eeprom_phy_id  = (id1 >> 16) << 10;
				eeprom_phy_id |= (id2 & 0xfc00) << 16;
				eeprom_phy_id |= (id2 & 0x03ff) <<  0;
			}
		}

		switch (nic_cfg & NIC_SRAM_DATA_CFG_LED_MODE_MASK) {
		case NIC_SRAM_DATA_CFG_LED_TRIPLE_SPD:
			eeprom_led_mode = led_mode_three_link;
			break;

		case NIC_SRAM_DATA_CFG_LED_LINK_SPD:
			eeprom_led_mode = led_mode_link10;
			break;

		default:
			eeprom_led_mode = led_mode_auto;
			break;
		};
		if ((tp->pci_chip_rev_id == CHIPREV_ID_5703_A1 ||
		     tp->pci_chip_rev_id == CHIPREV_ID_5703_A2) &&
		    (nic_cfg & NIC_SRAM_DATA_CFG_EEPROM_WP))
			tp->tg3_flags |= TG3_FLAG_EEPROM_WRITE_PROT;

		if (nic_cfg & NIC_SRAM_DATA_CFG_ASF_ENABLE)
			tp->tg3_flags |= TG3_FLAG_ENABLE_ASF;
		if (nic_cfg & NIC_SRAM_DATA_CFG_FIBER_WOL)
			tp->tg3_flags |= TG3_FLAG_SERDES_WOL_CAP;
	}

	/* Now read the physical PHY_ID from the chip and verify
	 * that it is sane.  If it doesn't look good, we fall back
	 * to either the hard-coded table based PHY_ID and failing
	 * that the value found in the eeprom area.
	 */
	err  = tg3_readphy(tp, MII_PHYSID1, &hw_phy_id_1);
	err |= tg3_readphy(tp, MII_PHYSID2, &hw_phy_id_2);

	hw_phy_id  = (hw_phy_id_1 & 0xffff) << 10;
	hw_phy_id |= (hw_phy_id_2 & 0xfc00) << 16;
	hw_phy_id |= (hw_phy_id_2 & 0x03ff) <<  0;

	hw_phy_id_masked = hw_phy_id & PHY_ID_MASK;

	if (!err && KNOWN_PHY_ID(hw_phy_id_masked)) {
		tp->phy_id = hw_phy_id;
	} else {
		/* phy_id currently holds the value found in the
		 * subsys_id_to_phy_id[] table or PHY_ID_INVALID
		 * if a match was not found there.
		 */
		if (tp->phy_id == PHY_ID_INVALID) {
			if (!eeprom_signature_found ||
			    !KNOWN_PHY_ID(eeprom_phy_id & PHY_ID_MASK))
				return -ENODEV;
			tp->phy_id = eeprom_phy_id;
		}
	}

	err = tg3_phy_reset(tp, 1);
	if (err)
		return err;

	if (tp->pci_chip_rev_id == CHIPREV_ID_5701_A0 ||
	    tp->pci_chip_rev_id == CHIPREV_ID_5701_B0) {
		u32 mii_tg3_ctrl;
		
		/* These chips, when reset, only advertise 10Mb
		 * capabilities.  Fix that.
		 */
		err  = tg3_writephy(tp, MII_ADVERTISE,
				    (ADVERTISE_CSMA |
				     ADVERTISE_PAUSE_CAP |
				     ADVERTISE_10HALF |
				     ADVERTISE_10FULL |
				     ADVERTISE_100HALF |
				     ADVERTISE_100FULL));
		mii_tg3_ctrl = (MII_TG3_CTRL_ADV_1000_HALF |
				MII_TG3_CTRL_ADV_1000_FULL |
				MII_TG3_CTRL_AS_MASTER |
				MII_TG3_CTRL_ENABLE_AS_MASTER);
		if (tp->tg3_flags & TG3_FLAG_10_100_ONLY)
			mii_tg3_ctrl = 0;

		err |= tg3_writephy(tp, MII_TG3_CTRL, mii_tg3_ctrl);
		err |= tg3_writephy(tp, MII_BMCR,
				    (BMCR_ANRESTART | BMCR_ANENABLE));
	}

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703) {
		tg3_writephy(tp, MII_TG3_AUX_CTRL, 0x0c00);
		tg3_writephy(tp, MII_TG3_DSP_ADDRESS, 0x201f);
		tg3_writephy(tp, MII_TG3_DSP_RW_PORT, 0x2aaa);
	}

	if ((GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704) &&
	    (tp->pci_chip_rev_id == CHIPREV_ID_5704_A0)) {
		tg3_writephy(tp, 0x1c, 0x8d68);
		tg3_writephy(tp, 0x1c, 0x8d68);
	}

	/* Enable Ethernet@WireSpeed */
	tg3_writephy(tp, MII_TG3_AUX_CTRL, 0x7007);
	tg3_readphy(tp, MII_TG3_AUX_CTRL, &val);
	tg3_writephy(tp, MII_TG3_AUX_CTRL, (val | (1 << 15) | (1 << 4)));

	if (!err && ((tp->phy_id & PHY_ID_MASK) == PHY_ID_BCM5401)) {
		err = tg3_init_5401phy_dsp(tp);
	}

	/* Determine the PHY led mode. */
	if (tp->pdev->subsystem_vendor == PCI_VENDOR_ID_DELL) {
		tp->led_mode = led_mode_link10;
	} else {
		tp->led_mode = led_mode_three_link;
		if (eeprom_signature_found &&
		    eeprom_led_mode != led_mode_auto)
			tp->led_mode = eeprom_led_mode;
	}

	if (tp->phy_id == PHY_ID_SERDES)
		tp->link_config.advertising =
			(ADVERTISED_1000baseT_Half |
			 ADVERTISED_1000baseT_Full |
			 ADVERTISED_Autoneg |
			 ADVERTISED_FIBRE);
	if (tp->tg3_flags & TG3_FLAG_10_100_ONLY)
		tp->link_config.advertising &=
			~(ADVERTISED_1000baseT_Half |
			  ADVERTISED_1000baseT_Full);

	return err;
}

static void __devinit tg3_read_partno(struct tg3 *tp)
{
	unsigned char vpd_data[256];
	int i;

	for (i = 0; i < 256; i += 4) {
		u32 tmp;

		if (tg3_nvram_read(tp, 0x100 + i, &tmp))
			goto out_not_found;

		vpd_data[i + 0] = ((tmp >>  0) & 0xff);
		vpd_data[i + 1] = ((tmp >>  8) & 0xff);
		vpd_data[i + 2] = ((tmp >> 16) & 0xff);
		vpd_data[i + 3] = ((tmp >> 24) & 0xff);
	}

	/* Now parse and find the part number. */
	for (i = 0; i < 256; ) {
		unsigned char val = vpd_data[i];
		int block_end;

		if (val == 0x82 || val == 0x91) {
			i = (i + 3 +
			     (vpd_data[i + 1] +
			      (vpd_data[i + 2] << 8)));
			continue;
		}

		if (val != 0x90)
			goto out_not_found;

		block_end = (i + 3 +
			     (vpd_data[i + 1] +
			      (vpd_data[i + 2] << 8)));
		i += 3;
		while (i < block_end) {
			if (vpd_data[i + 0] == 'P' &&
			    vpd_data[i + 1] == 'N') {
				int partno_len = vpd_data[i + 2];

				if (partno_len > 24)
					goto out_not_found;

				memcpy(tp->board_part_number,
				       &vpd_data[i + 3],
				       partno_len);

				/* Success. */
				return;
			}
		}

		/* Part number not found. */
		goto out_not_found;
	}

out_not_found:
	strcpy(tp->board_part_number, "none");
}

static int __devinit tg3_get_invariants(struct tg3 *tp)
{
	u32 misc_ctrl_reg;
	u32 cacheline_sz_reg;
	u32 pci_state_reg, grc_misc_cfg;
	u16 pci_cmd;
	int err;

	/* If we have an AMD 762 or Intel ICH/ICH0 chipset, write
	 * reordering to the mailbox registers done by the host
	 * controller can cause major troubles.  We read back from
	 * every mailbox register write to force the writes to be
	 * posted to the chip in order.
	 */
	if (pci_find_device(PCI_VENDOR_ID_INTEL,
			    PCI_DEVICE_ID_INTEL_82801AA_8, NULL) ||
	    pci_find_device(PCI_VENDOR_ID_INTEL,
			    PCI_DEVICE_ID_INTEL_82801AB_8, NULL) ||
	    pci_find_device(PCI_VENDOR_ID_AMD,
			    PCI_DEVICE_ID_AMD_FE_GATE_700C, NULL))
		tp->tg3_flags |= TG3_FLAG_MBOX_WRITE_REORDER;

	/* Force memory write invalidate off.  If we leave it on,
	 * then on 5700_BX chips we have to enable a workaround.
	 * The workaround is to set the TG3PCI_DMA_RW_CTRL boundry
	 * to match the cacheline size.  The Broadcom driver have this
	 * workaround but turns MWI off all the times so never uses
	 * it.  This seems to suggest that the workaround is insufficient.
	 */
	pci_read_config_word(tp->pdev, PCI_COMMAND, &pci_cmd);
	pci_cmd &= ~PCI_COMMAND_INVALIDATE;
	pci_write_config_word(tp->pdev, PCI_COMMAND, pci_cmd);

	/* It is absolutely critical that TG3PCI_MISC_HOST_CTRL
	 * has the register indirect write enable bit set before
	 * we try to access any of the MMIO registers.  It is also
	 * critical that the PCI-X hw workaround situation is decided
	 * before that as well.
	 */
	pci_read_config_dword(tp->pdev, TG3PCI_MISC_HOST_CTRL,
			      &misc_ctrl_reg);

	tp->pci_chip_rev_id = (misc_ctrl_reg >>
			       MISC_HOST_CTRL_CHIPREV_SHIFT);

	/* Initialize misc host control in PCI block. */
	tp->misc_host_ctrl |= (misc_ctrl_reg &
			       MISC_HOST_CTRL_CHIPREV);
	pci_write_config_dword(tp->pdev, TG3PCI_MISC_HOST_CTRL,
			       tp->misc_host_ctrl);

	pci_read_config_dword(tp->pdev, TG3PCI_CACHELINESZ,
			      &cacheline_sz_reg);

	tp->pci_cacheline_sz = (cacheline_sz_reg >>  0) & 0xff;
	tp->pci_lat_timer    = (cacheline_sz_reg >>  8) & 0xff;
	tp->pci_hdr_type     = (cacheline_sz_reg >> 16) & 0xff;
	tp->pci_bist         = (cacheline_sz_reg >> 24) & 0xff;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703 &&
	    tp->pci_lat_timer < 64) {
		tp->pci_lat_timer = 64;

		cacheline_sz_reg  = ((tp->pci_cacheline_sz & 0xff) <<  0);
		cacheline_sz_reg |= ((tp->pci_lat_timer    & 0xff) <<  8);
		cacheline_sz_reg |= ((tp->pci_hdr_type     & 0xff) << 16);
		cacheline_sz_reg |= ((tp->pci_bist         & 0xff) << 24);

		pci_write_config_dword(tp->pdev, TG3PCI_CACHELINESZ,
				       cacheline_sz_reg);
	}

	pci_read_config_dword(tp->pdev, TG3PCI_PCISTATE,
			      &pci_state_reg);

	if ((pci_state_reg & PCISTATE_CONV_PCI_MODE) == 0) {
		tp->tg3_flags |= TG3_FLAG_PCIX_MODE;

		/* If this is a 5700 BX chipset, and we are in PCI-X
		 * mode, enable register write workaround.
		 *
		 * The workaround is to use indirect register accesses
		 * for all chip writes not to mailbox registers.
		 */
		if (GET_CHIP_REV(tp->pci_chip_rev_id) == CHIPREV_5700_BX) {
			u32 pm_reg;
			u16 pci_cmd;

			tp->tg3_flags |= TG3_FLAG_PCIX_TARGET_HWBUG;

			/* The chip can have it's power management PCI config
			 * space registers clobbered due to this bug.
			 * So explicitly force the chip into D0 here.
			 */
			pci_read_config_dword(tp->pdev, TG3PCI_PM_CTRL_STAT,
					      &pm_reg);
			pm_reg &= ~PCI_PM_CTRL_STATE_MASK;
			pm_reg |= PCI_PM_CTRL_PME_ENABLE | 0 /* D0 */;
			pci_write_config_dword(tp->pdev, TG3PCI_PM_CTRL_STAT,
					       pm_reg);

			/* Also, force SERR#/PERR# in PCI command. */
			pci_read_config_word(tp->pdev, PCI_COMMAND, &pci_cmd);
			pci_cmd |= PCI_COMMAND_PARITY | PCI_COMMAND_SERR;
			pci_write_config_word(tp->pdev, PCI_COMMAND, pci_cmd);
		}
	}

	/* Back to back register writes can cause problems on this chip,
	 * the workaround is to read back all reg writes except those to
	 * mailbox regs.  See tg3_write_indirect_reg32().
	 */
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5701)
		tp->tg3_flags |= TG3_FLAG_5701_REG_WRITE_BUG;

	if ((pci_state_reg & PCISTATE_BUS_SPEED_HIGH) != 0)
		tp->tg3_flags |= TG3_FLAG_PCI_HIGH_SPEED;
	if ((pci_state_reg & PCISTATE_BUS_32BIT) != 0)
		tp->tg3_flags |= TG3_FLAG_PCI_32BIT;

	/* Chip-specific fixup from Broadcom driver */
	if ((tp->pci_chip_rev_id == CHIPREV_ID_5704_A0) &&
	    (!(pci_state_reg & PCISTATE_RETRY_SAME_DMA))) {
		pci_state_reg |= PCISTATE_RETRY_SAME_DMA;
		pci_write_config_dword(tp->pdev, TG3PCI_PCISTATE, pci_state_reg);
	}

	/* Force the chip into D0. */
	err = tg3_set_power_state(tp, 0);
	if (err) {
		printk(KERN_ERR PFX "(%s) transition to D0 failed\n",
		       tp->pdev->slot_name);
		return err;
	}

	/* 5700 B0 chips do not support checksumming correctly due
	 * to hardware bugs.
	 */
	if (tp->pci_chip_rev_id == CHIPREV_ID_5700_B0)
		tp->tg3_flags |= TG3_FLAG_BROKEN_CHECKSUMS;

	/* Pseudo-header checksum is done by hardware logic and not
	 * the offload processers, so make the chip do the pseudo-
	 * header checksums on receive.  For transmit it is more
	 * convenient to do the pseudo-header checksum in software
	 * as Linux does that on transmit for us in all cases.
	 */
	tp->tg3_flags |= TG3_FLAG_NO_TX_PSEUDO_CSUM;
	tp->tg3_flags &= ~TG3_FLAG_NO_RX_PSEUDO_CSUM;

	/* Derive initial jumbo mode from MTU assigned in
	 * ether_setup() via the alloc_etherdev() call
	 */
	if (tp->dev->mtu > ETH_DATA_LEN)
		tp->tg3_flags |= TG3_FLAG_JUMBO_ENABLE;

	/* Determine WakeOnLan speed to use. */
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700 ||
	    tp->pci_chip_rev_id == CHIPREV_ID_5701_A0 ||
	    tp->pci_chip_rev_id == CHIPREV_ID_5701_B0 ||
	    tp->pci_chip_rev_id == CHIPREV_ID_5701_B2) {
		tp->tg3_flags &= ~(TG3_FLAG_WOL_SPEED_100MB);
	} else {
		tp->tg3_flags |= TG3_FLAG_WOL_SPEED_100MB;
	}

	/* Only 5701 and later support tagged irq status mode.
	 *
	 * However, since we are using NAPI avoid tagged irq status
	 * because the interrupt condition is more difficult to
	 * fully clear in that mode.
	 */
	tp->coalesce_mode = 0;

	if (GET_CHIP_REV(tp->pci_chip_rev_id) != CHIPREV_5700_AX &&
	    GET_CHIP_REV(tp->pci_chip_rev_id) != CHIPREV_5700_BX)
		tp->coalesce_mode |= HOSTCC_MODE_32BYTE;

	/* Initialize MAC MI mode, polling disabled. */
	tw32(MAC_MI_MODE, tp->mi_mode);
	tr32(MAC_MI_MODE);
	udelay(40);

	/* Initialize data/descriptor byte/word swapping. */
	tw32(GRC_MODE, tp->grc_mode);

	tg3_switch_clocks(tp);

	/* Clear this out for sanity. */
	tw32(TG3PCI_MEM_WIN_BASE_ADDR, 0);

	pci_read_config_dword(tp->pdev, TG3PCI_PCISTATE,
			      &pci_state_reg);
	if ((pci_state_reg & PCISTATE_CONV_PCI_MODE) == 0 &&
	    (tp->tg3_flags & TG3_FLAG_PCIX_TARGET_HWBUG) == 0) {
		u32 chiprevid = GET_CHIP_REV_ID(tp->misc_host_ctrl);

		if (chiprevid == CHIPREV_ID_5701_A0 ||
		    chiprevid == CHIPREV_ID_5701_B0 ||
		    chiprevid == CHIPREV_ID_5701_B2 ||
		    chiprevid == CHIPREV_ID_5701_B5) {
			unsigned long sram_base;

			/* Write some dummy words into the SRAM status block
			 * area, see if it reads back correctly.  If the return
			 * value is bad, force enable the PCIX workaround.
			 */
			sram_base = tp->regs + NIC_SRAM_WIN_BASE + NIC_SRAM_STATS_BLK;

			writel(0x00000000, sram_base);
			writel(0x00000000, sram_base + 4);
			writel(0xffffffff, sram_base + 4);
			if (readl(sram_base) != 0x00000000)
				tp->tg3_flags |= TG3_FLAG_PCIX_TARGET_HWBUG;
		}
	}

	udelay(50);
	tg3_nvram_init(tp);

	/* Determine if TX descriptors will reside in
	 * main memory or in the chip SRAM.
	 */
	if (tp->tg3_flags & TG3_FLAG_PCIX_TARGET_HWBUG)
		tp->tg3_flags |= TG3_FLAG_HOST_TXDS;

	grc_misc_cfg = tr32(GRC_MISC_CFG);
	grc_misc_cfg &= GRC_MISC_CFG_BOARD_ID_MASK;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704 &&
	    grc_misc_cfg == GRC_MISC_CFG_BOARD_ID_5704CIOBE) {
		tp->tg3_flags |= TG3_FLAG_SPLIT_MODE;
		tp->split_mode_max_reqs = SPLIT_MODE_5704_MAX_REQ;
	}

	/* this one is limited to 10/100 only */
	if (grc_misc_cfg == GRC_MISC_CFG_BOARD_ID_5702FE)
		tp->tg3_flags |= TG3_FLAG_10_100_ONLY;

	err = tg3_phy_probe(tp);
	if (err) {
		printk(KERN_ERR PFX "(%s) phy probe failed, err %d\n",
		       tp->pdev->slot_name, err);
		/* ... but do not return immediately ... */
	}

	tg3_read_partno(tp);

	if (tp->phy_id == PHY_ID_SERDES) {
		tp->tg3_flags &= ~TG3_FLAG_USE_MI_INTERRUPT;

		/* And override led_mode in case Dell ever makes
		 * a fibre board.
		 */
		tp->led_mode = led_mode_three_link;
	} else {
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700)
			tp->tg3_flags |= TG3_FLAG_USE_MI_INTERRUPT;
		else
			tp->tg3_flags &= ~TG3_FLAG_USE_MI_INTERRUPT;
	}

	/* 5700 {AX,BX} chips have a broken status block link
	 * change bit implementation, so we must use the
	 * status register in those cases.
	 */
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700)
		tp->tg3_flags |= TG3_FLAG_USE_LINKCHG_REG;
	else
		tp->tg3_flags &= ~TG3_FLAG_USE_LINKCHG_REG;

	/* The led_mode is set during tg3_phy_probe, here we might
	 * have to force the link status polling mechanism based
	 * upon subsystem IDs.
	 */
	if (tp->pdev->subsystem_vendor == PCI_VENDOR_ID_DELL &&
	    tp->phy_id != PHY_ID_SERDES) {
		tp->tg3_flags |= (TG3_FLAG_USE_MI_INTERRUPT |
				  TG3_FLAG_USE_LINKCHG_REG);
	}

	/* For all SERDES we poll the MAC status register. */
	if (tp->phy_id == PHY_ID_SERDES)
		tp->tg3_flags |= TG3_FLAG_POLL_SERDES;
	else
		tp->tg3_flags &= ~TG3_FLAG_POLL_SERDES;

	/* 5700 BX chips need to have their TX producer index mailboxes
	 * written twice to workaround a bug.
	 */
	if (GET_CHIP_REV(tp->pci_chip_rev_id) == CHIPREV_5700_BX)
		tp->tg3_flags |= TG3_FLAG_TXD_MBOX_HWBUG;
	else
		tp->tg3_flags &= ~TG3_FLAG_TXD_MBOX_HWBUG;

	/* 5700 chips can get confused if TX buffers straddle the
	 * 4GB address boundary in some cases.
	 */
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700)
		tp->dev->hard_start_xmit = tg3_start_xmit_4gbug;
	else
		tp->dev->hard_start_xmit = tg3_start_xmit;

	tp->rx_offset = 2;
/* XXX Xen: we trust our ASICs, for better or worse ;-) */
#if 0
	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5701 &&
	    (tp->tg3_flags & TG3_FLAG_PCIX_MODE) != 0)
		tp->rx_offset = 0;
#endif

	/* By default, disable wake-on-lan.  User can change this
	 * using ETHTOOL_SWOL.
	 */
	tp->tg3_flags &= ~TG3_FLAG_WOL_ENABLE;

	return err;
}

static int __devinit tg3_get_device_address(struct tg3 *tp)
{
	struct net_device *dev = tp->dev;
	u32 hi, lo, mac_offset;

	if (PCI_FUNC(tp->pdev->devfn) == 0)
		mac_offset = 0x7c;
	else
		mac_offset = 0xcc;

	/* First try to get it from MAC address mailbox. */
	tg3_read_mem(tp, NIC_SRAM_MAC_ADDR_HIGH_MBOX, &hi);
	if ((hi >> 16) == 0x484b) {
		dev->dev_addr[0] = (hi >>  8) & 0xff;
		dev->dev_addr[1] = (hi >>  0) & 0xff;

		tg3_read_mem(tp, NIC_SRAM_MAC_ADDR_LOW_MBOX, &lo);
		dev->dev_addr[2] = (lo >> 24) & 0xff;
		dev->dev_addr[3] = (lo >> 16) & 0xff;
		dev->dev_addr[4] = (lo >>  8) & 0xff;
		dev->dev_addr[5] = (lo >>  0) & 0xff;
	}
	/* Next, try NVRAM. */
	else if (!tg3_nvram_read(tp, mac_offset + 0, &hi) &&
		 !tg3_nvram_read(tp, mac_offset + 4, &lo)) {
		dev->dev_addr[0] = ((hi >> 16) & 0xff);
		dev->dev_addr[1] = ((hi >> 24) & 0xff);
		dev->dev_addr[2] = ((lo >>  0) & 0xff);
		dev->dev_addr[3] = ((lo >>  8) & 0xff);
		dev->dev_addr[4] = ((lo >> 16) & 0xff);
		dev->dev_addr[5] = ((lo >> 24) & 0xff);
	}
	/* Finally just fetch it out of the MAC control regs. */
	else {
		hi = tr32(MAC_ADDR_0_HIGH);
		lo = tr32(MAC_ADDR_0_LOW);

		dev->dev_addr[5] = lo & 0xff;
		dev->dev_addr[4] = (lo >> 8) & 0xff;
		dev->dev_addr[3] = (lo >> 16) & 0xff;
		dev->dev_addr[2] = (lo >> 24) & 0xff;
		dev->dev_addr[1] = hi & 0xff;
		dev->dev_addr[0] = (hi >> 8) & 0xff;
	}

	if (!is_valid_ether_addr(&dev->dev_addr[0]))
		return -EINVAL;

	return 0;
}

static int __devinit tg3_do_test_dma(struct tg3 *tp, u32 *buf, dma_addr_t buf_dma, int size, int to_device)
{
	struct tg3_internal_buffer_desc test_desc;
	u32 sram_dma_descs;
	int i, ret;

	sram_dma_descs = NIC_SRAM_DMA_DESC_POOL_BASE;

	tw32(FTQ_RCVBD_COMP_FIFO_ENQDEQ, 0);
	tw32(FTQ_RCVDATA_COMP_FIFO_ENQDEQ, 0);
	tw32(RDMAC_STATUS, 0);
	tw32(WDMAC_STATUS, 0);

	tw32(BUFMGR_MODE, 0);
	tw32(FTQ_RESET, 0);

	/* pci_alloc_consistent gives only non-DAC addresses */
	test_desc.addr_hi = 0;
	test_desc.addr_lo = buf_dma & 0xffffffff;
	test_desc.nic_mbuf = 0x00002100;
	test_desc.len = size;
	if (to_device) {
		test_desc.cqid_sqid = (13 << 8) | 2;
		tw32(RDMAC_MODE, RDMAC_MODE_RESET);
		tr32(RDMAC_MODE);
		udelay(40);

		tw32(RDMAC_MODE, RDMAC_MODE_ENABLE);
		tr32(RDMAC_MODE);
		udelay(40);
	} else {
		test_desc.cqid_sqid = (16 << 8) | 7;
		tw32(WDMAC_MODE, WDMAC_MODE_RESET);
		tr32(WDMAC_MODE);
		udelay(40);

		tw32(WDMAC_MODE, WDMAC_MODE_ENABLE);
		tr32(WDMAC_MODE);
		udelay(40);
	}
	test_desc.flags = 0x00000004;

	for (i = 0; i < (sizeof(test_desc) / sizeof(u32)); i++) {
		u32 val;

		val = *(((u32 *)&test_desc) + i);
		pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR,
				       sram_dma_descs + (i * sizeof(u32)));
		pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_DATA, val);
	}
	pci_write_config_dword(tp->pdev, TG3PCI_MEM_WIN_BASE_ADDR, 0);

	if (to_device) {
		tw32(FTQ_DMA_HIGH_READ_FIFO_ENQDEQ, sram_dma_descs);
	} else {
		tw32(FTQ_DMA_HIGH_WRITE_FIFO_ENQDEQ, sram_dma_descs);
	}

	ret = -ENODEV;
	for (i = 0; i < 40; i++) {
		u32 val;

		if (to_device)
			val = tr32(FTQ_RCVBD_COMP_FIFO_ENQDEQ);
		else
			val = tr32(FTQ_RCVDATA_COMP_FIFO_ENQDEQ);
		if ((val & 0xffff) == sram_dma_descs) {
			ret = 0;
			break;
		}

		udelay(100);
	}

	return ret;
}

#define TEST_BUFFER_SIZE	0x400

static int __devinit tg3_test_dma(struct tg3 *tp)
{
	dma_addr_t buf_dma;
	u32 *buf;
	int ret;

	buf = pci_alloc_consistent(tp->pdev, TEST_BUFFER_SIZE, &buf_dma);
	if (!buf) {
		ret = -ENOMEM;
		goto out_nofree;
	}

	tw32(TG3PCI_CLOCK_CTRL, 0);

	if ((tp->tg3_flags & TG3_FLAG_PCIX_MODE) == 0) {
		tp->dma_rwctrl =
			(0x7 << DMA_RWCTRL_PCI_WRITE_CMD_SHIFT) |
			(0x6 << DMA_RWCTRL_PCI_READ_CMD_SHIFT) |
			(0x7 << DMA_RWCTRL_WRITE_WATER_SHIFT) |
			(0x7 << DMA_RWCTRL_READ_WATER_SHIFT) |
			(0x0f << DMA_RWCTRL_MIN_DMA_SHIFT);
		/* XXX 5705 note: set MIN_DMA to zero here */
	} else {
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704)
			tp->dma_rwctrl =
				(0x7 << DMA_RWCTRL_PCI_WRITE_CMD_SHIFT) |
				(0x6 << DMA_RWCTRL_PCI_READ_CMD_SHIFT) |
				(0x3 << DMA_RWCTRL_WRITE_WATER_SHIFT) |
				(0x7 << DMA_RWCTRL_READ_WATER_SHIFT) |
				(0x00 << DMA_RWCTRL_MIN_DMA_SHIFT);
		else
			tp->dma_rwctrl =
				(0x7 << DMA_RWCTRL_PCI_WRITE_CMD_SHIFT) |
				(0x6 << DMA_RWCTRL_PCI_READ_CMD_SHIFT) |
				(0x3 << DMA_RWCTRL_WRITE_WATER_SHIFT) |
				(0x3 << DMA_RWCTRL_READ_WATER_SHIFT) |
				(0x0f << DMA_RWCTRL_MIN_DMA_SHIFT);

		/* Wheee, some more chip bugs... */
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703 ||
		    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704) {
			u32 ccval = (tr32(TG3PCI_CLOCK_CTRL) & 0x1f);

			if (ccval == 0x6 || ccval == 0x7)
				tp->dma_rwctrl |= DMA_RWCTRL_ONE_DMA;
		}
	}

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704)
		tp->dma_rwctrl &= ~(DMA_RWCTRL_MIN_DMA
				    << DMA_RWCTRL_MIN_DMA_SHIFT);

	/* We don't do this on x86 because it seems to hurt performace.
	 * It does help things on other platforms though.
	 */
#ifndef CONFIG_X86
	{
		u8 byte;
		int cacheline_size;
		pci_read_config_byte(tp->pdev, PCI_CACHE_LINE_SIZE, &byte);

		if (byte == 0)
			cacheline_size = 1024;
		else
			cacheline_size = (int) byte * 4;

		tp->dma_rwctrl &= ~(DMA_RWCTRL_READ_BNDRY_MASK |
				    DMA_RWCTRL_WRITE_BNDRY_MASK);

		switch (cacheline_size) {
		case 16:
			tp->dma_rwctrl |=
				(DMA_RWCTRL_READ_BNDRY_16 |
				 DMA_RWCTRL_WRITE_BNDRY_16);
			break;

		case 32:
			tp->dma_rwctrl |=
				(DMA_RWCTRL_READ_BNDRY_32 |
				 DMA_RWCTRL_WRITE_BNDRY_32);
			break;

		case 64:
			tp->dma_rwctrl |=
				(DMA_RWCTRL_READ_BNDRY_64 |
				 DMA_RWCTRL_WRITE_BNDRY_64);
			break;

		case 128:
			tp->dma_rwctrl |=
				(DMA_RWCTRL_READ_BNDRY_128 |
				 DMA_RWCTRL_WRITE_BNDRY_128);
			break;

		case 256:
			tp->dma_rwctrl |=
				(DMA_RWCTRL_READ_BNDRY_256 |
				 DMA_RWCTRL_WRITE_BNDRY_256);
			break;

		case 512:
			tp->dma_rwctrl |=
				(DMA_RWCTRL_READ_BNDRY_512 |
				 DMA_RWCTRL_WRITE_BNDRY_512);
			break;

		case 1024:
			tp->dma_rwctrl |=
				(DMA_RWCTRL_READ_BNDRY_1024 |
				 DMA_RWCTRL_WRITE_BNDRY_1024);
			break;
		};
	}
#endif

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5701) {
		/* Remove this if it causes problems for some boards. */
		tp->dma_rwctrl |= DMA_RWCTRL_USE_MEM_READ_MULT;
	}

	tw32(TG3PCI_DMA_RW_CTRL, tp->dma_rwctrl);

	if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5700 &&
	    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5701)
		return 0;

	ret = 0;
	while (1) {
		u32 *p, i;

		p = buf;
		for (i = 0; i < TEST_BUFFER_SIZE / sizeof(u32); i++)
			p[i] = i;

		/* Send the buffer to the chip. */
		ret = tg3_do_test_dma(tp, buf, buf_dma, TEST_BUFFER_SIZE, 1);
		if (ret)
			break;

		p = buf;
		for (i = 0; i < TEST_BUFFER_SIZE / sizeof(u32); i++)
			p[i] = 0;

		/* Now read it back. */
		ret = tg3_do_test_dma(tp, buf, buf_dma, TEST_BUFFER_SIZE, 0);
		if (ret)
			break;

		/* Verify it. */
		p = buf;
		for (i = 0; i < TEST_BUFFER_SIZE / sizeof(u32); i++) {
			if (p[i] == i)
				continue;

			if ((tp->dma_rwctrl & DMA_RWCTRL_WRITE_BNDRY_MASK) ==
			    DMA_RWCTRL_WRITE_BNDRY_DISAB) {
				tp->dma_rwctrl |= DMA_RWCTRL_WRITE_BNDRY_16;
				tw32(TG3PCI_DMA_RW_CTRL, tp->dma_rwctrl);
				break;
			} else {
				ret = -ENODEV;
				goto out;
			}
		}

		if (i == (TEST_BUFFER_SIZE / sizeof(u32))) {
			/* Success. */
			ret = 0;
			break;
		}
	}

out:
	pci_free_consistent(tp->pdev, TEST_BUFFER_SIZE, buf, buf_dma);
out_nofree:
	return ret;
}

static void __devinit tg3_init_link_config(struct tg3 *tp)
{
	tp->link_config.advertising =
		(ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full |
		 ADVERTISED_100baseT_Half | ADVERTISED_100baseT_Full |
		 ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full |
		 ADVERTISED_Autoneg | ADVERTISED_MII);
	tp->link_config.speed = SPEED_INVALID;
	tp->link_config.duplex = DUPLEX_INVALID;
	tp->link_config.autoneg = AUTONEG_ENABLE;
	netif_carrier_off(tp->dev);
	tp->link_config.active_speed = SPEED_INVALID;
	tp->link_config.active_duplex = DUPLEX_INVALID;
	tp->link_config.phy_is_low_power = 0;
	tp->link_config.orig_speed = SPEED_INVALID;
	tp->link_config.orig_duplex = DUPLEX_INVALID;
	tp->link_config.orig_autoneg = AUTONEG_INVALID;
}

static void __devinit tg3_init_bufmgr_config(struct tg3 *tp)
{
	tp->bufmgr_config.mbuf_read_dma_low_water =
		DEFAULT_MB_RDMA_LOW_WATER;
	tp->bufmgr_config.mbuf_mac_rx_low_water =
		DEFAULT_MB_MACRX_LOW_WATER;
	tp->bufmgr_config.mbuf_high_water =
		DEFAULT_MB_HIGH_WATER;

	tp->bufmgr_config.mbuf_read_dma_low_water_jumbo =
		DEFAULT_MB_RDMA_LOW_WATER_JUMBO;
	tp->bufmgr_config.mbuf_mac_rx_low_water_jumbo =
		DEFAULT_MB_MACRX_LOW_WATER_JUMBO;
	tp->bufmgr_config.mbuf_high_water_jumbo =
		DEFAULT_MB_HIGH_WATER_JUMBO;

	tp->bufmgr_config.dma_low_water = DEFAULT_DMA_LOW_WATER;
	tp->bufmgr_config.dma_high_water = DEFAULT_DMA_HIGH_WATER;
}

static char * __devinit tg3_phy_string(struct tg3 *tp)
{
	switch (tp->phy_id & PHY_ID_MASK) {
	case PHY_ID_BCM5400:	return "5400";
	case PHY_ID_BCM5401:	return "5401";
	case PHY_ID_BCM5411:	return "5411";
	case PHY_ID_BCM5701:	return "5701";
	case PHY_ID_BCM5703:	return "5703";
	case PHY_ID_BCM5704:	return "5704";
	case PHY_ID_BCM8002:	return "8002";
	case PHY_ID_SERDES:	return "serdes";
	default:		return "unknown";
	};
}

static int __devinit tg3_init_one(struct pci_dev *pdev,
				  const struct pci_device_id *ent)
{
	static int tg3_version_printed = 0;
	unsigned long tg3reg_base, tg3reg_len;
	struct net_device *dev;
	struct tg3 *tp;
	int i, err, pci_using_dac, pm_cap;

	if (tg3_version_printed++ == 0)
		printk(KERN_INFO "%s", version);

	err = pci_enable_device(pdev);
	if (err) {
		printk(KERN_ERR PFX "Cannot enable PCI device, "
		       "aborting.\n");
		return err;
	}

	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM)) {
		printk(KERN_ERR PFX "Cannot find proper PCI device "
		       "base address, aborting.\n");
		err = -ENODEV;
		goto err_out_disable_pdev;
	}

	err = pci_request_regions(pdev, DRV_MODULE_NAME);
	if (err) {
		printk(KERN_ERR PFX "Cannot obtain PCI resources, "
		       "aborting.\n");
		goto err_out_disable_pdev;
	}

	pci_set_master(pdev);

	/* Find power-management capability. */
	pm_cap = pci_find_capability(pdev, PCI_CAP_ID_PM);
	if (pm_cap == 0) {
		printk(KERN_ERR PFX "Cannot find PowerManagement capability, "
		       "aborting.\n");
		goto err_out_free_res;
	}

	/* Configure DMA attributes. */
	if (!pci_set_dma_mask(pdev, (u64) 0xffffffffffffffff)) {
		pci_using_dac = 1;
	} else {
		err = pci_set_dma_mask(pdev, (u64) 0xffffffff);
		if (err) {
			printk(KERN_ERR PFX "No usable DMA configuration, "
			       "aborting.\n");
			goto err_out_free_res;
		}
		pci_using_dac = 0;
	}

	tg3reg_base = pci_resource_start(pdev, 0);
	tg3reg_len = pci_resource_len(pdev, 0);

	dev = alloc_etherdev(sizeof(*tp));
	if (!dev) {
		printk(KERN_ERR PFX "Etherdev alloc failed, aborting.\n");
		err = -ENOMEM;
		goto err_out_free_res;
	}

	SET_MODULE_OWNER(dev);

	if (pci_using_dac)
		dev->features |= NETIF_F_HIGHDMA;
#if TG3_VLAN_TAG_USED
	dev->features |= NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX;
	dev->vlan_rx_register = tg3_vlan_rx_register;
	dev->vlan_rx_kill_vid = tg3_vlan_rx_kill_vid;
#endif
#if TG3_DO_TSO != 0
	dev->features |= NETIF_F_TSO;
#endif

	tp = dev->priv;
	tp->pdev = pdev;
	tp->dev = dev;
	tp->pm_cap = pm_cap;
	tp->mac_mode = TG3_DEF_MAC_MODE;
	tp->rx_mode = TG3_DEF_RX_MODE;
	tp->tx_mode = TG3_DEF_TX_MODE;
	tp->mi_mode = MAC_MI_MODE_BASE;
	if (tg3_debug > 0)
		tp->msg_enable = tg3_debug;
	else
		tp->msg_enable = TG3_DEF_MSG_ENABLE;

	/* The word/byte swap controls here control register access byte
	 * swapping.  DMA data byte swapping is controlled in the GRC_MODE
	 * setting below.
	 */
	tp->misc_host_ctrl =
		MISC_HOST_CTRL_MASK_PCI_INT |
		MISC_HOST_CTRL_WORD_SWAP |
		MISC_HOST_CTRL_INDIR_ACCESS |
		MISC_HOST_CTRL_PCISTATE_RW;

	/* The NONFRM (non-frame) byte/word swap controls take effect
	 * on descriptor entries, anything which isn't packet data.
	 *
	 * The StrongARM chips on the board (one for tx, one for rx)
	 * are running in big-endian mode.
	 */
	tp->grc_mode = (GRC_MODE_WSWAP_DATA | GRC_MODE_BSWAP_DATA |
			GRC_MODE_WSWAP_NONFRM_DATA);
#ifdef __BIG_ENDIAN
	tp->grc_mode |= GRC_MODE_BSWAP_NONFRM_DATA;
#endif
	spin_lock_init(&tp->lock);
	spin_lock_init(&tp->tx_lock);
	spin_lock_init(&tp->indirect_lock);
	PREPARE_TQUEUE(&tp->reset_task, tg3_reset_task, tp);

	tp->regs = (unsigned long) ioremap(tg3reg_base, tg3reg_len);
	if (tp->regs == 0UL) {
		printk(KERN_ERR PFX "Cannot map device registers, "
		       "aborting.\n");
		err = -ENOMEM;
		goto err_out_free_dev;
	}

	tg3_init_link_config(tp);

	tg3_init_bufmgr_config(tp);

	tp->rx_pending = TG3_DEF_RX_RING_PENDING;
	tp->rx_jumbo_pending = TG3_DEF_RX_JUMBO_RING_PENDING;
	tp->tx_pending = TG3_DEF_TX_RING_PENDING;

	dev->open = tg3_open;
	dev->stop = tg3_close;
	dev->get_stats = tg3_get_stats;
	dev->set_multicast_list = tg3_set_rx_mode;
	dev->set_mac_address = tg3_set_mac_addr;
	dev->do_ioctl = tg3_ioctl;
	dev->tx_timeout = tg3_tx_timeout;
#ifdef NAPI
	dev->poll = tg3_poll;
	dev->weight = 64;
#endif
	dev->watchdog_timeo = TG3_TX_TIMEOUT;
	dev->change_mtu = tg3_change_mtu;
	dev->irq = pdev->irq;

	err = tg3_get_invariants(tp);
	if (err) {
		printk(KERN_ERR PFX "Problem fetching invariants of chip, "
		       "aborting.\n");
		goto err_out_iounmap;
	}

	err = tg3_get_device_address(tp);
	if (err) {
		printk(KERN_ERR PFX "Could not obtain valid ethernet address, "
		       "aborting.\n");
		goto err_out_iounmap;
	}

	err = tg3_test_dma(tp);
	if (err) {
		printk(KERN_ERR PFX "DMA engine test failed, aborting.\n");
		goto err_out_iounmap;
	}

	/* Tigon3 can do ipv4 only... and some chips have buggy
	 * checksumming.
	 */
	if ((tp->tg3_flags & TG3_FLAG_BROKEN_CHECKSUMS) == 0) {
		dev->features |= NETIF_F_SG | NETIF_F_IP_CSUM;
		tp->tg3_flags |= TG3_FLAG_RX_CHECKSUMS;
	} else
		tp->tg3_flags &= ~TG3_FLAG_RX_CHECKSUMS;

	err = register_netdev(dev);
	if (err) {
		printk(KERN_ERR PFX "Cannot register net device, "
		       "aborting.\n");
		goto err_out_iounmap;
	}

	pci_set_drvdata(pdev, dev);

	/* Now that we have fully setup the chip, save away a snapshot
	 * of the PCI config space.  We need to restore this after
	 * GRC_MISC_CFG core clock resets and some resume events.
	 */
	pci_save_state(tp->pdev, tp->pci_cfg_state);

	printk(KERN_INFO "%s: Tigon3 [partno(%s) rev %04x PHY(%s)] (PCI%s:%s:%s) %sBaseT Ethernet ",
	       dev->name,
	       tp->board_part_number,
	       tp->pci_chip_rev_id,
	       tg3_phy_string(tp),
	       ((tp->tg3_flags & TG3_FLAG_PCIX_MODE) ? "X" : ""),
	       ((tp->tg3_flags & TG3_FLAG_PCI_HIGH_SPEED) ?
		((tp->tg3_flags & TG3_FLAG_PCIX_MODE) ? "133MHz" : "66MHz") :
		((tp->tg3_flags & TG3_FLAG_PCIX_MODE) ? "100MHz" : "33MHz")),
	       ((tp->tg3_flags & TG3_FLAG_PCI_32BIT) ? "32-bit" : "64-bit"),
	       (tp->tg3_flags & TG3_FLAG_10_100_ONLY) ? "10/100" : "10/100/1000");

	for (i = 0; i < 6; i++)
		printk("%2.2x%c", dev->dev_addr[i],
		       i == 5 ? '\n' : ':');

	return 0;

err_out_iounmap:
	iounmap((void *) tp->regs);

err_out_free_dev:
	kfree(dev);

err_out_free_res:
	pci_release_regions(pdev);

err_out_disable_pdev:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void __devexit tg3_remove_one(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);

	if (dev) {
		unregister_netdev(dev);
		iounmap((void *) ((struct tg3 *)(dev->priv))->regs);
		kfree(dev);
		pci_release_regions(pdev);
		pci_disable_device(pdev);
		pci_set_drvdata(pdev, NULL);
	}
}

static int tg3_suspend(struct pci_dev *pdev, u32 state)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct tg3 *tp = dev->priv;
	int err;

	if (!netif_running(dev))
		return 0;

	tg3_netif_stop(tp);

	spin_lock_irq(&tp->lock);
	spin_lock(&tp->tx_lock);
	tg3_disable_ints(tp);
	spin_unlock(&tp->tx_lock);
	spin_unlock_irq(&tp->lock);

	netif_device_detach(dev);

	spin_lock_irq(&tp->lock);
	spin_lock(&tp->tx_lock);
	tg3_halt(tp);
	spin_unlock(&tp->tx_lock);
	spin_unlock_irq(&tp->lock);

	err = tg3_set_power_state(tp, state);
	if (err) {
		spin_lock_irq(&tp->lock);
		spin_lock(&tp->tx_lock);

		tg3_init_rings(tp);
		tg3_init_hw(tp);

		spin_unlock(&tp->tx_lock);
		spin_unlock_irq(&tp->lock);

		netif_device_attach(dev);
		tg3_netif_start(tp);
	}

	return err;
}

static int tg3_resume(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct tg3 *tp = dev->priv;
	int err;

	if (!netif_running(dev))
		return 0;

	err = tg3_set_power_state(tp, 0);
	if (err)
		return err;

	netif_device_attach(dev);

	spin_lock_irq(&tp->lock);
	spin_lock(&tp->tx_lock);

	tg3_init_rings(tp);
	tg3_init_hw(tp);
	tg3_enable_ints(tp);

	spin_unlock(&tp->tx_lock);
	spin_unlock_irq(&tp->lock);

	tg3_netif_start(tp);

	return 0;
}

static struct pci_driver tg3_driver = {
	.name		= DRV_MODULE_NAME,
	.id_table	= tg3_pci_tbl,
	.probe		= tg3_init_one,
	.remove		= __devexit_p(tg3_remove_one),
	.suspend	= tg3_suspend,
	.resume		= tg3_resume
};

static int __init tg3_init(void)
{
	return pci_module_init(&tg3_driver);
}

static void __exit tg3_cleanup(void)
{
	pci_unregister_driver(&tg3_driver);
}

module_init(tg3_init);
module_exit(tg3_cleanup);
