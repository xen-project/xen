/* 8139cp.c: A Linux PCI Ethernet driver for the RealTek 8139C+ chips. */
/*
	Copyright 2001 Jeff Garzik <jgarzik@mandrakesoft.com>

	Copyright (C) 2000, 2001 David S. Miller (davem@redhat.com) [sungem.c]
	Copyright 2001 Manfred Spraul				    [natsemi.c]
	Copyright 1999-2001 by Donald Becker.			    [natsemi.c]
       	Written 1997-2001 by Donald Becker.			    [8139too.c]
	Copyright 1998-2001 by Jes Sorensen, <jes@trained-monkey.org>. [acenic.c]

	This software may be used and distributed according to the terms of
	the GNU General Public License (GPL), incorporated herein by reference.
	Drivers based on or derived from this code fall under the GPL and must
	retain the authorship, copyright and license notice.  This file is not
	a complete program and may only be used when the entire operating
	system is licensed under the GPL.

	See the file COPYING in this distribution for more information.

	TODO, in rough priority order:
	* dev->tx_timeout
	* LinkChg interrupt
	* ETHTOOL_[GS]SET
	* Support forcing media type with a module parameter,
	  like dl2k.c/sundance.c
	* Implement PCI suspend/resume
	* Constants (module parms?) for Rx work limit
	* support 64-bit PCI DMA
	* Complete reset on PciErr
	* Consider Rx interrupt mitigation using TimerIntr
	* Implement 8139C+ statistics dump; maybe not...
	  h/w stats can be reset only by software reset
	* Rx checksumming
	* Tx checksumming
	* ETHTOOL_GREGS, ETHTOOL_[GS]WOL,
	  ETHTOOL_[GS]MSGLVL, ETHTOOL_NWAY_RST
	* Jumbo frames / dev->change_mtu
	* Investigate using skb->priority with h/w VLAN priority
	* Investigate using High Priority Tx Queue with skb->priority
	* Adjust Rx FIFO threshold and Max Rx DMA burst on Rx FIFO error
	* Adjust Tx FIFO threshold and Max Tx DMA burst on Tx FIFO error

 */

#define DRV_NAME		"8139cp"
#define DRV_VERSION		"0.0.5"
#define DRV_RELDATE		"Oct 19, 2001"


#include <linux/config.h>
#include <linux/module.h>
//#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/ethtool.h>
#include <asm/io.h>
#include <asm/uaccess.h>

/* These identify the driver base version and may not be removed. */
static char version[] __devinitdata =
KERN_INFO DRV_NAME " 10/100 PCI Ethernet driver v" DRV_VERSION " (" DRV_RELDATE ")\n";

MODULE_AUTHOR("Jeff Garzik <jgarzik@mandrakesoft.com>");
MODULE_DESCRIPTION("RealTek RTL-8139C+ series 10/100 PCI Ethernet driver");
MODULE_LICENSE("GPL");

static int debug = -1;
MODULE_PARM (debug, "i");
MODULE_PARM_DESC (debug, "8139cp bitmapped message enable number");

/* Maximum number of multicast addresses to filter (vs. Rx-all-multicast).
   The RTL chips use a 64 element hash table based on the Ethernet CRC.  */
static int multicast_filter_limit = 32;
MODULE_PARM (multicast_filter_limit, "i");
MODULE_PARM_DESC (multicast_filter_limit, "8139cp maximum number of filtered multicast addresses");

/* Set the copy breakpoint for the copy-only-tiny-buffer Rx structure. */
#if defined(__alpha__) || defined(__arm__) || defined(__hppa__) \
        || defined(__sparc_) || defined(__ia64__) \
        || defined(__sh__) || defined(__mips__)
static int rx_copybreak = 1518;
#else
static int rx_copybreak = 100;
#endif
MODULE_PARM (rx_copybreak, "i");
MODULE_PARM_DESC (rx_copybreak, "8139cp Breakpoint at which Rx packets are copied");

#define PFX			DRV_NAME ": "

#define CP_DEF_MSG_ENABLE	(NETIF_MSG_DRV		| \
				 NETIF_MSG_PROBE 	| \
				 NETIF_MSG_LINK)
#define CP_REGS_SIZE		(0xff + 1)
#define CP_RX_RING_SIZE		64
#define CP_TX_RING_SIZE		64
#define CP_RING_BYTES		\
		((sizeof(struct cp_desc) * CP_RX_RING_SIZE) +	\
		(sizeof(struct cp_desc) * CP_TX_RING_SIZE))
#define NEXT_TX(N)		(((N) + 1) & (CP_TX_RING_SIZE - 1))
#define NEXT_RX(N)		(((N) + 1) & (CP_RX_RING_SIZE - 1))
#define TX_BUFFS_AVAIL(CP)					\
	(((CP)->tx_tail <= (CP)->tx_head) ?			\
	  (CP)->tx_tail + (CP_TX_RING_SIZE - 1) - (CP)->tx_head :	\
	  (CP)->tx_tail - (CP)->tx_head - 1)
#define CP_CHIP_VERSION		0x76

#define PKT_BUF_SZ		1536	/* Size of each temporary Rx buffer.*/
#define RX_OFFSET		2

/* The following settings are log_2(bytes)-4:  0 == 16 bytes .. 6==1024, 7==end of packet. */
#define RX_FIFO_THRESH		5	/* Rx buffer level before first PCI xfer.  */
#define RX_DMA_BURST		4	/* Maximum PCI burst, '4' is 256 */
#define TX_DMA_BURST		6	/* Maximum PCI burst, '6' is 1024 */
#define TX_EARLY_THRESH		256	/* Early Tx threshold, in bytes */

/* Time in jiffies before concluding the transmitter is hung. */
#define TX_TIMEOUT  (6*HZ)


enum {
	/* NIC register offsets */
	MAC0		= 0x00,	/* Ethernet hardware address. */
	MAR0		= 0x08,	/* Multicast filter. */
	TxRingAddr	= 0x20, /* 64-bit start addr of Tx ring */
	HiTxRingAddr	= 0x28, /* 64-bit start addr of high priority Tx ring */
	Cmd		= 0x37, /* Command register */
	IntrMask	= 0x3C, /* Interrupt mask */
	IntrStatus	= 0x3E, /* Interrupt status */
	TxConfig	= 0x40, /* Tx configuration */
	ChipVersion	= 0x43, /* 8-bit chip version, inside TxConfig */
	RxConfig	= 0x44, /* Rx configuration */
	Cfg9346		= 0x50, /* EEPROM select/control; Cfg reg [un]lock */
	Config1		= 0x52, /* Config1 */
	Config3		= 0x59, /* Config3 */
	Config4		= 0x5A, /* Config4 */
	MultiIntr	= 0x5C, /* Multiple interrupt select */
	Config5		= 0xD8,	/* Config5 */
	TxPoll		= 0xD9,	/* Tell chip to check Tx descriptors for work */
	CpCmd		= 0xE0, /* C+ Command register (C+ mode only) */
	RxRingAddr	= 0xE4, /* 64-bit start addr of Rx ring */
	TxThresh	= 0xEC, /* Early Tx threshold */
	OldRxBufAddr	= 0x30, /* DMA address of Rx ring buffer (C mode) */
	OldTSD0		= 0x10, /* DMA address of first Tx desc (C mode) */

	/* Tx and Rx status descriptors */
	DescOwn		= (1 << 31), /* Descriptor is owned by NIC */
	RingEnd		= (1 << 30), /* End of descriptor ring */
	FirstFrag	= (1 << 29), /* First segment of a packet */
	LastFrag	= (1 << 28), /* Final segment of a packet */
	TxError		= (1 << 23), /* Tx error summary */
	RxError		= (1 << 20), /* Rx error summary */
	IPCS		= (1 << 18), /* Calculate IP checksum */
	UDPCS		= (1 << 17), /* Calculate UDP/IP checksum */
	TCPCS		= (1 << 16), /* Calculate TCP/IP checksum */
	IPFail		= (1 << 15), /* IP checksum failed */
	UDPFail		= (1 << 14), /* UDP/IP checksum failed */
	TCPFail		= (1 << 13), /* TCP/IP checksum failed */
	NormalTxPoll	= (1 << 6),  /* One or more normal Tx packets to send */
	PID1		= (1 << 17), /* 2 protocol id bits:  0==non-IP, */
	PID0		= (1 << 16), /* 1==UDP/IP, 2==TCP/IP, 3==IP */
	TxFIFOUnder	= (1 << 25), /* Tx FIFO underrun */
	TxOWC		= (1 << 22), /* Tx Out-of-window collision */
	TxLinkFail	= (1 << 21), /* Link failed during Tx of packet */
	TxMaxCol	= (1 << 20), /* Tx aborted due to excessive collisions */
	TxColCntShift	= 16,	     /* Shift, to get 4-bit Tx collision cnt */
	TxColCntMask	= 0x01 | 0x02 | 0x04 | 0x08, /* 4-bit collision count */
	RxErrFrame	= (1 << 27), /* Rx frame alignment error */
	RxMcast		= (1 << 26), /* Rx multicast packet rcv'd */
	RxErrCRC	= (1 << 18), /* Rx CRC error */
	RxErrRunt	= (1 << 19), /* Rx error, packet < 64 bytes */
	RxErrLong	= (1 << 21), /* Rx error, packet > 4096 bytes */
	RxErrFIFO	= (1 << 22), /* Rx error, FIFO overflowed, pkt bad */

	/* RxConfig register */
	RxCfgFIFOShift	= 13,	     /* Shift, to get Rx FIFO thresh value */
	RxCfgDMAShift	= 8,	     /* Shift, to get Rx Max DMA value */
	AcceptErr	= 0x20,	     /* Accept packets with CRC errors */
	AcceptRunt	= 0x10,	     /* Accept runt (<64 bytes) packets */
	AcceptBroadcast	= 0x08,	     /* Accept broadcast packets */
	AcceptMulticast	= 0x04,	     /* Accept multicast packets */
	AcceptMyPhys	= 0x02,	     /* Accept pkts with our MAC as dest */
	AcceptAllPhys	= 0x01,	     /* Accept all pkts w/ physical dest */

	/* IntrMask / IntrStatus registers */
	PciErr		= (1 << 15), /* System error on the PCI bus */
	TimerIntr	= (1 << 14), /* Asserted when TCTR reaches TimerInt value */
	LenChg		= (1 << 13), /* Cable length change */
	SWInt		= (1 << 8),  /* Software-requested interrupt */
	TxEmpty		= (1 << 7),  /* No Tx descriptors available */
	RxFIFOOvr	= (1 << 6),  /* Rx FIFO Overflow */
	LinkChg		= (1 << 5),  /* Packet underrun, or link change */
	RxEmpty		= (1 << 4),  /* No Rx descriptors available */
	TxErr		= (1 << 3),  /* Tx error */
	TxOK		= (1 << 2),  /* Tx packet sent */
	RxErr		= (1 << 1),  /* Rx error */
	RxOK		= (1 << 0),  /* Rx packet received */
	IntrResvd	= (1 << 10), /* reserved, according to RealTek engineers,
					but hardware likes to raise it */

	IntrAll		= PciErr | TimerIntr | LenChg | SWInt | TxEmpty |
			  RxFIFOOvr | LinkChg | RxEmpty | TxErr | TxOK |
			  RxErr | RxOK | IntrResvd,

	/* C mode command register */
	CmdReset	= (1 << 4),  /* Enable to reset; self-clearing */
	RxOn		= (1 << 3),  /* Rx mode enable */
	TxOn		= (1 << 2),  /* Tx mode enable */

	/* C+ mode command register */
	RxChkSum	= (1 << 5),  /* Rx checksum offload enable */
	PCIMulRW	= (1 << 3),  /* Enable PCI read/write multiple */
	CpRxOn		= (1 << 1),  /* Rx mode enable */
	CpTxOn		= (1 << 0),  /* Tx mode enable */

	/* Cfg9436 EEPROM control register */
	Cfg9346_Lock	= 0x00,	     /* Lock ConfigX/MII register access */
	Cfg9346_Unlock	= 0xC0,	     /* Unlock ConfigX/MII register access */

	/* TxConfig register */
	IFG		= (1 << 25) | (1 << 24), /* standard IEEE interframe gap */
	TxDMAShift	= 8,	     /* DMA burst value (0-7) is shift this many bits */

	/* Early Tx Threshold register */
	TxThreshMask	= 0x3f,	     /* Mask bits 5-0 */
	TxThreshMax	= 2048,	     /* Max early Tx threshold */

	/* Config1 register */
	DriverLoaded	= (1 << 5),  /* Software marker, driver is loaded */
	PMEnable	= (1 << 0),  /* Enable various PM features of chip */

	/* Config3 register */
	PARMEnable	= (1 << 6),  /* Enable auto-loading of PHY parms */

	/* Config5 register */
	PMEStatus	= (1 << 0),  /* PME status can be reset by PCI RST# */
};

static const unsigned int cp_intr_mask =
	PciErr | LinkChg |
	RxOK | RxErr | RxEmpty | RxFIFOOvr |
	TxOK | TxErr | TxEmpty;

static const unsigned int cp_rx_config =
	  (RX_FIFO_THRESH << RxCfgFIFOShift) |
	  (RX_DMA_BURST << RxCfgDMAShift);

struct cp_desc {
	u32		opts1;
	u32		opts2;
	u32		addr_lo;
	u32		addr_hi;
};

struct ring_info {
	struct sk_buff		*skb;
	dma_addr_t		mapping;
	unsigned		frag;
};

struct cp_extra_stats {
	unsigned long		rx_frags;
};

struct cp_private {
	unsigned		tx_head;
	unsigned		tx_tail;
	unsigned		rx_tail;

	void			*regs;
	struct net_device	*dev;
	spinlock_t		lock;

	struct cp_desc		*rx_ring;
	struct cp_desc		*tx_ring;
	struct ring_info	tx_skb[CP_TX_RING_SIZE];
	struct ring_info	rx_skb[CP_RX_RING_SIZE];
	unsigned		rx_buf_sz;
	dma_addr_t		ring_dma;

	u32			msg_enable;

	struct net_device_stats net_stats;
	struct cp_extra_stats	cp_stats;

	struct pci_dev		*pdev;
	u32			rx_config;

	struct sk_buff		*frag_skb;
	unsigned		dropping_frag : 1;
};

#define cpr8(reg)	readb(cp->regs + (reg))
#define cpr16(reg)	readw(cp->regs + (reg))
#define cpr32(reg)	readl(cp->regs + (reg))
#define cpw8(reg,val)	writeb((val), cp->regs + (reg))
#define cpw16(reg,val)	writew((val), cp->regs + (reg))
#define cpw32(reg,val)	writel((val), cp->regs + (reg))
#define cpw8_f(reg,val) do {			\
	writeb((val), cp->regs + (reg));	\
	readb(cp->regs + (reg));		\
	} while (0)
#define cpw16_f(reg,val) do {			\
	writew((val), cp->regs + (reg));	\
	readw(cp->regs + (reg));		\
	} while (0)
#define cpw32_f(reg,val) do {			\
	writel((val), cp->regs + (reg));	\
	readl(cp->regs + (reg));		\
	} while (0)


static void __cp_set_rx_mode (struct net_device *dev);
static void cp_tx (struct cp_private *cp);
static void cp_clean_rings (struct cp_private *cp);


static struct pci_device_id cp_pci_tbl[] __devinitdata = {
	{ PCI_VENDOR_ID_REALTEK, PCI_DEVICE_ID_REALTEK_8139,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
	{ },
};
MODULE_DEVICE_TABLE(pci, cp_pci_tbl);

static inline void cp_rx_skb (struct cp_private *cp, struct sk_buff *skb)
{
	skb->protocol = eth_type_trans (skb, cp->dev);

	cp->net_stats.rx_packets++;
	cp->net_stats.rx_bytes += skb->len;
	cp->dev->last_rx = jiffies;
	netif_rx (skb);
}

static inline void cp_rx_err_acct (struct cp_private *cp, unsigned rx_tail,
				   u32 status, u32 len)
{
	if (netif_msg_rx_err (cp))
		printk (KERN_DEBUG
			"%s: rx err, slot %d status 0x%x len %d\n",
			cp->dev->name, rx_tail, status, len);
	cp->net_stats.rx_errors++;
	if (status & RxErrFrame)
		cp->net_stats.rx_frame_errors++;
	if (status & RxErrCRC)
		cp->net_stats.rx_crc_errors++;
	if (status & RxErrRunt)
		cp->net_stats.rx_length_errors++;
	if (status & RxErrLong)
		cp->net_stats.rx_length_errors++;
	if (status & RxErrFIFO)
		cp->net_stats.rx_fifo_errors++;
}

static void cp_rx_frag (struct cp_private *cp, unsigned rx_tail,
			struct sk_buff *skb, u32 status, u32 len)
{
	struct sk_buff *copy_skb, *frag_skb = cp->frag_skb;
	unsigned orig_len = frag_skb ? frag_skb->len : 0;
	unsigned target_len = orig_len + len;
	unsigned first_frag = status & FirstFrag;
	unsigned last_frag = status & LastFrag;

	if (netif_msg_rx_status (cp))
		printk (KERN_DEBUG "%s: rx %s%sfrag, slot %d status 0x%x len %d\n",
			cp->dev->name,
			cp->dropping_frag ? "dropping " : "",
			first_frag ? "first " :
			last_frag ? "last " : "",
			rx_tail, status, len);

	cp->cp_stats.rx_frags++;

	if (!frag_skb && !first_frag)
		cp->dropping_frag = 1;
	if (cp->dropping_frag)
		goto drop_frag;

	copy_skb = dev_alloc_skb (target_len + RX_OFFSET);
	if (!copy_skb) {
		printk(KERN_WARNING "%s: rx slot %d alloc failed\n",
		       cp->dev->name, rx_tail);

		cp->dropping_frag = 1;
drop_frag:
		if (frag_skb) {
			dev_kfree_skb_irq(frag_skb);
			cp->frag_skb = NULL;
		}
		if (last_frag) {
			cp->net_stats.rx_dropped++;
			cp->dropping_frag = 0;
		}
		return;
	}

	copy_skb->dev = cp->dev;
	skb_reserve(copy_skb, RX_OFFSET);
	skb_put(copy_skb, target_len);
	if (frag_skb) {
		memcpy(copy_skb->data, frag_skb->data, orig_len);
		dev_kfree_skb_irq(frag_skb);
	}
	pci_dma_sync_single(cp->pdev, cp->rx_skb[rx_tail].mapping,
			    len, PCI_DMA_FROMDEVICE);
	memcpy(copy_skb->data + orig_len, skb->data, len);

	copy_skb->ip_summed = CHECKSUM_NONE;

	if (last_frag) {
		if (status & (RxError | RxErrFIFO)) {
			cp_rx_err_acct(cp, rx_tail, status, len);
			dev_kfree_skb_irq(copy_skb);
		} else
			cp_rx_skb(cp, copy_skb);
		cp->frag_skb = NULL;
	} else {
		cp->frag_skb = copy_skb;
	}
}

static void cp_rx (struct cp_private *cp)
{
	unsigned rx_tail = cp->rx_tail;
	unsigned rx_work = 100;

	while (rx_work--) {
		u32 status, len;
		dma_addr_t mapping;
		struct sk_buff *skb, *copy_skb;
		unsigned copying_skb, buflen;

		skb = cp->rx_skb[rx_tail].skb;
		if (!skb)
			BUG();
		rmb();
		status = le32_to_cpu(cp->rx_ring[rx_tail].opts1);
		if (status & DescOwn)
			break;

		len = (status & 0x1fff) - 4;
		mapping = cp->rx_skb[rx_tail].mapping;

		if ((status & (FirstFrag | LastFrag)) != (FirstFrag | LastFrag)) {
			cp_rx_frag(cp, rx_tail, skb, status, len);
			goto rx_next;
		}

		if (status & (RxError | RxErrFIFO)) {
			cp_rx_err_acct(cp, rx_tail, status, len);
			goto rx_next;
		}

		copying_skb = (len <= rx_copybreak);

		if (netif_msg_rx_status(cp))
			printk(KERN_DEBUG "%s: rx slot %d status 0x%x len %d copying? %d\n",
			       cp->dev->name, rx_tail, status, len,
			       copying_skb);

		buflen = copying_skb ? len : cp->rx_buf_sz;
		copy_skb = dev_alloc_skb (buflen + RX_OFFSET);
		if (!copy_skb) {
			cp->net_stats.rx_dropped++;
			goto rx_next;
		}

		skb_reserve(copy_skb, RX_OFFSET);
		copy_skb->dev = cp->dev;

		if (!copying_skb) {
			pci_unmap_single(cp->pdev, mapping,
					 buflen, PCI_DMA_FROMDEVICE);
			skb->ip_summed = CHECKSUM_NONE;
			skb_trim(skb, len);

			mapping =
			cp->rx_skb[rx_tail].mapping =
				pci_map_single(cp->pdev, copy_skb->data,
					       buflen, PCI_DMA_FROMDEVICE);
			cp->rx_skb[rx_tail].skb = copy_skb;
			skb_put(copy_skb, buflen);
		} else {
			skb_put(copy_skb, len);
			pci_dma_sync_single(cp->pdev, mapping, len, PCI_DMA_FROMDEVICE);
			memcpy(copy_skb->data, skb->data, len);

			/* We'll reuse the original ring buffer. */
			skb = copy_skb;
		}

		cp_rx_skb(cp, skb);

rx_next:
		if (rx_tail == (CP_RX_RING_SIZE - 1))
			cp->rx_ring[rx_tail].opts1 =
				cpu_to_le32(DescOwn | RingEnd | cp->rx_buf_sz);
		else
			cp->rx_ring[rx_tail].opts1 =
				cpu_to_le32(DescOwn | cp->rx_buf_sz);
		cp->rx_ring[rx_tail].opts2 = 0;
		cp->rx_ring[rx_tail].addr_lo = cpu_to_le32(mapping);
		rx_tail = NEXT_RX(rx_tail);
	}

	if (!rx_work)
		printk(KERN_WARNING "%s: rx work limit reached\n", cp->dev->name);

	cp->rx_tail = rx_tail;
}

static void cp_interrupt (int irq, void *dev_instance, struct pt_regs *regs)
{
	struct net_device *dev = dev_instance;
	struct cp_private *cp = dev->priv;
	u16 status;

	status = cpr16(IntrStatus);
	if (!status || (status == 0xFFFF))
		return;

	if (netif_msg_intr(cp))
		printk(KERN_DEBUG "%s: intr, status %04x cmd %02x cpcmd %04x\n",
		        dev->name, status, cpr8(Cmd), cpr16(CpCmd));

	spin_lock(&cp->lock);

	if (status & (RxOK | RxErr | RxEmpty | RxFIFOOvr))
		cp_rx(cp);
	if (status & (TxOK | TxErr | TxEmpty | SWInt))
		cp_tx(cp);

	cpw16_f(IntrStatus, status);

	if (status & PciErr) {
		u16 pci_status;

		pci_read_config_word(cp->pdev, PCI_STATUS, &pci_status);
		pci_write_config_word(cp->pdev, PCI_STATUS, pci_status);
		printk(KERN_ERR "%s: PCI bus error, status=%04x, PCI status=%04x\n",
		       dev->name, status, pci_status);
	}

	spin_unlock(&cp->lock);
}

static void cp_tx (struct cp_private *cp)
{
	unsigned tx_head = cp->tx_head;
	unsigned tx_tail = cp->tx_tail;

	while (tx_tail != tx_head) {
		struct sk_buff *skb;
		u32 status;

		rmb();
		status = le32_to_cpu(cp->tx_ring[tx_tail].opts1);
		if (status & DescOwn)
			break;

		skb = cp->tx_skb[tx_tail].skb;
		if (!skb)
			BUG();

		pci_unmap_single(cp->pdev, cp->tx_skb[tx_tail].mapping,
					skb->len, PCI_DMA_TODEVICE);

		if (status & LastFrag) {
			if (status & (TxError | TxFIFOUnder)) {
				if (netif_msg_tx_err(cp))
					printk(KERN_DEBUG "%s: tx err, status 0x%x\n",
					       cp->dev->name, status);
				cp->net_stats.tx_errors++;
				if (status & TxOWC)
					cp->net_stats.tx_window_errors++;
				if (status & TxMaxCol)
					cp->net_stats.tx_aborted_errors++;
				if (status & TxLinkFail)
					cp->net_stats.tx_carrier_errors++;
				if (status & TxFIFOUnder)
					cp->net_stats.tx_fifo_errors++;
			} else {
				cp->net_stats.collisions +=
					((status >> TxColCntShift) & TxColCntMask);
				cp->net_stats.tx_packets++;
				cp->net_stats.tx_bytes += skb->len;
				if (netif_msg_tx_done(cp))
					printk(KERN_DEBUG "%s: tx done, slot %d\n", cp->dev->name, tx_tail);
			}
			dev_kfree_skb_irq(skb);
		}

		cp->tx_skb[tx_tail].skb = NULL;

		tx_tail = NEXT_TX(tx_tail);
	}

	cp->tx_tail = tx_tail;

	if (netif_queue_stopped(cp->dev) && (TX_BUFFS_AVAIL(cp) > 1))
		netif_wake_queue(cp->dev);
}

static int cp_start_xmit (struct sk_buff *skb, struct net_device *dev)
{
	struct cp_private *cp = dev->priv;
	unsigned entry;
	u32 eor;

	spin_lock_irq(&cp->lock);

	if (TX_BUFFS_AVAIL(cp) <= (skb_shinfo(skb)->nr_frags + 1)) {
		netif_stop_queue(dev);
		spin_unlock_irq(&cp->lock);
		return 1;
	}

	entry = cp->tx_head;
	eor = (entry == (CP_TX_RING_SIZE - 1)) ? RingEnd : 0;
	if (skb_shinfo(skb)->nr_frags == 0) {
		struct cp_desc *txd = &cp->tx_ring[entry];
		u32 mapping, len;

		len = skb->len;
		mapping = pci_map_single(cp->pdev, skb->data, len, PCI_DMA_TODEVICE);
		eor = (entry == (CP_TX_RING_SIZE - 1)) ? RingEnd : 0;
		txd->opts2 = 0;
		txd->addr_lo = cpu_to_le32(mapping);
		wmb();

#ifdef CP_TX_CHECKSUM
		txd->opts1 = cpu_to_le32(eor | len | DescOwn | FirstFrag |
			LastFrag | IPCS | UDPCS | TCPCS);
#else
		txd->opts1 = cpu_to_le32(eor | len | DescOwn | FirstFrag |
			LastFrag);
#endif
		wmb();

		cp->tx_skb[entry].skb = skb;
		cp->tx_skb[entry].mapping = mapping;
		cp->tx_skb[entry].frag = 0;
		entry = NEXT_TX(entry);
	} else {
		struct cp_desc *txd;
		u32 first_len, first_mapping;
		int frag, first_entry = entry;

		/* We must give this initial chunk to the device last.
		 * Otherwise we could race with the device.
		 */
		first_len = skb->len - skb->data_len;
		first_mapping = pci_map_single(cp->pdev, skb->data,
					       first_len, PCI_DMA_TODEVICE);
		cp->tx_skb[entry].skb = skb;
		cp->tx_skb[entry].mapping = first_mapping;
		cp->tx_skb[entry].frag = 1;
		entry = NEXT_TX(entry);

		for (frag = 0; frag < skb_shinfo(skb)->nr_frags; frag++) {
			skb_frag_t *this_frag = &skb_shinfo(skb)->frags[frag];
			u32 len, mapping;
			u32 ctrl;

			len = this_frag->size;
			mapping = pci_map_single(cp->pdev,
						 ((void *) page_address(this_frag->page) +
						  this_frag->page_offset),
						 len, PCI_DMA_TODEVICE);
			eor = (entry == (CP_TX_RING_SIZE - 1)) ? RingEnd : 0;
#ifdef CP_TX_CHECKSUM
			ctrl = eor | len | DescOwn | IPCS | UDPCS | TCPCS;
#else
			ctrl = eor | len | DescOwn;
#endif
			if (frag == skb_shinfo(skb)->nr_frags - 1)
				ctrl |= LastFrag;

			txd = &cp->tx_ring[entry];
			txd->opts2 = 0;
			txd->addr_lo = cpu_to_le32(mapping);
			wmb();

			txd->opts1 = cpu_to_le32(ctrl);
			wmb();

			cp->tx_skb[entry].skb = skb;
			cp->tx_skb[entry].mapping = mapping;
			cp->tx_skb[entry].frag = frag + 2;
			entry = NEXT_TX(entry);
		}

		txd = &cp->tx_ring[first_entry];
		txd->opts2 = 0;
		txd->addr_lo = cpu_to_le32(first_mapping);
		wmb();

#ifdef CP_TX_CHECKSUM
		txd->opts1 = cpu_to_le32(first_len | FirstFrag | DescOwn | IPCS | UDPCS | TCPCS);
#else
		txd->opts1 = cpu_to_le32(first_len | FirstFrag | DescOwn);
#endif
		wmb();
	}
	cp->tx_head = entry;
	if (netif_msg_tx_queued(cp))
		printk(KERN_DEBUG "%s: tx queued, slot %d, skblen %d\n",
		       dev->name, entry, skb->len);
	if (TX_BUFFS_AVAIL(cp) < 0)
		BUG();
	if (TX_BUFFS_AVAIL(cp) == 0)
		netif_stop_queue(dev);

	spin_unlock_irq(&cp->lock);

	cpw8(TxPoll, NormalTxPoll);
	dev->trans_start = jiffies;

	return 0;
}

/* Set or clear the multicast filter for this adaptor.
   This routine is not state sensitive and need not be SMP locked. */

static unsigned const ethernet_polynomial = 0x04c11db7U;
static inline u32 ether_crc (int length, unsigned char *data)
{
	int crc = -1;

	while (--length >= 0) {
		unsigned char current_octet = *data++;
		int bit;
		for (bit = 0; bit < 8; bit++, current_octet >>= 1)
			crc = (crc << 1) ^ ((crc < 0) ^ (current_octet & 1) ?
			     ethernet_polynomial : 0);
	}

	return crc;
}

static void __cp_set_rx_mode (struct net_device *dev)
{
	struct cp_private *cp = dev->priv;
	u32 mc_filter[2];	/* Multicast hash filter */
	int i, rx_mode;
	u32 tmp;

	/* Note: do not reorder, GCC is clever about common statements. */
	if (dev->flags & IFF_PROMISC) {
		/* Unconditionally log net taps. */
		printk (KERN_NOTICE "%s: Promiscuous mode enabled.\n",
			dev->name);
		rx_mode =
		    AcceptBroadcast | AcceptMulticast | AcceptMyPhys |
		    AcceptAllPhys;
		mc_filter[1] = mc_filter[0] = 0xffffffff;
	} else if ((dev->mc_count > multicast_filter_limit)
		   || (dev->flags & IFF_ALLMULTI)) {
		/* Too many to filter perfectly -- accept all multicasts. */
		rx_mode = AcceptBroadcast | AcceptMulticast | AcceptMyPhys;
		mc_filter[1] = mc_filter[0] = 0xffffffff;
	} else {
		struct dev_mc_list *mclist;
		rx_mode = AcceptBroadcast | AcceptMyPhys;
		mc_filter[1] = mc_filter[0] = 0;
		for (i = 0, mclist = dev->mc_list; mclist && i < dev->mc_count;
		     i++, mclist = mclist->next) {
			int bit_nr = ether_crc(ETH_ALEN, mclist->dmi_addr) >> 26;

			mc_filter[bit_nr >> 5] |= cpu_to_le32(1 << (bit_nr & 31));
			rx_mode |= AcceptMulticast;
		}
	}

	/* We can safely update without stopping the chip. */
	tmp = cp_rx_config | rx_mode;
	if (cp->rx_config != tmp) {
		cpw32_f (RxConfig, tmp);
		cp->rx_config = tmp;
	}
	cpw32_f (MAR0 + 0, mc_filter[0]);
	cpw32_f (MAR0 + 4, mc_filter[1]);
}

static void cp_set_rx_mode (struct net_device *dev)
{
	unsigned long flags;
	struct cp_private *cp = dev->priv;

	spin_lock_irqsave (&cp->lock, flags);
	__cp_set_rx_mode(dev);
	spin_unlock_irqrestore (&cp->lock, flags);
}

static void __cp_get_stats(struct cp_private *cp)
{
	/* XXX implement */
}

static struct net_device_stats *cp_get_stats(struct net_device *dev)
{
	struct cp_private *cp = dev->priv;

	/* The chip only need report frame silently dropped. */
	spin_lock_irq(&cp->lock);
 	if (netif_running(dev) && netif_device_present(dev))
 		__cp_get_stats(cp);
	spin_unlock_irq(&cp->lock);

	return &cp->net_stats;
}

static void cp_stop_hw (struct cp_private *cp)
{
	cpw16(IntrMask, 0);
	cpr16(IntrMask);
	cpw8(Cmd, 0);
	cpw16(CpCmd, 0);
	cpr16(CpCmd);
	cpw16(IntrStatus, ~(cpr16(IntrStatus)));
	synchronize_irq();
	udelay(10);

	cp->rx_tail = 0;
	cp->tx_head = cp->tx_tail = 0;
}

static void cp_reset_hw (struct cp_private *cp)
{
	unsigned work = 1000;

	cpw8(Cmd, CmdReset);

	while (work--) {
		if (!(cpr8(Cmd) & CmdReset))
			return;

		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(10);
	}

	printk(KERN_ERR "%s: hardware reset timeout\n", cp->dev->name);
}

static void cp_init_hw (struct cp_private *cp)
{
	struct net_device *dev = cp->dev;

	cp_reset_hw(cp);

	cpw8_f (Cfg9346, Cfg9346_Unlock);

	/* Restore our idea of the MAC address. */
	cpw32_f (MAC0 + 0, cpu_to_le32 (*(u32 *) (dev->dev_addr + 0)));
	cpw32_f (MAC0 + 4, cpu_to_le32 (*(u32 *) (dev->dev_addr + 4)));

	cpw8(Cmd, RxOn | TxOn);
	cpw16(CpCmd, PCIMulRW | CpRxOn | CpTxOn);
	cpw8(TxThresh, 0x06); /* XXX convert magic num to a constant */

	__cp_set_rx_mode(dev);
	cpw32_f (TxConfig, IFG | (TX_DMA_BURST << TxDMAShift));

	cpw8(Config1, cpr8(Config1) | DriverLoaded | PMEnable);
	cpw8(Config3, PARMEnable); /* disables magic packet and WOL */
	cpw8(Config5, cpr8(Config5) & PMEStatus); /* disables more WOL stuff */

	cpw32_f(HiTxRingAddr, 0);
	cpw32_f(HiTxRingAddr + 4, 0);
	cpw32_f(OldRxBufAddr, 0);
	cpw32_f(OldTSD0, 0);
	cpw32_f(OldTSD0 + 4, 0);
	cpw32_f(OldTSD0 + 8, 0);
	cpw32_f(OldTSD0 + 12, 0);

	cpw32_f(RxRingAddr, cp->ring_dma);
	cpw32_f(RxRingAddr + 4, 0);
	cpw32_f(TxRingAddr, cp->ring_dma + (sizeof(struct cp_desc) * CP_RX_RING_SIZE));
	cpw32_f(TxRingAddr + 4, 0);

	cpw16(MultiIntr, 0);

	cpw16(IntrMask, cp_intr_mask);

	cpw8_f (Cfg9346, Cfg9346_Lock);
}

static int cp_refill_rx (struct cp_private *cp)
{
	unsigned i;

	for (i = 0; i < CP_RX_RING_SIZE; i++) {
		struct sk_buff *skb;

		skb = dev_alloc_skb(cp->rx_buf_sz + RX_OFFSET);
		if (!skb)
			goto err_out;

		skb->dev = cp->dev;
		skb_reserve(skb, RX_OFFSET);
		skb_put(skb, cp->rx_buf_sz);

		cp->rx_skb[i].mapping = pci_map_single(cp->pdev,
			skb->data, cp->rx_buf_sz, PCI_DMA_FROMDEVICE);
		cp->rx_skb[i].skb = skb;
		cp->rx_skb[i].frag = 0;

		if (i == (CP_RX_RING_SIZE - 1))
			cp->rx_ring[i].opts1 =
				cpu_to_le32(DescOwn | RingEnd | cp->rx_buf_sz);
		else
			cp->rx_ring[i].opts1 =
				cpu_to_le32(DescOwn | cp->rx_buf_sz);
		cp->rx_ring[i].opts2 = 0;
		cp->rx_ring[i].addr_lo = cpu_to_le32(cp->rx_skb[i].mapping);
		cp->rx_ring[i].addr_hi = 0;
	}

	return 0;

err_out:
	cp_clean_rings(cp);
	return -ENOMEM;
}

static int cp_init_rings (struct cp_private *cp)
{
	memset(cp->tx_ring, 0, sizeof(struct cp_desc) * CP_TX_RING_SIZE);
	cp->tx_ring[CP_TX_RING_SIZE - 1].opts1 = cpu_to_le32(RingEnd);

	cp->rx_tail = 0;
	cp->tx_head = cp->tx_tail = 0;

	return cp_refill_rx (cp);
}

static int cp_alloc_rings (struct cp_private *cp)
{
	cp->rx_ring = pci_alloc_consistent(cp->pdev, CP_RING_BYTES, &cp->ring_dma);
	if (!cp->rx_ring)
		return -ENOMEM;
	cp->tx_ring = &cp->rx_ring[CP_RX_RING_SIZE];
	return cp_init_rings(cp);
}

static void cp_clean_rings (struct cp_private *cp)
{
	unsigned i;

	memset(cp->rx_ring, 0, sizeof(struct cp_desc) * CP_RX_RING_SIZE);
	memset(cp->tx_ring, 0, sizeof(struct cp_desc) * CP_TX_RING_SIZE);

	for (i = 0; i < CP_RX_RING_SIZE; i++) {
		if (cp->rx_skb[i].skb) {
			pci_unmap_single(cp->pdev, cp->rx_skb[i].mapping,
					 cp->rx_buf_sz, PCI_DMA_FROMDEVICE);
			dev_kfree_skb(cp->rx_skb[i].skb);
		}
	}

	for (i = 0; i < CP_TX_RING_SIZE; i++) {
		if (cp->tx_skb[i].skb) {
			struct sk_buff *skb = cp->tx_skb[i].skb;
			pci_unmap_single(cp->pdev, cp->tx_skb[i].mapping,
					 skb->len, PCI_DMA_TODEVICE);
			dev_kfree_skb(skb);
			cp->net_stats.tx_dropped++;
		}
	}

	memset(&cp->rx_skb, 0, sizeof(struct ring_info) * CP_RX_RING_SIZE);
	memset(&cp->tx_skb, 0, sizeof(struct ring_info) * CP_TX_RING_SIZE);
}

static void cp_free_rings (struct cp_private *cp)
{
	cp_clean_rings(cp);
	pci_free_consistent(cp->pdev, CP_RING_BYTES, cp->rx_ring, cp->ring_dma);
	cp->rx_ring = NULL;
	cp->tx_ring = NULL;
}

static int cp_open (struct net_device *dev)
{
	struct cp_private *cp = dev->priv;
	int rc;

	if (netif_msg_ifup(cp))
		printk(KERN_DEBUG "%s: enabling interface\n", dev->name);

	cp->rx_buf_sz = (dev->mtu <= 1500 ? PKT_BUF_SZ : dev->mtu + 32);

	rc = cp_alloc_rings(cp);
	if (rc)
		return rc;

	cp_init_hw(cp);

	rc = request_irq(dev->irq, cp_interrupt, SA_SHIRQ, dev->name, dev);
	if (rc)
		goto err_out_hw;

	netif_start_queue(dev);

	return 0;

err_out_hw:
	cp_stop_hw(cp);
	cp_free_rings(cp);
	return rc;
}

static int cp_close (struct net_device *dev)
{
	struct cp_private *cp = dev->priv;

	if (netif_msg_ifdown(cp))
		printk(KERN_DEBUG "%s: disabling interface\n", dev->name);

	netif_stop_queue(dev);
	cp_stop_hw(cp);
	free_irq(dev->irq, dev);
	cp_free_rings(cp);
	return 0;
}

static int cp_ethtool_ioctl (struct cp_private *cp, void *useraddr)
{
	u32 ethcmd;

	/* dev_ioctl() in ../../net/core/dev.c has already checked
	   capable(CAP_NET_ADMIN), so don't bother with that here.  */

	if (copy_from_user (&ethcmd, useraddr, sizeof (ethcmd)))
		return -EFAULT;

	switch (ethcmd) {

	case ETHTOOL_GDRVINFO:
		{
			struct ethtool_drvinfo info = { ETHTOOL_GDRVINFO };
			strcpy (info.driver, DRV_NAME);
			strcpy (info.version, DRV_VERSION);
			strcpy (info.bus_info, cp->pdev->slot_name);
			if (copy_to_user (useraddr, &info, sizeof (info)))
				return -EFAULT;
			return 0;
		}

	default:
		break;
	}

	return -EOPNOTSUPP;
}


static int cp_ioctl (struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct cp_private *cp = dev->priv;
	int rc = 0;

	switch (cmd) {
	case SIOCETHTOOL:
		return cp_ethtool_ioctl(cp, (void *) rq->ifr_data);

	default:
		rc = -EOPNOTSUPP;
		break;
	}

	return rc;
}



/* Serial EEPROM section. */

/*  EEPROM_Ctrl bits. */
#define EE_SHIFT_CLK	0x04	/* EEPROM shift clock. */
#define EE_CS			0x08	/* EEPROM chip select. */
#define EE_DATA_WRITE	0x02	/* EEPROM chip data in. */
#define EE_WRITE_0		0x00
#define EE_WRITE_1		0x02
#define EE_DATA_READ	0x01	/* EEPROM chip data out. */
#define EE_ENB			(0x80 | EE_CS)

/* Delay between EEPROM clock transitions.
   No extra delay is needed with 33Mhz PCI, but 66Mhz may change this.
 */

#define eeprom_delay()	readl(ee_addr)

/* The EEPROM commands include the alway-set leading bit. */
#define EE_WRITE_CMD	(5)
#define EE_READ_CMD		(6)
#define EE_ERASE_CMD	(7)

static int __devinit read_eeprom (void *ioaddr, int location, int addr_len)
{
	int i;
	unsigned retval = 0;
	void *ee_addr = ioaddr + Cfg9346;
	int read_cmd = location | (EE_READ_CMD << addr_len);

	writeb (EE_ENB & ~EE_CS, ee_addr);
	writeb (EE_ENB, ee_addr);
	eeprom_delay ();

	/* Shift the read command bits out. */
	for (i = 4 + addr_len; i >= 0; i--) {
		int dataval = (read_cmd & (1 << i)) ? EE_DATA_WRITE : 0;
		writeb (EE_ENB | dataval, ee_addr);
		eeprom_delay ();
		writeb (EE_ENB | dataval | EE_SHIFT_CLK, ee_addr);
		eeprom_delay ();
	}
	writeb (EE_ENB, ee_addr);
	eeprom_delay ();

	for (i = 16; i > 0; i--) {
		writeb (EE_ENB | EE_SHIFT_CLK, ee_addr);
		eeprom_delay ();
		retval =
		    (retval << 1) | ((readb (ee_addr) & EE_DATA_READ) ? 1 :
				     0);
		writeb (EE_ENB, ee_addr);
		eeprom_delay ();
	}

	/* Terminate the EEPROM access. */
	writeb (~EE_CS, ee_addr);
	eeprom_delay ();

	return retval;
}

static int __devinit cp_init_one (struct pci_dev *pdev,
				  const struct pci_device_id *ent)
{
	struct net_device *dev;
	struct cp_private *cp;
	int rc;
	void *regs;
	long pciaddr;
	unsigned addr_len, i;
	u8 pci_rev, cache_size;
	u16 pci_command;

#ifndef MODULE
	static int version_printed;
	if (version_printed++ == 0)
		printk("%s", version);
#endif

	pci_read_config_byte(pdev, PCI_REVISION_ID, &pci_rev);

	if (pdev->vendor == PCI_VENDOR_ID_REALTEK &&
	    pdev->device == PCI_DEVICE_ID_REALTEK_8139 && pci_rev < 0x20) {
		printk(KERN_ERR PFX "pci dev %s (id %04x:%04x rev %02x) is not an 8139C+ compatible chip\n",
		       pdev->slot_name, pdev->vendor, pdev->device, pci_rev);
		printk(KERN_ERR PFX "Ensure the \"8139too\" driver is installed!\n");
		return -ENODEV;
	}

	dev = alloc_etherdev(sizeof(struct cp_private));
	if (!dev)
		return -ENOMEM;
	SET_MODULE_OWNER(dev);
	cp = dev->priv;
	cp->pdev = pdev;
	cp->dev = dev;
	cp->msg_enable = (debug < 0 ? CP_DEF_MSG_ENABLE : debug);
	spin_lock_init (&cp->lock);

	rc = pci_enable_device(pdev);
	if (rc)
		goto err_out_free;

	rc = pci_request_regions(pdev, DRV_NAME);
	if (rc)
		goto err_out_disable;

	if (pdev->irq < 2) {
		rc = -EIO;
		printk(KERN_ERR PFX "invalid irq (%d) for pci dev %s\n",
		       pdev->irq, pdev->slot_name);
		goto err_out_res;
	}
	pciaddr = pci_resource_start(pdev, 1);
	if (!pciaddr) {
		rc = -EIO;
		printk(KERN_ERR PFX "no MMIO resource for pci dev %s\n",
		       pdev->slot_name);
		goto err_out_res;
	}
	if (pci_resource_len(pdev, 1) < CP_REGS_SIZE) {
		rc = -EIO;
		printk(KERN_ERR PFX "MMIO resource (%lx) too small on pci dev %s\n",
		       pci_resource_len(pdev, 1), pdev->slot_name);
		goto err_out_res;
	}

	regs = ioremap_nocache(pciaddr, CP_REGS_SIZE);
	if (!regs) {
		rc = -EIO;
		printk(KERN_ERR PFX "Cannot map PCI MMIO (%lx@%lx) on pci dev %s\n",
		       pci_resource_len(pdev, 1), pciaddr, pdev->slot_name);
		goto err_out_res;
	}
	dev->base_addr = (unsigned long) regs;
	cp->regs = regs;

	cp_stop_hw(cp);

	/* read MAC address from EEPROM */
	addr_len = read_eeprom (regs, 0, 8) == 0x8129 ? 8 : 6;
	for (i = 0; i < 3; i++)
		((u16 *) (dev->dev_addr))[i] =
		    le16_to_cpu (read_eeprom (regs, i + 7, addr_len));

	dev->open = cp_open;
	dev->stop = cp_close;
	dev->set_multicast_list = cp_set_rx_mode;
	dev->hard_start_xmit = cp_start_xmit;
	dev->get_stats = cp_get_stats;
	dev->do_ioctl = cp_ioctl;
#if 0
	dev->tx_timeout = cp_tx_timeout;
	dev->watchdog_timeo = TX_TIMEOUT;
#endif
#ifdef CP_TX_CHECKSUM
	dev->features |= NETIF_F_SG | NETIF_F_IP_CSUM;
#endif

	dev->irq = pdev->irq;

	rc = register_netdev(dev);
	if (rc)
		goto err_out_iomap;

	printk (KERN_INFO "%s: %s at 0x%lx, "
		"%02x:%02x:%02x:%02x:%02x:%02x, "
		"IRQ %d\n",
		dev->name,
		"RTL-8139C+",
		dev->base_addr,
		dev->dev_addr[0], dev->dev_addr[1],
		dev->dev_addr[2], dev->dev_addr[3],
		dev->dev_addr[4], dev->dev_addr[5],
		dev->irq);

	pci_set_drvdata(pdev, dev);

	/*
	 * Looks like this is necessary to deal with on all architectures,
	 * even this %$#%$# N440BX Intel based thing doesn't get it right.
	 * Ie. having two NICs in the machine, one will have the cache
	 * line set at boot time, the other will not.
	 */
	pci_read_config_byte(pdev, PCI_CACHE_LINE_SIZE, &cache_size);
	cache_size <<= 2;
	if (cache_size != SMP_CACHE_BYTES) {
		printk(KERN_INFO "%s: PCI cache line size set incorrectly "
		       "(%i bytes) by BIOS/FW, ", dev->name, cache_size);
		if (cache_size > SMP_CACHE_BYTES)
			printk("expecting %i\n", SMP_CACHE_BYTES);
		else {
			printk("correcting to %i\n", SMP_CACHE_BYTES);
			pci_write_config_byte(pdev, PCI_CACHE_LINE_SIZE,
					      SMP_CACHE_BYTES >> 2);
		}
	}

	/* enable busmastering and memory-write-invalidate */
	pci_read_config_word(pdev, PCI_COMMAND, &pci_command);
	if (!(pci_command & PCI_COMMAND_INVALIDATE)) {
		pci_command |= PCI_COMMAND_INVALIDATE;
		pci_write_config_word(pdev, PCI_COMMAND, pci_command);
	}
	pci_set_master(pdev);

	return 0;

err_out_iomap:
	iounmap(regs);
err_out_res:
	pci_release_regions(pdev);
err_out_disable:
	pci_disable_device(pdev);
err_out_free:
	kfree(dev);
	return rc;
}

static void __devexit cp_remove_one (struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct cp_private *cp = dev->priv;

	if (!dev)
		BUG();
	unregister_netdev(dev);
	iounmap(cp->regs);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	kfree(dev);
}

static struct pci_driver cp_driver = {
	name:		DRV_NAME,
	id_table:	cp_pci_tbl,
	probe:		cp_init_one,
	remove:		__devexit_p(cp_remove_one),
};

static int __init cp_init (void)
{
#ifdef MODULE
	printk("%s", version);
#endif
	return pci_module_init (&cp_driver);
}

static void __exit cp_exit (void)
{
	pci_unregister_driver (&cp_driver);
}

module_init(cp_init);
module_exit(cp_exit);
