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

#include "e100.h"
#include "e100_config.h"

extern u16 e100_eeprom_read(struct e100_private *, u16);
extern int e100_wait_exec_cmplx(struct e100_private *, u32,u8, u8);
extern void e100_phy_reset(struct e100_private *bdp);
extern void e100_phy_autoneg(struct e100_private *bdp);
extern void e100_phy_set_loopback(struct e100_private *bdp);
extern void e100_force_speed_duplex(struct e100_private *bdp);

static u8 e100_diag_selftest(struct net_device *);
static u8 e100_diag_eeprom(struct net_device *);
static u8 e100_diag_loopback(struct net_device *);

static u8 e100_diag_one_loopback (struct net_device *, u8);
static u8 e100_diag_rcv_loopback_pkt(struct e100_private *);
static void e100_diag_config_loopback(struct e100_private *, u8, u8, u8 *,u8 *);
static u8 e100_diag_loopback_alloc(struct e100_private *);
static void e100_diag_loopback_cu_ru_exec(struct e100_private *);
static u8 e100_diag_check_pkt(u8 *);
static void e100_diag_loopback_free(struct e100_private *);

#define LB_PACKET_SIZE 1500

/**
 * e100_run_diag - main test execution handler - checks mask of requests and calls the diag routines  
 * @dev: atapter's net device data struct
 * @test_info: array with test request mask also used to store test results
 *
 * RETURNS: updated flags field of struct ethtool_test
 */
u32
e100_run_diag(struct net_device *dev, u64 *test_info, u32 flags)
{
	struct e100_private* bdp = dev->priv;
	u8 test_result = true;

	e100_isolate_driver(bdp);

	if (flags & ETH_TEST_FL_OFFLINE) {
		u8 fail_mask;
		
		fail_mask = e100_diag_selftest(dev);
		if (fail_mask) {
			test_result = false;
			if (fail_mask & REGISTER_TEST_FAIL)
				test_info [E100_REG_TEST_FAIL] = true;
			if (fail_mask & ROM_TEST_FAIL)
				test_info [E100_ROM_TEST_FAIL] = true;
			if (fail_mask & SELF_TEST_FAIL)
				test_info [E100_MAC_TEST_FAIL] = true;
			if (fail_mask & TEST_TIMEOUT)
				test_info [E100_CHIP_TIMEOUT] = true;
		}

		fail_mask = e100_diag_loopback(dev);
		if (fail_mask) {
			test_result = false;
			if (fail_mask & PHY_LOOPBACK)
				test_info [E100_LPBK_PHY_FAIL] = true;
			if (fail_mask & MAC_LOOPBACK)
				test_info [E100_LPBK_MAC_FAIL] = true;
		}
	}

	if (!e100_diag_eeprom(dev)) {
		test_result = false;
		test_info [E100_EEPROM_TEST_FAIL] = true;
	}

	set_current_state(TASK_UNINTERRUPTIBLE);
	schedule_timeout(HZ * 2);
    	e100_deisolate_driver(bdp, false);

	return flags | (test_result ? 0 : ETH_TEST_FL_FAILED);
}

/**
 * e100_diag_selftest - run hardware selftest 
 * @dev: atapter's net device data struct
 */
static u8
e100_diag_selftest(struct net_device *dev)
{
	struct e100_private *bdp = dev->priv;
	u32 st_timeout, st_result;
	u8 retval = 0;

	if (!e100_selftest(bdp, &st_timeout, &st_result)) {
		if (!st_timeout) {
			if (st_result & CB_SELFTEST_REGISTER_BIT)
				retval |= REGISTER_TEST_FAIL;
			if (st_result & CB_SELFTEST_DIAG_BIT)
				retval |= SELF_TEST_FAIL;
			if (st_result & CB_SELFTEST_ROM_BIT)
				retval |= ROM_TEST_FAIL;
		} else {
            		retval = TEST_TIMEOUT;
		}
	}

	e100_configure_device(bdp);

	return retval;
}

/**
 * e100_diag_eeprom - validate eeprom checksum correctness
 * @dev: atapter's net device data struct
 *
 */
static u8
e100_diag_eeprom (struct net_device *dev)
{
	struct e100_private *bdp = dev->priv;
	u16 i, eeprom_sum, eeprom_actual_csm;

	for (i = 0, eeprom_sum = 0; i < (bdp->eeprom_size - 1); i++) {
		eeprom_sum += e100_eeprom_read(bdp, i);
	}

	eeprom_actual_csm = e100_eeprom_read(bdp, bdp->eeprom_size - 1);

	if (eeprom_actual_csm == (u16)(EEPROM_SUM - eeprom_sum)) {
		return true;
	}

	return false;
}

/**
 * e100_diag_loopback - performs loopback test  
 * @dev: atapter's net device data struct
 */
static u8
e100_diag_loopback (struct net_device *dev)
{
	u8 rc = 0;

	printk(KERN_DEBUG "%s: PHY loopback test starts\n", dev->name);
	e100_sw_reset(dev->priv, PORT_SELECTIVE_RESET);
	if (!e100_diag_one_loopback(dev, PHY_LOOPBACK)) {
		rc |= PHY_LOOPBACK;
	}
	printk(KERN_DEBUG "%s: PHY loopback test ends\n", dev->name);

	printk(KERN_DEBUG "%s: MAC loopback test starts\n", dev->name);
	e100_sw_reset(dev->priv, PORT_SELECTIVE_RESET);
	if (!e100_diag_one_loopback(dev, MAC_LOOPBACK)) {
		rc |= MAC_LOOPBACK;
	}
	printk(KERN_DEBUG "%s: MAC loopback test ends\n", dev->name);

	return rc;
}

/**
 * e100_diag_loopback - performs loopback test  
 * @dev: atapter's net device data struct
 * @mode: lopback test type
 */
static u8
e100_diag_one_loopback (struct net_device *dev, u8 mode)
{
        struct e100_private *bdp = dev->priv;
        u8 res = false;
   	u8 saved_dynamic_tbd = false;
   	u8 saved_extended_tcb = false;

	if (!e100_diag_loopback_alloc(bdp))
		return false;

	/* change the config block to standard tcb and the correct loopback */
        e100_diag_config_loopback(bdp, true, mode,
				  &saved_extended_tcb, &saved_dynamic_tbd);

	e100_diag_loopback_cu_ru_exec(bdp);

        if (e100_diag_rcv_loopback_pkt(bdp)) {
		res = true;
	}

        e100_diag_loopback_free(bdp);

        /* change the config block to previous tcb mode and the no loopback */
        e100_diag_config_loopback(bdp, false, mode,
				  &saved_extended_tcb, &saved_dynamic_tbd);
	return res;
}

/**
 * e100_diag_config_loopback - setup/clear loopback before/after lpbk test
 * @bdp: atapter's private data struct
 * @set_loopback: true if the function is called to set lb
 * @loopback_mode: the loopback mode(MAC or PHY)
 * @tcb_extended: true if need to set extended tcb mode after clean loopback
 * @dynamic_tbd: true if needed to set dynamic tbd mode after clean loopback
 *
 */
void
e100_diag_config_loopback(struct e100_private* bdp,
			  u8 set_loopback,
			  u8 loopback_mode,
			  u8* tcb_extended,
			  u8* dynamic_tbd)
{
	/* if set_loopback == true - we want to clear tcb_extended/dynamic_tbd.
	 * the previous values are saved in the params tcb_extended/dynamic_tbd
	 * if set_loopback == false - we want to restore previous value.
	 */
	if (set_loopback || (*tcb_extended))
		  *tcb_extended = e100_config_tcb_ext_enable(bdp,*tcb_extended);

	if (set_loopback || (*dynamic_tbd))
		 *dynamic_tbd = e100_config_dynamic_tbd(bdp,*dynamic_tbd);

	if (set_loopback) {
		/* ICH PHY loopback is broken */
		if (bdp->flags & IS_ICH && loopback_mode == PHY_LOOPBACK)
			loopback_mode = MAC_LOOPBACK;
		/* Configure loopback on MAC */
		e100_config_loopback_mode(bdp,loopback_mode);
	} else {
		e100_config_loopback_mode(bdp,NO_LOOPBACK);
	}

	e100_config(bdp);

	if (loopback_mode == PHY_LOOPBACK) {
		if (set_loopback)
                        /* Set PHY loopback mode */
                        e100_phy_set_loopback(bdp);
                else {	/* Back to normal speed and duplex */
                	if (bdp->params.e100_speed_duplex == E100_AUTONEG)
				/* Reset PHY and do autoneg */
                        	e100_phy_autoneg(bdp);
			else    
				/* Reset PHY and force speed and duplex */
				e100_force_speed_duplex(bdp);
		}
                /* Wait for PHY state change */
		set_current_state(TASK_UNINTERRUPTIBLE);
                schedule_timeout(HZ);
	} else { /* For MAC loopback wait 500 msec to take effect */
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(HZ / 2);
	}
}
  
/**
 * e100_diag_loopback_alloc - alloc & initate tcb and rfd for the loopback
 * @bdp: atapter's private data struct
 *
 */
static u8
e100_diag_loopback_alloc(struct e100_private *bdp)
{
	dma_addr_t dma_handle;
	tcb_t *tcb;
	rfd_t *rfd;
	tbd_t *tbd;

	/* tcb, tbd and transmit buffer are allocated */
	tcb = pci_alloc_consistent(bdp->pdev,
				   (sizeof (tcb_t) + sizeof (tbd_t) +
				    LB_PACKET_SIZE),
				   &dma_handle);
        if (tcb == NULL)
		return false;

	memset(tcb, 0x00, sizeof (tcb_t) + sizeof (tbd_t) + LB_PACKET_SIZE);
	tcb->tcb_phys = dma_handle;
	tcb->tcb_hdr.cb_status = 0;
	tcb->tcb_hdr.cb_cmd =
		cpu_to_le16(CB_EL_BIT | CB_TRANSMIT | CB_TX_SF_BIT);
	/* Next command is null */
	tcb->tcb_hdr.cb_lnk_ptr = cpu_to_le32(0xffffffff);
	tcb->tcb_cnt = 0;
	tcb->tcb_thrshld = bdp->tx_thld;
	tcb->tcb_tbd_num = 1;
	/* Set up tcb tbd pointer */
	tcb->tcb_tbd_ptr = cpu_to_le32(tcb->tcb_phys + sizeof (tcb_t));
	tbd = (tbd_t *) ((u8 *) tcb + sizeof (tcb_t));
	/* Set up tbd transmit buffer */
	tbd->tbd_buf_addr =
		cpu_to_le32(le32_to_cpu(tcb->tcb_tbd_ptr) + sizeof (tbd_t));
	tbd->tbd_buf_cnt = __constant_cpu_to_le16(1024);
	/* The value of first 512 bytes is FF */
	memset((void *) ((u8 *) tbd + sizeof (tbd_t)), 0xFF, 512);
	/* The value of second 512 bytes is BA */
	memset((void *) ((u8 *) tbd + sizeof (tbd_t) + 512), 0xBA, 512);
	wmb();
	rfd = pci_alloc_consistent(bdp->pdev, sizeof (rfd_t), &dma_handle);

	if (rfd == NULL) {
		pci_free_consistent(bdp->pdev,
				    sizeof (tcb_t) + sizeof (tbd_t) +
				    LB_PACKET_SIZE, tcb, tcb->tcb_phys);
		return false;
	}

	memset(rfd, 0x00, sizeof (rfd_t));

	/* init all fields in rfd */
	rfd->rfd_header.cb_cmd = cpu_to_le16(RFD_EL_BIT);
	rfd->rfd_sz = cpu_to_le16(ETH_FRAME_LEN + CHKSUM_SIZE);
	/* dma_handle is physical address of rfd */
	bdp->loopback.dma_handle = dma_handle;
	bdp->loopback.tcb = tcb;
	bdp->loopback.rfd = rfd;
	wmb();
	return true;
}

/**
 * e100_diag_loopback_cu_ru_exec - activates cu and ru to send & receive the pkt
 * @bdp: atapter's private data struct
 *
 */
static void
e100_diag_loopback_cu_ru_exec(struct e100_private *bdp)
{
	/*load CU & RU base */ 
	if (!e100_wait_exec_cmplx(bdp, 0, SCB_CUC_LOAD_BASE, 0))
		printk(KERN_ERR "e100: SCB_CUC_LOAD_BASE failed\n");
	if(!e100_wait_exec_cmplx(bdp, 0, SCB_RUC_LOAD_BASE, 0))
		printk(KERN_ERR "e100: SCB_RUC_LOAD_BASE failed!\n");
	if(!e100_wait_exec_cmplx(bdp, bdp->loopback.dma_handle, SCB_RUC_START, 0))
		printk(KERN_ERR "e100: SCB_RUC_START failed!\n");

	bdp->next_cu_cmd = START_WAIT;
	e100_start_cu(bdp, bdp->loopback.tcb);
	bdp->last_tcb = NULL;
	rmb();
}
/**
 * e100_diag_check_pkt - checks if a given packet is a loopback packet
 * @bdp: atapter's private data struct
 *
 * Returns true if OK false otherwise.
 */
static u8
e100_diag_check_pkt(u8 *datap)
{
	int i;
	for (i = 0; i<512; i++) {
		if( !((*datap)==0xFF && (*(datap + 512) == 0xBA)) ) {
			printk (KERN_ERR "e100: check loopback packet failed at: %x\n", i);
			return false;
			}
	}
	printk (KERN_DEBUG "e100: Check received loopback packet OK\n");
	return true;
}

/**
 * e100_diag_rcv_loopback_pkt - waits for receive and checks lpbk packet
 * @bdp: atapter's private data struct
 *
 * Returns true if OK false otherwise.
 */
static u8
e100_diag_rcv_loopback_pkt(struct e100_private* bdp) 
{    
	rfd_t *rfdp;
	u16 rfd_status;
	unsigned long expires = jiffies + HZ * 2;

        rfdp =bdp->loopback.rfd;

        rfd_status = le16_to_cpu(rfdp->rfd_header.cb_status);

        while (!(rfd_status & RFD_STATUS_COMPLETE)) { 
		if (time_before(jiffies, expires)) {
			yield();
			rmb();
			rfd_status = le16_to_cpu(rfdp->rfd_header.cb_status);
		} else {
			break;
		}
        }

        if (rfd_status & RFD_STATUS_COMPLETE) {
		printk(KERN_DEBUG "e100: Loopback packet received\n");
                return e100_diag_check_pkt(((u8 *)rfdp+bdp->rfd_size));
	}
	else {
		printk(KERN_ERR "e100: Loopback packet not received\n");
		return false;
	}
}

/**
 * e100_diag_loopback_free - free data allocated for loopback pkt send/receive
 * @bdp: atapter's private data struct
 *
 */
static void
e100_diag_loopback_free (struct e100_private *bdp)
{
        pci_free_consistent(bdp->pdev,
			    sizeof(tcb_t) + sizeof(tbd_t) + LB_PACKET_SIZE,
			    bdp->loopback.tcb, bdp->loopback.tcb->tcb_phys);

        pci_free_consistent(bdp->pdev, sizeof(rfd_t), bdp->loopback.rfd,
			    bdp->loopback.dma_handle);
}

