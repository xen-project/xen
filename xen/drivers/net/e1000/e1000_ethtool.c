/*******************************************************************************

  
  Copyright(c) 1999 - 2002 Intel Corporation. All rights reserved.
  
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

/* ethtool support for e1000 */

#include "e1000.h"

#include <asm/uaccess.h>

extern char e1000_driver_name[];
extern char e1000_driver_version[];

extern int e1000_up(struct e1000_adapter *adapter);
extern void e1000_down(struct e1000_adapter *adapter);
extern void e1000_reset(struct e1000_adapter *adapter);

static char e1000_gstrings_stats[][ETH_GSTRING_LEN] = {
	"rx_packets", "tx_packets", "rx_bytes", "tx_bytes", "rx_errors",
	"tx_errors", "rx_dropped", "tx_dropped", "multicast", "collisions",
	"rx_length_errors", "rx_over_errors", "rx_crc_errors",
	"rx_frame_errors", "rx_fifo_errors", "rx_missed_errors",
	"tx_aborted_errors", "tx_carrier_errors", "tx_fifo_errors",
	"tx_heartbeat_errors", "tx_window_errors",
};
#define E1000_STATS_LEN	sizeof(e1000_gstrings_stats) / ETH_GSTRING_LEN

static void
e1000_ethtool_gset(struct e1000_adapter *adapter, struct ethtool_cmd *ecmd)
{
	struct e1000_hw *hw = &adapter->hw;

	if(hw->media_type == e1000_media_type_copper) {

		ecmd->supported = (SUPPORTED_10baseT_Half |
		                   SUPPORTED_10baseT_Full |
		                   SUPPORTED_100baseT_Half |
		                   SUPPORTED_100baseT_Full |
		                   SUPPORTED_1000baseT_Full|
		                   SUPPORTED_Autoneg |
		                   SUPPORTED_TP);

		ecmd->advertising = ADVERTISED_TP;

		if(hw->autoneg == 1) {
			ecmd->advertising |= ADVERTISED_Autoneg;

			/* the e1000 autoneg seems to match ethtool nicely */

			ecmd->advertising |= hw->autoneg_advertised;
		}

		ecmd->port = PORT_TP;
		ecmd->phy_address = hw->phy_addr;

		if(hw->mac_type == e1000_82543)
			ecmd->transceiver = XCVR_EXTERNAL;
		else
			ecmd->transceiver = XCVR_INTERNAL;

	} else {
		ecmd->supported   = (SUPPORTED_1000baseT_Full |
				     SUPPORTED_FIBRE |
				     SUPPORTED_Autoneg);

		ecmd->advertising = (SUPPORTED_1000baseT_Full |
				     SUPPORTED_FIBRE |
				     SUPPORTED_Autoneg);

		ecmd->port = PORT_FIBRE;

		if(hw->mac_type >= e1000_82545)
			ecmd->transceiver = XCVR_INTERNAL;
		else
			ecmd->transceiver = XCVR_EXTERNAL;
	}

	if(netif_carrier_ok(adapter->netdev)) {

		e1000_get_speed_and_duplex(hw, &adapter->link_speed,
		                                   &adapter->link_duplex);
		ecmd->speed = adapter->link_speed;

		/* unfortunatly FULL_DUPLEX != DUPLEX_FULL
		 *          and HALF_DUPLEX != DUPLEX_HALF */

		if(adapter->link_duplex == FULL_DUPLEX)
			ecmd->duplex = DUPLEX_FULL;
		else
			ecmd->duplex = DUPLEX_HALF;
	} else {
		ecmd->speed = -1;
		ecmd->duplex = -1;
	}

	ecmd->autoneg = (hw->autoneg ? AUTONEG_ENABLE : AUTONEG_DISABLE);
}

static int
e1000_ethtool_sset(struct e1000_adapter *adapter, struct ethtool_cmd *ecmd)
{
	struct e1000_hw *hw = &adapter->hw;

	if(ecmd->autoneg == AUTONEG_ENABLE) {
		hw->autoneg = 1;
		hw->autoneg_advertised = 0x002F;
		ecmd->advertising = 0x002F;
	} else {
		hw->autoneg = 0;
		switch(ecmd->speed + ecmd->duplex) {
		case SPEED_10 + DUPLEX_HALF:
			hw->forced_speed_duplex = e1000_10_half;
			break;
		case SPEED_10 + DUPLEX_FULL:
			hw->forced_speed_duplex = e1000_10_full;
			break;
		case SPEED_100 + DUPLEX_HALF:
			hw->forced_speed_duplex = e1000_100_half;
			break;
		case SPEED_100 + DUPLEX_FULL:
			hw->forced_speed_duplex = e1000_100_full;
			break;
		case SPEED_1000 + DUPLEX_FULL:
			hw->autoneg = 1;
			hw->autoneg_advertised = ADVERTISE_1000_FULL;
			break;
		case SPEED_1000 + DUPLEX_HALF: /* not supported */
		default:
			return -EINVAL;
		}
	}

	/* reset the link */

	if(netif_running(adapter->netdev)) {
		e1000_down(adapter);
		e1000_up(adapter);
	} else
		e1000_reset(adapter);

	return 0;
}

static inline int
e1000_eeprom_size(struct e1000_hw *hw)
{
	if((hw->mac_type > e1000_82544) &&
	   (E1000_READ_REG(hw, EECD) & E1000_EECD_SIZE))
		return 512;
	else
		return 128;
}

static void
e1000_ethtool_gdrvinfo(struct e1000_adapter *adapter,
                       struct ethtool_drvinfo *drvinfo)
{
	strncpy(drvinfo->driver,  e1000_driver_name, 32);
	strncpy(drvinfo->version, e1000_driver_version, 32);
	strncpy(drvinfo->fw_version, "N/A", 32);
	strncpy(drvinfo->bus_info, adapter->pdev->slot_name, 32);
	drvinfo->n_stats = E1000_STATS_LEN;
#define E1000_REGS_LEN 32
	drvinfo->regdump_len  = E1000_REGS_LEN * sizeof(uint32_t);
	drvinfo->eedump_len  = e1000_eeprom_size(&adapter->hw);
}

static void
e1000_ethtool_gregs(struct e1000_adapter *adapter,
                    struct ethtool_regs *regs, uint32_t *regs_buff)
{
	struct e1000_hw *hw = &adapter->hw;

	regs->version = (1 << 24) | (hw->revision_id << 16) | hw->device_id;

	regs_buff[0]  = E1000_READ_REG(hw, CTRL);
	regs_buff[1]  = E1000_READ_REG(hw, STATUS);

	regs_buff[2]  = E1000_READ_REG(hw, RCTL);
	regs_buff[3]  = E1000_READ_REG(hw, RDLEN);
	regs_buff[4]  = E1000_READ_REG(hw, RDH);
	regs_buff[5]  = E1000_READ_REG(hw, RDT);
	regs_buff[6]  = E1000_READ_REG(hw, RDTR);

	regs_buff[7]  = E1000_READ_REG(hw, TCTL);
	regs_buff[8]  = E1000_READ_REG(hw, TDLEN);
	regs_buff[9]  = E1000_READ_REG(hw, TDH);
	regs_buff[10] = E1000_READ_REG(hw, TDT);
	regs_buff[11] = E1000_READ_REG(hw, TIDV);

	return;
}

static int
e1000_ethtool_geeprom(struct e1000_adapter *adapter,
                      struct ethtool_eeprom *eeprom, uint16_t *eeprom_buff)
{
	struct e1000_hw *hw = &adapter->hw;
	int max_len, first_word, last_word;
	int ret_val = 0;
	int i;

	if(eeprom->len == 0) {
		ret_val = -EINVAL;
		goto geeprom_error;
	}

	eeprom->magic = hw->vendor_id | (hw->device_id << 16);

	max_len = e1000_eeprom_size(hw);

	if(eeprom->offset > eeprom->offset + eeprom->len) {
		ret_val = -EINVAL;
		goto geeprom_error;
	}

	if((eeprom->offset + eeprom->len) > max_len)
		eeprom->len = (max_len - eeprom->offset);

	first_word = eeprom->offset >> 1;
	last_word = (eeprom->offset + eeprom->len - 1) >> 1;

	for(i = 0; i <= (last_word - first_word); i++)
		e1000_read_eeprom(hw, first_word + i, &eeprom_buff[i]);

geeprom_error:
	return ret_val;
}

static int
e1000_ethtool_seeprom(struct e1000_adapter *adapter,
                      struct ethtool_eeprom *eeprom, void *user_data)
{
	struct e1000_hw *hw = &adapter->hw;
	uint16_t *eeprom_buff;
	int max_len, first_word, last_word;
	void *ptr;
	int i;

	if(eeprom->len == 0)
		return -EOPNOTSUPP;

	if(eeprom->magic != (hw->vendor_id | (hw->device_id << 16)))
		return -EFAULT;

	max_len = e1000_eeprom_size(hw);

	if((eeprom->offset + eeprom->len) > max_len)
		eeprom->len = (max_len - eeprom->offset);

	first_word = eeprom->offset >> 1;
	last_word = (eeprom->offset + eeprom->len - 1) >> 1;
	eeprom_buff = kmalloc(max_len, GFP_KERNEL);
	if(eeprom_buff == NULL)
		return -ENOMEM;

	ptr = (void *)eeprom_buff;

	if(eeprom->offset & 1) {
		/* need read/modify/write of first changed EEPROM word */
		/* only the second byte of the word is being modified */
		e1000_read_eeprom(hw, first_word, &eeprom_buff[0]);
		ptr++;
	}
	if((eeprom->offset + eeprom->len) & 1) {
		/* need read/modify/write of last changed EEPROM word */
		/* only the first byte of the word is being modified */
		e1000_read_eeprom(hw, last_word,
		                  &eeprom_buff[last_word - first_word]);
	}
	if(copy_from_user(ptr, user_data, eeprom->len)) {
		kfree(eeprom_buff);
		return -EFAULT;
	}

	for(i = 0; i <= (last_word - first_word); i++)
		e1000_write_eeprom(hw, first_word + i, eeprom_buff[i]);

	/* Update the checksum over the first part of the EEPROM if needed */
	if(first_word <= EEPROM_CHECKSUM_REG)
		e1000_update_eeprom_checksum(hw);

	kfree(eeprom_buff);

	return 0;
}

static void
e1000_ethtool_gwol(struct e1000_adapter *adapter, struct ethtool_wolinfo *wol)
{
	struct e1000_hw *hw = &adapter->hw;

	switch(adapter->hw.device_id) {
	case E1000_DEV_ID_82542:
	case E1000_DEV_ID_82543GC_FIBER:
	case E1000_DEV_ID_82543GC_COPPER:
	case E1000_DEV_ID_82544EI_FIBER:
		wol->supported = 0;
		wol->wolopts   = 0;
		return;

	case E1000_DEV_ID_82546EB_FIBER:
		/* Wake events only supported on port A for dual fiber */
		if(E1000_READ_REG(hw, STATUS) & E1000_STATUS_FUNC_1) {
			wol->supported = 0;
			wol->wolopts   = 0;
			return;
		}
		/* Fall Through */

	default:
		wol->supported = WAKE_UCAST | WAKE_MCAST
			         | WAKE_BCAST | WAKE_MAGIC;

		wol->wolopts = 0;
		if(adapter->wol & E1000_WUFC_EX)
			wol->wolopts |= WAKE_UCAST;
		if(adapter->wol & E1000_WUFC_MC)
			wol->wolopts |= WAKE_MCAST;
		if(adapter->wol & E1000_WUFC_BC)
			wol->wolopts |= WAKE_BCAST;
		if(adapter->wol & E1000_WUFC_MAG)
			wol->wolopts |= WAKE_MAGIC;
		return;
	}
}

static int
e1000_ethtool_swol(struct e1000_adapter *adapter, struct ethtool_wolinfo *wol)
{
	struct e1000_hw *hw = &adapter->hw;

	switch(adapter->hw.device_id) {
	case E1000_DEV_ID_82542:
	case E1000_DEV_ID_82543GC_FIBER:
	case E1000_DEV_ID_82543GC_COPPER:
	case E1000_DEV_ID_82544EI_FIBER:
		return wol->wolopts ? -EOPNOTSUPP : 0;

	case E1000_DEV_ID_82546EB_FIBER:
		/* Wake events only supported on port A for dual fiber */
		if(E1000_READ_REG(hw, STATUS) & E1000_STATUS_FUNC_1)
			return wol->wolopts ? -EOPNOTSUPP : 0;
		/* Fall Through */

	default:
		if(wol->wolopts & (WAKE_ARP | WAKE_MAGICSECURE | WAKE_PHY))
			return -EOPNOTSUPP;

		adapter->wol = 0;

		if(wol->wolopts & WAKE_UCAST)
			adapter->wol |= E1000_WUFC_EX;
		if(wol->wolopts & WAKE_MCAST)
			adapter->wol |= E1000_WUFC_MC;
		if(wol->wolopts & WAKE_BCAST)
			adapter->wol |= E1000_WUFC_BC;
		if(wol->wolopts & WAKE_MAGIC)
			adapter->wol |= E1000_WUFC_MAG;
	}

	return 0;
}


/* toggle LED 4 times per second = 2 "blinks" per second */
#define E1000_ID_INTERVAL	(HZ/4)

/* bit defines for adapter->led_status */
#define E1000_LED_ON		0

static void
e1000_led_blink_callback(unsigned long data)
{
	struct e1000_adapter *adapter = (struct e1000_adapter *) data;

	if(test_and_change_bit(E1000_LED_ON, &adapter->led_status))
		e1000_led_off(&adapter->hw);
	else
		e1000_led_on(&adapter->hw);

	mod_timer(&adapter->blink_timer, jiffies + E1000_ID_INTERVAL);
}

static int
e1000_ethtool_led_blink(struct e1000_adapter *adapter, struct ethtool_value *id)
{
	if(!adapter->blink_timer.function) {
		init_timer(&adapter->blink_timer);
		adapter->blink_timer.function = e1000_led_blink_callback;
		adapter->blink_timer.data = (unsigned long) adapter;
	}

	e1000_setup_led(&adapter->hw);
	mod_timer(&adapter->blink_timer, jiffies);

	set_current_state(TASK_INTERRUPTIBLE);
	if(id->data)
		schedule_timeout(id->data * HZ);
	else
		schedule_timeout(MAX_SCHEDULE_TIMEOUT);

	del_timer_sync(&adapter->blink_timer);
	e1000_led_off(&adapter->hw);
	clear_bit(E1000_LED_ON, &adapter->led_status);
	e1000_cleanup_led(&adapter->hw);

	return 0;
}

int
e1000_ethtool_ioctl(struct net_device *netdev, struct ifreq *ifr)
{
	struct e1000_adapter *adapter = netdev->priv;
	void *addr = ifr->ifr_data;
	uint32_t cmd;

	if(get_user(cmd, (uint32_t *) addr))
		return -EFAULT;

	switch(cmd) {
	case ETHTOOL_GSET: {
		struct ethtool_cmd ecmd = {ETHTOOL_GSET};
		e1000_ethtool_gset(adapter, &ecmd);
		if(copy_to_user(addr, &ecmd, sizeof(ecmd)))
			return -EFAULT;
		return 0;
	}
	case ETHTOOL_SSET: {
		struct ethtool_cmd ecmd;
		if(!capable(CAP_NET_ADMIN))
			return -EPERM;
		if(copy_from_user(&ecmd, addr, sizeof(ecmd)))
			return -EFAULT;
		return e1000_ethtool_sset(adapter, &ecmd);
	}
	case ETHTOOL_GDRVINFO: {
		struct ethtool_drvinfo drvinfo = {ETHTOOL_GDRVINFO};
		e1000_ethtool_gdrvinfo(adapter, &drvinfo);
		if(copy_to_user(addr, &drvinfo, sizeof(drvinfo)))
			return -EFAULT;
		return 0;
	}
	case ETHTOOL_GSTRINGS: {
		struct ethtool_gstrings gstrings = { ETHTOOL_GSTRINGS };
		char *strings = NULL;

		if(copy_from_user(&gstrings, addr, sizeof(gstrings)))
			return -EFAULT;
		switch(gstrings.string_set) {
		case ETH_SS_STATS:
			gstrings.len = E1000_STATS_LEN;
			strings = *e1000_gstrings_stats;
			break;
		default:
			return -EOPNOTSUPP;
		}
		if(copy_to_user(addr, &gstrings, sizeof(gstrings)))
			return -EFAULT;
		addr += offsetof(struct ethtool_gstrings, data);
		if(copy_to_user(addr, strings,
		   gstrings.len * ETH_GSTRING_LEN))
			return -EFAULT;
		return 0;
	}
	case ETHTOOL_GREGS: {
		struct ethtool_regs regs = {ETHTOOL_GREGS};
		uint32_t regs_buff[E1000_REGS_LEN];

		if(copy_from_user(&regs, addr, sizeof(regs)))
			return -EFAULT;
		e1000_ethtool_gregs(adapter, &regs, regs_buff);
		if(copy_to_user(addr, &regs, sizeof(regs)))
			return -EFAULT;

		addr += offsetof(struct ethtool_regs, data);
		if(copy_to_user(addr, regs_buff, regs.len))
			return -EFAULT;

		return 0;
	}
	case ETHTOOL_NWAY_RST: {
		if(!capable(CAP_NET_ADMIN))
			return -EPERM;
		if(netif_running(netdev)) {
			e1000_down(adapter);
			e1000_up(adapter);
		}
		return 0;
	}
	case ETHTOOL_PHYS_ID: {
		struct ethtool_value id;
		if(copy_from_user(&id, addr, sizeof(id)))
			return -EFAULT;
		return e1000_ethtool_led_blink(adapter, &id);
	}
	case ETHTOOL_GLINK: {
		struct ethtool_value link = {ETHTOOL_GLINK};
		link.data = netif_carrier_ok(netdev);
		if(copy_to_user(addr, &link, sizeof(link)))
			return -EFAULT;
		return 0;
	}
	case ETHTOOL_GWOL: {
		struct ethtool_wolinfo wol = {ETHTOOL_GWOL};
		e1000_ethtool_gwol(adapter, &wol);
		if(copy_to_user(addr, &wol, sizeof(wol)) != 0)
			return -EFAULT;
		return 0;
	}
	case ETHTOOL_SWOL: {
		struct ethtool_wolinfo wol;
		if(!capable(CAP_NET_ADMIN))
			return -EPERM;
		if(copy_from_user(&wol, addr, sizeof(wol)) != 0)
			return -EFAULT;
		return e1000_ethtool_swol(adapter, &wol);
	}
	case ETHTOOL_GEEPROM: {
		struct ethtool_eeprom eeprom = {ETHTOOL_GEEPROM};
		uint16_t *eeprom_buff;
		void *ptr;
		int max_len, err = 0;

		max_len = e1000_eeprom_size(&adapter->hw);

		eeprom_buff = kmalloc(max_len, GFP_KERNEL);

		if(eeprom_buff == NULL)
			return -ENOMEM;

		if(copy_from_user(&eeprom, addr, sizeof(eeprom))) {
			err = -EFAULT;
			goto err_geeprom_ioctl;
		}

		if((err = e1000_ethtool_geeprom(adapter, &eeprom,
						eeprom_buff)))
			goto err_geeprom_ioctl;

		if(copy_to_user(addr, &eeprom, sizeof(eeprom))) {
			err = -EFAULT;
			goto err_geeprom_ioctl;
		}

		addr += offsetof(struct ethtool_eeprom, data);
		ptr = ((void *)eeprom_buff) + (eeprom.offset & 1);

		if(copy_to_user(addr, ptr, eeprom.len))
			err = -EFAULT;

err_geeprom_ioctl:
		kfree(eeprom_buff);
		return err;
	}
	case ETHTOOL_SEEPROM: {
		struct ethtool_eeprom eeprom;

		if(!capable(CAP_NET_ADMIN))
			return -EPERM;

		if(copy_from_user(&eeprom, addr, sizeof(eeprom)))
			return -EFAULT;

		addr += offsetof(struct ethtool_eeprom, data);
		return e1000_ethtool_seeprom(adapter, &eeprom, addr);
	}
	case ETHTOOL_GSTATS: {
		struct {
			struct ethtool_stats cmd;
			uint64_t data[E1000_STATS_LEN];
		} stats = { {ETHTOOL_GSTATS, E1000_STATS_LEN} };
		int i;

		for(i = 0; i < E1000_STATS_LEN; i++)
			stats.data[i] =
				((unsigned long *)&adapter->net_stats)[i];
		if(copy_to_user(addr, &stats, sizeof(stats)))
			return -EFAULT;
		return 0;
	}
	default:
		return -EOPNOTSUPP;
	}
}


