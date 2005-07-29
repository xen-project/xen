/**
 * (C) Copyright IBM Corp. 2005
 *
 * $Id: XmlToBinInterface.java,v 1.3 2005/06/20 21:07:37 rvaldez Exp $
 *
 * Author: Ray Valdez
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * XmlToBinInterface Class.  
 * <p>
 *
 * Defines constants used by XmToBin.
 *
 * <p>
 *
 *	policy binary structures
 *
 *	typedef struct {
 *        u32 magic;
 *
 *        u32 policyversion;
 *        u32 len;
 *
 *        u16 primary_policy_code;
 *        u16 primary_buffer_offset;
 *        u16 secondary_policy_code;
 *        u16 secondary_buffer_offset;
 *	u16 resource_offset;
 *
 *	} acm_policy_buffer_t;
 *
 *	typedef struct {
 *        u16 policy_code;
 *        u16 ste_max_types;
 *        u16 ste_max_ssidrefs;
 *        u16 ste_ssid_offset;
 *	} acm_ste_policy_buffer_t;
 *
 *  	typedef struct {
 *        uint16 policy_code;
 *        uint16 chwall_max_types;
 *        uint16 chwall_max_ssidrefs;
 *        uint16 chwall_max_conflictsets;
 *        uint16 chwall_ssid_offset;
 *        uint16 chwall_conflict_sets_offset;
 *        uint16 chwall_running_types_offset;
 *        uint16 chwall_conflict_aggregate_offset;
 *	} acm_chwall_policy_buffer_t;
 *
 *	typedef struct {
 *	u16 partition_max;
 *	u16 partition_offset;
 *	u16 vlan_max;
 *	u16 vlan_offset;
 *	u16 slot_max;
 *	u16 slot_offset;
 *	} acm_resource_buffer_t;
 *
 *	typedef struct {
 *	u16 id;
 *	u16 ssid_ste;
 *	u16 ssid_chwall;
 *	} acm_partition_entry_t;
 *
 *	typedef struct {
 *	u16 vlan;
 *	u16 ssid_ste;
 *	} acm_vlan_entry_t;
 *
 *	typedef struct {
 *	u16 bus;
 *	u16 slot;
 *	u16 ssid_ste;
 *	} acm_slot_entry_t;
 *
 *       
 *
 */
public interface XmlToBinInterface
{
  /* policy code  (uint16) */
  final int policyCodeSize = 2;

  /* max_types    (uint16) */
  final int maxTypesSize = 2;

  /* max_ssidrefs (uint16) */
  final int maxSsidrefSize = 2;

  /* ssid_offset  (uint32) */
  final int ssidOffsetSize = 2;

  final short markSymbol = 0x0001;

  final int u32Size = 4;
  final int u16Size = 2;

  /* num of bytes for acm_ste_policy_buffer_t */
  final short steHeaderSize = (4 * u16Size); 
  /* byte for acm_chinese_wall_policy_buffer_t */
  final short chwHeaderSize = (8 * u16Size); 

  final short primaryPolicyCodeSize = u16Size;
  final short primaryBufferOffsetSize = u16Size ;

  final int secondaryPolicyCodeSz = u16Size;
  final int secondaryBufferOffsetSz = u16Size;
  final short resourceOffsetSz = u16Size;

  final short partitionBufferSz = (2 * u16Size);
  final short partitionEntrySz = (3 * u16Size);

  final short slotBufferSz = (2 * u16Size);
  final short slotEntrySz = (3 * u16Size);

  final short vlanBufferSz = (2 * u16Size);
  final short vlanEntrySz = (2 * u16Size);

  final short binaryBufferHeaderSz = (3 * u32Size + 4* u16Size);

  /* copied directlty from policy_ops.h */
  final int POLICY_INTERFACE_VERSION = 0xAAAA0003;

  /* copied directly from acm.h */
  final int ACM_MAGIC  =  0x0001debc;
  final short ACM_NULL_POLICY = 0;
  final short ACM_CHINESE_WALL_POLICY = 1;
  final short ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY = 2;
  final short ACM_CHINESE_WALL_AND_SIMPLE_TYPE_ENFORCEMENT_POLICY = 3;
  final short ACM_EMPTY_POLICY = 4;
}
