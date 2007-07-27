/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#ifndef _PAPR_H
#define _PAPR_H

/*
 * Class is one of the following:
 *
 *   Crit: Continuous forward progress must be made, encountering any
 *   busy resource must cause the function to be backed out and return
 *   with a "hardware busy" return code.
 *
 *   Norm: Similar to Crit, however, wait loops for slow hardware
 *   access are allowed.
 *
 */
/*      NAME                    Token      Class Mandatory      Set     */
#define H_UNUSED                0x0000  /* Crit Yes             pft     */
#define H_REMOVE                0x0004  /* Crit Yes             pft     */
#define H_ENTER                 0x0008  /* Crit Yes             pft     */
#define H_READ                  0x000c  /* Crit Yes             pft     */
#define H_CLEAR_MOD             0x0010  /* Crit Yes             pft     */
#define H_CLEAR_REF             0x0014  /* Crit Yes             pft     */
#define H_PROTECT               0x0018  /* Crit Yes             pft     */
#define H_GET_TCE               0x001c  /* Crit Yes             tce     */
#define H_PUT_TCE               0x0020  /* Crit Yes             tce     */
#define H_SET_SPRG0             0x0024  /* Crit Yes             sprg0   */
#define H_SET_DABR              0x0028  /* Crit Yes-dabr exists dabr    */
#define H_PAGE_INIT             0x002c  /* Crit Yes             copy    */
#define H_SET_ASR               0x0030  /* Crit Yes-on Istar    asr     */
#define H_ASR_ON                0x0034  /* Crit Yes-on Istar    asr     */
#define H_ASR_OFF               0x0038  /* Crit Yes-on Istar    asr     */
#define H_LOGICAL_CI_LOAD       0x003c  /* Norm Yes             debug   */
#define H_LOGICAL_CI_STORE      0x0040  /* Norm Yes             debug   */
#define H_LOGICAL_CACHE_LOAD    0x0044  /* Crit Yes             debug   */
#define H_LOGICAL_CACHE_STORE   0x0048  /* Crit Yes             debug   */
#define H_LOGICAL_ICBI          0x004c  /* Norm Yes             debug   */
#define H_LOGICAL_DCBF          0x0050  /* Norm Yes             debug   */
#define H_GET_TERM_CHAR         0x0054  /* Crit Yes             term    */
#define H_PUT_TERM_CHAR         0x0058  /* Crit Yes             term    */
#define H_REAL_TO_LOGICAL       0x005c  /* Norm Yes             perf    */
#define H_HYPERVISOR_DATA       0x0060  /* Norm See below       dump    */
                                        /* is mandatory if enabled by HSC
                                         * and is disabled by default */
#define H_EOI                   0x0064  /* Crit Yes             int     */
#define H_CPPR                  0x0068  /* Crit Yes             int     */
#define H_IPI                   0x006c  /* Crit Yes             int     */
#define H_IPOLL                 0x0070  /* Crit Yes             int     */
#define H_XIRR                  0x0074  /* Crit Yes             int     */
#define H_MIGRATE_PCI_TCE       0x0078  /* Norm Yes-if LRDR     migrate */
#define H_PERFMON               0x007c  /* Norm Yes-if PMU      perfmon */
#define H_CEDE                  0x00e0  /* Crit Yes             splpar  */
#define H_CONFER                0x00e4
#define H_PROD                  0x00e8
#define H_GET_PPP               0x00ec
#define H_SET_PPP               0x00f0
#define H_PURR                  0x00f4
#define H_PIC                   0x00f8
#define H_REG_CRQ               0x00fc
#define H_FREE_CRQ              0x0100
#define H_VIO_SIGNAL            0x0104
#define H_SEND_CRQ              0x0108
#define H_PUTRTCE               0x010c
#define H_COPY_RDMA             0x0110
#define H_REGISTER_LOGICAL_LAN  0x0114
#define H_FREE_LOGICAL_LAN      0x0118
#define H_ADD_LOGICAL_LAN_BUFFER 0x011c
#define H_SEND_LOGICAL_LAN      0x0120
#define H_BULK_REMOVE           0x0124
#define H_WRITE_RDMA            0x0128
#define H_READ_RDMA             0x012c
#define H_MULTICAST_CTRL        0x0130
#define H_SET_XDABR             0x0134
#define H_STUFF_TCE             0x0138
#define H_PUT_TCE_INDIRECT      0x013c
#define H_PUT_RTCE_INDERECT     0x0140
#define H_MASS_MAP_TCE          0x0144
#define H_ALRDMA                0x0148
#define H_CHANGE_LOGICAL_LAN_MAC 0x014c
#define H_VTERM_PARTNER_INFO    0x0150
#define H_REGISTER_VTERM        0x0154
#define H_FREE_VTERM            0x0158
#define H_HCA_RESV_BEGIN        0x015c
#define H_HCA_RESV_END          0x01c0
#define H_GRANT_LOGICAL         0x01c4
#define H_RESCIND_LOGICAL       0x01c8
#define H_ACCEPT_LOGICAL        0x01cc
#define H_RETURN_LOGICAL        0x01d0
#define H_FREE_LOGICAL_LAN_BUFFER 0x01d4

#define RPA_HCALL_END           0x01d4  /* set to last entry */

/*
 * Hidden
 */
#define H_PCI_CONFIG_READ       0x610c  /* PHYP # 0x500c */
#define H_PCI_CONFIG_WRITE      0x6110  /* PHYP # 0x5010 */
#define H_THREAD_CONTROL        0x6144  /* PHYP # 0x5044 H_CPU_CONTROL */
#define H_GET_XIVE              0x614c  /* PHYP # 0x504c */
#define H_SET_XIVE              0x6150  /* PHYP # 0x5050 */
#define H_INTERRUPT             0x6154  /* PHYP # 0x5054 */

#define HYPE_HCALL_END          H_INTERRUPT /* XXX */

/*
 * Hypervisor Call Return Codes
 */
#define H_PARTIAL_STORE 16
#define H_PAGE_REGISTERED 15
#define H_IN_PROGRESS   14
#define H_Sensor_CH     13      /* Sensor value >= Critical high        */
#define H_Sensor_WH     12      /* Sensor value >= Warning high         */
#define H_Sensor_Norm   11      /* Sensor value normal                  */
#define H_Sensor_WL     10      /* Sensor value <= Warning low          */
#define H_Sensor_CL      9      /* Sensor value <= Critical low         */
#define H_Partial        5
#define H_Constrained    4
#define H_Closed         2      /* virtual terminal session is closed   */
#define H_Busy           1      /* Hardware Busy -- Retry Later         */
#define H_Success        0
#define H_Hardware      -1      /* Error                                */
#define H_Function      -2      /* Not Supported                        */
#define H_Privilege     -3      /* Caller not in privileged mode        */
#define H_Parameter     -4      /* Outside Valid Range for Partition
                                 * or conflicting                       */
#define H_Bad_Mode      -5      /* Illegal MSR value                    */
#define H_PTEG_FULL     -6      /* The requested pteg was full          */
#define H_NOT_FOUND     -7      /* The requested pte was not found      */
#define H_RESERVED_DABR -8      /* The requested address is reserved
                                 * by the Hypervisor on this
                                 * processor                            */
#define H_UNAVAIL       -9      /* Requested resource unavailable */
#define H_INVAL         -10     /* Requested parameter is invalid */
#define H_Permission    -11
#define H_Dropped       -12
#define H_S_Parm        -13
#define H_D_Parm        -14
#define H_R_Parm        -15
#define H_Resource      -16
#define H_ADAPTER_PARM  -17

#define H_Rescinded     -18     /* FIXME: check RPA value */

/*
 * compatibility With Linux Labels, perhpas we should ifdef this linux
 * and/or kernel.
 */
#define H_Not_Found             H_NOT_FOUND
#define H_ANDCOND               H_andcond
#define H_LARGE_PAGE            H_Large_Page
#define H_ICACHE_INVALIDATE     H_I_Cache_Inv
#define H_ICACHE_SYNCHRONIZE    H_I_Cache_Sync
#define H_ZERO_PAGE             H_Zero_Page
#define H_COPY_PAGE             H_Copy_Page
#define H_EXACT                 H_Exact
#define H_PTEG_Full             H_PTEG_FULL
#define H_PP1                   H_pp1
#define H_PP2                   H_pp2

#ifndef __ASSEMBLY__

#include <xen/types.h>
/*
 * The Hcall() Flags Field Definition 
 */
#define H_NUMA_CEC      (~(1UL << (63 - 15 + 1) - 1)) /* bits 0-15    */

#define H_Blank_1       (1UL<<(63-17))

#define H_Exact         (1UL<<(63-24))
#define H_R_XLATE       (1UL<<(63-25))
#define H_READ_4        (1UL<<(63-26))

#define H_AVPN          (1UL<<(63-32))
#define H_andcond       (1UL<<(63-33))

#define H_I_Cache_Inv   (1UL<<(63-40))
#define H_I_Cache_Sync  (1UL<<(63-41))
#define H_Blank_2       (1UL<<(63-42))

#define H_Zero_Page     (1UL<<(63-48))
#define H_Copy_Page     (1UL<<(63-49))
#define H_Blank_3       (1UL<<(63-50))

#define H_N             (1UL<<(63-61))
#define H_pp1           (1UL<<(63-62))
#define H_pp2           (1UL<<(63-63))

#define H_VM_MAP_ICACHE_INVALIDATE      (1UL<<(63-40))
#define H_VM_MAP_ICACHE_SYNCRONIZE      (1UL<<(63-41))
#define H_VM_MAP_INVALIDATE_TRANSLATION (1UL<<(63-42))
#define H_VM_MAP_INSERT_TRANSLATION     (1UL<<(63-43))
#define H_VM_MAP_LARGE_PAGE             (1UL<<(63-44))
#define H_VM_MAP_ZERO_PAGE              (1UL<<(63-48))

enum {
    INVALID_LOGICAL_ADDRESS = (~((ulong)0)),
};

#endif /* ! __ASSEMBLY__ */
#endif /* ! _HYPE_CALLS_H */
