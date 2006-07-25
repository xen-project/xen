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

/*
 * Details of the 970-specific HID registers.
 */

#ifndef _ASM_HID_H_
#define _ASM_HID_H_

#include <xen/types.h>

union hid0 {
    struct hid0_bits {
        ulong   _unused_0_8:    9;
        ulong   nap:            1;
        ulong   _unused_10:     1;
        ulong   dpm:            1;  /* Dynamic Power Management */
        ulong   _unused_12_14:  3;
        ulong   nhr:            1;  /* Not Hard Reset */
        ulong   inorder:        1;
        ulong   _reserved17:    1;
        ulong   tb_ctrl:        1;
        ulong   ext_tb_enb:     1;  /* timebase is linked to external clock */
        ulong   _unused_20_22:  3;
        ulong   hdice:          1;  /* HDEC enable */
        ulong   eb_therm:       1;  /* Enable ext thermal ints */
        ulong   _unused_25_30:  6;
        ulong   en_attn:        1;  /* Enable attn instruction */
        ulong   _unused_32_63:  32;
    } bits;
    ulong word;
};

union hid1 {
    struct hid1_bits {
        ulong bht_pm:           3; /* branch history table prediction mode */
        ulong en_ls:            1; /* enable link stack */
        ulong en_cc:            1; /* enable count cache */
        ulong en_ic:            1; /* enable inst cache */
        ulong _reserved_6:      1;
        ulong pf_mode:          2; /* prefetch mode */
        ulong en_icbi:          1; /* enable forced icbi match mode */
        ulong en_if_cach:       1; /* i-fetch cacheability control */
        ulong en_ic_rec:        1; /* i-cache parity error recovery */
        ulong en_id_rec:        1; /* i-dir parity error recovery */
        ulong en_er_rec:        1; /* i-ERAT parity error recovery */
        ulong ic_pe:            1;
        ulong icd0_pe:          1;
        ulong _reserved_16:     1;
        ulong ier_pe:           1;
        ulong en_sp_itw:        1;
        ulong _reserved_19_63:  45;
    } bits;
    ulong word;
};

union hid4 {
    struct hid4_bits {
        ulong   lpes0:          1;  /* LPAR Environment Selector bit 0 */
        ulong   rmlr12:         2;  /* RMLR 1:2 */
        ulong   lpid25:         4;  /* LPAR ID bits 2:5 */
        ulong   rmor:           16; /* real mode offset region */
        ulong   rm_ci:          1;  /* real mode cache-inhibit */
        ulong   force_ai:       1;  /* Force alignment interrupt */
        ulong   _unused:        32;
        ulong   lpes1:          1;  /* LPAR Environment Selector bit 1 */
        ulong   rmlr0:          1;  /* RMLR 0 */
        ulong   _reserved:      1;
        ulong   dis_splarx:     1;  /* Disable spec. lwarx/ldarx */
        ulong   lg_pg_dis:      1;  /* Disable large page support */
        ulong   lpid01:         2;  /* LPAR ID bits 0:1 */
    } bits;
    ulong word;
};

union hid5 {
    struct hid5_bits {
        ulong  _reserved_0_31:  32;
        ulong   hrmor:          16;
        ulong   _reserver_48_49:2;
        ulong   _unused_50_55:  6;
        ulong   DCBZ_size:      1;
        ulong   DCBZ32_ill:     1;
        ulong  _unused_58_63:   6;
    } bits;
    ulong word;
};

#endif
