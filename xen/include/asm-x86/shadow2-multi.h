/******************************************************************************
 * arch/x86/shadow2-multi.h
 *
 * Shadow2 declarations which will be multiply compiled.
 * Parts of this code are Copyright (c) 2006 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

extern int 
SHADOW2_INTERNAL_NAME(sh2_map_and_validate_gl1e, SHADOW_LEVELS, GUEST_LEVELS)(
    struct vcpu *v, mfn_t gl1mfn, void *new_gl1p, u32 size);
extern int 
SHADOW2_INTERNAL_NAME(sh2_map_and_validate_gl2e, SHADOW_LEVELS, GUEST_LEVELS)(
    struct vcpu *v, mfn_t gl2mfn, void *new_gl2p, u32 size);
extern int 
SHADOW2_INTERNAL_NAME(sh2_map_and_validate_gl2he, SHADOW_LEVELS, GUEST_LEVELS)(
    struct vcpu *v, mfn_t gl2mfn, void *new_gl2p, u32 size);
extern int 
SHADOW2_INTERNAL_NAME(sh2_map_and_validate_gl3e, SHADOW_LEVELS, GUEST_LEVELS)(
    struct vcpu *v, mfn_t gl3mfn, void *new_gl3p, u32 size);
extern int 
SHADOW2_INTERNAL_NAME(sh2_map_and_validate_gl4e, SHADOW_LEVELS, GUEST_LEVELS)(
    struct vcpu *v, mfn_t gl4mfn, void *new_gl4p, u32 size);

extern void 
SHADOW2_INTERNAL_NAME(sh2_destroy_l1_shadow, SHADOW_LEVELS, GUEST_LEVELS)(
    struct vcpu *v, mfn_t smfn);
extern void 
SHADOW2_INTERNAL_NAME(sh2_destroy_l2_shadow, SHADOW_LEVELS, GUEST_LEVELS)(
    struct vcpu *v, mfn_t smfn);
extern void 
SHADOW2_INTERNAL_NAME(sh2_destroy_l3_shadow, SHADOW_LEVELS, GUEST_LEVELS)(
    struct vcpu *v, mfn_t smfn);
extern void 
SHADOW2_INTERNAL_NAME(sh2_destroy_l4_shadow, SHADOW_LEVELS, GUEST_LEVELS)(
    struct vcpu *v, mfn_t smfn);

extern void
SHADOW2_INTERNAL_NAME(sh2_unpin_all_l3_subshadows, 3, 3)
    (struct vcpu *v, mfn_t smfn);

extern void 
SHADOW2_INTERNAL_NAME(sh2_unhook_32b_mappings, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl2mfn);
extern void 
SHADOW2_INTERNAL_NAME(sh2_unhook_pae_mappings, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl3mfn);
extern void 
SHADOW2_INTERNAL_NAME(sh2_unhook_64b_mappings, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl4mfn);

extern int
SHADOW2_INTERNAL_NAME(sh2_remove_write_access, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl1mfn, mfn_t readonly_mfn);
extern int
SHADOW2_INTERNAL_NAME(sh2_remove_all_mappings, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl1mfn, mfn_t target_mfn);

extern void
SHADOW2_INTERNAL_NAME(sh2_clear_shadow_entry, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, void *ep, mfn_t smfn);

extern int
SHADOW2_INTERNAL_NAME(sh2_remove_l1_shadow, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl2mfn, mfn_t sl1mfn);
extern int
SHADOW2_INTERNAL_NAME(sh2_remove_l2_shadow, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl3mfn, mfn_t sl2mfn);
extern int
SHADOW2_INTERNAL_NAME(sh2_remove_l3_shadow, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl4mfn, mfn_t sl3mfn);

#if SHADOW2_AUDIT & SHADOW2_AUDIT_ENTRIES
int 
SHADOW2_INTERNAL_NAME(sh2_audit_l1_table, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl1mfn, mfn_t x);
int 
SHADOW2_INTERNAL_NAME(sh2_audit_fl1_table, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl1mfn, mfn_t x);
int 
SHADOW2_INTERNAL_NAME(sh2_audit_l2_table, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl2mfn, mfn_t x);
int 
SHADOW2_INTERNAL_NAME(sh2_audit_l3_table, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl3mfn, mfn_t x);
int 
SHADOW2_INTERNAL_NAME(sh2_audit_l4_table, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl4mfn, mfn_t x);
#endif

#if SHADOW_LEVELS == GUEST_LEVELS
extern mfn_t
SHADOW2_INTERNAL_NAME(sh2_make_monitor_table, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v);
extern void
SHADOW2_INTERNAL_NAME(sh2_destroy_monitor_table, SHADOW_LEVELS, GUEST_LEVELS)
    (struct vcpu *v, mfn_t mmfn);
#endif

extern struct shadow2_entry_points 
SHADOW2_INTERNAL_NAME(shadow2_entry, SHADOW_LEVELS, GUEST_LEVELS);
