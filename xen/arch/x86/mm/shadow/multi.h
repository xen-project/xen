/******************************************************************************
 * arch/x86/mm/shadow/multi.h
 *
 * Shadow declarations which will be multiply compiled.
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

extern int
SHADOW_INTERNAL_NAME(sh_map_and_validate_gl1e, GUEST_LEVELS)(
    struct vcpu *v, mfn_t gl1mfn, void *new_gl1p, u32 size);
extern int
SHADOW_INTERNAL_NAME(sh_map_and_validate_gl2e, GUEST_LEVELS)(
    struct vcpu *v, mfn_t gl2mfn, void *new_gl2p, u32 size);
extern int
SHADOW_INTERNAL_NAME(sh_map_and_validate_gl2he, GUEST_LEVELS)(
    struct vcpu *v, mfn_t gl2mfn, void *new_gl2p, u32 size);
extern int
SHADOW_INTERNAL_NAME(sh_map_and_validate_gl3e, GUEST_LEVELS)(
    struct vcpu *v, mfn_t gl3mfn, void *new_gl3p, u32 size);
extern int
SHADOW_INTERNAL_NAME(sh_map_and_validate_gl4e, GUEST_LEVELS)(
    struct vcpu *v, mfn_t gl4mfn, void *new_gl4p, u32 size);

extern void
SHADOW_INTERNAL_NAME(sh_destroy_l1_shadow, GUEST_LEVELS)(
    struct domain *d, mfn_t smfn);
extern void
SHADOW_INTERNAL_NAME(sh_destroy_l2_shadow, GUEST_LEVELS)(
    struct domain *d, mfn_t smfn);
extern void
SHADOW_INTERNAL_NAME(sh_destroy_l3_shadow, GUEST_LEVELS)(
    struct domain *d, mfn_t smfn);
extern void
SHADOW_INTERNAL_NAME(sh_destroy_l4_shadow, GUEST_LEVELS)(
    struct domain *d, mfn_t smfn);

extern void
SHADOW_INTERNAL_NAME(sh_unhook_32b_mappings, GUEST_LEVELS)
    (struct domain *d, mfn_t sl2mfn, int user_only);
extern void
SHADOW_INTERNAL_NAME(sh_unhook_pae_mappings, GUEST_LEVELS)
    (struct domain *d, mfn_t sl3mfn, int user_only);
extern void
SHADOW_INTERNAL_NAME(sh_unhook_64b_mappings, GUEST_LEVELS)
    (struct domain *d, mfn_t sl4mfn, int user_only);

extern int
SHADOW_INTERNAL_NAME(sh_rm_write_access_from_l1, GUEST_LEVELS)
    (struct domain *d, mfn_t sl1mfn, mfn_t readonly_mfn);
extern int
SHADOW_INTERNAL_NAME(sh_rm_mappings_from_l1, GUEST_LEVELS)
    (struct domain *d, mfn_t sl1mfn, mfn_t target_mfn);

extern void
SHADOW_INTERNAL_NAME(sh_clear_shadow_entry, GUEST_LEVELS)
    (struct domain *d, void *ep, mfn_t smfn);

extern int
SHADOW_INTERNAL_NAME(sh_remove_l1_shadow, GUEST_LEVELS)
    (struct domain *d, mfn_t sl2mfn, mfn_t sl1mfn);
extern int
SHADOW_INTERNAL_NAME(sh_remove_l2_shadow, GUEST_LEVELS)
    (struct domain *d, mfn_t sl3mfn, mfn_t sl2mfn);
extern int
SHADOW_INTERNAL_NAME(sh_remove_l3_shadow, GUEST_LEVELS)
    (struct domain *d, mfn_t sl4mfn, mfn_t sl3mfn);

#if SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES
int
SHADOW_INTERNAL_NAME(sh_audit_l1_table, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl1mfn, mfn_t x);
int
SHADOW_INTERNAL_NAME(sh_audit_fl1_table, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl1mfn, mfn_t x);
int
SHADOW_INTERNAL_NAME(sh_audit_l2_table, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl2mfn, mfn_t x);
int
SHADOW_INTERNAL_NAME(sh_audit_l3_table, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl3mfn, mfn_t x);
int
SHADOW_INTERNAL_NAME(sh_audit_l4_table, GUEST_LEVELS)
    (struct vcpu *v, mfn_t sl4mfn, mfn_t x);
#endif

extern const struct paging_mode
SHADOW_INTERNAL_NAME(sh_paging_mode, GUEST_LEVELS);

#if SHADOW_OPTIMIZATIONS & SHOPT_OUT_OF_SYNC
extern void
SHADOW_INTERNAL_NAME(sh_resync_l1, GUEST_LEVELS)
     (struct vcpu *v, mfn_t gmfn, mfn_t snpmfn);

extern int
SHADOW_INTERNAL_NAME(sh_safe_not_to_sync, GUEST_LEVELS)
     (struct vcpu*v, mfn_t gmfn);

extern int
SHADOW_INTERNAL_NAME(sh_rm_write_access_from_sl1p, GUEST_LEVELS)
     (struct domain *d, mfn_t gmfn, mfn_t smfn, unsigned long off);
#endif
