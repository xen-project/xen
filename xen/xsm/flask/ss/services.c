/*
 * Implementation of the security services.
 *
 * Authors : Stephen Smalley, <sds@epoch.ncsc.mil>
 *           James Morris <jmorris@redhat.com>
 *
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *
 *    Support for enhanced MLS infrastructure.
 *
 * Updated: Frank Mayer <mayerf@tresys.com> and Karl MacMillan <kmacmillan@tresys.com>
 *
 *     Added conditional policy language extensions
 *
 * Updated: Hewlett-Packard <paul.moore@hp.com>
 *
 *      Added support for the policy capability bitmap
 *
 * Updated: Chad Sellers <csellers@tresys.com>
 *
 *  Added validation of kernel classes and permissions
 *
 * Updated: KaiGai Kohei <kaigai@ak.jp.nec.com>
 *
 *  Added support for bounds domain and audit messaged on masked permissions
 *
 * Copyright (C) 2008, 2009 NEC Corporation
 * Copyright (C) 2006, 2007 Hewlett-Packard Development Company, L.P.
 * Copyright (C) 2004-2006 Trusted Computer Solutions, Inc.
 * Copyright (C) 2003 - 2004, 2006 Tresys Technology, LLC
 * Copyright (C) 2003 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *    This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, version 2.
 */

/* Ported to Xen 3.0, George Coker, <gscoker@alpha.ncsc.mil> */

#include <xen/lib.h>
#include <xen/xmalloc.h>
#include <xen/string.h>
#include <xen/spinlock.h>
#include <xen/rwlock.h>
#include <xen/errno.h>
#include "flask.h"
#include "avc.h"
#include "avc_ss.h"
#include "security.h"
#include "context.h"
#include "policydb.h"
#include "sidtab.h"
#include "services.h"
#include "conditional.h"
#include "mls.h"

unsigned int policydb_loaded_version;

static DEFINE_RWLOCK(policy_rwlock);
#define POLICY_RDLOCK read_lock(&policy_rwlock)
#define POLICY_WRLOCK write_lock(&policy_rwlock)
#define POLICY_RDUNLOCK read_unlock(&policy_rwlock)
#define POLICY_WRUNLOCK write_unlock(&policy_rwlock)

static DEFINE_SPINLOCK(load_sem);
#define LOAD_LOCK spin_lock(&load_sem)
#define LOAD_UNLOCK spin_unlock(&load_sem)

static struct sidtab sidtab;
struct policydb policydb;
int ss_initialized = 0;

/*
 * The largest sequence number that has been used when
 * providing an access decision to the access vector cache.
 * The sequence number only changes when a policy change
 * occurs.
 */
static u32 latest_granting = 0;

/* Forward declaration. */
static int context_struct_to_string(struct context *context, char **scontext,
                                                            u32 *scontext_len);

static int context_struct_compute_av(struct context *scontext,
				     struct context *tcontext,
				     u16 tclass,
				     u32 requested,
				     struct av_decision *avd);

/*
 * Return the boolean value of a constraint expression
 * when it is applied to the specified source and target
 * security contexts.
 *
 * xcontext is a special beast...  It is used by the validatetrans rules
 * only.  For these rules, scontext is the context before the transition,
 * tcontext is the context after the transition, and xcontext is the context
 * of the process performing the transition.  All other callers of
 * constraint_expr_eval should pass in NULL for xcontext.
 */
static int constraint_expr_eval(struct context *scontext,
                            struct context *tcontext, struct context *xcontext, 
                                                struct constraint_expr *cexpr)
{
    u32 val1, val2;
    struct context *c;
    struct role_datum *r1, *r2;
    struct mls_level *l1, *l2;
    struct constraint_expr *e;
    int s[CEXPR_MAXDEPTH];
    int sp = -1;

    for ( e = cexpr; e; e = e->next )
    {
        switch ( e->expr_type )
        {
            case CEXPR_NOT:
                BUG_ON(sp < 0);
                s[sp] = !s[sp];
            break;
            case CEXPR_AND:
                BUG_ON(sp < 1);
                sp--;
                s[sp] &= s[sp+1];
            break;
            case CEXPR_OR:
                BUG_ON(sp < 1);
                sp--;
                s[sp] |= s[sp+1];
            break;
            case CEXPR_ATTR:
                if ( sp == (CEXPR_MAXDEPTH-1) )
                    return 0;
            switch ( e->attr )
            {
                case CEXPR_USER:
                    val1 = scontext->user;
                    val2 = tcontext->user;
                    break;
                case CEXPR_TYPE:
                    val1 = scontext->type;
                    val2 = tcontext->type;
                    break;
                case CEXPR_ROLE:
                    val1 = scontext->role;
                    val2 = tcontext->role;
                    r1 = policydb.role_val_to_struct[val1 - 1];
                    r2 = policydb.role_val_to_struct[val2 - 1];
                switch ( e->op )
                {
                    case CEXPR_DOM:
                        s[++sp] = ebitmap_get_bit(&r1->dominates, val2 - 1);
                    continue;
                    case CEXPR_DOMBY:
                        s[++sp] = ebitmap_get_bit(&r2->dominates, val1 - 1);
                    continue;
                    case CEXPR_INCOMP:
                        s[++sp] = ( !ebitmap_get_bit(&r1->dominates,
                                         val2 - 1) &&
                                !ebitmap_get_bit(&r2->dominates,
                                         val1 - 1) );
                    continue;
                    default:
                    break;
                }
                break;
                case CEXPR_L1L2:
                    l1 = &(scontext->range.level[0]);
                    l2 = &(tcontext->range.level[0]);
                    goto mls_ops;
                case CEXPR_L1H2:
                    l1 = &(scontext->range.level[0]);
                    l2 = &(tcontext->range.level[1]);
                    goto mls_ops;
                case CEXPR_H1L2:
                    l1 = &(scontext->range.level[1]);
                    l2 = &(tcontext->range.level[0]);
                    goto mls_ops;
                case CEXPR_H1H2:
                    l1 = &(scontext->range.level[1]);
                    l2 = &(tcontext->range.level[1]);
                    goto mls_ops;
                case CEXPR_L1H1:
                    l1 = &(scontext->range.level[0]);
                    l2 = &(scontext->range.level[1]);
                    goto mls_ops;
                case CEXPR_L2H2:
                    l1 = &(tcontext->range.level[0]);
                    l2 = &(tcontext->range.level[1]);
                    goto mls_ops;
mls_ops:
            switch ( e->op )
            {
                case CEXPR_EQ:
                    s[++sp] = mls_level_eq(l1, l2);
                continue;
                case CEXPR_NEQ:
                    s[++sp] = !mls_level_eq(l1, l2);
                continue;
                case CEXPR_DOM:
                    s[++sp] = mls_level_dom(l1, l2);
                continue;
                case CEXPR_DOMBY:
                    s[++sp] = mls_level_dom(l2, l1);
                continue;
                case CEXPR_INCOMP:
                    s[++sp] = mls_level_incomp(l2, l1);
                continue;
                default:
                    BUG();
                    return 0;
            }
            break;
            default:
                BUG();
                return 0;
            }

            switch ( e->op )
            {
                case CEXPR_EQ:
                    s[++sp] = (val1 == val2);
                break;
                case CEXPR_NEQ:
                    s[++sp] = (val1 != val2);
                break;
                default:
                    BUG();
                    return 0;
            }
            break;
            case CEXPR_NAMES:
                if ( sp == (CEXPR_MAXDEPTH-1) )
                    return 0;
                c = scontext;
                if ( e->attr & CEXPR_TARGET )
                    c = tcontext;
                else if ( e->attr & CEXPR_XTARGET )
                {
                    c = xcontext;
                    if ( !c )
                    {
                        BUG();
                        return 0;
                    }
                }
                if ( e->attr & CEXPR_USER )
                    val1 = c->user;
                else if ( e->attr & CEXPR_ROLE )
                    val1 = c->role;
                else if ( e->attr & CEXPR_TYPE )
                    val1 = c->type;
                else
                {
                    BUG();
                    return 0;
                }

            switch ( e->op )
            {
                case CEXPR_EQ:
                    s[++sp] = ebitmap_get_bit(&e->names, val1 - 1);
                break;
                case CEXPR_NEQ:
                    s[++sp] = !ebitmap_get_bit(&e->names, val1 - 1);
                break;
                default:
                    BUG();
                    return 0;
            }
            break;
            default:
                BUG();
                return 0;
        }
    }

    BUG_ON(sp != 0);
    return s[0];
}

/*
 * security_dump_masked_av - dumps masked permissions during
 * security_compute_av due to RBAC, MLS/Constraint and Type bounds.
 */
static int dump_masked_av_helper(void *k, void *d, void *args)
{
    struct perm_datum *pdatum = d;
    char **permission_names = args;

    BUG_ON(pdatum->value < 1 || pdatum->value > 32);

    permission_names[pdatum->value - 1] = (char *)k;

    return 0;
}

static void security_dump_masked_av(struct context *scontext,
				    struct context *tcontext,
				    u16 tclass,
				    u32 permissions,
				    const char *reason)
{
    struct common_datum *common_dat;
    struct class_datum *tclass_dat;
    char *tclass_name;
    char *scontext_name = NULL;
    char *tcontext_name = NULL;
    char *permission_names[32];
    int index;
    u32 length;
    unsigned char need_comma = 0;

    if ( !permissions )
        return;

    tclass_name = policydb.p_class_val_to_name[tclass - 1];
    tclass_dat = policydb.class_val_to_struct[tclass - 1];
    common_dat = tclass_dat->comdatum;

    /* init permission_names */
    if ( common_dat &&
         hashtab_map(common_dat->permissions.table,
                     dump_masked_av_helper, permission_names) < 0 )
        goto out;

    if ( hashtab_map(tclass_dat->permissions.table,
                    dump_masked_av_helper, permission_names) < 0 )
        goto out;

	/* get scontext/tcontext in text form */
    if ( context_struct_to_string(scontext,
                                 &scontext_name, &length) < 0 )
        goto out;

    if ( context_struct_to_string(tcontext,
                                 &tcontext_name, &length) < 0 )
        goto out;

    printk("Flask: op=security_compute_av reason=%s "
           "scontext=%s tcontext=%s tclass=%s perms=",
           reason, scontext_name, tcontext_name, tclass_name);

    for ( index = 0; index < 32; index++ )
    {
        u32 mask = (1 << index);

        if ( (mask & permissions) == 0 )
            continue;

        printk("%s%s",
               need_comma ? "," : "",
               permission_names[index]
               ? permission_names[index] : "????");
        need_comma = 1;
    }
    printk("\n");
out:
    /* release scontext/tcontext */
    xfree(tcontext_name);
    xfree(scontext_name);

    return;
}

/*
 * security_boundary_permission - drops violated permissions
 * on boundary constraint.
 */
static void type_attribute_bounds_av(struct context *scontext,
                                     struct context *tcontext,
                                     u16 tclass,
                                     u32 requested,
                                     struct av_decision *avd)
{
    struct context lo_scontext;
    struct context lo_tcontext;
    struct av_decision lo_avd;
    struct type_datum *source
        = policydb.type_val_to_struct[scontext->type - 1];
    struct type_datum *target
        = policydb.type_val_to_struct[tcontext->type - 1];
    u32 masked = 0;

    if ( source->bounds )
    {
        memset(&lo_avd, 0, sizeof(lo_avd));

        memcpy(&lo_scontext, scontext, sizeof(lo_scontext));
        lo_scontext.type = source->bounds;

        context_struct_compute_av(&lo_scontext,
                                  tcontext,
                                  tclass,
                                  requested,
                                  &lo_avd);
        if ( (lo_avd.allowed & avd->allowed) == avd->allowed )
            return;		/* no masked permission */
        masked = ~lo_avd.allowed & avd->allowed;
    }

    if ( target->bounds )
    {
        memset(&lo_avd, 0, sizeof(lo_avd));

        memcpy(&lo_tcontext, tcontext, sizeof(lo_tcontext));
        lo_tcontext.type = target->bounds;

        context_struct_compute_av(scontext,
                                  &lo_tcontext,
                                  tclass,
                                  requested,
                                  &lo_avd);
        if ( (lo_avd.allowed & avd->allowed) == avd->allowed )
            return;		/* no masked permission */
        masked = ~lo_avd.allowed & avd->allowed;
    }

    if ( source->bounds && target->bounds )
    {
        memset(&lo_avd, 0, sizeof(lo_avd));
        /*
         * lo_scontext and lo_tcontext are already
         * set up.
         */

        context_struct_compute_av(&lo_scontext,
                                  &lo_tcontext,
                                  tclass,
                                  requested,
                                  &lo_avd);
        if ( (lo_avd.allowed & avd->allowed) == avd->allowed )
            return;		/* no masked permission */
        masked = ~lo_avd.allowed & avd->allowed;
    }

    if ( masked )
    {
        /* mask violated permissions */
        avd->allowed &= ~masked;

        /* audit masked permissions */
        security_dump_masked_av(scontext, tcontext,
                                tclass, masked, "bounds");
    }
}

/*
 * Compute access vectors based on a context structure pair for
 * the permissions in a particular class.
 */
static int context_struct_compute_av(struct context *scontext,
				     struct context *tcontext,
				     u16 tclass,
				     u32 requested,
				     struct av_decision *avd)
{
    struct constraint_node *constraint;
    struct role_allow *ra;
    struct avtab_key avkey;
    struct avtab_node *node;
    struct class_datum *tclass_datum;
    struct ebitmap *sattr, *tattr;
    struct ebitmap_node *snode, *tnode;
    unsigned int i, j;

    /*
     * Initialize the access vectors to the default values.
     */
    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;
    avd->seqno = latest_granting;
    avd->flags = 0;

    /*
     * We do not presently support policydb.handle_unknown == allow in Xen.
     */
    if ( !tclass || tclass > policydb.p_classes.nprim )
        return -EINVAL;

    tclass_datum = policydb.class_val_to_struct[tclass - 1];

    /*
     * If a specific type enforcement rule was defined for
     * this permission check, then use it.
     */
    avkey.target_class = tclass;
    avkey.specified = AVTAB_AV;
    sattr = &policydb.type_attr_map[scontext->type - 1];
    tattr = &policydb.type_attr_map[tcontext->type - 1];
    ebitmap_for_each_positive_bit(sattr, snode, i)
    {
        ebitmap_for_each_positive_bit(tattr, tnode, j)
        {
            avkey.source_type = i + 1;
            avkey.target_type = j + 1;
            for ( node = avtab_search_node(&policydb.te_avtab, &avkey);
                 node != NULL;
                 node = avtab_search_node_next(node, avkey.specified) )
            {
                if ( node->key.specified == AVTAB_ALLOWED )
                    avd->allowed |= node->datum.data;
                else if ( node->key.specified == AVTAB_AUDITALLOW )
                    avd->auditallow |= node->datum.data;
                else if ( node->key.specified == AVTAB_AUDITDENY )
                    avd->auditdeny &= node->datum.data;
            }

            /* Check conditional av table for additional permissions */
            cond_compute_av(&policydb.te_cond_avtab, &avkey, avd);

        }
    }

    /*
     * Remove any permissions prohibited by a constraint (this includes
     * the MLS policy).
     */
    constraint = tclass_datum->constraints;
    while ( constraint )
    {
        if ( (constraint->permissions & (avd->allowed) ) &&
            !constraint_expr_eval(scontext, tcontext, NULL, constraint->expr))
        {
	    avd->allowed &= ~(constraint->permissions);
        }
        constraint = constraint->next;
    }

    /*
     * If checking process transition permission and the
     * role is changing, then check the (current_role, new_role)
     * pair.
     */
    if ( tclass == SECCLASS_DOMAIN &&
         (avd->allowed & DOMAIN__TRANSITION) &&
         scontext->role != tcontext->role )
    {
        for ( ra = policydb.role_allow; ra; ra = ra->next )
        {
            if ( scontext->role == ra->role && tcontext->role == ra->new_role )
                break;
        }
        if (!ra)
            avd->allowed &= ~DOMAIN__TRANSITION;
    }

    /*
     * If the given source and target types have boundary
     * constraint, lazy checks have to mask any violated
     * permission and notice it to userspace via audit.
     */
    type_attribute_bounds_av(scontext, tcontext,
			     tclass, requested, avd);
    return 0;
}

static int security_validtrans_handle_fail(struct context *ocontext,
                struct context *ncontext, struct context *tcontext, u16 tclass)
{
    char *o = NULL, *n = NULL, *t = NULL;
    u32 olen, nlen, tlen;

    if ( context_struct_to_string(ocontext, &o, &olen) < 0 )
        goto out;
    if ( context_struct_to_string(ncontext, &n, &nlen) < 0 )
        goto out;
    if ( context_struct_to_string(tcontext, &t, &tlen) < 0 )
        goto out;
    printk("security_validate_transition:  denied for"
              " oldcontext=%s newcontext=%s taskcontext=%s tclass=%s",
              o, n, t, policydb.p_class_val_to_name[tclass-1]);
out:
    xfree(o);
    xfree(n);
    xfree(t);

    if ( !flask_enforcing )
        return 0;
    return -EPERM;
}

int security_validate_transition(u32 oldsid, u32 newsid, u32 tasksid,
                                 u16 tclass)
{
    struct context *ocontext;
    struct context *ncontext;
    struct context *tcontext;
    struct class_datum *tclass_datum;
    struct constraint_node *constraint;
    int rc = 0;

    if ( !ss_initialized )
        return 0;

    POLICY_RDLOCK;

    if ( !tclass || tclass > policydb.p_classes.nprim )
    {
        printk(KERN_ERR "security_validate_transition: "
                                            "unrecognized class %d\n", tclass);
        rc = -EINVAL;
        goto out;
    }
    tclass_datum = policydb.class_val_to_struct[tclass - 1];

    ocontext = sidtab_search(&sidtab, oldsid);
    if ( !ocontext )
    {
        printk(KERN_ERR "security_validate_transition: "
               " unrecognized SID %d\n", oldsid);
        rc = -EINVAL;
        goto out;
    }

    ncontext = sidtab_search(&sidtab, newsid);
    if ( !ncontext )
    {
        printk(KERN_ERR "security_validate_transition: "
               " unrecognized SID %d\n", newsid);
        rc = -EINVAL;
        goto out;
    }

    tcontext = sidtab_search(&sidtab, tasksid);
    if ( !tcontext )
    {
        printk(KERN_ERR "security_validate_transition: "
               " unrecognized SID %d\n", tasksid);
        rc = -EINVAL;
        goto out;
    }

    constraint = tclass_datum->validatetrans;
    while ( constraint )
    {
        if ( !constraint_expr_eval(ocontext, ncontext, tcontext,
                                                            constraint->expr) )
        {
            rc = security_validtrans_handle_fail(ocontext, ncontext,
                                                 tcontext, tclass);
            goto out;
        }
        constraint = constraint->next;
    }

out:
    POLICY_RDUNLOCK;
    return rc;
}

/**
 * security_compute_av - Compute access vector decisions.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions
 * @avd: access vector decisions
 *
 * Compute a set of access vector decisions based on the
 * SID pair (@ssid, @tsid) for the permissions in @tclass.
 * Return -%EINVAL if any of the parameters are invalid or %0
 * if the access vector decisions were computed successfully.
 */
int security_compute_av(u32 ssid, u32 tsid, u16 tclass, u32 requested,
                        struct av_decision *avd)
{
    struct context *scontext = NULL, *tcontext = NULL;
    int rc = 0;

    if ( !ss_initialized )
    {
        avd->allowed = 0xffffffff;
        avd->auditallow = 0;
        avd->auditdeny = 0xffffffff;
        avd->seqno = latest_granting;
        return 0;
    }

    POLICY_RDLOCK;

    scontext = sidtab_search(&sidtab, ssid);
    if ( !scontext )
    {
        printk("security_compute_av:  unrecognized SID %d\n", ssid);
        rc = -EINVAL;
        goto out;
    }
    tcontext = sidtab_search(&sidtab, tsid);
    if ( !tcontext )
    {
        printk("security_compute_av:  unrecognized SID %d\n", tsid);
        rc = -EINVAL;
        goto out;
    }

    rc = context_struct_compute_av(scontext, tcontext, tclass, requested, avd);

    /* permissive domain? */
    if ( ebitmap_get_bit(&policydb.permissive_map, scontext->type) )
        avd->flags |= AVD_FLAGS_PERMISSIVE;
out:
    POLICY_RDUNLOCK;
    return rc;
}

/*
 * Write the security context string representation of
 * the context structure `context' into a dynamically
 * allocated string of the correct size.  Set `*scontext'
 * to point to this string and set `*scontext_len' to
 * the length of the string.
 */
static int context_struct_to_string(struct context *context, char **scontext, u32 *scontext_len)
{
    char *scontextp;

    *scontext = NULL;
    *scontext_len = 0;

    /* Compute the size of the context. */
    *scontext_len += strlen(policydb.p_user_val_to_name[context->user - 1]) + 1;
    *scontext_len += strlen(policydb.p_role_val_to_name[context->role - 1]) + 1;
    *scontext_len += strlen(policydb.p_type_val_to_name[context->type - 1]) + 1;
    *scontext_len += mls_compute_context_len(context);

    /* Allocate space for the context; caller must free this space. */
    scontextp = xmalloc_array(char, *scontext_len);
    if ( !scontextp )
        return -ENOMEM;

    *scontext = scontextp;

    /*
     * Copy the user name, role name and type name into the context.
     */
    snprintf(scontextp, *scontext_len, "%s:%s:%s",
        policydb.p_user_val_to_name[context->user - 1],
        policydb.p_role_val_to_name[context->role - 1],
        policydb.p_type_val_to_name[context->type - 1]);
    scontextp += strlen(policydb.p_user_val_to_name[context->user - 1]) +
                 1 + strlen(policydb.p_role_val_to_name[context->role - 1]) +
                 1 + strlen(policydb.p_type_val_to_name[context->type - 1]);

    mls_sid_to_context(context, &scontextp);

    *scontextp = 0;

    return 0;
}

#include "initial_sid_to_string.h"

/**
 * security_sid_to_context - Obtain a context for a given SID.
 * @sid: security identifier, SID
 * @scontext: security context
 * @scontext_len: length in bytes
 *
 * Write the string representation of the context associated with @sid
 * into a dynamically allocated string of the correct size.  Set @scontext
 * to point to this string and set @scontext_len to the length of the string.
 */
int security_sid_to_context(u32 sid, char **scontext, u32 *scontext_len)
{
    struct context *context;
    int rc = 0;

    if ( !ss_initialized )
    {
        if ( sid <= SECINITSID_NUM )
        {
            char *scontextp;

            *scontext_len = strlen(initial_sid_to_string[sid]) + 1;
            scontextp = xmalloc_array(char, *scontext_len);
            if ( !scontextp )
                return -ENOMEM;
            strlcpy(scontextp, initial_sid_to_string[sid], *scontext_len);
            *scontext = scontextp;
            goto out;
        }
        printk(KERN_ERR "security_sid_to_context:  called before initial "
               "load_policy on unknown SID %d\n", sid);
        rc = -EINVAL;
        goto out;
    }
    POLICY_RDLOCK;
    context = sidtab_search(&sidtab, sid);
    if ( !context )
    {
        printk(KERN_ERR "security_sid_to_context:  unrecognized SID "
               "%d\n", sid);
        rc = -EINVAL;
        goto out_unlock;
    }
    rc = context_struct_to_string(context, scontext, scontext_len);
out_unlock:
    POLICY_RDUNLOCK;
out:
    return rc;

}

/**
 * security_context_to_sid - Obtain a SID for a given security context.
 * @scontext: security context
 * @scontext_len: length in bytes
 * @sid: security identifier, SID
 *
 * Obtains a SID associated with the security context that
 * has the string representation specified by @scontext.
 * Returns -%EINVAL if the context is invalid, -%ENOMEM if insufficient
 * memory is available, or 0 on success.
 */
int security_context_to_sid(char *scontext, u32 scontext_len, u32 *sid)
{
    char *scontext2;
    struct context context;
    struct role_datum *role;
    struct type_datum *typdatum;
    struct user_datum *usrdatum;
    char *scontextp, *p, oldc;
    int rc = 0;

    if ( !ss_initialized )
    {
        int i;

        for ( i = 1; i < SECINITSID_NUM; i++ )
        {
            if ( !strcmp(initial_sid_to_string[i], scontext) )
            {
                *sid = i;
                goto out;
            }
        }
        *sid = SECINITSID_XEN;
        goto out;
    }
    *sid = SECSID_NULL;

    /* Copy the string so that we can modify the copy as we parse it.
       The string should already by null terminated, but we append a
       null suffix to the copy to avoid problems with the existing
       attr package, which doesn't view the null terminator as part
       of the attribute value. */
    scontext2 = xmalloc_array(char, scontext_len+1);
    if ( !scontext2 )
    {
        rc = -ENOMEM;
        goto out;
    }
    memcpy(scontext2, scontext, scontext_len);
    scontext2[scontext_len] = 0;

    context_init(&context);
    *sid = SECSID_NULL;

    POLICY_RDLOCK;

    /* Parse the security context. */

    rc = -EINVAL;
    scontextp = (char *) scontext2;

    /* Extract the user. */
    p = scontextp;
    while ( *p && *p != ':' )
        p++;

    if (*p == 0)
        goto out_unlock;

    *p++ = 0;

    usrdatum = hashtab_search(policydb.p_users.table, scontextp);
    if ( !usrdatum )
        goto out_unlock;

    context.user = usrdatum->value;

    /* Extract role. */
    scontextp = p;
    while ( *p && *p != ':' )
        p++;

    if ( *p == 0 )
        goto out_unlock;

    *p++ = 0;

    role = hashtab_search(policydb.p_roles.table, scontextp);
    if ( !role )
        goto out_unlock;
    context.role = role->value;

    /* Extract type. */
    scontextp = p;
    while ( *p && *p != ':' )
        p++;
    oldc = *p;
    *p++ = 0;

    typdatum = hashtab_search(policydb.p_types.table, scontextp);
    if ( !typdatum || typdatum->attribute )
        goto out_unlock;

    context.type = typdatum->value;

    rc = mls_context_to_sid(oldc, &p, &context, &sidtab);
    if ( rc )
        goto out_unlock;

    if ( (p - scontext2) < scontext_len )
    {
        rc = -EINVAL;
        goto out_unlock;
    }

    /* Check the validity of the new context. */
    if ( !policydb_context_isvalid(&policydb, &context) )
    {
        rc = -EINVAL;
        goto out_unlock;
    }
    /* Obtain the new sid. */
    rc = sidtab_context_to_sid(&sidtab, &context, sid);
out_unlock:
    POLICY_RDUNLOCK;
    context_destroy(&context);
    xfree(scontext2);
out:
    return rc;
}

static int compute_sid_handle_invalid_context(
                struct context *scontext, struct context *tcontext, u16 tclass,
                                                    struct context *newcontext)
{
    char *s = NULL, *t = NULL, *n = NULL;
    u32 slen, tlen, nlen;

    if ( context_struct_to_string(scontext, &s, &slen) < 0 )
        goto out;
    if ( context_struct_to_string(tcontext, &t, &tlen) < 0 )
        goto out;
    if ( context_struct_to_string(newcontext, &n, &nlen) < 0 )
        goto out;
    printk("security_compute_sid:  invalid context %s"
          " for scontext=%s"
          " tcontext=%s"
          " tclass=%s",
          n, s, t, policydb.p_class_val_to_name[tclass-1]);
out:
    xfree(s);
    xfree(t);
    xfree(n);
    if ( !flask_enforcing )
        return 0;
    return -EACCES;
}

static int security_compute_sid(u32 ssid,
                u32 tsid,
                u16 tclass,
                u32 specified,
                u32 *out_sid)
{
    struct context *scontext = NULL, *tcontext = NULL, newcontext;
    struct role_trans *roletr = NULL;
    struct avtab_key avkey;
    struct avtab_datum *avdatum;
    struct avtab_node *node;
    int rc = 0;

    if ( !ss_initialized )
    {
        switch ( tclass )
        {
            case SECCLASS_DOMAIN:
                *out_sid = ssid;
            break;
            default:
                *out_sid = tsid;
            break;
        }
        goto out;
    }

    POLICY_RDLOCK;

    scontext = sidtab_search(&sidtab, ssid);
    if ( !scontext )
    {
        printk(KERN_ERR "security_compute_sid:  unrecognized SID %d\n", ssid);
        rc = -EINVAL;
        goto out_unlock;
    }
    tcontext = sidtab_search(&sidtab, tsid);
    if ( !tcontext )
    {
        printk(KERN_ERR "security_compute_sid:  unrecognized SID %d\n", tsid);
        rc = -EINVAL;
        goto out_unlock;
    }

    context_init(&newcontext);

    /* Set the user identity. */
    switch ( specified )
    {
        case AVTAB_TRANSITION:
        case AVTAB_CHANGE:
            /* Use the process user identity. */
            newcontext.user = scontext->user;
        break;
        case AVTAB_MEMBER:
            /* Use the related object owner. */
            newcontext.user = tcontext->user;
        break;
    }

    /* Set the role and type to default values. */
    switch ( tclass )
    {
        case SECCLASS_DOMAIN:
            /* Use the current role and type of process. */
            newcontext.role = scontext->role;
            newcontext.type = scontext->type;
        break;
        default:
            /* Use the well-defined object role. */
            newcontext.role = OBJECT_R_VAL;
            /* Use the type of the related object. */
            newcontext.type = tcontext->type;
    }

    /* Look for a type transition/member/change rule. */
    avkey.source_type = scontext->type;
    avkey.target_type = tcontext->type;
    avkey.target_class = tclass;
    avkey.specified = specified;
    avdatum = avtab_search(&policydb.te_avtab, &avkey);

    /* If no permanent rule, also check for enabled conditional rules */
    if ( !avdatum )
    {
        node = avtab_search_node(&policydb.te_cond_avtab, &avkey);
        for ( ; node != NULL; node = avtab_search_node_next(node, specified) )
        {
            if ( node->key.specified & AVTAB_ENABLED )
            {
                avdatum = &node->datum;
                break;
            }
        }
    }

    if ( avdatum )
    {
        /* Use the type from the type transition/member/change rule. */
        newcontext.type = avdatum->data;
    }

    /* Check for class-specific changes. */
    switch ( tclass )
    {
        case SECCLASS_DOMAIN:
            if ( specified & AVTAB_TRANSITION )
            {
                /* Look for a role transition rule. */
                for ( roletr = policydb.role_tr; roletr; roletr = roletr->next )
                {
                    if ( roletr->role == scontext->role && 
                                            roletr->type == tcontext->type )
                    {
                        /* Use the role transition rule. */
                        newcontext.role = roletr->new_role;
                        break;
                    }
                }
            }
        break;
        default:
        break;
    }

    /* Set the MLS attributes.
       This is done last because it may allocate memory. */
    rc = mls_compute_sid(scontext, tcontext, tclass, specified, &newcontext);
    if ( rc )
        goto out_unlock;

    /* Check the validity of the context. */
    if ( !policydb_context_isvalid(&policydb, &newcontext) )
    {
        rc = compute_sid_handle_invalid_context(scontext, tcontext, tclass,
                                                                &newcontext);
        if ( rc )
            goto out_unlock;
    }
    /* Obtain the sid for the context. */
    rc = sidtab_context_to_sid(&sidtab, &newcontext, out_sid);
out_unlock:
    POLICY_RDUNLOCK;
    context_destroy(&newcontext);
out:
    return rc;
}

/**
 * security_transition_sid - Compute the SID for a new subject/object.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @out_sid: security identifier for new subject/object
 *
 * Compute a SID to use for labeling a new subject or object in the
 * class @tclass based on a SID pair (@ssid, @tsid).
 * Return -%EINVAL if any of the parameters are invalid, -%ENOMEM
 * if insufficient memory is available, or %0 if the new SID was
 * computed successfully.
 */
int security_transition_sid(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid)
{
    return security_compute_sid(ssid, tsid, tclass, AVTAB_TRANSITION, out_sid);
}

/**
 * security_member_sid - Compute the SID for member selection.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @out_sid: security identifier for selected member
 *
 * Compute a SID to use when selecting a member of a polyinstantiated
 * object of class @tclass based on a SID pair (@ssid, @tsid).
 * Return -%EINVAL if any of the parameters are invalid, -%ENOMEM
 * if insufficient memory is available, or %0 if the SID was
 * computed successfully.
 */
int security_member_sid(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid)
{
    return security_compute_sid(ssid, tsid, tclass, AVTAB_MEMBER, out_sid);
}

/**
 * security_change_sid - Compute the SID for object relabeling.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @out_sid: security identifier for selected member
 *
 * Compute a SID to use for relabeling an object of class @tclass
 * based on a SID pair (@ssid, @tsid).
 * Return -%EINVAL if any of the parameters are invalid, -%ENOMEM
 * if insufficient memory is available, or %0 if the SID was
 * computed successfully.
 */
int security_change_sid(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid)
{
    return security_compute_sid(ssid, tsid, tclass, AVTAB_CHANGE, out_sid);
}

/*
 * Verify that each kernel class that is defined in the
 * policy is correct
 */
static int validate_classes(struct policydb *p)
{
    int i;
    struct class_datum *cladatum;
    struct perm_datum *perdatum;
    u32 nprim, perm_val, pol_val;
    u16 class_val;
    const struct selinux_class_perm *kdefs = &selinux_class_perm;
    const char *def_class, *def_perm, *pol_class;
    struct symtab *perms;

    for ( i = 1; i < kdefs->cts_len; i++ )
    {
        def_class = kdefs->class_to_string[i];
        if ( !def_class )
            continue;
        if ( i > p->p_classes.nprim )
        {
            printk(KERN_INFO
                   "Flask:  class %s not defined in policy\n",
                   def_class);
            return -EINVAL;
        }
        pol_class = p->p_class_val_to_name[i-1];
        if ( strcmp(pol_class, def_class) )
        {
            printk(KERN_ERR
                   "Flask:  class %d is incorrect, found %s but should be %s\n",
                   i, pol_class, def_class);
            return -EINVAL;
        }
    }
    for ( i = 0; i < kdefs->av_pts_len; i++ )
    {
        class_val = kdefs->av_perm_to_string[i].tclass;
        perm_val = kdefs->av_perm_to_string[i].value;
        def_perm = kdefs->av_perm_to_string[i].name;
        if ( class_val > p->p_classes.nprim )
            continue;
        pol_class = p->p_class_val_to_name[class_val-1];
        cladatum = hashtab_search(p->p_classes.table, pol_class);
        BUG_ON( !cladatum );
        perms = &cladatum->permissions;
        nprim = 1 << (perms->nprim - 1);
        if ( perm_val > nprim )
        {
            printk(KERN_INFO
                   "Flask:  permission %s in class %s not defined in policy\n",
                   def_perm, pol_class);
            return -EINVAL;
        }
        perdatum = hashtab_search(perms->table, def_perm);
        if ( perdatum == NULL )
        {
            printk(KERN_ERR
                   "Flask:  permission %s in class %s not found in policy\n",
                   def_perm, pol_class);
            return -EINVAL;
        }
        pol_val = 1 << (perdatum->value - 1);
        if ( pol_val != perm_val )
        {
            printk(KERN_ERR
                   "Flask:  permission %s in class %s has incorrect value\n",
                   def_perm, pol_class);
            return -EINVAL;
        }
    }
    return 0;
}

/* Clone the SID into the new SID table. */
static int clone_sid(u32 sid, struct context *context, void *arg)
{
    struct sidtab *s = arg;

    return sidtab_insert(s, sid, context);
}

static inline int convert_context_handle_invalid_context(struct context *context)
{
    int rc = 0;

    if ( flask_enforcing )
        rc = -EINVAL;
    else
    {
        char *s;
        u32 len;

        context_struct_to_string(context, &s, &len);
        printk(KERN_ERR "Flask:  context %s is invalid\n", s);
        xfree(s);
    }
    return rc;
}

struct convert_context_args {
    struct policydb *oldp;
    struct policydb *newp;
};

/*
 * Convert the values in the security context
 * structure `c' from the values specified
 * in the policy `p->oldp' to the values specified
 * in the policy `p->newp'.  Verify that the
 * context is valid under the new policy.
 */
static int convert_context(u32 key, struct context *c, void *p)
{
    struct convert_context_args *args;
    struct context oldc;
    struct role_datum *role;
    struct type_datum *typdatum;
    struct user_datum *usrdatum;
    char *s;
    u32 len;
    int rc;

    args = p;

    rc = context_cpy(&oldc, c);
    if ( rc )
        goto out;

    rc = -EINVAL;

    /* Convert the user. */
    usrdatum = hashtab_search(args->newp->p_users.table,
                              args->oldp->p_user_val_to_name[c->user - 1]);
    if ( !usrdatum )
        goto bad;

    c->user = usrdatum->value;

    /* Convert the role. */
    role = hashtab_search(args->newp->p_roles.table,
                          args->oldp->p_role_val_to_name[c->role - 1]);
    if ( !role )
        goto bad;

    c->role = role->value;

    /* Convert the type. */
    typdatum = hashtab_search(args->newp->p_types.table,
                              args->oldp->p_type_val_to_name[c->type - 1]);
    if ( !typdatum )
        goto bad;

    c->type = typdatum->value;

    rc = mls_convert_context(args->oldp, args->newp, c);
    if ( rc )
        goto bad;

    /* Check the validity of the new context. */
    if ( !policydb_context_isvalid(args->newp, c) )
    {
        rc = convert_context_handle_invalid_context(&oldc);
        if ( rc )
            goto bad;
    }

    context_destroy(&oldc);
out:
    return rc;
bad:
    context_struct_to_string(&oldc, &s, &len);
    context_destroy(&oldc);
    printk(KERN_ERR "Flask:  invalidating context %s\n", s);
    xfree(s);
    goto out;
}

static int security_preserve_bools(struct policydb *p);

/**
 * security_load_policy - Load a security policy configuration.
 * @data: binary policy data
 * @len: length of data in bytes
 *
 * Load a new set of security policy configuration data,
 * validate it and convert the SID table as necessary.
 * This function will flush the access vector cache after
 * loading the new policy.
 */
int security_load_policy(const void *data, size_t len)
{
    struct policydb oldpolicydb, newpolicydb;
    struct sidtab oldsidtab, newsidtab;
    struct convert_context_args args;
    u32 seqno;
    int rc = 0;
    struct policy_file file = { data, len }, *fp = &file;

    LOAD_LOCK;

    if ( !ss_initialized )
    {
        if ( policydb_read(&policydb, fp) )
        {
            LOAD_UNLOCK;
            return -EINVAL;
        }
        if ( policydb_load_isids(&policydb, &sidtab) )
        {
            LOAD_UNLOCK;
            policydb_destroy(&policydb);
            return -EINVAL;
        }
        if ( validate_classes(&policydb) )
        {
            LOAD_UNLOCK;
            printk(KERN_ERR
                   "Flask:  the definition of a class is incorrect\n");
            sidtab_destroy(&sidtab);
            policydb_destroy(&policydb);
            return -EINVAL;
        }
        policydb_loaded_version = policydb.policyvers;
        ss_initialized = 1;
        seqno = ++latest_granting;
        LOAD_UNLOCK;
        avc_ss_reset(seqno);
        return 0;
    }

#if 0
    sidtab_hash_eval(&sidtab, "sids");
#endif

    if ( policydb_read(&newpolicydb, fp) )
    {
        LOAD_UNLOCK;
        return -EINVAL;
    }

    sidtab_init(&newsidtab);

    /* Verify that the kernel defined classes are correct. */
    if ( validate_classes(&newpolicydb) )
    {
        printk(KERN_ERR
               "Flask:  the definition of a class is incorrect\n");
        rc = -EINVAL;
        goto err;
    }

    rc = security_preserve_bools(&newpolicydb);
    if ( rc )
    {
        printk(KERN_ERR "Flask:  unable to preserve booleans\n");
        goto err;
    }

    /* Clone the SID table. */
    sidtab_shutdown(&sidtab);
    if ( sidtab_map(&sidtab, clone_sid, &newsidtab) )
    {
        rc = -ENOMEM;
        goto err;
    }

    /* Convert the internal representations of contexts
       in the new SID table and remove invalid SIDs. */
    args.oldp = &policydb;
    args.newp = &newpolicydb;
    sidtab_map_remove_on_error(&newsidtab, convert_context, &args);

    /* Save the old policydb and SID table to free later. */
    memcpy(&oldpolicydb, &policydb, sizeof policydb);
    sidtab_set(&oldsidtab, &sidtab);

    /* Install the new policydb and SID table. */
    POLICY_WRLOCK;
    memcpy(&policydb, &newpolicydb, sizeof policydb);
    sidtab_set(&sidtab, &newsidtab);
    seqno = ++latest_granting;
    policydb_loaded_version = policydb.policyvers;
    POLICY_WRUNLOCK;
    LOAD_UNLOCK;

    /* Free the old policydb and SID table. */
    policydb_destroy(&oldpolicydb);
    sidtab_destroy(&oldsidtab);

    avc_ss_reset(seqno);

    return 0;

err:
    LOAD_UNLOCK;
    sidtab_destroy(&newsidtab);
    policydb_destroy(&newpolicydb);
    return rc;

}

int security_get_allow_unknown(void)
{
    return policydb.allow_unknown;
}

/**
 * security_irq_sid - Obtain the SID for a physical irq.
 * @pirq: physical irq
 * @out_sid: security identifier
 */
int security_irq_sid(int pirq, u32 *out_sid)
{
    int rc = 0;
    struct ocontext *c;

    POLICY_RDLOCK;

    c = policydb.ocontexts[OCON_PIRQ];
    
    while ( c )
    {
        if ( c->u.pirq == pirq )
            break;
        c = c->next;
    }

    if ( c )
    {
        if ( !c->sid )
        {
            rc = sidtab_context_to_sid(&sidtab, &c->context, &c->sid);
            if ( rc )
                goto out;
        }
        *out_sid = c->sid;
    }
    else
    {
        *out_sid = SECINITSID_IRQ;
    }

out:
    POLICY_RDUNLOCK;
    return rc;
}

/**
 * security_iomem_sid - Obtain the SID for a page of iomem.
 * @mfn: iomem mfn
 * @out_sid: security identifier
 */
int security_iomem_sid(unsigned long mfn, u32 *out_sid)
{
    struct ocontext *c;
    int rc = 0;

    POLICY_RDLOCK;

    c = policydb.ocontexts[OCON_IOMEM];
    while ( c )
    {
        if ( c->u.iomem.low_iomem <= mfn  && c->u.iomem.high_iomem >= mfn )
            break;
        c = c->next;
    }

    if ( c )
    {
        if ( !c->sid )
        {
            rc = sidtab_context_to_sid(&sidtab, &c->context, &c->sid);
            if ( rc )
                goto out;
        }
        *out_sid = c->sid;
    }
    else
    {
        *out_sid = SECINITSID_IOMEM;
    }

out:
    POLICY_RDUNLOCK;
    return rc;
}

int security_iterate_iomem_sids(unsigned long start, unsigned long end,
                                security_iterate_fn fn, void *data)
{
    struct ocontext *c;
    int rc = 0;

    POLICY_RDLOCK;

    c = policydb.ocontexts[OCON_IOMEM];
    while (c && c->u.iomem.high_iomem < start)
        c = c->next;

    while (c && c->u.iomem.low_iomem <= end) {
        if (!c->sid)
        {
            rc = sidtab_context_to_sid(&sidtab, &c->context, &c->sid);
            if ( rc )
                goto out;
        }
        if (start < c->u.iomem.low_iomem) {
            /* found a gap */
            rc = fn(data, SECINITSID_IOMEM, start, c->u.iomem.low_iomem - 1);
            if (rc)
                goto out;
            start = c->u.iomem.low_iomem;
        }
        if (end <= c->u.iomem.high_iomem) {
            /* iteration ends in the middle of this range */
            rc = fn(data, c->sid, start, end);
            goto out;
        }

        rc = fn(data, c->sid, start, c->u.iomem.high_iomem);
        if (rc)
            goto out;
        start = c->u.iomem.high_iomem + 1;

        c = c->next;
    }

    rc = fn(data, SECINITSID_IOMEM, start, end);

out:
    POLICY_RDUNLOCK;
    return rc;
}

/**
 * security_ioport_sid - Obtain the SID for an ioport.
 * @ioport: ioport
 * @out_sid: security identifier
 */
int security_ioport_sid(u32 ioport, u32 *out_sid)
{
    struct ocontext *c;
    int rc = 0;

    POLICY_RDLOCK;

    c = policydb.ocontexts[OCON_IOPORT];
    while ( c )
    {
        if ( c->u.ioport.low_ioport <= ioport &&
             c->u.ioport.high_ioport >= ioport )
            break;
        c = c->next;
    }

    if ( c )
    {
        if ( !c->sid )
        {
            rc = sidtab_context_to_sid(&sidtab, &c->context, &c->sid);
            if ( rc )
                goto out;
        }
        *out_sid = c->sid;
    }
    else
    {
        *out_sid = SECINITSID_IOPORT;
    }

out:
    POLICY_RDUNLOCK;
    return rc;
}

int security_iterate_ioport_sids(u32 start, u32 end,
                                security_iterate_fn fn, void *data)
{
    struct ocontext *c;
    int rc = 0;

    POLICY_RDLOCK;

    c = policydb.ocontexts[OCON_IOPORT];
    while (c && c->u.ioport.high_ioport < start)
        c = c->next;

    while (c && c->u.ioport.low_ioport <= end) {
        if (!c->sid)
        {
            rc = sidtab_context_to_sid(&sidtab, &c->context, &c->sid);
            if ( rc )
                goto out;
        }
        if (start < c->u.ioport.low_ioport) {
            /* found a gap */
            rc = fn(data, SECINITSID_IOPORT, start, c->u.ioport.low_ioport - 1);
            if (rc)
                goto out;
            start = c->u.ioport.low_ioport;
        }
        if (end <= c->u.ioport.high_ioport) {
            /* iteration ends in the middle of this range */
            rc = fn(data, c->sid, start, end);
            goto out;
        }

        rc = fn(data, c->sid, start, c->u.ioport.high_ioport);
        if (rc)
            goto out;
        start = c->u.ioport.high_ioport + 1;

        c = c->next;
    }

    rc = fn(data, SECINITSID_IOPORT, start, end);

out:
    POLICY_RDUNLOCK;
    return rc;
}

/**
 * security_device_sid - Obtain the SID for a PCI device.
 * @ioport: device
 * @out_sid: security identifier
 */
int security_device_sid(u32 device, u32 *out_sid)
{
    struct ocontext *c;
    int rc = 0;

    POLICY_RDLOCK;

    c = policydb.ocontexts[OCON_DEVICE];
    while ( c )
    {
        if ( c->u.device == device )
            break;
        c = c->next;
    }

    if ( c )
    {
        if ( !c->sid )
        {
            rc = sidtab_context_to_sid(&sidtab, &c->context, &c->sid);
            if ( rc )
                goto out;
        }
        *out_sid = c->sid;
    }
    else
    {
        *out_sid = SECINITSID_DEVICE;
    }

out:
    POLICY_RDUNLOCK;
    return rc;
}

int security_devicetree_sid(const char *path, u32 *out_sid)
{
    struct ocontext *c;
    int rc = 0;

    POLICY_RDLOCK;

    c = policydb.ocontexts[OCON_DTREE];
    while ( c )
    {
        if ( strcmp(c->u.name, path) == 0 )
            break;
        c = c->next;
    }

    if ( c )
    {
        if ( !c->sid )
        {
            rc = sidtab_context_to_sid(&sidtab, &c->context, &c->sid);
            if ( rc )
                goto out;
        }
        *out_sid = c->sid;
    }
    else
    {
        *out_sid = SECINITSID_DEVICE;
    }

out:
    POLICY_RDUNLOCK;
    return rc;
}

int security_find_bool(const char *name)
{
    int i, rv = -ENOENT;
    POLICY_RDLOCK;
    for ( i = 0; i < policydb.p_bools.nprim; i++ )
    {
        if (!strcmp(name, policydb.p_bool_val_to_name[i]))
        {
            rv = i;
            break;
        }
    }

    POLICY_RDUNLOCK;
    return rv;
}

int security_get_bools(int *len, char ***names, int **values, size_t *maxstr)
{
    int i, rc = -ENOMEM;

    POLICY_RDLOCK;
    if ( names )
        *names = NULL;
    *values = NULL;
    if ( maxstr )
        *maxstr = 0;

    *len = policydb.p_bools.nprim;
    if ( !*len )
    {
        rc = 0;
        goto out;
    }

    if ( names )
    {
        *names = xzalloc_array(char *, *len);
        if ( !*names )
            goto err;
    }

    *values = xmalloc_array(int, *len);
    if ( !*values )
        goto err;

    for ( i = 0; i < *len; i++ )
    {
        size_t name_len = strlen(policydb.p_bool_val_to_name[i]);

        (*values)[i] = policydb.bool_val_to_struct[i]->state;
        if ( names ) {
            (*names)[i] = xmalloc_array(char, name_len + 1);
            if ( !(*names)[i] )
                goto err;
            strlcpy((*names)[i], policydb.p_bool_val_to_name[i], name_len + 1);
        }
        if ( maxstr && name_len > *maxstr )
            *maxstr = name_len;
    }
    rc = 0;
out:
    POLICY_RDUNLOCK;
    return rc;
err:
    if ( names && *names )
    {
        for ( i = 0; i < *len; i++ )
            xfree((*names)[i]);
        xfree(*names);
    }
    xfree(*values);
    goto out;
}


int security_set_bools(int len, int *values)
{
    int i, rc = 0;
    int lenp, seqno = 0;
    struct cond_node *cur;

    POLICY_WRLOCK;

    lenp = policydb.p_bools.nprim;
    if ( len != lenp )
    {
        rc = -EFAULT;
        goto out;
    }

    printk(KERN_INFO "Flask: committed booleans { ");
    for ( i = 0; i < len; i++ )
    {
        if ( values[i] )
        {
            policydb.bool_val_to_struct[i]->state = 1;
        }
        else
        {
            policydb.bool_val_to_struct[i]->state = 0;
        }
        if ( i != 0 )
            printk(", ");
        printk("%s:%d", policydb.p_bool_val_to_name[i],
               policydb.bool_val_to_struct[i]->state);
    }
    printk(" }\n");

    for ( cur = policydb.cond_list; cur != NULL; cur = cur->next )
    {
        rc = evaluate_cond_node(&policydb, cur);
        if ( rc )
            goto out;
    }

    seqno = ++latest_granting;

out:
    POLICY_WRUNLOCK;
    if ( !rc )
    {
        avc_ss_reset(seqno);
    }
    return rc;
}

int security_get_bool_value(unsigned int b)
{
    int rc = 0;
    unsigned int len;

    POLICY_RDLOCK;

    len = policydb.p_bools.nprim;
    if ( b >= len )
    {
        rc = -ENOENT;
        goto out;
    }

    rc = policydb.bool_val_to_struct[b]->state;
out:
    POLICY_RDUNLOCK;
    return rc;
}

char *security_get_bool_name(unsigned int b)
{
    unsigned int len;
    char *rv = NULL;

    POLICY_RDLOCK;

    len = policydb.p_bools.nprim;
    if ( b >= len )
    {
        goto out;
    }

    len = strlen(policydb.p_bool_val_to_name[b]) + 1;
    rv = xmalloc_array(char, len);
    if ( !rv )
        goto out;
    memcpy(rv, policydb.p_bool_val_to_name[b], len);
out:
    POLICY_RDUNLOCK;
    return rv;
}

static int security_preserve_bools(struct policydb *p)
{
    int rc, nbools = 0, *bvalues = NULL, i;
    char **bnames = NULL;
    struct cond_bool_datum *booldatum;
    struct cond_node *cur;

    rc = security_get_bools(&nbools, &bnames, &bvalues, NULL);
    if ( rc )
        return rc;
    for ( i = 0; i < nbools; i++ )
    {
        booldatum = hashtab_search(p->p_bools.table, bnames[i]);
        if ( booldatum )
            booldatum->state = bvalues[i];
    }
    for ( cur = p->cond_list; cur; cur = cur->next )
    {
        rc = evaluate_cond_node(p, cur);
        if ( rc )
            goto out;
    }

out:
    if ( bnames )
    {
        for ( i = 0; i < nbools; i++ )
            xfree(bnames[i]);
    }
    xfree(bnames);
    xfree(bvalues);
    return rc;
}

int security_ocontext_add( u32 ocon, unsigned long low, unsigned long high
                            ,u32 sid )
{
    int ret = 0;
    struct ocontext *c;
    struct ocontext *prev;
    struct ocontext *add;

    if ( (add = xzalloc(struct ocontext)) == NULL )
        return -ENOMEM;
    add->sid = sid;

    POLICY_WRLOCK;
    switch( ocon )
    {
    case OCON_PIRQ:
        add->u.pirq = (u16)low;
        if ( high != low )
        {
            ret = -EINVAL;
            break;
        }

        c = policydb.ocontexts[OCON_PIRQ];
        while ( c )
        {
            if ( c->u.pirq == add->u.pirq )
            {
                if ( c->sid == sid )
                    break;
                printk("flask: Duplicate pirq %d\n", add->u.pirq);
                ret = -EEXIST;
                break;
            }
            c = c->next;
        }

        if ( ret == 0 )
        {
            add->next = policydb.ocontexts[OCON_PIRQ];
            policydb.ocontexts[OCON_PIRQ] = add;
        }
        break;

    case OCON_IOPORT:
        add->u.ioport.low_ioport = low;
        add->u.ioport.high_ioport = high;

        prev = NULL;
        c = policydb.ocontexts[OCON_IOPORT];

        while ( c && c->u.ioport.high_ioport < low ) {
            prev = c;
            c = c->next;
        }

        if (c && c->u.ioport.low_ioport <= high)
        {
            if (c->u.ioport.low_ioport == low &&
                c->u.ioport.high_ioport == high && c->sid == sid)
                break;

            printk("flask: IO Port overlap with entry %#x - %#x\n",
                   c->u.ioport.low_ioport, c->u.ioport.high_ioport);
            ret = -EEXIST;
            break;
        }

        if (prev) {
            add->next = prev->next;
            prev->next = add;
        } else {
            add->next = policydb.ocontexts[OCON_IOPORT];
            policydb.ocontexts[OCON_IOPORT] = add;
        }
        break;

    case OCON_IOMEM:
        add->u.iomem.low_iomem = low;
        add->u.iomem.high_iomem = high;

        prev = NULL;
        c = policydb.ocontexts[OCON_IOMEM];

        while ( c && c->u.iomem.high_iomem < low ) {
            prev = c;
            c = c->next;
        }

        if (c && c->u.iomem.low_iomem <= high)
        {
            if (c->u.iomem.low_iomem == low &&
                c->u.iomem.high_iomem == high && c->sid == sid)
                break;

            printk("flask: IO Memory overlap with entry %#"PRIx64" - %#"PRIx64"\n",
                   c->u.iomem.low_iomem, c->u.iomem.high_iomem);
            ret = -EEXIST;
            break;
        }

        if (prev) {
            add->next = prev->next;
            prev->next = add;
        } else {
            add->next = policydb.ocontexts[OCON_IOMEM];
            policydb.ocontexts[OCON_IOMEM] = add;
        }
        break;

     case OCON_DEVICE:
        add->u.device = low;
        if ( high != low )
        {
            ret = -EINVAL;
            break;
        }

        c = policydb.ocontexts[OCON_DEVICE];
        while ( c )
        {
            if ( c->u.device == add->u.device )
            {
                if ( c->sid == sid )
                    break;

                printk("flask: Duplicate PCI Device %#x\n", add->u.device);
                ret = -EEXIST;
                break;
            }
            c = c->next;
        }

        if ( ret == 0 )
        {
            add->next = policydb.ocontexts[OCON_DEVICE];
            policydb.ocontexts[OCON_DEVICE] = add;
        }
        break;

     default:
         ret = -EINVAL;
    }
    POLICY_WRUNLOCK;

    if ( ret != 0 )
        xfree(add);
    return ret;
}

int security_ocontext_del( u32 ocon, unsigned long low, unsigned long high )
{
    int ret = 0;
    struct ocontext *c, *before_c;

    POLICY_WRLOCK;
    switch( ocon )
    {
    case OCON_PIRQ:
        for ( before_c = NULL, c = policydb.ocontexts[OCON_PIRQ];
              c; before_c = c, c = c->next )
        {
            if ( c->u.pirq == low )
            {
                if ( before_c == NULL )
                {
                    policydb.ocontexts[OCON_PIRQ] = c->next;
                    xfree(c);
                    goto out;
                }
                else
                {
                    before_c->next = c->next;
                    xfree(c);
                    goto out;
                }
            }
        }

        printk("flask: ocontext not found: pirq %ld\n", low);
        ret = -ENOENT;
        break;

    case OCON_IOPORT:
        for ( before_c = NULL, c = policydb.ocontexts[OCON_IOPORT];
              c; before_c = c, c = c->next )
        {
            if ( c->u.ioport.low_ioport == low &&
                 c->u.ioport.high_ioport == high )
            {
                if ( before_c == NULL )
                {
                    policydb.ocontexts[OCON_IOPORT] = c->next;
                    xfree(c);
                    goto out;
                }
                else
                {
                    before_c->next = c->next;
                    xfree(c);
                    goto out;
                }
            }
        }

        printk("flask: ocontext not found: ioport %#lx - %#lx\n", low, high);
        ret = -ENOENT;
        break;

    case OCON_IOMEM:
        for ( before_c = NULL, c = policydb.ocontexts[OCON_IOMEM];
              c; before_c = c, c = c->next )
        {
            if ( c->u.iomem.low_iomem == low &&
                 c->u.iomem.high_iomem == high )
            {
                if ( before_c == NULL )
                {
                    policydb.ocontexts[OCON_IOMEM] = c->next;
                    xfree(c);
                    goto out;
                }
                else
                {
                    before_c->next = c->next;
                    xfree(c);
                    goto out;
                }
            }
        }

        printk("flask: ocontext not found: iomem %#lx - %#lx\n", low, high);
        ret = -ENOENT;
        break;

    case OCON_DEVICE:
        for ( before_c = NULL, c = policydb.ocontexts[OCON_DEVICE];
              c; before_c = c, c = c->next )
        {
            if ( c->u.device == low )
            {
                if ( before_c == NULL )
                {
                    policydb.ocontexts[OCON_DEVICE] = c->next;
                    xfree(c);
                    goto out;
                }
                else
                {
                    before_c->next = c->next;
                    xfree(c);
                    goto out;
                }
            }
        }

        printk("flask: ocontext not found: pcidevice %#lx\n", low);
        ret = -ENOENT;
        break;

    default:
        ret = -EINVAL;
    }

  out:
    POLICY_WRUNLOCK;
    return ret;
}

int security_devicetree_setlabel(char *path, u32 sid)
{
    int ret = 0;
    struct ocontext *c;
    struct ocontext **pcurr;
    struct ocontext *add = NULL;

    if ( sid )
    {
        add = xzalloc(struct ocontext);
        if ( add == NULL )
        {
            xfree(path);
            return -ENOMEM;
        }
        add->sid = sid;
        add->u.name = path;
    }
    else
    {
        ret = -ENOENT;
    }

    POLICY_WRLOCK;

    pcurr = &policydb.ocontexts[OCON_DTREE];
    c = *pcurr;
    while ( c )
    {
        if ( strcmp(c->u.name, path) == 0 )
        {
            if ( sid )
            {
                ret = -EEXIST;
                break;
            }
            else
            {
                *pcurr = c->next;
                xfree(c->u.name);
                xfree(c);
                ret = 0;
                break;
            }
        }
        pcurr = &c->next;
        c = *pcurr;
    }

    if ( add && ret == 0 )
    {
        add->next = policydb.ocontexts[OCON_DTREE];
        policydb.ocontexts[OCON_DTREE] = add;
        add = NULL;
        path = NULL;
    }

    POLICY_WRUNLOCK;

    xfree(add);
    xfree(path);
    return ret;
}
