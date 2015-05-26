/*
 *  This file contains the flask_op hypercall and associated functions.
 *
 *  Author:  George Coker, <gscoker@alpha.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */
#ifndef COMPAT
#include <xen/errno.h>
#include <xen/event.h>
#include <xsm/xsm.h>
#include <xen/guest_access.h>
#include <xen/err.h>

#include <public/xsm/flask_op.h>

#include <avc.h>
#include <avc_ss.h>
#include <objsec.h>
#include <conditional.h>

#define ret_t long
#define _copy_to_guest copy_to_guest
#define _copy_from_guest copy_from_guest

enum flask_bootparam_t __read_mostly flask_bootparam = FLASK_BOOTPARAM_PERMISSIVE;
static void parse_flask_param(char *s);
custom_param("flask", parse_flask_param);

bool_t __read_mostly flask_enforcing = 0;
boolean_param("flask_enforcing", flask_enforcing);

#define MAX_POLICY_SIZE 0x4000000

#define FLASK_COPY_OUT \
    ( \
        1UL<<FLASK_CONTEXT_TO_SID | \
        1UL<<FLASK_SID_TO_CONTEXT | \
        1UL<<FLASK_ACCESS | \
        1UL<<FLASK_CREATE | \
        1UL<<FLASK_RELABEL | \
        1UL<<FLASK_USER | \
        1UL<<FLASK_GETBOOL | \
        1UL<<FLASK_SETBOOL | \
        1UL<<FLASK_AVC_HASHSTATS | \
        1UL<<FLASK_AVC_CACHESTATS | \
        1UL<<FLASK_MEMBER | \
        1UL<<FLASK_GET_PEER_SID | \
   0)

static DEFINE_SPINLOCK(sel_sem);

/* global data for booleans */
static int bool_num = 0;
static int *bool_pending_values = NULL;
static int flask_security_make_bools(void);

extern int ss_initialized;

extern struct xsm_operations *original_ops;

static void __init parse_flask_param(char *s)
{
    if ( !strcmp(s, "enforcing") )
    {
        flask_enforcing = 1;
        flask_bootparam = FLASK_BOOTPARAM_ENFORCING;
    }
    else if ( !strcmp(s, "late") )
    {
        flask_enforcing = 1;
        flask_bootparam = FLASK_BOOTPARAM_LATELOAD;
    }
    else if ( !strcmp(s, "disabled") )
        flask_bootparam = FLASK_BOOTPARAM_DISABLED;
    else if ( !strcmp(s, "permissive") )
        flask_bootparam = FLASK_BOOTPARAM_PERMISSIVE;
    else
        flask_bootparam = FLASK_BOOTPARAM_INVALID;
}

static int domain_has_security(struct domain *d, u32 perms)
{
    struct domain_security_struct *dsec;
    
    dsec = d->ssid;
    if ( !dsec )
        return -EACCES;
        
    return avc_has_perm(dsec->sid, SECINITSID_SECURITY, SECCLASS_SECURITY, 
                        perms, NULL);
}

#endif /* COMPAT */

static int flask_security_user(struct xen_flask_userlist *arg)
{
    char *user;
    u32 *sids;
    u32 nsids;
    int rv;

    rv = domain_has_security(current->domain, SECURITY__COMPUTE_USER);
    if ( rv )
        return rv;

    user = safe_copy_string_from_guest(arg->u.user, arg->size, PAGE_SIZE);
    if ( IS_ERR(user) )
        return PTR_ERR(user);

    rv = security_get_user_sids(arg->start_sid, user, &sids, &nsids);
    if ( rv < 0 )
        goto out;

    if ( nsids * sizeof(sids[0]) > arg->size )
        nsids = arg->size / sizeof(sids[0]);

    arg->size = nsids;

    if ( _copy_to_guest(arg->u.sids, sids, nsids) )
        rv = -EFAULT;

    xfree(sids);
 out:
    xfree(user);
    return rv;
}

#ifndef COMPAT

static int flask_security_relabel(struct xen_flask_transition *arg)
{
    int rv;

    rv = domain_has_security(current->domain, SECURITY__COMPUTE_RELABEL);
    if ( rv )
        return rv;

    rv = security_change_sid(arg->ssid, arg->tsid, arg->tclass, &arg->newsid);

    return rv;
}

static int flask_security_create(struct xen_flask_transition *arg)
{
    int rv;

    rv = domain_has_security(current->domain, SECURITY__COMPUTE_CREATE);
    if ( rv )
        return rv;

    rv = security_transition_sid(arg->ssid, arg->tsid, arg->tclass, &arg->newsid);

    return rv;
}

static int flask_security_access(struct xen_flask_access *arg)
{
    struct av_decision avd;
    int rv;

    rv = domain_has_security(current->domain, SECURITY__COMPUTE_AV);
    if ( rv )
        return rv;

    rv = security_compute_av(arg->ssid, arg->tsid, arg->tclass, arg->req, &avd);
    if ( rv < 0 )
        return rv;

    arg->allowed = avd.allowed;
    arg->audit_allow = avd.auditallow;
    arg->audit_deny = avd.auditdeny;
    arg->seqno = avd.seqno;
                
    return rv;
}

static int flask_security_member(struct xen_flask_transition *arg)
{
    int rv;

    rv = domain_has_security(current->domain, SECURITY__COMPUTE_MEMBER);
    if ( rv )
        return rv;

    rv = security_member_sid(arg->ssid, arg->tsid, arg->tclass, &arg->newsid);

    return rv;
}

static int flask_security_setenforce(struct xen_flask_setenforce *arg)
{
    int enforce = !!(arg->enforcing);
    int rv;

    if ( enforce == flask_enforcing )
        return 0;

    rv = domain_has_security(current->domain, SECURITY__SETENFORCE);
    if ( rv )
        return rv;

    flask_enforcing = enforce;

    if ( flask_enforcing )
        avc_ss_reset(0);

    return 0;
}

#endif /* COMPAT */

static int flask_security_context(struct xen_flask_sid_context *arg)
{
    int rv;
    char *buf;

    rv = domain_has_security(current->domain, SECURITY__CHECK_CONTEXT);
    if ( rv )
        return rv;

    buf = safe_copy_string_from_guest(arg->context, arg->size, PAGE_SIZE);
    if ( IS_ERR(buf) )
        return PTR_ERR(buf);

    rv = security_context_to_sid(buf, arg->size, &arg->sid);
    if ( rv < 0 )
        goto out;

 out:
    xfree(buf);

    return rv;
}

static int flask_security_sid(struct xen_flask_sid_context *arg)
{
    int rv;
    char *context;
    u32 len;

    rv = domain_has_security(current->domain, SECURITY__CHECK_CONTEXT);
    if ( rv )
        return rv;

    rv = security_sid_to_context(arg->sid, &context, &len);
    if ( rv < 0 )
        return rv;

    rv = 0;

    if ( len > arg->size )
        rv = -ERANGE;

    arg->size = len;

    if ( !rv && _copy_to_guest(arg->context, context, len) )
        rv = -EFAULT;

    xfree(context);

    return rv;
}

#ifndef COMPAT

static int flask_disable(void)
{
    static int flask_disabled = 0;

    if ( ss_initialized )
    {
        /* Not permitted after initial policy load. */
        return -EINVAL;
    }

    if ( flask_disabled )
    {
        /* Only do this once. */
        return -EINVAL;
    }

    printk("Flask:  Disabled at runtime.\n");

    flask_disabled = 1;

    /* Reset xsm_ops to the original module. */
    xsm_ops = original_ops;

    return 0;
}

static int flask_security_setavc_threshold(struct xen_flask_setavc_threshold *arg)
{
    int rv = 0;

    if ( arg->threshold != avc_cache_threshold )
    {
        rv = domain_has_security(current->domain, SECURITY__SETSECPARAM);
        if ( rv )
            goto out;
        avc_cache_threshold = arg->threshold;
    }

 out:
    return rv;
}

#endif /* COMPAT */

static int flask_security_resolve_bool(struct xen_flask_boolean *arg)
{
    char *name;

    if ( arg->bool_id != -1 )
        return 0;

    name = safe_copy_string_from_guest(arg->name, arg->size, PAGE_SIZE);
    if ( IS_ERR(name) )
        return PTR_ERR(name);

    arg->bool_id = security_find_bool(name);
    arg->size = 0;

    xfree(name);

    return 0;
}

static int flask_security_set_bool(struct xen_flask_boolean *arg)
{
    int rv;

    rv = domain_has_security(current->domain, SECURITY__SETBOOL);
    if ( rv )
        return rv;

    rv = flask_security_resolve_bool(arg);
    if ( rv )
        return rv;

    spin_lock(&sel_sem);

    if ( arg->commit )
    {
        int num;
        int *values;

        rv = security_get_bools(&num, NULL, &values, NULL);
        if ( rv != 0 )
            goto out;

        if ( arg->bool_id >= num )
        {
            xfree(values);
            rv = -ENOENT;
            goto out;
        }
        values[arg->bool_id] = !!(arg->new_value);

        arg->enforcing = arg->pending = !!(arg->new_value);

        if ( bool_pending_values )
            bool_pending_values[arg->bool_id] = !!(arg->new_value);

        rv = security_set_bools(num, values);
        xfree(values);
    }
    else
    {
        if ( !bool_pending_values )
            rv = flask_security_make_bools();
        if ( !rv && arg->bool_id >= bool_num )
            rv = -ENOENT;
        if ( rv )
            goto out;

        bool_pending_values[arg->bool_id] = !!(arg->new_value);
        arg->pending = !!(arg->new_value);
        arg->enforcing = security_get_bool_value(arg->bool_id);

        rv = 0;
    }

 out:
    spin_unlock(&sel_sem);
    return rv;
}

static int flask_security_get_bool(struct xen_flask_boolean *arg)
{
    int rv;

    rv = flask_security_resolve_bool(arg);
    if ( rv )
        return rv;

    spin_lock(&sel_sem);

    rv = security_get_bool_value(arg->bool_id);
    if ( rv < 0 )
        goto out;

    arg->enforcing = rv;

    if ( bool_pending_values )
        arg->pending = bool_pending_values[arg->bool_id];
    else
        arg->pending = rv;

    rv = 0;

    if ( arg->size )
    {
        char *nameout = security_get_bool_name(arg->bool_id);
        size_t nameout_len = strlen(nameout);
        if ( nameout_len > arg->size )
            rv = -ERANGE;
        arg->size = nameout_len;
 
        if ( !rv && _copy_to_guest(arg->name, nameout, nameout_len) )
            rv = -EFAULT;
        xfree(nameout);
    }

 out:
    spin_unlock(&sel_sem);
    return rv;
}

#ifndef COMPAT

static int flask_security_commit_bools(void)
{
    int rv;

    spin_lock(&sel_sem);

    rv = domain_has_security(current->domain, SECURITY__SETBOOL);
    if ( rv )
        goto out;

    if ( bool_pending_values )
        rv = security_set_bools(bool_num, bool_pending_values);

 out:
    spin_unlock(&sel_sem);
    return rv;
}

static int flask_security_make_bools(void)
{
    int ret = 0;
    int num;
    int *values = NULL;
    
    xfree(bool_pending_values);
    
    ret = security_get_bools(&num, NULL, &values, NULL);
    if ( ret != 0 )
        goto out;

    bool_num = num;
    bool_pending_values = values;

 out:
    return ret;
}

#ifdef FLASK_AVC_STATS

static int flask_security_avc_cachestats(struct xen_flask_cache_stats *arg)
{
    struct avc_cache_stats *st;

    if ( arg->cpu >= nr_cpu_ids )
        return -ENOENT;
    if ( !cpu_online(arg->cpu) )
        return -ENOENT;

    st = &per_cpu(avc_cache_stats, arg->cpu);

    arg->lookups = st->lookups;
    arg->hits = st->hits;
    arg->misses = st->misses;
    arg->allocations = st->allocations;
    arg->reclaims = st->reclaims;
    arg->frees = st->frees;

    return 0;
}

#endif
#endif /* COMPAT */

static int flask_security_load(struct xen_flask_load *load)
{
    int ret;
    void *buf = NULL;
    bool_t is_reload = ss_initialized;

    ret = domain_has_security(current->domain, SECURITY__LOAD_POLICY);
    if ( ret )
        return ret;

    if ( load->size > MAX_POLICY_SIZE )
        return -EINVAL;

    buf = xmalloc_bytes(load->size);
    if ( !buf )
        return -ENOMEM;

    if ( _copy_from_guest(buf, load->buffer, load->size) )
    {
        ret = -EFAULT;
        goto out_free;
    }

    spin_lock(&sel_sem);

    ret = security_load_policy(buf, load->size);
    if ( ret )
        goto out;

    if ( !is_reload )
        printk(XENLOG_INFO "Flask: Policy loaded, continuing in %s mode.\n",
            flask_enforcing ? "enforcing" : "permissive");

    xfree(bool_pending_values);
    bool_pending_values = NULL;
    ret = 0;

 out:
    spin_unlock(&sel_sem);
 out_free:
    xfree(buf);
    return ret;
}

static int flask_devicetree_label(struct xen_flask_devicetree_label *arg)
{
    int rv;
    char *buf;
    u32 sid = arg->sid;
    u32 perm = sid ? SECURITY__ADD_OCONTEXT : SECURITY__DEL_OCONTEXT;

    rv = domain_has_security(current->domain, perm);
    if ( rv )
        return rv;

    buf = safe_copy_string_from_guest(arg->path, arg->length, PAGE_SIZE);
    if ( IS_ERR(buf) )
        return PTR_ERR(buf);

    /* buf is consumed or freed by this function */
    rv = security_devicetree_setlabel(buf, sid);

    return rv;
}

#ifndef COMPAT

static int flask_ocontext_del(struct xen_flask_ocontext *arg)
{
    int rv;

    if ( arg->low > arg->high )
        return -EINVAL;

    rv = domain_has_security(current->domain, SECURITY__DEL_OCONTEXT);
    if ( rv )
        return rv;

    return security_ocontext_del(arg->ocon, arg->low, arg->high);
}

static int flask_ocontext_add(struct xen_flask_ocontext *arg)
{
    int rv;

    if ( arg->low > arg->high )
        return -EINVAL;

    rv = domain_has_security(current->domain, SECURITY__ADD_OCONTEXT);
    if ( rv )
        return rv;

    return security_ocontext_add(arg->ocon, arg->low, arg->high, arg->sid);
}

static int flask_get_peer_sid(struct xen_flask_peersid *arg)
{
    int rv = -EINVAL;
    struct domain *d = current->domain;
    struct domain *peer;
    struct evtchn *chn;
    struct domain_security_struct *dsec;

    spin_lock(&d->event_lock);

    if ( !port_is_valid(d, arg->evtchn) )
        goto out;

    chn = evtchn_from_port(d, arg->evtchn);
    if ( chn->state != ECS_INTERDOMAIN )
        goto out;

    peer = chn->u.interdomain.remote_dom;
    if ( !peer )
        goto out;

    dsec = peer->ssid;
    arg->sid = dsec->sid;
    rv = 0;

 out:
    spin_unlock(&d->event_lock);
    return rv;
}

static int flask_relabel_domain(struct xen_flask_relabel *arg)
{
    int rc;
    struct domain *d;
    struct domain_security_struct *csec = current->domain->ssid;
    struct domain_security_struct *dsec;
    struct avc_audit_data ad;
    AVC_AUDIT_DATA_INIT(&ad, NONE);

    d = rcu_lock_domain_by_any_id(arg->domid);
    if ( d == NULL )
        return -ESRCH;

    ad.sdom = current->domain;
    ad.tdom = d;
    dsec = d->ssid;

    if ( arg->domid == DOMID_SELF )
    {
        rc = avc_has_perm(dsec->sid, arg->sid, SECCLASS_DOMAIN2, DOMAIN2__RELABELSELF, &ad);
        if ( rc )
            goto out;
    }
    else
    {
        rc = avc_has_perm(csec->sid, dsec->sid, SECCLASS_DOMAIN2, DOMAIN2__RELABELFROM, &ad);
        if ( rc )
            goto out;

        rc = avc_has_perm(csec->sid, arg->sid, SECCLASS_DOMAIN2, DOMAIN2__RELABELTO, &ad);
        if ( rc )
            goto out;
    }

    rc = avc_has_perm(dsec->sid, arg->sid, SECCLASS_DOMAIN, DOMAIN__TRANSITION, &ad);
    if ( rc )
        goto out;

    dsec->sid = arg->sid;
    dsec->self_sid = arg->sid;
    security_transition_sid(dsec->sid, dsec->sid, SECCLASS_DOMAIN,
                            &dsec->self_sid);
    if ( d->target )
    {
        struct domain_security_struct *tsec = d->target->ssid;
        security_transition_sid(tsec->sid, dsec->sid, SECCLASS_DOMAIN,
                                &dsec->target_sid);
    }

 out:
    rcu_unlock_domain(d);
    return rc;
}

#endif /* !COMPAT */

ret_t do_flask_op(XEN_GUEST_HANDLE_PARAM(xsm_op_t) u_flask_op)
{
    xen_flask_op_t op;
    int rv;

    if ( copy_from_guest(&op, u_flask_op, 1) )
        return -EFAULT;

    if ( op.interface_version != XEN_FLASK_INTERFACE_VERSION )
        return -ENOSYS;

    switch ( op.cmd )
    {
    case FLASK_LOAD:
        rv = flask_security_load(&op.u.load);
        break;

    case FLASK_GETENFORCE:
        rv = flask_enforcing;
        break;

    case FLASK_SETENFORCE:
        rv = flask_security_setenforce(&op.u.enforce);
        break;

    case FLASK_CONTEXT_TO_SID:
        rv = flask_security_context(&op.u.sid_context);
        break;

    case FLASK_SID_TO_CONTEXT:
        rv = flask_security_sid(&op.u.sid_context);
        break;

    case FLASK_ACCESS:
        rv = flask_security_access(&op.u.access);
        break;

    case FLASK_CREATE:
        rv = flask_security_create(&op.u.transition);
        break;

    case FLASK_RELABEL:
        rv = flask_security_relabel(&op.u.transition);
        break;

    case FLASK_USER:
        rv = flask_security_user(&op.u.userlist);
        break;

    case FLASK_POLICYVERS:
        rv = POLICYDB_VERSION_MAX;
        break;

    case FLASK_GETBOOL:
        rv = flask_security_get_bool(&op.u.boolean);
        break;

    case FLASK_SETBOOL:
        rv = flask_security_set_bool(&op.u.boolean);
        break;

    case FLASK_COMMITBOOLS:
        rv = flask_security_commit_bools();
        break;

    case FLASK_MLS:
        rv = flask_mls_enabled;
        break;    

    case FLASK_DISABLE:
        rv = flask_disable();
        break;

    case FLASK_GETAVC_THRESHOLD:
        rv = avc_cache_threshold;
        break;

    case FLASK_SETAVC_THRESHOLD:
        rv = flask_security_setavc_threshold(&op.u.setavc_threshold);
        break;

    case FLASK_AVC_HASHSTATS:
        rv = avc_get_hash_stats(&op.u.hash_stats);
        break;

#ifdef FLASK_AVC_STATS
    case FLASK_AVC_CACHESTATS:
        rv = flask_security_avc_cachestats(&op.u.cache_stats);
        break;
#endif

    case FLASK_MEMBER:
        rv = flask_security_member(&op.u.transition);
        break;

    case FLASK_ADD_OCONTEXT:
        rv = flask_ocontext_add(&op.u.ocontext);
        break;

    case FLASK_DEL_OCONTEXT:
        rv = flask_ocontext_del(&op.u.ocontext);
        break;

    case FLASK_GET_PEER_SID:
        rv = flask_get_peer_sid(&op.u.peersid);
        break;

    case FLASK_RELABEL_DOMAIN:
        rv = flask_relabel_domain(&op.u.relabel);
        break;

    case FLASK_DEVICETREE_LABEL:
        rv = flask_devicetree_label(&op.u.devicetree_label);
        break;

    default:
        rv = -ENOSYS;
    }

    if ( rv < 0 )
        goto out;

    if ( (FLASK_COPY_OUT&(1UL<<op.cmd)) )
    {
        if ( copy_to_guest(u_flask_op, &op, 1) )
            rv = -EFAULT;
    }

 out:
    return rv;
}

#if defined(CONFIG_COMPAT) && !defined(COMPAT)
#undef _copy_to_guest
#define _copy_to_guest copy_to_compat
#undef _copy_from_guest
#define _copy_from_guest copy_from_compat

#include <compat/event_channel.h>
#include <compat/xsm/flask_op.h>

CHECK_flask_access;
CHECK_flask_cache_stats;
CHECK_flask_hash_stats;
CHECK_flask_ocontext;
CHECK_flask_peersid;
CHECK_flask_relabel;
CHECK_flask_setavc_threshold;
CHECK_flask_setenforce;
CHECK_flask_transition;

#define COMPAT
#define safe_copy_string_from_guest(ch, sz, mx) ({ \
    XEN_GUEST_HANDLE_PARAM(char) gh; \
    guest_from_compat_handle(gh, ch); \
    safe_copy_string_from_guest(gh, sz, mx); \
})

#define xen_flask_load compat_flask_load
#define flask_security_load compat_security_load

#define xen_flask_userlist compat_flask_userlist
#define flask_security_user compat_security_user

#define xen_flask_sid_context compat_flask_sid_context
#define flask_security_context compat_security_context
#define flask_security_sid compat_security_sid

#define xen_flask_boolean compat_flask_boolean
#define flask_security_resolve_bool compat_security_resolve_bool
#define flask_security_get_bool compat_security_get_bool
#define flask_security_set_bool compat_security_set_bool

#define xen_flask_devicetree_label compat_flask_devicetree_label
#define flask_devicetree_label compat_devicetree_label

#define xen_flask_op_t compat_flask_op_t
#undef ret_t
#define ret_t int
#define do_flask_op compat_flask_op

#include "flask_op.c"
#endif
