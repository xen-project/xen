/*
 *  This file contains the flask_op hypercall and associated functions.
 *
 *  Author:  George Coker, <gscoker@alpha.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#include <xen/errno.h>
#include <xsm/xsm.h>
#include <xen/guest_access.h>

#include <public/xsm/flask_op.h>

#include <avc.h>
#include <avc_ss.h>
#include <objsec.h>
#include <conditional.h>

#ifdef FLASK_DEVELOP
int flask_enforcing = 0;
integer_param("flask_enforcing", flask_enforcing);
#endif

#ifdef FLASK_BOOTPARAM
int flask_enabled = 1;
integer_param("flask_enabled", flask_enabled);
#endif

static DEFINE_SPINLOCK(sel_sem);

/* global data for booleans */
static int bool_num = 0;
static int *bool_pending_values = NULL;

extern int ss_initialized;

extern struct xsm_operations *original_ops;

static int domain_has_security(struct domain *d, u32 perms)
{
    struct domain_security_struct *dsec;
    
    dsec = d->ssid;
    if ( !dsec )
        return -EACCES;
        
    return avc_has_perm(dsec->sid, SECINITSID_SECURITY, SECCLASS_SECURITY, 
                                                                perms, NULL);
}

static int flask_security_user(char *buf, int size)
{
    char *page = NULL;
    char *con, *user, *ptr;
    u32 sid, *sids;
    int length;
    char *newcon;
    int i, rc;
    u32 len, nsids;
        
    length = domain_has_security(current->domain, SECURITY__COMPUTE_USER);
    if ( length )
        return length;
            
    length = -ENOMEM;
    con = xmalloc_array(char, size+1);
    if ( !con )
        return length;
    memset(con, 0, size+1);
    
    user = xmalloc_array(char, size+1);
    if ( !user )
        goto out;
    memset(user, 0, size+1);
    
    length = -ENOMEM;
    page = xmalloc_bytes(PAGE_SIZE);
    if ( !page )
        goto out2;
    memset(page, 0, PAGE_SIZE);

    length = -EFAULT;
    if ( copy_from_user(page, buf, size) )
        goto out2;
        
    length = -EINVAL;
    if ( sscanf(page, "%s %s", con, user) != 2 )
        goto out2;

    length = security_context_to_sid(con, strlen(con)+1, &sid);
    if ( length < 0 )
        goto out2;
            
    length = security_get_user_sids(sid, user, &sids, &nsids);
    if ( length < 0 )
        goto out2;
    
    memset(page, 0, PAGE_SIZE);
    length = snprintf(page, PAGE_SIZE, "%u", nsids) + 1;
    ptr = page + length;
    for ( i = 0; i < nsids; i++ )
    {
        rc = security_sid_to_context(sids[i], &newcon, &len);
        if ( rc )
        {
            length = rc;
            goto out3;
        }
        if ( (length + len) >= PAGE_SIZE )
        {
            xfree(newcon);
            length = -ERANGE;
            goto out3;
        }
        memcpy(ptr, newcon, len);
        xfree(newcon);
        ptr += len;
        length += len;
    }
    
    if ( copy_to_user(buf, page, length) )
        length = -EFAULT;
        
out3:
    xfree(sids);
out2:
    if ( page )
        xfree(page);
    xfree(user);
out:
    xfree(con);
    return length;
}

static int flask_security_relabel(char *buf, int size)
{
    char *scon, *tcon;
    u32 ssid, tsid, newsid;
    u16 tclass;
    int length;
    char *newcon;
    u32 len;

    length = domain_has_security(current->domain, SECURITY__COMPUTE_RELABEL);
    if ( length )
        return length;
            
    length = -ENOMEM;
    scon = xmalloc_array(char, size+1);
    if ( !scon )
        return length;
    memset(scon, 0, size+1);
        
    tcon = xmalloc_array(char, size+1);
    if ( !tcon )
        goto out;
    memset(tcon, 0, size+1);
        
    length = -EINVAL;
    if ( sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3 )
        goto out2;
            
    length = security_context_to_sid(scon, strlen(scon)+1, &ssid);
    if ( length < 0 )
        goto out2;
    length = security_context_to_sid(tcon, strlen(tcon)+1, &tsid);
    if ( length < 0 )
        goto out2;
            
    length = security_change_sid(ssid, tsid, tclass, &newsid);
    if ( length < 0 )
        goto out2;
            
    length = security_sid_to_context(newsid, &newcon, &len);
    if ( length < 0 )
        goto out2;
            
    if ( len > PAGE_SIZE )
    {
        length = -ERANGE;
        goto out3;
    }
        
    if ( copy_to_user(buf, newcon, len) )
        len = -EFAULT;

    length = len;
        
out3:
    xfree(newcon);
out2:
    xfree(tcon);
out:
    xfree(scon);
    return length;
}

static int flask_security_create(char *buf, int size)
{
    char *scon, *tcon;
    u32 ssid, tsid, newsid;
    u16 tclass;
    int length;
    char *newcon;
    u32 len;

    length = domain_has_security(current->domain, SECURITY__COMPUTE_CREATE);
    if ( length )
        return length;

    length = -ENOMEM;
    scon = xmalloc_array(char, size+1);
    if ( !scon )
        return length;
    memset(scon, 0, size+1);

    tcon = xmalloc_array(char, size+1);
    if ( !tcon )
        goto out;
    memset(tcon, 0, size+1);

    length = -EINVAL;
    if ( sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3 )
        goto out2;

    length = security_context_to_sid(scon, strlen(scon)+1, &ssid);
    if ( length < 0 )
        goto out2;

    length = security_context_to_sid(tcon, strlen(tcon)+1, &tsid);
    if ( length < 0 )
        goto out2;

    length = security_transition_sid(ssid, tsid, tclass, &newsid);
    if ( length < 0 )
        goto out2;

    length = security_sid_to_context(newsid, &newcon, &len);
    if ( length < 0 )    
        goto out2;

    if ( len > PAGE_SIZE )
    {
        printk( "%s:  context size (%u) exceeds payload "
                "max\n", __FUNCTION__, len);
        length = -ERANGE;
        goto out3;
    }

    if ( copy_to_user(buf, newcon, len) )
        len = -EFAULT;

    length = len;
        
out3:
    xfree(newcon);
out2:
    xfree(tcon);
out:
    xfree(scon);
    return length;
}

static int flask_security_access(char *buf, int size)
{
    char *page = NULL;
    char *scon, *tcon;
    u32 ssid, tsid;
    u16 tclass;
    u32 req;
    struct av_decision avd;
    int length;

    length = domain_has_security(current->domain, SECURITY__COMPUTE_AV);
    if ( length )
        return length;

    length = -ENOMEM;
    scon = xmalloc_array(char, size+1);
    if (!scon)
        return length;
    memset(scon, 0, size+1);

    tcon = xmalloc_array(char, size+1);
    if ( !tcon )
        goto out;
    memset( tcon, 0, size+1 );

    length = -EINVAL;
    if (sscanf(buf, "%s %s %hu %x", scon, tcon, &tclass, &req) != 4)
        goto out2;

    length = security_context_to_sid(scon, strlen(scon)+1, &ssid);
    if ( length < 0 )
        goto out2;

    length = security_context_to_sid(tcon, strlen(tcon)+1, &tsid);
    if ( length < 0 )
        goto out2;

    length = security_compute_av(ssid, tsid, tclass, req, &avd);
    if ( length < 0 )
        goto out2;

    page = (char *)xmalloc_bytes(PAGE_SIZE);
    if ( !page )
    {
        length = -ENOMEM;
        goto out2;
    }

    memset(page, 0, PAGE_SIZE);

    length = snprintf(page, PAGE_SIZE, "%x %x %x %x %u", 
                                        avd.allowed, avd.decided,
                                        avd.auditallow, avd.auditdeny, 
                                        avd.seqno);
                
    if ( copy_to_user(buf, page, length) )
        length = -EFAULT;
        
out2:
    xfree(tcon);
out:
    xfree(scon);
    return length;
}

static int flask_security_member(char *buf, int size)
{
    char *scon, *tcon;
    u32 ssid, tsid, newsid;
    u16 tclass;
    int length;
    char *newcon;
    u32 len;

    length = domain_has_security(current->domain, SECURITY__COMPUTE_MEMBER);
    if ( length )
        return length;

    length = -ENOMEM;
    scon = xmalloc_array(char, size+1);
    if ( !scon )
        return length;
    memset(scon, 0, size+1);

    tcon = xmalloc_array(char, size+1);
    if ( !tcon )
        goto out;
    memset(tcon, 0, size+1);

    length = -EINVAL;
    if ( sscanf(buf, "%s, %s, %hu", scon, tcon, &tclass) != 3 )
        goto out2;

    length = security_context_to_sid(scon, strlen(scon)+1, &ssid);
    if ( length < 0 )
        goto out2;

    length = security_context_to_sid(tcon, strlen(tcon)+1, &tsid);
    if ( length < 0 )
        goto out2;

    length = security_member_sid(ssid, tsid, tclass, &newsid);
    if ( length < 0 )
        goto out2;

    length = security_sid_to_context(newsid, &newcon, &len);
    if ( length < 0 )
        goto out2;

    if ( len > PAGE_SIZE )
    {
        printk("%s:  context size (%u) exceeds payload "
                "max\n", __FUNCTION__, len);
        length = -ERANGE;
        goto out3;
    }

    if ( copy_to_user(buf, newcon, len) )
        len = -EFAULT;

    length = len;

out3:
    xfree(newcon);
out2:
    xfree(tcon);
out:
    xfree(scon);
    return length;
}

static int flask_security_setenforce(char *buf, int count)
{
    char *page = NULL;
    int length;
    int new_value;

    if ( count < 0 || count >= PAGE_SIZE )
        return -ENOMEM;

    page = (char *)xmalloc_bytes(PAGE_SIZE);
    if ( !page )
        return -ENOMEM;
    memset(page, 0, PAGE_SIZE);
    length = -EFAULT;
    if ( copy_from_user(page, buf, count) )
        goto out;

    length = -EINVAL;
    if ( sscanf(page, "%d", &new_value) != 1 )
        goto out;

    if ( new_value != flask_enforcing )
    {
        length = domain_has_security(current->domain, SECURITY__SETENFORCE);
        if ( length )
            goto out;
        flask_enforcing = new_value;
        if ( flask_enforcing )
            avc_ss_reset(0);
    }
    length = count;

out:
    xfree(page);
    return length;
}

static int flask_security_context(char *buf, int count)
{
    char *page = NULL;
    u32 sid;
    int length;

    length = domain_has_security(current->domain, SECURITY__CHECK_CONTEXT);
    if ( length )
        goto out;

    if ( count < 0 || count >= PAGE_SIZE )
        return -ENOMEM;

    page = (char *)xmalloc_bytes(PAGE_SIZE);
    if ( !page )
        return -ENOMEM;
    memset(page, 0, PAGE_SIZE);
    length = -EFAULT;
    if ( copy_from_user(page, buf, count) )
        goto out;

    length = security_context_to_sid(page, count, &sid);
    if ( length < 0 )
        goto out;

    memset(page, 0, PAGE_SIZE);
    length = snprintf(page, PAGE_SIZE, "%u", sid);

    if ( copy_to_user(buf, page, count) )
        length = -EFAULT;

out:
    xfree(page);
    return length;
}

static int flask_security_sid(char *buf, int count)
{
    char *page = NULL;
    char *context;
    u32 sid;
    u32 len;
    int length;

    length = domain_has_security(current->domain, SECURITY__CHECK_CONTEXT);
    if ( length )
        goto out;

    if ( count < 0 || count >= PAGE_SIZE )
        return -ENOMEM;

    page = (char *)xmalloc_bytes(PAGE_SIZE);
    if ( !page )
        return -ENOMEM;
    memset(page, 0, PAGE_SIZE);
    length = -EFAULT;
    if ( copy_from_user(page, buf, count) )
        goto out;

    if ( sscanf(page, "%u", &sid) != 1 )
        goto out;

    length = security_sid_to_context(sid, &context, &len);
    if ( length < 0 )
        goto out;

    if ( copy_to_user(buf, context, len) )
        length = -EFAULT;
    
    xfree(context);

out:
    xfree(page);
    return length;
}

int flask_disable(void)
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

static int flask_security_disable(char *buf, int count)
{
    char *page = NULL;
    int length;
    int new_value;

    if ( count < 0 || count >= PAGE_SIZE )
        return -ENOMEM;
    page = (char *)xmalloc_bytes(PAGE_SIZE);
    if ( !page )
        return -ENOMEM;
    memset(page, 0, PAGE_SIZE);
    length = -EFAULT;
    if ( copy_from_user(page, buf, count) )
        goto out;

    length = -EINVAL;
    if ( sscanf(page, "%d", &new_value) != 1 )
        goto out;

    if ( new_value )
    {
        length = flask_disable();
        if ( length < 0 )
            goto out;
    }

    length = count;

out:
    xfree(page);
    return length;
}

static int flask_security_setavc_threshold(char *buf, int count)
{
    char *page = NULL;
    int ret;
    int new_value;

    if ( count < 0 || count >= PAGE_SIZE )
    {
        ret = -ENOMEM;
        goto out;
    }

    page = (char*)xmalloc_bytes(PAGE_SIZE);
    if (!page)
        return -ENOMEM;
    memset(page, 0, PAGE_SIZE);

    if ( copy_from_user(page, buf, count) )
    {
        ret = -EFAULT;
        goto out_free;
    }

    if ( sscanf(page, "%u", &new_value) != 1 )
    {
        ret = -EINVAL;
        goto out_free;
    }

    if ( new_value != avc_cache_threshold )
    {
        ret = domain_has_security(current->domain, SECURITY__SETSECPARAM);
        if ( ret )
            goto out_free;
        avc_cache_threshold = new_value;
    }
    ret = count;

out_free:
    xfree(page);
out:
    return ret;
}

static int flask_security_set_bool(char *buf, int count)
{
    char *page = NULL;
    int length = -EFAULT;
    int i, new_value;

    spin_lock(&sel_sem);

    length = domain_has_security(current->domain, SECURITY__SETBOOL);
    if ( length )
        goto out;

    if ( count < 0 || count >= PAGE_SIZE )
    {
        length = -ENOMEM;
        goto out;
    }

    page = (char *)xmalloc_bytes(PAGE_SIZE);
    if ( !page )
    {
        length = -ENOMEM;
        goto out;
    }
    memset(page, 0, PAGE_SIZE);

    if ( copy_from_user(page, buf, count) )
        goto out;

    length = -EINVAL;
    if ( sscanf(page, "%d %d", &i, &new_value) != 2 )
        goto out;

    if ( new_value )
    {
        new_value = 1;
    }

    bool_pending_values[i] = new_value;
    length = count;

out:
    spin_unlock(&sel_sem);
    if ( page )
        xfree(page);
    return length;
}

static int flask_security_commit_bools(char *buf, int count)
{
    char *page = NULL;
    int length = -EFAULT;
    int new_value;

    spin_lock(&sel_sem);

    length = domain_has_security(current->domain, SECURITY__SETBOOL);
    if ( length )
        goto out;

    if ( count < 0 || count >= PAGE_SIZE )
    {
        length = -ENOMEM;
        goto out;
    }

    page = (char *)xmalloc_bytes(PAGE_SIZE);
    if ( !page )
    {
        length = -ENOMEM;
        goto out;
    }
    memset(page, 0, PAGE_SIZE);

    if ( copy_from_user(page, buf, count) )
        goto out;

    length = -EINVAL;
    if ( sscanf(page, "%d", &new_value) != 1 )
        goto out;

    if ( new_value )
        security_set_bools(bool_num, bool_pending_values);
    
    length = count;

out:
    spin_unlock(&sel_sem);
    if ( page )
        xfree(page);
    return length;
}

static int flask_security_get_bool(char *buf, int count)
{
    char *page = NULL;
    int length;
    int i, cur_enforcing;
    
    spin_lock(&sel_sem);
    
    length = -EFAULT;

    if ( count < 0 || count > PAGE_SIZE )
    {
        length = -EINVAL;
        goto out;
    }

    page = (char *)xmalloc_bytes(PAGE_SIZE);
    if ( !page )
    {
        length = -ENOMEM;
        goto out;
    }
    memset(page, 0, PAGE_SIZE);

    if ( copy_from_user(page, buf, count) )
        goto out;

    length = -EINVAL;
    if ( sscanf(page, "%d", &i) != 1 )
        goto out;

    cur_enforcing = security_get_bool_value(i);
    if ( cur_enforcing < 0 )
    {
        length = cur_enforcing;
        goto out;
    }

    length = snprintf(page, PAGE_SIZE, "%d %d", cur_enforcing,
                bool_pending_values[i]);
    if ( length < 0 )
        goto out;

    if ( copy_to_user(buf, page, length) )
        length = -EFAULT;

out:
    spin_unlock(&sel_sem);
    if ( page )
        xfree(page);
    return length;
}

static int flask_security_make_bools(void)
{
    int i, ret = 0;
    char **names = NULL;
    int num;
    int *values = NULL;
    
    xfree(bool_pending_values);
    
    ret = security_get_bools(&num, &names, &values);
    if ( ret != 0 )
        goto out;

    bool_num = num;
    bool_pending_values = values;

out:
    if ( names )
    {
        for ( i = 0; i < num; i++ )
            xfree(names[i]);
        xfree(names);
    }    
    return ret;
}

#ifdef FLASK_AVC_STATS

static int flask_security_avc_cachestats(char *buf, int count)
{
    char *page = NULL;
    int len = 0;
    int length = 0;
    long long idx = 0;
    int cpu;
    struct avc_cache_stats *st;

    page = (char *)xmalloc_bytes(PAGE_SIZE);
    if ( !page )
        return -ENOMEM;
    memset(page, 0, PAGE_SIZE);

    len = snprintf(page, PAGE_SIZE, "lookups hits misses allocations reclaims "
                                                                   "frees\n");
    memcpy(buf, page, len);
    buf += len;
    length += len;

    for ( cpu = idx; cpu < NR_CPUS; ++cpu )
    {
        if ( !cpu_possible(cpu) )
            continue;
        idx = cpu + 1;
        st = &per_cpu(avc_cache_stats, cpu);

        len = snprintf(page, PAGE_SIZE, "%u %u %u %u %u %u\n", st->lookups,
                                       st->hits, st->misses, st->allocations,
                                                       st->reclaims, st->frees);
        memcpy(buf, page, len);
        buf += len;
        length += len;
    }

    xfree(page);    
    return length;
}

#endif

static int flask_security_load(char *buf, int count)
{
    int ret;
    int length;
    void *data = NULL;

    spin_lock(&sel_sem);

    length = domain_has_security(current->domain, SECURITY__LOAD_POLICY);
    if ( length )
        goto out;

    if ( (count < 0) || (count > 64 * 1024 * 1024) 
                               || (data = xmalloc_array(char, count)) == NULL )
    {
        length = -ENOMEM;
        goto out;
    }

    length = -EFAULT;
    if ( copy_from_user(data, buf, count) != 0 )
        goto out;

    length = security_load_policy(data, count);
    if ( length )
        goto out;

    ret = flask_security_make_bools();
    if ( ret )
        length = ret;
    else
        length = count;

out:
    spin_unlock(&sel_sem);
    xfree(data);
    return length;
}

long do_flask_op(XEN_GUEST_HANDLE(xsm_op_t) u_flask_op)
{
    flask_op_t curop, *op = &curop;
    int rc = 0;
    int length = 0;
    char *page = NULL;

    if ( copy_from_guest(op, u_flask_op, 1) )
        return -EFAULT;

    switch ( op->cmd )
    {

    case FLASK_LOAD:
    {
        length = flask_security_load(op->buf, op->size);
    }
    break;
    
    case FLASK_GETENFORCE:
    {
        page = (char *)xmalloc_bytes(PAGE_SIZE);
        if ( !page )
            return -ENOMEM;
        memset(page, 0, PAGE_SIZE);
        
        length = snprintf(page, PAGE_SIZE, "%d", flask_enforcing);
        
        if ( copy_to_user(op->buf, page, length) )
        {
            rc = -EFAULT;
            goto out;
        }
    }
    break;    

    case FLASK_SETENFORCE:
    {
        length = flask_security_setenforce(op->buf, op->size);
    }
    break;    

    case FLASK_CONTEXT_TO_SID:
    {
        length = flask_security_context(op->buf, op->size);
    }
    break;    

    case FLASK_SID_TO_CONTEXT:
    {
        length = flask_security_sid(op->buf, op->size);
    }
    break; 

    case FLASK_ACCESS:
    {
        length = flask_security_access(op->buf, op->size);
    }
    break;    

    case FLASK_CREATE:
    {
        length = flask_security_create(op->buf, op->size);
    }
    break;    

    case FLASK_RELABEL:
    {
        length = flask_security_relabel(op->buf, op->size);
    }
    break;

    case FLASK_USER:
    {
        length = flask_security_user(op->buf, op->size);
    }
    break;    

    case FLASK_POLICYVERS:
    {
        page = (char *)xmalloc_bytes(PAGE_SIZE);
        if ( !page )
            return -ENOMEM;
        memset(page, 0, PAGE_SIZE);

        length = snprintf(page, PAGE_SIZE, "%d", POLICYDB_VERSION_MAX);

        if ( copy_to_user(op->buf, page, length) )
        {
            rc = -EFAULT;
            goto out;
        }
    }
    break;    

    case FLASK_GETBOOL:
    {
        length = flask_security_get_bool(op->buf, op->size);
    }
    break;

    case FLASK_SETBOOL:
    {
        length = flask_security_set_bool(op->buf, op->size);
    }
    break;

    case FLASK_COMMITBOOLS:
    {
        length = flask_security_commit_bools(op->buf, op->size);
    }
    break;

    case FLASK_MLS:
    {
        page = (char *)xmalloc_bytes(PAGE_SIZE);
        if ( !page )
            return -ENOMEM;
        memset(page, 0, PAGE_SIZE);

        length = snprintf(page, PAGE_SIZE, "%d", flask_mls_enabled);

        if ( copy_to_user(op->buf, page, length) )
        {
            rc = -EFAULT;
            goto out;
        }
    }
    break;    

    case FLASK_DISABLE:
    {
        length = flask_security_disable(op->buf, op->size);
    }
    break;    

    case FLASK_GETAVC_THRESHOLD:
    {
        page = (char *)xmalloc_bytes(PAGE_SIZE);
        if ( !page )
            return -ENOMEM;
        memset(page, 0, PAGE_SIZE);

        length = snprintf(page, PAGE_SIZE, "%d", avc_cache_threshold);

        if ( copy_to_user(op->buf, page, length) )
        {
            rc = -EFAULT;
            goto out;
        }
    }
    break;

    case FLASK_SETAVC_THRESHOLD:
    {
        length = flask_security_setavc_threshold(op->buf, op->size);
    }
    break;

    case FLASK_AVC_HASHSTATS:
    {
        page = (char *)xmalloc_bytes(PAGE_SIZE);
        if ( !page )
            return -ENOMEM;
        memset(page, 0, PAGE_SIZE);

        length = avc_get_hash_stats(page);

        if ( copy_to_user(op->buf, page, length) )
        {
            rc = -EFAULT;
            goto out;
        }
    }
    break;

#ifdef FLASK_AVC_STATS    
    case FLASK_AVC_CACHESTATS:
    {
        length = flask_security_avc_cachestats(op->buf, op->size);
    }
    break;
#endif    

    case FLASK_MEMBER:
    {
        length = flask_security_member(op->buf, op->size);
    }
    break;    

    default:
        length = -ENOSYS;
        break;

    }

    if ( length < 0 )
    {
        rc = length;
        goto out;
    }
    op->size = length;
    if ( copy_to_guest(u_flask_op, op, 1) )
        rc = -EFAULT;

out:
    if ( page )
        xfree(page);
    return rc;
}

