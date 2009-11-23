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

#define MAX_POLICY_SIZE 0x4000000
#define FLASK_COPY_IN \
    ( \
        1UL<<FLASK_LOAD | \
        1UL<<FLASK_SETENFORCE | \
        1UL<<FLASK_CONTEXT_TO_SID | \
        1UL<<FLASK_SID_TO_CONTEXT | \
        1UL<<FLASK_ACCESS | \
        1UL<<FLASK_CREATE | \
        1UL<<FLASK_RELABEL | \
        1UL<<FLASK_USER | \
        1UL<<FLASK_GETBOOL | \
        1UL<<FLASK_SETBOOL | \
        1UL<<FLASK_COMMITBOOLS | \
        1UL<<FLASK_DISABLE | \
        1UL<<FLASK_SETAVC_THRESHOLD | \
        1UL<<FLASK_MEMBER | \
        1UL<<FLASK_ADD_OCONTEXT | \
        1UL<<FLASK_DEL_OCONTEXT \
    )

#define FLASK_COPY_OUT \
    ( \
        1UL<<FLASK_GETENFORCE | \
        1UL<<FLASK_CONTEXT_TO_SID | \
        1UL<<FLASK_SID_TO_CONTEXT | \
        1UL<<FLASK_ACCESS | \
        1UL<<FLASK_CREATE | \
        1UL<<FLASK_RELABEL | \
        1UL<<FLASK_USER | \
        1UL<<FLASK_POLICYVERS | \
        1UL<<FLASK_GETBOOL | \
        1UL<<FLASK_MLS | \
        1UL<<FLASK_GETAVC_THRESHOLD | \
        1UL<<FLASK_AVC_HASHSTATS | \
        1UL<<FLASK_AVC_CACHESTATS | \
        1UL<<FLASK_MEMBER \
    )

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

static int flask_security_user(char *buf, uint32_t size)
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

    length = -EINVAL;
    if ( sscanf(buf, "%s %s", con, user) != 2 )
        goto out2;

    length = security_context_to_sid(con, strlen(con)+1, &sid);
    if ( length < 0 )
        goto out2;
            
    length = security_get_user_sids(sid, user, &sids, &nsids);
    if ( length < 0 )
        goto out2;
    
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
    
    if ( length > size )
    {
        printk( "%s:  context size (%u) exceeds payload "
                "max\n", __FUNCTION__, length);
        length = -ERANGE;
        goto out3;
    }

    memset(buf, 0, size);
    memcpy(buf, page, length);
        
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

static int flask_security_relabel(char *buf, uint32_t size)
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
            
    if ( len > size )
    {
        printk( "%s:  context size (%u) exceeds payload "
                "max\n", __FUNCTION__, len);
        length = -ERANGE;
        goto out3;
    }

    memset(buf, 0, size);
    memcpy(buf, newcon, len);
    length = len;

out3:
    xfree(newcon);
out2:
    xfree(tcon);
out:
    xfree(scon);
    return length;
}

static int flask_security_create(char *buf, uint32_t size)
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

    if ( len > size )
    {
        printk( "%s:  context size (%u) exceeds payload "
                "max\n", __FUNCTION__, len);
        length = -ERANGE;
        goto out3;
    }

    memset(buf, 0, size);
    memcpy(buf, newcon, len);
    length = len;
        
out3:
    xfree(newcon);
out2:
    xfree(tcon);
out:
    xfree(scon);
    return length;
}

static int flask_security_access(char *buf, uint32_t size)
{
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

    memset(buf, 0, size);
    length = snprintf(buf, size, "%x %x %x %x %u", 
                                        avd.allowed, 0xffffffff,
                                        avd.auditallow, avd.auditdeny, 
                                        avd.seqno);
                
out2:
    xfree(tcon);
out:
    xfree(scon);
    return length;
}

static int flask_security_member(char *buf, uint32_t size)
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

    if ( len > size )
    {
        printk("%s:  context size (%u) exceeds payload "
                "max\n", __FUNCTION__, len);
        length = -ERANGE;
        goto out3;
    }

    memset(buf, 0, size);
    memcpy(buf, newcon, len);
    length = len;

out3:
    xfree(newcon);
out2:
    xfree(tcon);
out:
    xfree(scon);
    return length;
}

static int flask_security_setenforce(char *buf, uint32_t count)
{
    int length;
    int new_value;

    if ( sscanf(buf, "%d", &new_value) != 1 )
        return -EINVAL;

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
    return length;
}

static int flask_security_context(char *buf, uint32_t count)
{
    u32 sid;
    int length;

    length = domain_has_security(current->domain, SECURITY__CHECK_CONTEXT);
    if ( length )
        goto out;

    length = security_context_to_sid(buf, count, &sid);
    if ( length < 0 )
        goto out;

    memset(buf, 0, count);
    length = snprintf(buf, count, "%u", sid);

out:
    return length;
}

static int flask_security_sid(char *buf, uint32_t count)
{
    char *context;
    u32 sid;
    u32 len;
    int length;

    length = domain_has_security(current->domain, SECURITY__CHECK_CONTEXT);
    if ( length )
        goto out;

    if ( sscanf(buf, "%u", &sid) != 1 )
        goto out;

    length = security_sid_to_context(sid, &context, &len);
    if ( length < 0 )
        goto out;

    memset(buf, 0, count);
    memcpy(buf, context, len);
    length = len;

    xfree(context);

out:
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

static int flask_security_disable(char *buf, uint32_t count)
{
    int length;
    int new_value;

    length = -EINVAL;
    if ( sscanf(buf, "%d", &new_value) != 1 )
        goto out;

    if ( new_value )
    {
        length = flask_disable();
        if ( length < 0 )
            goto out;
    }

    length = count;

out:
    return length;
}

static int flask_security_setavc_threshold(char *buf, uint32_t count)
{
    int ret;
    int new_value;

    if ( sscanf(buf, "%u", &new_value) != 1 )
    {
        ret = -EINVAL;
        goto out;
    }

    if ( new_value != avc_cache_threshold )
    {
        ret = domain_has_security(current->domain, SECURITY__SETSECPARAM);
        if ( ret )
            goto out;
        avc_cache_threshold = new_value;
    }
    ret = count;

out:
    return ret;
}

static int flask_security_set_bool(char *buf, uint32_t count)
{
    int length = -EFAULT;
    int i, new_value;

    spin_lock(&sel_sem);

    length = domain_has_security(current->domain, SECURITY__SETBOOL);
    if ( length )
        goto out;

    length = -EINVAL;
    if ( sscanf(buf, "%d %d", &i, &new_value) != 2 )
        goto out;

    if ( new_value )
    {
        new_value = 1;
    }

    bool_pending_values[i] = new_value;
    length = count;

out:
    spin_unlock(&sel_sem);
    return length;
}

static int flask_security_commit_bools(char *buf, uint32_t count)
{
    int length = -EFAULT;
    int new_value;

    spin_lock(&sel_sem);

    length = domain_has_security(current->domain, SECURITY__SETBOOL);
    if ( length )
        goto out;

    length = -EINVAL;
    if ( sscanf(buf, "%d", &new_value) != 1 )
        goto out;

    if ( new_value )
        security_set_bools(bool_num, bool_pending_values);
    
    length = count;

out:
    spin_unlock(&sel_sem);
    return length;
}

static int flask_security_get_bool(char *buf, uint32_t count)
{
    int length;
    int i, cur_enforcing;
    
    spin_lock(&sel_sem);
    
    length = -EINVAL;
    if ( sscanf(buf, "%d", &i) != 1 )
        goto out;

    cur_enforcing = security_get_bool_value(i);
    if ( cur_enforcing < 0 )
    {
        length = cur_enforcing;
        goto out;
    }

    memset(buf, 0, count);
    length = snprintf(buf, count, "%d %d", cur_enforcing,
                bool_pending_values[i]);

out:
    spin_unlock(&sel_sem);
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

static int flask_security_avc_cachestats(char *buf, uint32_t count)
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
    if ( len > count ) {
        length = -EINVAL;
        goto out;
    }
    
    memcpy(buf, page, len);
    buf += len;
    length += len;
    count -= len;

    for ( cpu = idx; cpu < NR_CPUS; ++cpu )
    {
        if ( !cpu_possible(cpu) )
            continue;
        idx = cpu + 1;
        st = &per_cpu(avc_cache_stats, cpu);

        len = snprintf(page, PAGE_SIZE, "%u %u %u %u %u %u\n", st->lookups,
                                       st->hits, st->misses, st->allocations,
                                                       st->reclaims, st->frees);
        if ( len > count ) {
            length = -EINVAL;
            goto out;
        }
        memcpy(buf, page, len);
        buf += len;
        length += len;
        count -= len;
    }

out:
    xfree(page);    
    return length;
}

#endif

static int flask_security_load(char *buf, uint32_t count)
{
    int ret;
    int length;

    spin_lock(&sel_sem);

    length = domain_has_security(current->domain, SECURITY__LOAD_POLICY);
    if ( length )
        goto out;

    length = security_load_policy(buf, count);
    if ( length )
        goto out;

    ret = flask_security_make_bools();
    if ( ret )
        length = ret;
    else
        length = count;

out:
    spin_unlock(&sel_sem);
    return length;
}

static int flask_ocontext_del(char *buf, uint32_t size)
{
    int len = 0;
    char *ocontext;
    unsigned long low  = 0;
    unsigned long high = 0;

    len = domain_has_security(current->domain, SECURITY__DEL_OCONTEXT);
    if ( len )
        return len;

    if ( (ocontext = xmalloc_bytes(size) ) == NULL )
        return -ENOMEM;

    len = sscanf(buf, "%s %lu %lu", ocontext, &low, &high);
    if ( len < 2 )
    {
        len = -EINVAL;
        goto out;
    }
    else if ( len == 2 )
        high = low;

    if ( low > high )
    {
        len = -EINVAL;
        goto out;
    }

    len = security_ocontext_del(ocontext, low, high);
  out:
    xfree(ocontext);
    return len;
}

static int flask_ocontext_add(char *buf, uint32_t size)
{
    int len = 0;
    u32 sid = 0;
    unsigned long low  = 0;
    unsigned long high = 0;
    char *scontext;
    char *ocontext;

    len = domain_has_security(current->domain, SECURITY__ADD_OCONTEXT);
    if ( len )
        return len;

    if ( (scontext = xmalloc_bytes(size) ) == NULL )
        return -ENOMEM;

    if ( (ocontext = xmalloc_bytes(size) ) == NULL )
    {
        xfree(scontext);
        return -ENOMEM;
    }

    memset(scontext, 0, size);
    memset(ocontext, 0, size);

    len = sscanf(buf, "%s %s %lu %lu", ocontext, scontext, &low, &high);
    if ( len < 3 )
    {
        len = -EINVAL;
        goto out;
    }
    else if ( len == 3 )
        high = low;

    if ( low > high )
    {
        len = -EINVAL;
        goto out;
    }
    len = security_context_to_sid(scontext, strlen(scontext)+1, &sid);
    if ( len < 0 )
    {
        len = -EINVAL;
        goto out;
    }
    len = security_ocontext_add(ocontext, low, high, sid);
out:
    xfree(ocontext);
    xfree(scontext);
    return len;
}

long do_flask_op(XEN_GUEST_HANDLE(xsm_op_t) u_flask_op)
{
    flask_op_t curop, *op = &curop;
    int rc = 0;
    int length = 0;
    char *arg = NULL;

    if ( copy_from_guest(op, u_flask_op, 1) )
        return -EFAULT;

    if ( op->cmd > FLASK_LAST)
        return -EINVAL;

    if ( op->size > MAX_POLICY_SIZE )
        return -EINVAL;

    if ( (op->buf == NULL && op->size != 0) || 
                                    (op->buf != NULL && op->size == 0) )
        return -EINVAL;

    arg = xmalloc_bytes(op->size + 1);
    if ( !arg )
        return -ENOMEM;

    memset(arg, 0, op->size + 1);

    if ( (FLASK_COPY_IN&(1UL<<op->cmd)) && op->buf != NULL && 
           copy_from_guest(arg, guest_handle_from_ptr(op->buf, char), op->size) )
    {
        rc = -EFAULT;
        goto out;
    }

    switch ( op->cmd )
    {

    case FLASK_LOAD:
    {
        length = flask_security_load(arg, op->size);
    }
    break;
    
    case FLASK_GETENFORCE:
    {
        length = snprintf(arg, op->size, "%d", flask_enforcing);
    }
    break;    

    case FLASK_SETENFORCE:
    {
        length = flask_security_setenforce(arg, op->size);
    }
    break;    

    case FLASK_CONTEXT_TO_SID:
    {
        length = flask_security_context(arg, op->size);
    }
    break;    

    case FLASK_SID_TO_CONTEXT:
    {
        length = flask_security_sid(arg, op->size);
    }
    break; 

    case FLASK_ACCESS:
    {
        length = flask_security_access(arg, op->size);
    }
    break;    

    case FLASK_CREATE:
    {
        length = flask_security_create(arg, op->size);
    }
    break;    

    case FLASK_RELABEL:
    {
        length = flask_security_relabel(arg, op->size);
    }
    break;

    case FLASK_USER:
    {
        length = flask_security_user(arg, op->size);
    }
    break;    

    case FLASK_POLICYVERS:
    {
        length = snprintf(arg, op->size, "%d", POLICYDB_VERSION_MAX);
    }
    break;    

    case FLASK_GETBOOL:
    {
        length = flask_security_get_bool(arg, op->size);
    }
    break;

    case FLASK_SETBOOL:
    {
        length = flask_security_set_bool(arg, op->size);
    }
    break;

    case FLASK_COMMITBOOLS:
    {
        length = flask_security_commit_bools(arg, op->size);
    }
    break;

    case FLASK_MLS:
    {
        length = snprintf(arg, op->size, "%d", flask_mls_enabled);
    }
    break;    

    case FLASK_DISABLE:
    {
        length = flask_security_disable(arg, op->size);
    }
    break;    

    case FLASK_GETAVC_THRESHOLD:
    {
        length = snprintf(arg, op->size, "%d", avc_cache_threshold);
    }
    break;

    case FLASK_SETAVC_THRESHOLD:
    {
        length = flask_security_setavc_threshold(arg, op->size);
    }
    break;

    case FLASK_AVC_HASHSTATS:
    {
        length = avc_get_hash_stats(arg, op->size);
    }
    break;

#ifdef FLASK_AVC_STATS    
    case FLASK_AVC_CACHESTATS:
    {
        length = flask_security_avc_cachestats(arg, op->size);
    }
    break;
#endif

    case FLASK_MEMBER:
    {
        length = flask_security_member(arg, op->size);
    }
    break;    

    case FLASK_ADD_OCONTEXT:
    {
        length = flask_ocontext_add(arg, op->size);
        break;
    }

    case FLASK_DEL_OCONTEXT:
    {
        length = flask_ocontext_del(arg, op->size);
        break;
    }

    default:
        length = -ENOSYS;
        break;

    }

    if ( length < 0 )
    {
        rc = length;
        goto out;
    }
    
    if ( (FLASK_COPY_OUT&(1UL<<op->cmd)) && op->buf != NULL && 
             copy_to_guest(guest_handle_from_ptr(op->buf, char), arg, op->size) )
    {
        rc = -EFAULT;
        goto out;
    }

    op->size = length;
    if ( copy_to_guest(u_flask_op, op, 1) )
        rc = -EFAULT;

out:
    xfree(arg);
    return rc;
}
