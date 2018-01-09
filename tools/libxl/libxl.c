/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 * Author Stefano Stabellini <stefano.stabellini@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_osdeps.h"

#include "libxl_internal.h"
#include "libxl_arch.h"

#define PAGE_TO_MEMKB(pages) ((pages) * 4)
#define BACKEND_STRING_SIZE 5

int libxl_ctx_alloc(libxl_ctx **pctx, int version,
                    unsigned flags, xentoollog_logger * lg)
{
    libxl_ctx *ctx = NULL;
    libxl__gc gc_buf, *gc = NULL;
    int rc;

    if (version != LIBXL_VERSION) { rc = ERROR_VERSION; goto out; }

    ctx = malloc(sizeof(*ctx));
    if (!ctx) {
        xtl_log(lg, XTL_ERROR, errno, "libxl",
                "%s:%d:%s: Failed to allocate context\n",
                __FILE__, __LINE__, __func__);
        rc = ERROR_NOMEM; goto out;
    }

    memset(ctx, 0, sizeof(libxl_ctx));
    ctx->lg = lg;

    /* First initialise pointers etc. (cannot fail) */

    ctx->nogc_gc.alloc_maxsize = -1;
    ctx->nogc_gc.owner = ctx;

    LIBXL_TAILQ_INIT(&ctx->occurred);

    ctx->osevent_hooks = 0;

    ctx->poller_app = 0;
    LIBXL_LIST_INIT(&ctx->pollers_event);
    LIBXL_LIST_INIT(&ctx->pollers_idle);
    LIBXL_LIST_INIT(&ctx->pollers_fds_changed);

    LIBXL_LIST_INIT(&ctx->efds);
    LIBXL_TAILQ_INIT(&ctx->etimes);

    ctx->watch_slots = 0;
    LIBXL_SLIST_INIT(&ctx->watch_freeslots);
    libxl__ev_fd_init(&ctx->watch_efd);

    ctx->xce = 0;
    LIBXL_LIST_INIT(&ctx->evtchns_waiting);
    libxl__ev_fd_init(&ctx->evtchn_efd);

    LIBXL_LIST_INIT(&ctx->aos_inprogress);

    LIBXL_TAILQ_INIT(&ctx->death_list);
    libxl__ev_xswatch_init(&ctx->death_watch);

    ctx->childproc_hooks = &libxl__childproc_default_hooks;
    ctx->childproc_user = 0;
        
    ctx->sigchld_selfpipe[0] = -1;
    ctx->sigchld_selfpipe[1] = -1;
    libxl__ev_fd_init(&ctx->sigchld_selfpipe_efd);

    /* The mutex is special because we can't idempotently destroy it */

    if (libxl__init_recursive_mutex(ctx, &ctx->lock) < 0) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Failed to initialize mutex");
        free(ctx);
        ctx = 0;
        rc = ERROR_FAIL;
        goto out;
    }

    /* Now ctx is safe for ctx_free; failures simply set rc and "goto out" */
    LIBXL_INIT_GC(gc_buf,ctx);
    gc = &gc_buf;
    /* Now gc is useable */

    rc = libxl__atfork_init(ctx);
    if (rc) goto out;

    ctx->poller_app = libxl__poller_get(gc);
    if (!ctx->poller_app) {
        rc = ERROR_FAIL;
        goto out;
    }

    ctx->xch = xc_interface_open(lg,lg,0);
    if (!ctx->xch) {
        LOGEV(ERROR, errno, "cannot open libxc handle");
        rc = ERROR_FAIL; goto out;
    }

    ctx->xsh = xs_daemon_open();
    if (!ctx->xsh)
        ctx->xsh = xs_domain_open();
    if (!ctx->xsh) {
        LOGEV(ERROR, errno, "cannot connect to xenstore");
        rc = ERROR_FAIL; goto out;
    }

    *pctx = ctx;
    return 0;

 out:
    if (gc) libxl__free_all(gc);
    libxl_ctx_free(ctx);
    *pctx = NULL;
    return rc;
}

static void free_disable_deaths(libxl__gc *gc,
                                struct libxl__evgen_domain_death_list *l) {
    libxl_evgen_domain_death *death;
    while ((death = LIBXL_TAILQ_FIRST(l)))
        libxl__evdisable_domain_death(gc, death);
}

static void discard_events(struct libxl__event_list *l) {
    /* doesn't bother unlinking from the list, so l is corrupt on return */
    libxl_event *ev, *next;
    LIBXL_TAILQ_FOREACH_SAFE(ev, l, link, next)
        libxl_event_free(0, ev);
}

int libxl_ctx_free(libxl_ctx *ctx)
{
    if (!ctx) return 0;

    int i;
    GC_INIT(ctx);

    CTX_LOCK;
    assert(!ctx->osevent_in_hook);
    CTX->osevent_in_hook += 1000; /* make violations easier to debug */

    /* Deregister all libxl__ev_KINDs: */

    free_disable_deaths(gc, &CTX->death_list);
    free_disable_deaths(gc, &CTX->death_reported);

    libxl_evgen_disk_eject *eject;
    while ((eject = LIBXL_LIST_FIRST(&CTX->disk_eject_evgens)))
        libxl__evdisable_disk_eject(gc, eject);

    libxl_childproc_setmode(CTX,0,0);
    for (i = 0; i < ctx->watch_nslots; i++)
        assert(!libxl__watch_slot_contents(gc, i));
    assert(!libxl__ev_fd_isregistered(&ctx->watch_efd));
    assert(!libxl__ev_fd_isregistered(&ctx->evtchn_efd));
    assert(!libxl__ev_fd_isregistered(&ctx->sigchld_selfpipe_efd));

    /* Now there should be no more events requested from the application: */

    assert(LIBXL_LIST_EMPTY(&ctx->efds));
    assert(LIBXL_TAILQ_EMPTY(&ctx->etimes));
    assert(LIBXL_LIST_EMPTY(&ctx->evtchns_waiting));
    assert(LIBXL_LIST_EMPTY(&ctx->aos_inprogress));

    if (ctx->xch) xc_interface_close(ctx->xch);
    libxl_version_info_dispose(&ctx->version_info);
    if (ctx->xsh) xs_daemon_close(ctx->xsh);
    if (ctx->xce) xenevtchn_close(ctx->xce);

    libxl__poller_put(ctx, ctx->poller_app);
    ctx->poller_app = NULL;
    assert(LIBXL_LIST_EMPTY(&ctx->pollers_event));
    assert(LIBXL_LIST_EMPTY(&ctx->pollers_fds_changed));
    libxl__poller *poller, *poller_tmp;
    LIBXL_LIST_FOREACH_SAFE(poller, &ctx->pollers_idle, entry, poller_tmp) {
        libxl__poller_dispose(poller);
        free(poller);
    }

    free(ctx->watch_slots);

    discard_events(&ctx->occurred);

    /* If we have outstanding children, then the application inherits
     * them; we wish the application good luck with understanding
     * this if and when it reaps them. */
    libxl__sigchld_notneeded(gc);
    libxl__pipe_close(ctx->sigchld_selfpipe);

    CTX_UNLOCK;
    pthread_mutex_destroy(&ctx->lock);

    GC_FREE;
    free(ctx);
    return 0;
}

void libxl_string_list_dispose(libxl_string_list *psl)
{
    int i;
    libxl_string_list sl = *psl;

    if (!sl)
        return;

    for (i = 0; sl[i] != NULL; i++) {
        free(sl[i]);
        sl[i] = NULL;
    }
    free(sl);
    *psl = NULL;
}

void libxl_string_list_copy(libxl_ctx *ctx,
                            libxl_string_list *dst,
                            const libxl_string_list *src)
{
    GC_INIT(ctx);
    int i, len;

    if (!*src) {
        *dst = NULL;
        goto out;
    }

    len = libxl_string_list_length(src);
    /* one extra slot for sentinel */
    *dst = libxl__calloc(NOGC, len + 1, sizeof(char *));

    for (i = 0; i < len; i++)
        (*dst)[i] = libxl__strdup(NOGC, (*src)[i]);

out:
    GC_FREE;
}

int libxl_string_list_length(const libxl_string_list *psl)
{
    int i = 0;

    if (*psl)
        while ((*psl)[i])
            i++;

    return i;
}

int libxl_key_value_list_length(const libxl_key_value_list *pkvl)
{
    int i = 0;
    libxl_key_value_list kvl = *pkvl;

    if (kvl) {
        while (kvl[2 * i]) /* Only checks keys */
            i++;
    }

    return i;
}

void libxl_key_value_list_dispose(libxl_key_value_list *pkvl)
{
    int i;
    libxl_key_value_list kvl = *pkvl;

    if (!kvl)
        return;

    for (i = 0; kvl[i] != NULL; i += 2) {
        free(kvl[i]);
        kvl[i] = NULL;
        if (kvl[i + 1]) {
            free(kvl[i + 1]);
            kvl[i+1] = NULL;
        }
    }
    free(kvl);
    *pkvl = NULL;
}

void libxl_key_value_list_copy(libxl_ctx *ctx,
                               libxl_key_value_list *dst,
                               const libxl_key_value_list *src)
{
    GC_INIT(ctx);
    int i, len;

    if (*src == NULL) {
        *dst = NULL;
        goto out;
    }

    len = libxl_key_value_list_length(src);
    /* one extra slot for sentinel */
    *dst = libxl__calloc(NOGC, len * 2 + 1, sizeof(char *));

    for (i = 0; i < len * 2; i += 2) {
        (*dst)[i] = libxl__strdup(NOGC, (*src)[i]);
        if ((*src)[i+1])
            (*dst)[i+1] = libxl__strdup(NOGC, (*src)[i+1]);
        else
            (*dst)[i+1] = NULL;
    }

out:
    GC_FREE;
}

void libxl_defbool_set(libxl_defbool *db, bool b)
{
    db->val = b ? LIBXL__DEFBOOL_TRUE : LIBXL__DEFBOOL_FALSE;
}

void libxl_defbool_unset(libxl_defbool *db)
{
    db->val = LIBXL__DEFBOOL_DEFAULT;
}

bool libxl_defbool_is_default(libxl_defbool db)
{
    return !db.val;
}

void libxl_defbool_setdefault(libxl_defbool *db, bool b)
{
    if (libxl_defbool_is_default(*db))
        libxl_defbool_set(db, b);
}

bool libxl_defbool_val(libxl_defbool db)
{
    assert(!libxl_defbool_is_default(db));
    return db.val > 0;
}

const char *libxl_defbool_to_string(libxl_defbool b)
{
    if (b.val < 0)
        return LIBXL__DEFBOOL_STR_FALSE;
    else if (b.val > 0)
        return LIBXL__DEFBOOL_STR_TRUE;
    else
        return LIBXL__DEFBOOL_STR_DEFAULT;
}

/******************************************************************************/


int libxl__domain_rename(libxl__gc *gc, uint32_t domid,
                         const char *old_name, const char *new_name,
                         xs_transaction_t trans)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *dom_path = 0;
    const char *name_path;
    char *got_old_name;
    unsigned int got_old_len;
    xs_transaction_t our_trans = 0;
    uint32_t stub_dm_domid;
    const char *stub_dm_old_name = NULL, *stub_dm_new_name = NULL;
    int rc;
    libxl_dominfo info;
    char *uuid;
    const char *vm_name_path;

    libxl_dominfo_init(&info);

    dom_path = libxl__xs_get_dompath(gc, domid);
    if (!dom_path) goto x_nomem;

    name_path= GCSPRINTF("%s/name", dom_path);
    if (!name_path) goto x_nomem;

    stub_dm_domid = libxl_get_stubdom_id(CTX, domid);
    if (stub_dm_domid) {
        stub_dm_old_name = libxl__stub_dm_name(gc, old_name);
        stub_dm_new_name = libxl__stub_dm_name(gc, new_name);
    }

 retry_transaction:
    if (!trans) {
        trans = our_trans = xs_transaction_start(ctx->xsh);
        if (!our_trans) {
            LOGEV(ERROR, errno, "create xs transaction for domain (re)name");
            goto x_fail;
        }
    }

    if (!new_name) {
        LOG(ERROR, "new domain name not specified");
        rc = ERROR_INVAL;
        goto x_rc;
    }

    if (new_name[0]) {
        /* nonempty names must be unique */
        uint32_t domid_e;
        rc = libxl_name_to_domid(ctx, new_name, &domid_e);
        if (rc == ERROR_INVAL) {
            /* no such domain, good */
        } else if (rc != 0) {
            LOG(ERROR, "unexpected error checking for existing domain");
            goto x_rc;
        } else if (domid_e == domid) {
            /* domain already has this name, ok (but we do still
             * need the rest of the code as we may need to check
             * old_name, for example). */
        } else {
            LOG(ERROR, "domain with name \"%s\" already exists.", new_name);
            rc = ERROR_INVAL;
            goto x_rc;
        }
    }

    if (old_name) {
        got_old_name = xs_read(ctx->xsh, trans, name_path, &got_old_len);
        if (!got_old_name) {
            LOGEV(ERROR, errno,
                  "check old name for domain %"PRIu32" allegedly named `%s'",
                  domid,
                  old_name);
            goto x_fail;
        }
        if (strcmp(old_name, got_old_name)) {
            LOG(ERROR,
                "domain %"PRIu32" allegedly named "
                "`%s' is actually named `%s' - racing ?",
                domid,
                old_name,
                got_old_name);
            free(got_old_name);
            goto x_fail;
        }
        free(got_old_name);
    }
    if (!xs_write(ctx->xsh, trans, name_path,
                  new_name, strlen(new_name))) {
        LOG(ERROR,
            "failed to write new name `%s'"
            " for domain %"PRIu32" previously named `%s'",
            new_name,
            domid,
            old_name);
        goto x_fail;
    }

    /* update /vm/<uuid>/name */
    rc = libxl_domain_info(ctx, &info, domid);
    if (rc)
        goto x_rc;

    uuid = GCSPRINTF(LIBXL_UUID_FMT, LIBXL_UUID_BYTES(info.uuid));
    vm_name_path = GCSPRINTF("/vm/%s/name", uuid);
    if (libxl__xs_write_checked(gc, trans, vm_name_path, new_name))
        goto x_fail;

    if (stub_dm_domid) {
        rc = libxl__domain_rename(gc, stub_dm_domid,
                                  stub_dm_old_name,
                                  stub_dm_new_name,
                                  trans);
        if (rc) {
            LOGE(ERROR, "unable to rename stub-domain");
            goto x_rc;
        }
    }

    if (our_trans) {
        if (!xs_transaction_end(ctx->xsh, our_trans, 0)) {
            trans = our_trans = 0;
            if (errno != EAGAIN) {
                LOG(ERROR,
                    "failed to commit new name `%s'"
                    " for domain %"PRIu32" previously named `%s'",
                    new_name,
                    domid,
                    old_name);
                goto x_fail;
            }
            LOG(DEBUG,
                "need to retry rename transaction"
                " for domain %"PRIu32" (name_path=\"%s\", new_name=\"%s\")",
                domid,
                name_path,
                new_name);
            goto retry_transaction;
        }
        our_trans = 0;
    }

    rc = 0;
 x_rc:
    if (our_trans) xs_transaction_end(ctx->xsh, our_trans, 1);
    libxl_dominfo_dispose(&info);
    return rc;

 x_fail:  rc = ERROR_FAIL;  goto x_rc;
 x_nomem: rc = ERROR_NOMEM; goto x_rc;
}

int libxl_domain_rename(libxl_ctx *ctx, uint32_t domid,
                        const char *old_name, const char *new_name)
{
    GC_INIT(ctx);
    int rc;
    rc = libxl__domain_rename(gc, domid, old_name, new_name, XBT_NULL);
    GC_FREE;
    return rc;
}

int libxl_domain_resume(libxl_ctx *ctx, uint32_t domid, int suspend_cancel,
                        const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int rc = libxl__domain_resume(gc, domid, suspend_cancel);
    libxl__ao_complete(egc, ao, rc);
    return AO_INPROGRESS;
}

/*
 * Preserves a domain but rewrites xenstore etc to make it unique so
 * that the domain can be restarted.
 *
 * Does not modify info so that it may be reused.
 */
int libxl_domain_preserve(libxl_ctx *ctx, uint32_t domid,
                          libxl_domain_create_info *info, const char *name_suffix, libxl_uuid new_uuid)
{
    GC_INIT(ctx);
    struct xs_permissions roperm[2];
    xs_transaction_t t;
    char *preserved_name;
    char *uuid_string;
    char *vm_path;
    char *dom_path;

    int rc;

    preserved_name = GCSPRINTF("%s%s", info->name, name_suffix);
    if (!preserved_name) {
        GC_FREE;
        return ERROR_NOMEM;
    }

    uuid_string = libxl__uuid2string(gc, new_uuid);
    if (!uuid_string) {
        GC_FREE;
        return ERROR_NOMEM;
    }

    dom_path = libxl__xs_get_dompath(gc, domid);
    if (!dom_path) {
        GC_FREE;
        return ERROR_FAIL;
    }

    vm_path = GCSPRINTF("/vm/%s", uuid_string);
    if (!vm_path) {
        GC_FREE;
        return ERROR_FAIL;
    }

    roperm[0].id = 0;
    roperm[0].perms = XS_PERM_NONE;
    roperm[1].id = domid;
    roperm[1].perms = XS_PERM_READ;

 retry_transaction:
    t = xs_transaction_start(ctx->xsh);

    xs_rm(ctx->xsh, t, vm_path);
    xs_mkdir(ctx->xsh, t, vm_path);
    xs_set_permissions(ctx->xsh, t, vm_path, roperm, ARRAY_SIZE(roperm));

    xs_write(ctx->xsh, t, GCSPRINTF("%s/vm", dom_path), vm_path, strlen(vm_path));
    rc = libxl__domain_rename(gc, domid, info->name, preserved_name, t);
    if (rc) {
        GC_FREE;
        return rc;
    }

    xs_write(ctx->xsh, t, GCSPRINTF("%s/uuid", vm_path), uuid_string, strlen(uuid_string));

    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;

    GC_FREE;
    return 0;
}

static void xcinfo2xlinfo(libxl_ctx *ctx,
                          const xc_domaininfo_t *xcinfo,
                          libxl_dominfo *xlinfo)
{
    size_t size;

    memcpy(&(xlinfo->uuid), xcinfo->handle, sizeof(xen_domain_handle_t));
    xlinfo->domid = xcinfo->domain;
    xlinfo->ssidref = xcinfo->ssidref;
    if (libxl_flask_sid_to_context(ctx, xlinfo->ssidref,
                                   &xlinfo->ssid_label, &size) < 0)
        xlinfo->ssid_label = NULL;

    xlinfo->dying      = !!(xcinfo->flags&XEN_DOMINF_dying);
    xlinfo->shutdown   = !!(xcinfo->flags&XEN_DOMINF_shutdown);
    xlinfo->paused     = !!(xcinfo->flags&XEN_DOMINF_paused);
    xlinfo->blocked    = !!(xcinfo->flags&XEN_DOMINF_blocked);
    xlinfo->running    = !!(xcinfo->flags&XEN_DOMINF_running);
    xlinfo->never_stop = !!(xcinfo->flags&XEN_DOMINF_xs_domain);

    if (xlinfo->shutdown)
        xlinfo->shutdown_reason = (xcinfo->flags>>XEN_DOMINF_shutdownshift) & XEN_DOMINF_shutdownmask;
    else
        xlinfo->shutdown_reason = LIBXL_SHUTDOWN_REASON_UNKNOWN;

    xlinfo->outstanding_memkb = PAGE_TO_MEMKB(xcinfo->outstanding_pages);
    xlinfo->current_memkb = PAGE_TO_MEMKB(xcinfo->tot_pages);
    xlinfo->shared_memkb = PAGE_TO_MEMKB(xcinfo->shr_pages);
    xlinfo->paged_memkb = PAGE_TO_MEMKB(xcinfo->paged_pages);
    xlinfo->max_memkb = PAGE_TO_MEMKB(xcinfo->max_pages);
    xlinfo->cpu_time = xcinfo->cpu_time;
    xlinfo->vcpu_max_id = xcinfo->max_vcpu_id;
    xlinfo->vcpu_online = xcinfo->nr_online_vcpus;
    xlinfo->cpupool = xcinfo->cpupool;
    xlinfo->domain_type = (xcinfo->flags & XEN_DOMINF_hvm_guest) ?
        LIBXL_DOMAIN_TYPE_HVM : LIBXL_DOMAIN_TYPE_PV;
}

libxl_dominfo * libxl_list_domain(libxl_ctx *ctx, int *nb_domain_out)
{
    libxl_dominfo *ptr = NULL;
    int i, ret;
    xc_domaininfo_t info[1024];
    int size = 0;
    uint32_t domid = 0;
    GC_INIT(ctx);

    while ((ret = xc_domain_getinfolist(ctx->xch, domid, 1024, info)) > 0) {
        ptr = libxl__realloc(NOGC, ptr, (size + ret) * sizeof(libxl_dominfo));
        for (i = 0; i < ret; i++) {
            xcinfo2xlinfo(ctx, &info[i], &ptr[size + i]);
        }
        domid = info[ret - 1].domain + 1;
        size += ret;
    }

    if (ret < 0) {
        LOGE(ERROR, "getting domain info list");
        free(ptr);
        GC_FREE;
        return NULL;
    }

    *nb_domain_out = size;
    GC_FREE;
    return ptr;
}

int libxl_domain_info(libxl_ctx *ctx, libxl_dominfo *info_r,
                      uint32_t domid) {
    xc_domaininfo_t xcinfo;
    int ret;
    GC_INIT(ctx);

    ret = xc_domain_getinfolist(ctx->xch, domid, 1, &xcinfo);
    if (ret<0) {
        LOGE(ERROR, "getting domain info list");
        GC_FREE;
        return ERROR_FAIL;
    }
    if (ret==0 || xcinfo.domain != domid) {
        GC_FREE;
        return ERROR_DOMAIN_NOTFOUND;
    }

    if (info_r)
        xcinfo2xlinfo(ctx, &xcinfo, info_r);
    GC_FREE;
    return 0;
}

/* Returns:
 *   0 - success
 *   ERROR_FAIL + errno == ENOENT - no entry found
 *   ERROR_$FOO + errno != ENOENT - other failure
 */
static int cpupool_info(libxl__gc *gc,
                        libxl_cpupoolinfo *info,
                        uint32_t poolid,
                        bool exact /* exactly poolid or >= poolid */)
{
    xc_cpupoolinfo_t *xcinfo;
    int rc = ERROR_FAIL;

    xcinfo = xc_cpupool_getinfo(CTX->xch, poolid);
    if (xcinfo == NULL)
    {
        if (exact || errno != ENOENT)
            LOGE(ERROR, "failed to get info for cpupool%d", poolid);
        return ERROR_FAIL;
    }

    if (exact && xcinfo->cpupool_id != poolid)
    {
        LOG(ERROR, "got info for cpupool%d, wanted cpupool%d\n",
            xcinfo->cpupool_id, poolid);
        goto out;
    }

    info->poolid = xcinfo->cpupool_id;
    info->pool_name = libxl_cpupoolid_to_name(CTX, info->poolid);
    if (!info->pool_name) {
        rc = ERROR_FAIL;
        goto out;
    }
    info->sched = xcinfo->sched_id;
    info->n_dom = xcinfo->n_dom;
    rc = libxl_cpu_bitmap_alloc(CTX, &info->cpumap, 0);
    if (rc)
        goto out;

    memcpy(info->cpumap.map, xcinfo->cpumap, info->cpumap.size);

    rc = 0;
out:
    xc_cpupool_infofree(CTX->xch, xcinfo);
    return rc;
}

int libxl_cpupool_info(libxl_ctx *ctx,
                       libxl_cpupoolinfo *info, uint32_t poolid)
{
    GC_INIT(ctx);
    int rc = cpupool_info(gc, info, poolid, true);
    GC_FREE;
    return rc;
}

libxl_cpupoolinfo * libxl_list_cpupool(libxl_ctx *ctx, int *nb_pool_out)
{
    GC_INIT(ctx);
    libxl_cpupoolinfo info, *ptr;

    int i;
    uint32_t poolid;

    ptr = NULL;

    poolid = 0;
    for (i = 0;; i++) {
        libxl_cpupoolinfo_init(&info);
        if (cpupool_info(gc, &info, poolid, false)) {
            libxl_cpupoolinfo_dispose(&info);
            if (errno != ENOENT) goto out;
            break;
        }

        ptr = libxl__realloc(NOGC, ptr, (i+1) * sizeof(libxl_cpupoolinfo));
        ptr[i] = info;
        poolid = info.poolid + 1;
        /* Don't dispose of info because it will be returned to caller */
    }

    *nb_pool_out = i;

    GC_FREE;
    return ptr;

out:
    libxl_cpupoolinfo_list_free(ptr, i);
    *nb_pool_out = 0;
    GC_FREE;
    return NULL;
}

/* this API call only list VM running on this host. A VM can
 * be an aggregate of multiple domains. */
libxl_vminfo * libxl_list_vm(libxl_ctx *ctx, int *nb_vm_out)
{
    GC_INIT(ctx);
    libxl_dominfo *info;
    libxl_vminfo *ptr = NULL;
    int idx, i, n_doms;

    info = libxl_list_domain(ctx, &n_doms);
    if (!info)
        goto out;

    /*
     * Always make sure to allocate at least one element; if we don't and we
     * request zero, libxl__calloc (might) think its internal call to calloc
     * has failed (if it returns null), if so it would kill our process.
     */
    ptr = libxl__calloc(NOGC, n_doms ? n_doms : 1, sizeof(libxl_vminfo));

    for (idx = i = 0; i < n_doms; i++) {
        if (libxl_is_stubdom(ctx, info[i].domid, NULL))
            continue;
        ptr[idx].uuid = info[i].uuid;
        ptr[idx].domid = info[i].domid;

        idx++;
    }
    *nb_vm_out = idx;
    libxl_dominfo_list_free(info, n_doms);

out:
    GC_FREE;
    return ptr;
}

static void remus_failover_cb(libxl__egc *egc,
                              libxl__domain_save_state *dss, int rc);

int libxl_domain_remus_start(libxl_ctx *ctx, libxl_domain_remus_info *info,
                             uint32_t domid, int send_fd, int recv_fd,
                             const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    libxl__domain_save_state *dss;
    int rc;

    libxl_domain_type type = libxl__domain_type(gc, domid);
    if (type == LIBXL_DOMAIN_TYPE_INVALID) {
        rc = ERROR_FAIL;
        goto out;
    }

    /* The caller must set this defbool */
    if (libxl_defbool_is_default(info->colo)) {
        LOG(ERROR, "colo mode must be enabled/disabled");
        rc = ERROR_FAIL;
        goto out;
    }

    libxl_defbool_setdefault(&info->allow_unsafe, false);
    libxl_defbool_setdefault(&info->blackhole, false);
    libxl_defbool_setdefault(&info->compression,
                             !libxl_defbool_val(info->colo));
    libxl_defbool_setdefault(&info->netbuf, true);
    libxl_defbool_setdefault(&info->diskbuf, true);

    if (libxl_defbool_val(info->colo) &&
        libxl_defbool_val(info->compression)) {
            LOG(ERROR, "cannot use memory checkpoint compression in COLO mode");
            rc = ERROR_FAIL;
            goto out;
    }

    if (!libxl_defbool_val(info->allow_unsafe) &&
        (libxl_defbool_val(info->blackhole) ||
         !libxl_defbool_val(info->netbuf) ||
         !libxl_defbool_val(info->diskbuf))) {
        LOG(ERROR, "Unsafe mode must be enabled to replicate to /dev/null,"
                   "disable network buffering and disk replication");
        rc = ERROR_FAIL;
        goto out;
    }


    GCNEW(dss);
    dss->ao = ao;
    dss->callback = remus_failover_cb;
    dss->domid = domid;
    dss->fd = send_fd;
    dss->recv_fd = recv_fd;
    dss->type = type;
    dss->live = 1;
    dss->debug = 0;
    dss->remus = info;
    if (libxl_defbool_val(info->colo))
        dss->checkpointed_stream = LIBXL_CHECKPOINTED_STREAM_COLO;
    else
        dss->checkpointed_stream = LIBXL_CHECKPOINTED_STREAM_REMUS;

    assert(info);

    /* Point of no return */
    if (libxl_defbool_val(info->colo))
        libxl__colo_save_setup(egc, &dss->css);
    else
        libxl__remus_setup(egc, &dss->rs);
    return AO_INPROGRESS;

 out:
    return AO_CREATE_FAIL(rc);
}

static void remus_failover_cb(libxl__egc *egc,
                              libxl__domain_save_state *dss, int rc)
{
    STATE_AO_GC(dss->ao);
    /*
     * With Remus, if we reach this point, it means either
     * backup died or some network error occurred preventing us
     * from sending checkpoints.
     */
    libxl__ao_complete(egc, ao, rc);
}

static void domain_suspend_cb(libxl__egc *egc,
                              libxl__domain_save_state *dss, int rc)
{
    STATE_AO_GC(dss->ao);
    int flrc;

    flrc = libxl__fd_flags_restore(gc, dss->fd, dss->fdfl);
    /* If suspend has failed already then report that error not this one. */
    if (flrc && !rc) rc = flrc;

    libxl__ao_complete(egc,ao,rc);

}

int libxl_domain_suspend(libxl_ctx *ctx, uint32_t domid, int fd, int flags,
                         const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int rc;

    libxl_domain_type type = libxl__domain_type(gc, domid);
    if (type == LIBXL_DOMAIN_TYPE_INVALID) {
        rc = ERROR_FAIL;
        goto out_err;
    }

    libxl__domain_save_state *dss;
    GCNEW(dss);

    dss->ao = ao;
    dss->callback = domain_suspend_cb;

    dss->domid = domid;
    dss->fd = fd;
    dss->type = type;
    dss->live = flags & LIBXL_SUSPEND_LIVE;
    dss->debug = flags & LIBXL_SUSPEND_DEBUG;
    dss->checkpointed_stream = LIBXL_CHECKPOINTED_STREAM_NONE;

    rc = libxl__fd_flags_modify_save(gc, dss->fd,
                                     ~(O_NONBLOCK|O_NDELAY), 0,
                                     &dss->fdfl);
    if (rc < 0) goto out_err;

    libxl__domain_save(egc, dss);
    return AO_INPROGRESS;

 out_err:
    return AO_CREATE_FAIL(rc);
}

int libxl_domain_pause(libxl_ctx *ctx, uint32_t domid)
{
    int ret;
    GC_INIT(ctx);
    ret = xc_domain_pause(ctx->xch, domid);
    if (ret<0) {
        LOGE(ERROR, "pausing domain %d", domid);
        GC_FREE;
        return ERROR_FAIL;
    }
    GC_FREE;
    return 0;
}

int libxl_domain_core_dump(libxl_ctx *ctx, uint32_t domid,
                           const char *filename,
                           const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int ret, rc;

    ret = xc_domain_dumpcore(ctx->xch, domid, filename);
    if (ret<0) {
        LOGE(ERROR, "core dumping domain %d to %s", domid, filename);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;
out:

    libxl__ao_complete(egc, ao, rc);

    return AO_INPROGRESS;
}

int libxl_domain_unpause(libxl_ctx *ctx, uint32_t domid)
{
    GC_INIT(ctx);
    int ret, rc = 0;

    libxl_domain_type type = libxl__domain_type(gc, domid);
    if (type == LIBXL_DOMAIN_TYPE_INVALID) {
        rc = ERROR_FAIL;
        goto out;
    }

    if (type == LIBXL_DOMAIN_TYPE_HVM) {
        rc = libxl__domain_resume_device_model(gc, domid);
        if (rc < 0) {
            LOG(ERROR, "failed to unpause device model for domain %u:%d",
                domid, rc);
            goto out;
        }
    }
    ret = xc_domain_unpause(ctx->xch, domid);
    if (ret<0) {
        LOGE(ERROR, "unpausing domain %d", domid);
        rc = ERROR_FAIL;
    }
 out:
    GC_FREE;
    return rc;
}

int libxl__domain_pvcontrol_available(libxl__gc *gc, uint32_t domid)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);

    uint64_t pvdriver = 0;
    int ret;

    libxl_domain_type domtype = libxl__domain_type(gc, domid);
    if (domtype == LIBXL_DOMAIN_TYPE_INVALID)
        return ERROR_FAIL;

    if (domtype == LIBXL_DOMAIN_TYPE_PV)
        return 1;

    ret = xc_hvm_param_get(ctx->xch, domid, HVM_PARAM_CALLBACK_IRQ, &pvdriver);
    if (ret<0) {
        LOGE(ERROR, "getting HVM callback IRQ");
        return ERROR_FAIL;
    }
    return !!pvdriver;
}

const char *libxl__domain_pvcontrol_xspath(libxl__gc *gc, uint32_t domid)
{
    const char *dom_path;

    dom_path = libxl__xs_get_dompath(gc, domid);
    if (!dom_path)
        return NULL;

    return GCSPRINTF("%s/control/shutdown", dom_path);
}

char * libxl__domain_pvcontrol_read(libxl__gc *gc, xs_transaction_t t,
                                    uint32_t domid)
{
    const char *shutdown_path;

    shutdown_path = libxl__domain_pvcontrol_xspath(gc, domid);
    if (!shutdown_path)
        return NULL;

    return libxl__xs_read(gc, t, shutdown_path);
}

int libxl__domain_pvcontrol_write(libxl__gc *gc, xs_transaction_t t,
                                  uint32_t domid, const char *cmd)
{
    const char *shutdown_path;

    shutdown_path = libxl__domain_pvcontrol_xspath(gc, domid);
    if (!shutdown_path)
        return ERROR_FAIL;

    return libxl__xs_printf(gc, t, shutdown_path, "%s", cmd);
}

static int libxl__domain_pvcontrol(libxl__gc *gc, uint32_t domid,
                                   const char *cmd)
{
    int ret;

    ret = libxl__domain_pvcontrol_available(gc, domid);
    if (ret < 0)
        return ret;

    if (!ret)
        return ERROR_NOPARAVIRT;

    return libxl__domain_pvcontrol_write(gc, XBT_NULL, domid, cmd);
}

int libxl_domain_shutdown(libxl_ctx *ctx, uint32_t domid)
{
    GC_INIT(ctx);
    int ret;
    ret = libxl__domain_pvcontrol(gc, domid, "poweroff");
    GC_FREE;
    return ret;
}

int libxl_domain_reboot(libxl_ctx *ctx, uint32_t domid)
{
    GC_INIT(ctx);
    int ret;
    ret = libxl__domain_pvcontrol(gc, domid, "reboot");
    GC_FREE;
    return ret;
}

static void domain_death_occurred(libxl__egc *egc,
                                  libxl_evgen_domain_death **evg_upd,
                                  const char *why) {
    /* Removes **evg_upd from death_list and puts it on death_reported
     * and advances *evg_upd to the next entry.
     * Call sites in domain_death_xswatch_callback must use "continue". */
    EGC_GC;
    libxl_evgen_domain_death *const evg = *evg_upd;

    LOG(DEBUG, "%s", why);

    libxl_evgen_domain_death *evg_next = LIBXL_TAILQ_NEXT(evg, entry);
    *evg_upd = evg_next;

    libxl_event *ev = NEW_EVENT(egc, DOMAIN_DEATH, evg->domid, evg->user);

    libxl__event_occurred(egc, ev);

    evg->death_reported = 1;
    LIBXL_TAILQ_REMOVE(&CTX->death_list, evg, entry);
    LIBXL_TAILQ_INSERT_HEAD(&CTX->death_reported, evg, entry);
}

static void domain_death_xswatch_callback(libxl__egc *egc, libxl__ev_xswatch *w,
                                        const char *wpath, const char *epath) {
    EGC_GC;
    libxl_evgen_domain_death *evg;
    int rc;

    CTX_LOCK;

    evg = LIBXL_TAILQ_FIRST(&CTX->death_list);

    for (;;) {
        if (!evg) goto out;

        int nentries = LIBXL_TAILQ_NEXT(evg, entry) ? 200 : 1;
        xc_domaininfo_t domaininfos[nentries];
        const xc_domaininfo_t *got = domaininfos, *gotend;

        rc = xc_domain_getinfolist(CTX->xch, evg->domid, nentries, domaininfos);
        if (rc == -1) {
            LIBXL__EVENT_DISASTER(egc, "xc_domain_getinfolist failed while"
                                  " processing @releaseDomain watch event",
                                  errno, 0);
            goto out;
        }
        gotend = &domaininfos[rc];

        LOG(DEBUG, "[evg=%p:%"PRIu32"] nentries=%d rc=%d %ld..%ld",
            evg, evg->domid, nentries, rc,
            rc>0 ? (long)domaininfos[0].domain : 0,
            rc>0 ? (long)domaininfos[rc-1].domain : 0);

        for (;;) {
            if (!evg) {
                LOG(DEBUG, "[evg=0] all reported");
                goto all_reported;
            }

            LOG(DEBUG, "[evg=%p:%"PRIu32"]"
                "   got=domaininfos[%d] got->domain=%ld",
                evg, evg->domid, (int)(got - domaininfos),
                got < gotend ? (long)got->domain : -1L);

            if (!rc) {
                domain_death_occurred(egc, &evg, "empty list");
                continue;
            }

            if (got == gotend) {
                LOG(DEBUG, " got==gotend");
                break;
            }

            if (got->domain > evg->domid) {
                /* ie, the list doesn't contain evg->domid any more so
                 * the domain has been destroyed */
                domain_death_occurred(egc, &evg, "missing from list");
                continue;
            }

            if (got->domain < evg->domid) {
                got++;
                continue;
            }

            assert(evg->domid == got->domain);
            LOG(DEBUG, " exists shutdown_reported=%d"" dominf.flags=%x",
                evg->shutdown_reported, got->flags);

            if (got->flags & XEN_DOMINF_dying) {
                domain_death_occurred(egc, &evg, "dying");
                continue;
            }

            if (!evg->shutdown_reported &&
                (got->flags & XEN_DOMINF_shutdown)) {
                libxl_event *ev = NEW_EVENT(egc, DOMAIN_SHUTDOWN,
                                            got->domain, evg->user);

                LOG(DEBUG, " shutdown reporting");

                ev->u.domain_shutdown.shutdown_reason =
                    (got->flags >> XEN_DOMINF_shutdownshift) &
                    XEN_DOMINF_shutdownmask;
                libxl__event_occurred(egc, ev);

                evg->shutdown_reported = 1;
            }
            evg = LIBXL_TAILQ_NEXT(evg, entry);
        }

        assert(rc); /* rc==0 results in us eating all evgs and quitting */
    }
 all_reported:
 out:

    LOG(DEBUG, "domain death search done");

    CTX_UNLOCK;
}

int libxl_evenable_domain_death(libxl_ctx *ctx, uint32_t domid,
                libxl_ev_user user, libxl_evgen_domain_death **evgen_out) {
    GC_INIT(ctx);
    libxl_evgen_domain_death *evg, *evg_search;
    int rc;
    
    CTX_LOCK;

    evg = malloc(sizeof(*evg));  if (!evg) { rc = ERROR_NOMEM; goto out; }
    memset(evg, 0, sizeof(*evg));
    evg->domid = domid;
    evg->user = user;

    LIBXL_TAILQ_INSERT_SORTED(&ctx->death_list, entry, evg, evg_search, ,
                              evg->domid > evg_search->domid);

    if (!libxl__ev_xswatch_isregistered(&ctx->death_watch)) {
        rc = libxl__ev_xswatch_register(gc, &ctx->death_watch,
                        domain_death_xswatch_callback, "@releaseDomain");
        if (rc) { libxl__evdisable_domain_death(gc, evg); goto out; }
    }

    *evgen_out = evg;
    rc = 0;

 out:
    CTX_UNLOCK;
    GC_FREE;
    return rc;
};

void libxl__evdisable_domain_death(libxl__gc *gc,
                                   libxl_evgen_domain_death *evg) {
    CTX_LOCK;

    if (!evg->death_reported)
        LIBXL_TAILQ_REMOVE(&CTX->death_list, evg, entry);
    else
        LIBXL_TAILQ_REMOVE(&CTX->death_reported, evg, entry);

    free(evg);

    if (!LIBXL_TAILQ_FIRST(&CTX->death_list) &&
        libxl__ev_xswatch_isregistered(&CTX->death_watch))
        libxl__ev_xswatch_deregister(gc, &CTX->death_watch);

    CTX_UNLOCK;
}

void libxl_evdisable_domain_death(libxl_ctx *ctx,
                                  libxl_evgen_domain_death *evg) {
    GC_INIT(ctx);
    libxl__evdisable_domain_death(gc, evg);
    GC_FREE;
}

static void disk_eject_xswatch_callback(libxl__egc *egc, libxl__ev_xswatch *w,
                                        const char *wpath, const char *epath) {
    EGC_GC;
    libxl_evgen_disk_eject *evg = (void*)w;
    const char *backend;
    char *value;
    char backend_type[BACKEND_STRING_SIZE+1];
    int rc;

    value = libxl__xs_read(gc, XBT_NULL, wpath);

    if (!value || strcmp(value,  "eject"))
        return;

    if (libxl__xs_printf(gc, XBT_NULL, wpath, "")) {
        LIBXL__EVENT_DISASTER(egc, "xs_write failed acknowledging eject",
                              errno, LIBXL_EVENT_TYPE_DISK_EJECT);
        return;
    }

    libxl_event *ev = NEW_EVENT(egc, DISK_EJECT, evg->domid, evg->user);
    libxl_device_disk *disk = &ev->u.disk_eject.disk;
    
    rc = libxl__xs_read_checked(gc, XBT_NULL, evg->be_ptr_path, &backend);
    if (rc) {
        LIBXL__EVENT_DISASTER(egc, "xs_read failed reading be_ptr_path",
                              errno, LIBXL_EVENT_TYPE_DISK_EJECT);
        return;
    }
    if (!backend) {
        /* device has been removed, not simply ejected */
        return;
    }

    sscanf(backend,
            "/local/domain/%d/backend/%" TOSTRING(BACKEND_STRING_SIZE)
           "[a-z]/%*d/%*d",
           &disk->backend_domid, backend_type);
    if (!strcmp(backend_type, "tap") || !strcmp(backend_type, "vbd")) {
        disk->backend = LIBXL_DISK_BACKEND_TAP;
    } else if (!strcmp(backend_type, "qdisk")) {
        disk->backend = LIBXL_DISK_BACKEND_QDISK;
    } else {
        disk->backend = LIBXL_DISK_BACKEND_UNKNOWN;
    }

    disk->pdev_path = strdup(""); /* xxx fixme malloc failure */
    disk->format = LIBXL_DISK_FORMAT_EMPTY;
    /* this value is returned to the user: do not free right away */
    disk->vdev = libxl__strdup(NOGC, evg->vdev);
    disk->removable = 1;
    disk->readwrite = 0;
    disk->is_cdrom = 1;

    libxl__event_occurred(egc, ev);
}

int libxl_evenable_disk_eject(libxl_ctx *ctx, uint32_t guest_domid,
                              const char *vdev, libxl_ev_user user,
                              libxl_evgen_disk_eject **evgen_out) {
    GC_INIT(ctx);
    CTX_LOCK;
    int rc;
    char *path;
    libxl_evgen_disk_eject *evg = NULL;

    evg = malloc(sizeof(*evg));  if (!evg) { rc = ERROR_NOMEM; goto out; }
    memset(evg, 0, sizeof(*evg));
    evg->user = user;
    evg->domid = guest_domid;
    LIBXL_LIST_INSERT_HEAD(&CTX->disk_eject_evgens, evg, entry);

    uint32_t domid = libxl_get_stubdom_id(ctx, guest_domid);

    if (!domid)
        domid = guest_domid;

    int devid = libxl__device_disk_dev_number(vdev, NULL, NULL);

    path = GCSPRINTF("%s/device/vbd/%d/eject",
                 libxl__xs_get_dompath(gc, domid),
                 devid);
    if (!path) { rc = ERROR_NOMEM; goto out; }

    const char *libxl_path = GCSPRINTF("%s/device/vbd/%d",
                                 libxl__xs_libxl_path(gc, domid),
                                 devid);
    evg->be_ptr_path = libxl__sprintf(NOGC, "%s/backend", libxl_path);

    const char *configured_vdev;
    rc = libxl__xs_read_checked(gc, XBT_NULL,
            GCSPRINTF("%s/dev", libxl_path), &configured_vdev);
    if (rc) goto out;

    evg->vdev = libxl__strdup(NOGC, configured_vdev);

    rc = libxl__ev_xswatch_register(gc, &evg->watch,
                                    disk_eject_xswatch_callback, path);
    if (rc) goto out;

    *evgen_out = evg;
    CTX_UNLOCK;
    GC_FREE;
    return 0;

 out:
    if (evg)
        libxl__evdisable_disk_eject(gc, evg);
    CTX_UNLOCK;
    GC_FREE;
    return rc;
}

void libxl__evdisable_disk_eject(libxl__gc *gc, libxl_evgen_disk_eject *evg) {
    CTX_LOCK;

    LIBXL_LIST_REMOVE(evg, entry);

    if (libxl__ev_xswatch_isregistered(&evg->watch))
        libxl__ev_xswatch_deregister(gc, &evg->watch);

    free(evg->vdev);
    free(evg->be_ptr_path);
    free(evg);

    CTX_UNLOCK;
}

void libxl_evdisable_disk_eject(libxl_ctx *ctx, libxl_evgen_disk_eject *evg) {
    GC_INIT(ctx);
    libxl__evdisable_disk_eject(gc, evg);
    GC_FREE;
}    

/* Callbacks for libxl_domain_destroy */

static void domain_destroy_cb(libxl__egc *egc, libxl__domain_destroy_state *dds,
                              int rc);

int libxl_domain_destroy(libxl_ctx *ctx, uint32_t domid,
                         const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    libxl__domain_destroy_state *dds;

    GCNEW(dds);
    dds->ao = ao;
    dds->domid = domid;
    dds->callback = domain_destroy_cb;
    libxl__domain_destroy(egc, dds);

    return AO_INPROGRESS;
}

static void domain_destroy_cb(libxl__egc *egc, libxl__domain_destroy_state *dds,
                              int rc)
{
    STATE_AO_GC(dds->ao);

    if (rc)
        LOG(ERROR, "destruction of domain %u failed", dds->domid);

    libxl__ao_complete(egc, ao, rc);
}

/* Callbacks for libxl__domain_destroy */

static void stubdom_destroy_callback(libxl__egc *egc,
                                     libxl__destroy_domid_state *dis,
                                     int rc);

static void domain_destroy_callback(libxl__egc *egc,
                                    libxl__destroy_domid_state *dis,
                                    int rc);

static void destroy_finish_check(libxl__egc *egc,
                                 libxl__domain_destroy_state *dds);

void libxl__domain_destroy(libxl__egc *egc, libxl__domain_destroy_state *dds)
{
    STATE_AO_GC(dds->ao);
    uint32_t stubdomid = libxl_get_stubdom_id(CTX, dds->domid);

    if (stubdomid) {
        dds->stubdom.ao = ao;
        dds->stubdom.domid = stubdomid;
        dds->stubdom.callback = stubdom_destroy_callback;
        dds->stubdom.soft_reset = false;
        libxl__destroy_domid(egc, &dds->stubdom);
    } else {
        dds->stubdom_finished = 1;
    }

    dds->domain.ao = ao;
    dds->domain.domid = dds->domid;
    dds->domain.callback = domain_destroy_callback;
    dds->domain.soft_reset = dds->soft_reset;
    libxl__destroy_domid(egc, &dds->domain);
}

static void stubdom_destroy_callback(libxl__egc *egc,
                                     libxl__destroy_domid_state *dis,
                                     int rc)
{
    STATE_AO_GC(dis->ao);
    libxl__domain_destroy_state *dds = CONTAINER_OF(dis, *dds, stubdom);
    const char *savefile;

    if (rc) {
        LOG(ERROR, "unable to destroy stubdom with domid %u", dis->domid);
        dds->rc = rc;
    }

    dds->stubdom_finished = 1;
    savefile = libxl__device_model_savefile(gc, dis->domid);
    rc = libxl__remove_file(gc, savefile);
    if (rc) {
        LOG(ERROR, "failed to remove device-model savefile %s", savefile);
    }

    destroy_finish_check(egc, dds);
}

static void domain_destroy_callback(libxl__egc *egc,
                                    libxl__destroy_domid_state *dis,
                                    int rc)
{
    STATE_AO_GC(dis->ao);
    libxl__domain_destroy_state *dds = CONTAINER_OF(dis, *dds, domain);

    if (rc) {
        LOG(ERROR, "unable to destroy guest with domid %u", dis->domid);
        dds->rc = rc;
    }

    dds->domain_finished = 1;
    destroy_finish_check(egc, dds);
}

static void destroy_finish_check(libxl__egc *egc,
                                 libxl__domain_destroy_state *dds)
{
    if (!(dds->domain_finished && dds->stubdom_finished))
        return;

    dds->callback(egc, dds, dds->rc);
}

/* Callbacks for libxl__destroy_domid */
static void devices_destroy_cb(libxl__egc *egc,
                               libxl__devices_remove_state *drs,
                               int rc);

static void domain_destroy_domid_cb(libxl__egc *egc,
                                    libxl__ev_child *destroyer,
                                    pid_t pid, int status);

void libxl__destroy_domid(libxl__egc *egc, libxl__destroy_domid_state *dis)
{
    STATE_AO_GC(dis->ao);
    libxl_ctx *ctx = CTX;
    uint32_t domid = dis->domid;
    char *dom_path;
    int rc, dm_present;

    libxl__ev_child_init(&dis->destroyer);

    rc = libxl_domain_info(ctx, NULL, domid);
    switch(rc) {
    case 0:
        break;
    case ERROR_DOMAIN_NOTFOUND:
        LOG(ERROR, "non-existant domain %d", domid);
    default:
        goto out;
    }

    switch (libxl__domain_type(gc, domid)) {
    case LIBXL_DOMAIN_TYPE_HVM:
        if (libxl_get_stubdom_id(CTX, domid)) {
            dm_present = 0;
            break;
        }
        /* fall through */
    case LIBXL_DOMAIN_TYPE_PVH:
    case LIBXL_DOMAIN_TYPE_PV:
        dm_present = libxl__dm_active(gc, domid);
        break;
    case LIBXL_DOMAIN_TYPE_INVALID:
        rc = ERROR_FAIL;
        goto out;
    default:
        abort();
    }

    dom_path = libxl__xs_get_dompath(gc, domid);
    if (!dom_path) {
        rc = ERROR_FAIL;
        goto out;
    }

    if (libxl__device_pci_destroy_all(gc, domid) < 0)
        LOG(ERROR, "pci shutdown failed for domid %d", domid);
    rc = xc_domain_pause(ctx->xch, domid);
    if (rc < 0) {
        LOGEV(ERROR, rc, "xc_domain_pause failed for %d", domid);
    }
    if (dm_present) {
        if (libxl__destroy_device_model(gc, domid) < 0)
            LOG(ERROR, "libxl__destroy_device_model failed for %d", domid);

        libxl__qmp_cleanup(gc, domid);
    }
    dis->drs.ao = ao;
    dis->drs.domid = domid;
    dis->drs.callback = devices_destroy_cb;
    dis->drs.force = 1;
    libxl__devices_destroy(egc, &dis->drs);
    return;

out:
    assert(rc);
    dis->callback(egc, dis, rc);
    return;
}

static void devices_destroy_cb(libxl__egc *egc,
                               libxl__devices_remove_state *drs,
                               int rc)
{
    STATE_AO_GC(drs->ao);
    libxl__destroy_domid_state *dis = CONTAINER_OF(drs, *dis, drs);
    libxl_ctx *ctx = CTX;
    uint32_t domid = dis->domid;
    char *dom_path;
    char *vm_path;
    libxl__domain_userdata_lock *lock;

    dom_path = libxl__xs_get_dompath(gc, domid);
    if (!dom_path) {
        rc = ERROR_FAIL;
        goto out;
    }

    if (rc < 0)
        LOG(ERROR, "libxl__devices_destroy failed for %d", domid);

    vm_path = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/vm", dom_path));
    if (vm_path)
        if (!xs_rm(ctx->xsh, XBT_NULL, vm_path))
            LOGE(ERROR, "xs_rm failed for %s", vm_path);

    if (!xs_rm(ctx->xsh, XBT_NULL, dom_path))
        LOGE(ERROR, "xs_rm failed for %s", dom_path);

    xs_rm(ctx->xsh, XBT_NULL, libxl__xs_libxl_path(gc, domid));
    xs_rm(ctx->xsh, XBT_NULL, GCSPRINTF( "/local/domain/%d/hvmloader", domid));

    /* This is async operation, we already hold CTX lock */
    lock = libxl__lock_domain_userdata(gc, domid);
    if (!lock) {
        rc = ERROR_LOCK_FAIL;
        goto out;
    }
    libxl__userdata_destroyall(gc, domid);

    libxl__unlock_domain_userdata(lock);

    /* Clean up qemu-save and qemu-resume files. They are
     * intermediate files created by libxc. Unfortunately they
     * don't fit in existing userdata scheme very well. In soft reset
     * case we need to keep the file.
     */
    if (!dis->soft_reset) {
        rc = libxl__remove_file(gc,
                                libxl__device_model_savefile(gc, domid));
        if (rc < 0) goto out;
    }
    rc = libxl__remove_file(gc,
             GCSPRINTF(LIBXL_DEVICE_MODEL_RESTORE_FILE".%u", domid));
    if (rc < 0) goto out;

    rc = libxl__ev_child_fork(gc, &dis->destroyer, domain_destroy_domid_cb);
    if (rc < 0) goto out;
    if (!rc) { /* child */
        ctx->xch = xc_interface_open(ctx->lg,0,0);
        if (!ctx->xch) goto badchild;

        if (!dis->soft_reset) {
            rc = xc_domain_destroy(ctx->xch, domid);
        } else {
            rc = xc_domain_pause(ctx->xch, domid);
            if (rc < 0) goto badchild;
            rc = xc_domain_soft_reset(ctx->xch, domid);
            if (rc < 0) goto badchild;
            rc = xc_domain_unpause(ctx->xch, domid);
        }
        if (rc < 0) goto badchild;
        _exit(0);

    badchild:
        if (errno > 0  && errno < 126) {
            _exit(errno);
        } else {
            LOGE(ERROR,
 "xc_domain_destroy failed for %d (with difficult errno value %d)",
                 domid, errno);
            _exit(-1);
        }
    }
    LOG(DEBUG, "forked pid %ld for destroy of domain %d", (long)rc, domid);

    return;

out:
    dis->callback(egc, dis, rc);
    return;
}

static void domain_destroy_domid_cb(libxl__egc *egc,
                                    libxl__ev_child *destroyer,
                                    pid_t pid, int status)
{
    libxl__destroy_domid_state *dis = CONTAINER_OF(destroyer, *dis, destroyer);
    STATE_AO_GC(dis->ao);
    int rc;

    if (status) {
        if (WIFEXITED(status) && WEXITSTATUS(status)<126) {
            LOGEV(ERROR, WEXITSTATUS(status),
                  "xc_domain_destroy failed for %"PRIu32"", dis->domid);
        } else {
            libxl_report_child_exitstatus(CTX, XTL_ERROR,
                                          "async domain destroy", pid, status);
        }
        rc = ERROR_FAIL;
        goto out;
    }
    rc = 0;

 out:
    dis->callback(egc, dis, rc);
}

static int libxl__console_tty_path(libxl__gc *gc, uint32_t domid, int cons_num,
                                   libxl_console_type type, char **tty_path)
{
    int rc;
    char *dom_path;

    dom_path = libxl__xs_get_dompath(gc, domid);
    if (!dom_path) {
        rc = ERROR_FAIL;
        goto out;
    }

    switch (type) {
    case LIBXL_CONSOLE_TYPE_SERIAL:
        *tty_path = GCSPRINTF("%s/serial/%d/tty", dom_path, cons_num);
        rc = 0;
        break;
    case LIBXL_CONSOLE_TYPE_PV:
        if (cons_num == 0)
            *tty_path = GCSPRINTF("%s/console/tty", dom_path);
        else
            *tty_path = GCSPRINTF("%s/device/console/%d/tty", dom_path,
                                  cons_num);
        rc = 0;
        break;
    default:
        rc = ERROR_INVAL;
        goto out;
    }

out:
    return rc;
}

int libxl_console_exec(libxl_ctx *ctx, uint32_t domid, int cons_num,
                       libxl_console_type type, int notify_fd)
{
    GC_INIT(ctx);
    char *p = GCSPRINTF("%s/xenconsole", libxl__private_bindir_path());
    char *domid_s = GCSPRINTF("%d", domid);
    char *cons_num_s = GCSPRINTF("%d", cons_num);
    char *notify_fd_s;
    char *cons_type_s;

    switch (type) {
    case LIBXL_CONSOLE_TYPE_PV:
        cons_type_s = "pv";
        break;
    case LIBXL_CONSOLE_TYPE_SERIAL:
        cons_type_s = "serial";
        break;
    default:
        goto out;
    }

    if (notify_fd != -1) {
        notify_fd_s = GCSPRINTF("%d", notify_fd);
        execl(p, p, domid_s, "--num", cons_num_s, "--type", cons_type_s,
              "--start-notify-fd", notify_fd_s, (void *)NULL);
    } else {
        execl(p, p, domid_s, "--num", cons_num_s, "--type", cons_type_s,
              (void *)NULL);
    }

out:
    GC_FREE;
    return ERROR_FAIL;
}

int libxl_console_get_tty(libxl_ctx *ctx, uint32_t domid, int cons_num,
                          libxl_console_type type, char **path)
{
    GC_INIT(ctx);
    char *tty_path;
    char *tty;
    int rc;

    rc = libxl__console_tty_path(gc, domid, cons_num, type, &tty_path);
    if (rc) {
        LOG(ERROR, "Failed to get tty path for domain %d\n", domid);
        goto out;
    }

    tty = libxl__xs_read(gc, XBT_NULL, tty_path);
    if (!tty || tty[0] == '\0') {
       LOGE(ERROR,"unable to read console tty path `%s'",tty_path);
       rc = ERROR_FAIL;
       goto out;
    }

    *path = libxl__strdup(NOGC, tty);
    rc = 0;
out:
    GC_FREE;
    return rc;
}

static int libxl__primary_console_find(libxl_ctx *ctx, uint32_t domid_vm,
                                       uint32_t *domid, int *cons_num,
                                       libxl_console_type *type)
{
    GC_INIT(ctx);
    uint32_t stubdomid = libxl_get_stubdom_id(ctx, domid_vm);
    int rc;

    if (stubdomid) {
        *domid = stubdomid;
        *cons_num = STUBDOM_CONSOLE_SERIAL;
        *type = LIBXL_CONSOLE_TYPE_PV;
    } else {
        switch (libxl__domain_type(gc, domid_vm)) {
        case LIBXL_DOMAIN_TYPE_HVM:
            *domid = domid_vm;
            *cons_num = 0;
            *type = LIBXL_CONSOLE_TYPE_SERIAL;
            break;
        case LIBXL_DOMAIN_TYPE_PVH:
        case LIBXL_DOMAIN_TYPE_PV:
            *domid = domid_vm;
            *cons_num = 0;
            *type = LIBXL_CONSOLE_TYPE_PV;
            break;
        case LIBXL_DOMAIN_TYPE_INVALID:
            rc = ERROR_INVAL;
            goto out;
        default: abort();
        }
    }

    rc = 0;
out:
    GC_FREE;
    return rc;
}

int libxl_primary_console_exec(libxl_ctx *ctx, uint32_t domid_vm, int notify_fd)
{
    uint32_t domid;
    int cons_num;
    libxl_console_type type;
    int rc;

    rc = libxl__primary_console_find(ctx, domid_vm, &domid, &cons_num, &type);
    if ( rc ) return rc;
    return libxl_console_exec(ctx, domid, cons_num, type, notify_fd);
}

int libxl_primary_console_get_tty(libxl_ctx *ctx, uint32_t domid_vm,
                                  char **path)
{
    uint32_t domid;
    int cons_num;
    libxl_console_type type;
    int rc;

    rc = libxl__primary_console_find(ctx, domid_vm, &domid, &cons_num, &type);
    if ( rc ) return rc;
    return libxl_console_get_tty(ctx, domid, cons_num, type, path);
}

int libxl_vncviewer_exec(libxl_ctx *ctx, uint32_t domid, int autopass)
{
    GC_INIT(ctx);
    const char *vnc_port;
    const char *vnc_listen = NULL, *vnc_pass = NULL;
    int port = 0, autopass_fd = -1;
    char *vnc_bin, *args[] = {
        "vncviewer",
        NULL, /* hostname:display */
        NULL, /* -autopass */
        NULL,
    };

    vnc_port = libxl__xs_read(gc, XBT_NULL,
                            GCSPRINTF(
                            "/local/domain/%d/console/vnc-port", domid));
    if (!vnc_port) {
        LOG(ERROR, "Cannot get vnc-port of domain %d", domid);
        goto x_fail;
    }

    port = atoi(vnc_port) - 5900;

    vnc_listen = libxl__xs_read(gc, XBT_NULL,
                                GCSPRINTF("/local/domain/%d/console/vnc-listen",
                                          domid));

    if ( autopass )
        vnc_pass = libxl__xs_read(gc, XBT_NULL,
                                  GCSPRINTF("/local/domain/%d/console/vnc-pass",
					    domid));

    if ( NULL == vnc_listen )
        vnc_listen = "localhost";

    if ( (vnc_bin = getenv("VNCVIEWER")) )
        args[0] = vnc_bin;

    args[1] = GCSPRINTF("%s:%d", vnc_listen, port);

    if ( vnc_pass ) {
        char tmpname[] = "/tmp/vncautopass.XXXXXX";
        autopass_fd = mkstemp(tmpname);
        if ( autopass_fd < 0 ) {
            LOGE(ERROR, "mkstemp %s failed", tmpname);
            goto x_fail;
        }

        if ( unlink(tmpname) ) {
            /* should never happen */
            LOGE(ERROR, "unlink %s failed", tmpname);
            goto x_fail;
        }

        if ( libxl_write_exactly(ctx, autopass_fd, vnc_pass, strlen(vnc_pass),
                                    tmpname, "vnc password") )
            goto x_fail;

        if ( lseek(autopass_fd, SEEK_SET, 0) ) {
            LOGE(ERROR, "rewind %s (autopass) failed", tmpname);
            goto x_fail;
        }

        args[2] = "-autopass";
    }

    libxl__exec(gc, autopass_fd, -1, -1, args[0], args, NULL);

 x_fail:
    GC_FREE;
    return ERROR_FAIL;
}

int libxl__get_domid(libxl__gc *gc, uint32_t *domid)
{
    int rc;
    const char *xs_domid;

    rc = libxl__xs_read_checked(gc, XBT_NULL, DOMID_XS_PATH, &xs_domid);
    if (rc) goto out;
    if (!xs_domid) {
        LOG(ERROR, "failed to get own domid (%s)", DOMID_XS_PATH);
        rc = ERROR_FAIL;
        goto out;
    }

    *domid = atoi(xs_domid);

out:
    return rc;
}

/******************************************************************************/

/* generic callback for devices that only need to set ao_complete */
void device_addrm_aocomplete(libxl__egc *egc, libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);

    if (aodev->rc) {
        if (aodev->dev) {
            LOG(ERROR, "unable to %s %s with id %u",
                        libxl__device_action_to_string(aodev->action),
                        libxl__device_kind_to_string(aodev->dev->kind),
                        aodev->dev->devid);
        } else {
            LOG(ERROR, "unable to %s device",
                       libxl__device_action_to_string(aodev->action));
        }
        goto out;
    }

out:
    libxl__ao_complete(egc, ao, aodev->rc);
    return;
}

/* common function to get next device id */
int libxl__device_nextid(libxl__gc *gc, uint32_t domid, char *device)
{
    char *libxl_dom_path, **l;
    unsigned int nb;
    int nextid = -1;

    if (!(libxl_dom_path = libxl__xs_libxl_path(gc, domid)))
        return nextid;

    l = libxl__xs_directory(gc, XBT_NULL,
        GCSPRINTF("%s/device/%s", libxl_dom_path, device),
                            &nb);
    if (l == NULL || nb == 0)
        nextid = 0;
    else
        nextid = strtoul(l[nb - 1], NULL, 10) + 1;

    return nextid;
}

int libxl__resolve_domid(libxl__gc *gc, const char *name, uint32_t *domid)
{
    if (!name)
        return 0;
    return libxl_domain_qualifier_to_domid(CTX, name, domid);
}

/******************************************************************************/

int libxl__device_disk_setdefault(libxl__gc *gc, libxl_device_disk *disk,
                                  uint32_t domid)
{
    int rc;

    libxl_defbool_setdefault(&disk->discard_enable, !!disk->readwrite);
    libxl_defbool_setdefault(&disk->colo_enable, false);
    libxl_defbool_setdefault(&disk->colo_restore_enable, false);

    rc = libxl__resolve_domid(gc, disk->backend_domname, &disk->backend_domid);
    if (rc < 0) return rc;

    /* Force Qdisk backend for CDROM devices of guests with a device model. */
    if (disk->is_cdrom != 0 &&
        libxl__domain_type(gc, domid) == LIBXL_DOMAIN_TYPE_HVM) {
        if (!(disk->backend == LIBXL_DISK_BACKEND_QDISK ||
              disk->backend == LIBXL_DISK_BACKEND_UNKNOWN)) {
            LOG(ERROR, "Backend for CD devices on HVM guests must be Qdisk");
            return ERROR_FAIL;
        }
        disk->backend = LIBXL_DISK_BACKEND_QDISK;
    }

    rc = libxl__device_disk_set_backend(gc, disk);
    return rc;
}

int libxl__device_from_disk(libxl__gc *gc, uint32_t domid,
                                   const libxl_device_disk *disk,
                                   libxl__device *device)
{
    int devid;

    devid = libxl__device_disk_dev_number(disk->vdev, NULL, NULL);
    if (devid==-1) {
        LOG(ERROR, "Invalid or unsupported"" virtual disk identifier %s",
            disk->vdev);
        return ERROR_INVAL;
    }

    device->backend_domid = disk->backend_domid;
    device->backend_devid = devid;

    switch (disk->backend) {
        case LIBXL_DISK_BACKEND_PHY:
            device->backend_kind = LIBXL__DEVICE_KIND_VBD;
            break;
        case LIBXL_DISK_BACKEND_TAP:
            device->backend_kind = LIBXL__DEVICE_KIND_VBD;
            break;
        case LIBXL_DISK_BACKEND_QDISK:
            device->backend_kind = LIBXL__DEVICE_KIND_QDISK;
            break;
        default:
            LOG(ERROR, "unrecognized disk backend type: %d", disk->backend);
            return ERROR_INVAL;
    }

    device->domid = domid;
    device->devid = devid;
    device->kind  = LIBXL__DEVICE_KIND_VBD;

    return 0;
}

/* Specific function called directly only by local disk attach,
 * all other users should instead use the regular
 * libxl__device_disk_add wrapper
 *
 * The (optionally) passed function get_vdev will be used to
 * set the vdev the disk should be attached to. When it is set the caller
 * must also pass get_vdev_user, which will be passed to get_vdev.
 *
 * The passed get_vdev function is also in charge of printing
 * the corresponding error message when appropiate.
 */
static void device_disk_add(libxl__egc *egc, uint32_t domid,
                           libxl_device_disk *disk,
                           libxl__ao_device *aodev,
                           char *get_vdev(libxl__gc *, void *,
                                          xs_transaction_t),
                           void *get_vdev_user)
{
    STATE_AO_GC(aodev->ao);
    flexarray_t *front = NULL;
    flexarray_t *back = NULL;
    char *dev = NULL, *script;
    libxl__device *device;
    int rc;
    libxl_ctx *ctx = gc->owner;
    xs_transaction_t t = XBT_NULL;
    libxl_domain_config d_config;
    libxl_device_disk disk_saved;
    libxl__domain_userdata_lock *lock = NULL;

    libxl_domain_config_init(&d_config);
    libxl_device_disk_init(&disk_saved);
    libxl_device_disk_copy(ctx, &disk_saved, disk);

    libxl_domain_type type = libxl__domain_type(gc, domid);
    if (type == LIBXL_DOMAIN_TYPE_INVALID) {
        rc = ERROR_FAIL;
        goto out;
    }

    /*
     * get_vdev != NULL -> local attach
     * get_vdev == NULL -> block attach
     *
     * We don't care about local attach state because it's only
     * intermediate state.
     */
    if (!get_vdev && aodev->update_json) {
        lock = libxl__lock_domain_userdata(gc, domid);
        if (!lock) {
            rc = ERROR_LOCK_FAIL;
            goto out;
        }

        rc = libxl__get_domain_configuration(gc, domid, &d_config);
        if (rc) goto out;

        DEVICE_ADD(disk, disks, domid, &disk_saved, COMPARE_DISK, &d_config);

        rc = libxl__dm_check_start(gc, &d_config, domid);
        if (rc) goto out;
    }

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;

        if (get_vdev) {
            assert(get_vdev_user);
            disk->vdev = get_vdev(gc, get_vdev_user, t);
            if (disk->vdev == NULL) {
                rc = ERROR_FAIL;
                goto out;
            }
        }

        rc = libxl__device_disk_setdefault(gc, disk, domid);
        if (rc) goto out;

        front = flexarray_make(gc, 16, 1);
        back = flexarray_make(gc, 16, 1);

        GCNEW(device);
        rc = libxl__device_from_disk(gc, domid, disk, device);
        if (rc != 0) {
            LOG(ERROR, "Invalid or unsupported"" virtual disk identifier %s",
                disk->vdev);
            goto out;
        }

        rc = libxl__device_exists(gc, t, device);
        if (rc < 0) goto out;
        if (rc == 1) {              /* already exists in xenstore */
            LOG(ERROR, "device already exists in xenstore");
            aodev->action = LIBXL__DEVICE_ACTION_ADD; /* for error message */
            rc = ERROR_DEVICE_EXISTS;
            goto out;
        }

        switch (disk->backend) {
            case LIBXL_DISK_BACKEND_PHY:
                dev = disk->pdev_path;

        do_backend_phy:
                flexarray_append(back, "params");
                flexarray_append(back, dev);

                script = libxl__abs_path(gc, disk->script?: "block",
                                         libxl__xen_script_dir_path());
                flexarray_append_pair(back, "script", script);

                assert(device->backend_kind == LIBXL__DEVICE_KIND_VBD);
                break;

            case LIBXL_DISK_BACKEND_TAP:
                if (dev == NULL) {
                    dev = libxl__blktap_devpath(gc, disk->pdev_path,
                                                disk->format);
                    if (!dev) {
                        LOG(ERROR, "failed to get blktap devpath for %p",
                            disk->pdev_path);
                        rc = ERROR_FAIL;
                        goto out;
                    }
                }
                flexarray_append(back, "tapdisk-params");
                flexarray_append(back, GCSPRINTF("%s:%s",
                    libxl__device_disk_string_of_format(disk->format),
                    disk->pdev_path));

                /* tap backends with scripts are rejected by
                 * libxl__device_disk_set_backend */
                assert(!disk->script);

                /* now create a phy device to export the device to the guest */
                goto do_backend_phy;
            case LIBXL_DISK_BACKEND_QDISK:
                flexarray_append(back, "params");
                flexarray_append(back, GCSPRINTF("%s:%s",
                              libxl__device_disk_string_of_format(disk->format),
                              disk->pdev_path ? : ""));
                if (libxl_defbool_val(disk->colo_enable)) {
                    flexarray_append(back, "colo-host");
                    flexarray_append(back, libxl__sprintf(gc, "%s", disk->colo_host));
                    flexarray_append(back, "colo-port");
                    flexarray_append(back, libxl__sprintf(gc, "%d", disk->colo_port));
                    flexarray_append(back, "colo-export");
                    flexarray_append(back, libxl__sprintf(gc, "%s", disk->colo_export));
                    flexarray_append(back, "active-disk");
                    flexarray_append(back, libxl__sprintf(gc, "%s", disk->active_disk));
                    flexarray_append(back, "hidden-disk");
                    flexarray_append(back, libxl__sprintf(gc, "%s", disk->hidden_disk));
                }
                assert(device->backend_kind == LIBXL__DEVICE_KIND_QDISK);
                break;
            default:
                LOG(ERROR, "unrecognized disk backend type: %d",
                    disk->backend);
                rc = ERROR_INVAL;
                goto out;
        }

        flexarray_append(back, "frontend-id");
        flexarray_append(back, GCSPRINTF("%d", domid));
        flexarray_append(back, "online");
        flexarray_append(back, "1");
        flexarray_append(back, "removable");
        flexarray_append(back, GCSPRINTF("%d", (disk->removable) ? 1 : 0));
        flexarray_append(back, "bootable");
        flexarray_append(back, GCSPRINTF("%d", 1));
        flexarray_append(back, "state");
        flexarray_append(back, GCSPRINTF("%d", XenbusStateInitialising));
        flexarray_append(back, "dev");
        flexarray_append(back, disk->vdev);
        flexarray_append(back, "type");
        flexarray_append(back, libxl__device_disk_string_of_backend(disk->backend));
        flexarray_append(back, "mode");
        flexarray_append(back, disk->readwrite ? "w" : "r");
        flexarray_append(back, "device-type");
        flexarray_append(back, disk->is_cdrom ? "cdrom" : "disk");
        if (disk->direct_io_safe) {
            flexarray_append(back, "direct-io-safe");
            flexarray_append(back, "1");
        }
        flexarray_append_pair(back, "discard-enable",
                              libxl_defbool_val(disk->discard_enable) ?
                              "1" : "0");

        flexarray_append(front, "backend-id");
        flexarray_append(front, GCSPRINTF("%d", disk->backend_domid));
        flexarray_append(front, "state");
        flexarray_append(front, GCSPRINTF("%d", XenbusStateInitialising));
        flexarray_append(front, "virtual-device");
        flexarray_append(front, GCSPRINTF("%d", device->devid));
        flexarray_append(front, "device-type");
        flexarray_append(front, disk->is_cdrom ? "cdrom" : "disk");

        /*
         * Old PV kernel disk frontends before 2.6.26 rely on tool stack to
         * write disk native protocol to frontend node. Xend does this, port
         * this behaviour to xl.
         *
         * New kernels write this node themselves. In that case it just
         * overwrites an existing node which is OK.
         */
        if (type == LIBXL_DOMAIN_TYPE_PV) {
            const char *protocol =
                xc_domain_get_native_protocol(ctx->xch, domid);
            if (protocol) {
                flexarray_append(front, "protocol");
                flexarray_append(front, libxl__strdup(gc, protocol));
            }
        }

        if (!get_vdev && aodev->update_json) {
            rc = libxl__set_domain_configuration(gc, domid, &d_config);
            if (rc) goto out;
        }

        libxl__device_generic_add(gc, t, device,
                                  libxl__xs_kvs_of_flexarray(gc, back),
                                  libxl__xs_kvs_of_flexarray(gc, front),
                                  NULL);

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

    aodev->dev = device;
    aodev->action = LIBXL__DEVICE_ACTION_ADD;
    libxl__wait_device_connection(egc, aodev);

    rc = 0;

out:
    libxl__xs_transaction_abort(gc, &t);
    if (lock) libxl__unlock_domain_userdata(lock);
    libxl_device_disk_dispose(&disk_saved);
    libxl_domain_config_dispose(&d_config);
    aodev->rc = rc;
    if (rc) aodev->callback(egc, aodev);
    return;
}

static void libxl__device_disk_add(libxl__egc *egc, uint32_t domid,
                                   libxl_device_disk *disk,
                                   libxl__ao_device *aodev)
{
    device_disk_add(egc, domid, disk, aodev, NULL, NULL);
}

static int libxl__device_disk_from_xenstore(libxl__gc *gc,
                                         const char *libxl_path,
                                         libxl_device_disk *disk)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    unsigned int len;
    char *tmp;
    int rc;

    libxl_device_disk_init(disk);

    const char *backend_path;
    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/backend", libxl_path),
                                &backend_path);
    if (rc) goto out;

    if (!backend_path) {
        LOG(ERROR, "disk %s does not exist (no backend path", libxl_path);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__backendpath_parse_domid(gc, backend_path, &disk->backend_domid);
    if (rc) {
        LOG(ERROR, "Unable to fetch device backend domid from %s", backend_path);
        goto out;
    }

    /*
     * "params" may not be present; but everything else must be.
     * colo releated entries(colo-host, colo-port, colo-export,
     * active-disk and hidden-disk) are present only if colo is
     * enabled.
     */
    tmp = xs_read(ctx->xsh, XBT_NULL,
                  GCSPRINTF("%s/params", libxl_path), &len);
    if (tmp && strchr(tmp, ':')) {
        disk->pdev_path = strdup(strchr(tmp, ':') + 1);
        free(tmp);
    } else {
        disk->pdev_path = tmp;
    }

    tmp = xs_read(ctx->xsh, XBT_NULL,
                  GCSPRINTF("%s/colo-host", libxl_path), &len);
    if (tmp) {
        libxl_defbool_set(&disk->colo_enable, true);
        disk->colo_host = tmp;

        tmp = xs_read(ctx->xsh, XBT_NULL,
                      GCSPRINTF("%s/colo-port", libxl_path), &len);
        if (!tmp) {
            LOG(ERROR, "Missing xenstore node %s/colo-port", libxl_path);
            goto cleanup;
        }
        disk->colo_port = atoi(tmp);

#define XS_READ_COLO(param, item) do {                                  \
        tmp = xs_read(ctx->xsh, XBT_NULL,                               \
                      GCSPRINTF("%s/"#param"", libxl_path), &len);         \
        if (!tmp) {                                                     \
            LOG(ERROR, "Missing xenstore node %s/"#param"", libxl_path);   \
            goto cleanup;                                               \
        }                                                               \
        disk->item = tmp;                                               \
} while (0)
        XS_READ_COLO(colo-export, colo_export);
        XS_READ_COLO(active-disk, active_disk);
        XS_READ_COLO(hidden-disk, hidden_disk);
#undef XS_READ_COLO
    } else {
        libxl_defbool_set(&disk->colo_enable, false);
    }

    tmp = libxl__xs_read(gc, XBT_NULL,
                         GCSPRINTF("%s/type", libxl_path));
    if (!tmp) {
        LOG(ERROR, "Missing xenstore node %s/type", libxl_path);
        goto cleanup;
    }
    libxl_string_to_backend(ctx, tmp, &(disk->backend));

    disk->vdev = xs_read(ctx->xsh, XBT_NULL,
                         GCSPRINTF("%s/dev", libxl_path), &len);
    if (!disk->vdev) {
        LOG(ERROR, "Missing xenstore node %s/dev", libxl_path);
        goto cleanup;
    }

    tmp = libxl__xs_read(gc, XBT_NULL, libxl__sprintf
                         (gc, "%s/removable", libxl_path));
    if (!tmp) {
        LOG(ERROR, "Missing xenstore node %s/removable", libxl_path);
        goto cleanup;
    }
    disk->removable = atoi(tmp);

    tmp = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/mode", libxl_path));
    if (!tmp) {
        LOG(ERROR, "Missing xenstore node %s/mode", libxl_path);
        goto cleanup;
    }
    if (!strcmp(tmp, "w"))
        disk->readwrite = 1;
    else
        disk->readwrite = 0;

    tmp = libxl__xs_read(gc, XBT_NULL,
                         GCSPRINTF("%s/device-type", libxl_path));
    if (!tmp) {
        LOG(ERROR, "Missing xenstore node %s/device-type", libxl_path);
        goto cleanup;
    }
    disk->is_cdrom = !strcmp(tmp, "cdrom");

    disk->format = LIBXL_DISK_FORMAT_UNKNOWN;

    return 0;
cleanup:
    rc = ERROR_FAIL;
 out:
    libxl_device_disk_dispose(disk);
    return rc;
}

int libxl_vdev_to_device_disk(libxl_ctx *ctx, uint32_t domid,
                              const char *vdev, libxl_device_disk *disk)
{
    GC_INIT(ctx);
    char *dom_xl_path, *libxl_path;
    int devid = libxl__device_disk_dev_number(vdev, NULL, NULL);
    int rc = ERROR_FAIL;

    if (devid < 0)
        return ERROR_INVAL;

    libxl_device_disk_init(disk);

    dom_xl_path = libxl__xs_libxl_path(gc, domid);
    if (!dom_xl_path) {
        goto out;
    }
    libxl_path = GCSPRINTF("%s/device/vbd/%d", dom_xl_path, devid);

    rc = libxl__device_disk_from_xenstore(gc, libxl_path, disk);
out:
    GC_FREE;
    return rc;
}


static int libxl__append_disk_list(libxl__gc *gc,
                                           uint32_t domid,
                                           libxl_device_disk **disks,
                                           int *ndisks)
{
    char *libxl_dir_path = NULL;
    char **dir = NULL;
    unsigned int n = 0;
    libxl_device_disk *pdisk = NULL, *pdisk_end = NULL;
    int rc=0;
    int initial_disks = *ndisks;

    libxl_dir_path = GCSPRINTF("%s/device/vbd",
                        libxl__xs_libxl_path(gc, domid));
    dir = libxl__xs_directory(gc, XBT_NULL, libxl_dir_path, &n);
    if (dir && n) {
        libxl_device_disk *tmp;
        tmp = realloc(*disks, sizeof (libxl_device_disk) * (*ndisks + n));
        if (tmp == NULL)
            return ERROR_NOMEM;
        *disks = tmp;
        pdisk = *disks + initial_disks;
        pdisk_end = *disks + initial_disks + n;
        for (; pdisk < pdisk_end; pdisk++, dir++) {
            const char *p;
            p = GCSPRINTF("%s/%s", libxl_dir_path, *dir);
            if ((rc=libxl__device_disk_from_xenstore(gc, p, pdisk)))
                goto out;
            *ndisks += 1;
        }
    }
out:
    return rc;
}

libxl_device_disk *libxl_device_disk_list(libxl_ctx *ctx, uint32_t domid, int *num)
{
    GC_INIT(ctx);
    libxl_device_disk *disks = NULL;
    int rc;

    *num = 0;

    rc = libxl__append_disk_list(gc, domid, &disks, num);
    if (rc) goto out_err;

    GC_FREE;
    return disks;

out_err:
    LOG(ERROR, "Unable to list disks");
    while (disks && *num) {
        (*num)--;
        libxl_device_disk_dispose(&disks[*num]);
    }
    free(disks);
    return NULL;
}

int libxl_device_disk_getinfo(libxl_ctx *ctx, uint32_t domid,
                              libxl_device_disk *disk, libxl_diskinfo *diskinfo)
{
    GC_INIT(ctx);
    char *dompath, *fe_path, *libxl_path;
    char *val;
    int rc;

    diskinfo->backend = NULL;

    dompath = libxl__xs_get_dompath(gc, domid);
    diskinfo->devid = libxl__device_disk_dev_number(disk->vdev, NULL, NULL);

    /* tap devices entries in xenstore are written as vbd devices. */
    fe_path = GCSPRINTF("%s/device/vbd/%d", dompath, diskinfo->devid);
    libxl_path = GCSPRINTF("%s/device/vbd/%d",
                           libxl__xs_libxl_path(gc, domid), diskinfo->devid);
    diskinfo->backend = xs_read(ctx->xsh, XBT_NULL,
                                GCSPRINTF("%s/backend", libxl_path), NULL);
    if (!diskinfo->backend) {
        GC_FREE;
        return ERROR_FAIL;
    }
    rc = libxl__backendpath_parse_domid(gc, diskinfo->backend,
                                        &diskinfo->backend_id);
    if (rc) goto out;

    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/state", fe_path));
    diskinfo->state = val ? strtoul(val, NULL, 10) : -1;
    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/event-channel", fe_path));
    diskinfo->evtch = val ? strtoul(val, NULL, 10) : -1;
    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/ring-ref", fe_path));
    diskinfo->rref = val ? strtoul(val, NULL, 10) : -1;
    diskinfo->frontend = xs_read(ctx->xsh, XBT_NULL,
                                 GCSPRINTF("%s/frontend", libxl_path), NULL);
    diskinfo->frontend_id = domid;

    GC_FREE;
    return 0;

 out:
    free(diskinfo->backend);
    return rc;
}

int libxl_cdrom_insert(libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disk,
                       const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int num = 0, i;
    libxl_device_disk *disks = NULL, disk_saved, disk_empty;
    libxl_domain_config d_config;
    int rc, dm_ver;
    libxl__device device;
    const char *be_path, *libxl_path;
    char * tmp;
    libxl__domain_userdata_lock *lock = NULL;
    xs_transaction_t t = XBT_NULL;
    flexarray_t *insert = NULL, *empty = NULL;

    libxl_domain_config_init(&d_config);
    libxl_device_disk_init(&disk_empty);
    libxl_device_disk_init(&disk_saved);
    libxl_device_disk_copy(ctx, &disk_saved, disk);

    disk_empty.format = LIBXL_DISK_FORMAT_EMPTY;
    disk_empty.vdev = libxl__strdup(NOGC, disk->vdev);
    disk_empty.pdev_path = libxl__strdup(NOGC, "");
    disk_empty.is_cdrom = 1;
    libxl__device_disk_setdefault(gc, &disk_empty, domid);

    libxl_domain_type type = libxl__domain_type(gc, domid);
    if (type == LIBXL_DOMAIN_TYPE_INVALID) {
        rc = ERROR_FAIL;
        goto out;
    }
    if (type != LIBXL_DOMAIN_TYPE_HVM) {
        LOG(ERROR, "cdrom-insert requires an HVM domain");
        rc = ERROR_INVAL;
        goto out;
    }

    if (libxl_get_stubdom_id(ctx, domid) != 0) {
        LOG(ERROR, "cdrom-insert doesn't work for stub domains");
        rc = ERROR_INVAL;
        goto out;
    }

    dm_ver = libxl__device_model_version_running(gc, domid);
    if (dm_ver == -1) {
        LOG(ERROR, "cannot determine device model version");
        rc = ERROR_FAIL;
        goto out;
    }

    disks = libxl_device_disk_list(ctx, domid, &num);
    for (i = 0; i < num; i++) {
        if (disks[i].is_cdrom && !strcmp(disk->vdev, disks[i].vdev))
        {
            /* Found.  Set backend type appropriately. */
            disk->backend=disks[i].backend;
            break;
        }
    }
    if (i == num) {
        LOG(ERROR, "Virtual device not found");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl__device_disk_setdefault(gc, disk, domid);
    if (rc) goto out;

    if (!disk->pdev_path) {
        disk->pdev_path = libxl__strdup(NOGC, "");
        disk->format = LIBXL_DISK_FORMAT_EMPTY;
    }

    rc = libxl__device_from_disk(gc, domid, disk, &device);
    if (rc) goto out;

    be_path = libxl__device_backend_path(gc, &device);
    libxl_path = libxl__device_libxl_path(gc, &device);

    insert = flexarray_make(gc, 4, 1);

    flexarray_append_pair(insert, "type",
                          libxl__device_disk_string_of_backend(disk->backend));
    if (disk->format != LIBXL_DISK_FORMAT_EMPTY)
        flexarray_append_pair(insert, "params",
                        GCSPRINTF("%s:%s",
                            libxl__device_disk_string_of_format(disk->format),
                            disk->pdev_path));
    else
        flexarray_append_pair(insert, "params", "");

    empty = flexarray_make(gc, 4, 1);
    flexarray_append_pair(empty, "type",
                          libxl__device_disk_string_of_backend(disk->backend));
    flexarray_append_pair(empty, "params", "");

    /* Note: CTX lock is already held at this point so lock hierarchy
     * is maintained.
     */
    lock = libxl__lock_domain_userdata(gc, domid);
    if (!lock) {
        rc = ERROR_LOCK_FAIL;
        goto out;
    }

    /* We need to eject the original image first. This is implemented
     * by inserting empty media. JSON is not updated.
     */
    if (dm_ver == LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN) {
        rc = libxl__qmp_insert_cdrom(gc, domid, &disk_empty);
        if (rc) goto out;
    }

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;
        /* Sanity check: make sure the device exists before writing here */
        tmp = libxl__xs_read(gc, t, GCSPRINTF("%s/frontend", libxl_path));
        if (!tmp)
        {
            LOG(ERROR, "Internal error: %s does not exist",
                GCSPRINTF("%s/frontend", libxl_path));
            rc = ERROR_FAIL;
            goto out;
        }

        char **kvs = libxl__xs_kvs_of_flexarray(gc, empty);

        rc = libxl__xs_writev(gc, t, be_path, kvs);
        if (rc) goto out;

        rc = libxl__xs_writev(gc, t, libxl_path, kvs);
        if (rc) goto out;

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

    rc = libxl__get_domain_configuration(gc, domid, &d_config);
    if (rc) goto out;

    DEVICE_ADD(disk, disks, domid, &disk_saved, COMPARE_DISK, &d_config);

    rc = libxl__dm_check_start(gc, &d_config, domid);
    if (rc) goto out;

    if (dm_ver == LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN) {
        rc = libxl__qmp_insert_cdrom(gc, domid, disk);
        if (rc) goto out;
    }

    for (;;) {
        rc = libxl__xs_transaction_start(gc, &t);
        if (rc) goto out;
        /* Sanity check: make sure the device exists before writing here */
        tmp = libxl__xs_read(gc, t, GCSPRINTF("%s/frontend", libxl_path));
        if (!tmp)
        {
            LOG(ERROR, "Internal error: %s does not exist",
                GCSPRINTF("%s/frontend", libxl_path));
            rc = ERROR_FAIL;
            goto out;
        }

        rc = libxl__set_domain_configuration(gc, domid, &d_config);
        if (rc) goto out;

        char **kvs = libxl__xs_kvs_of_flexarray(gc, insert);

        rc = libxl__xs_writev(gc, t, be_path, kvs);
        if (rc) goto out;

        rc = libxl__xs_writev(gc, t, libxl_path, kvs);
        if (rc) goto out;

        rc = libxl__xs_transaction_commit(gc, &t);
        if (!rc) break;
        if (rc < 0) goto out;
    }

    /* success, no actual async */
    libxl__ao_complete(egc, ao, 0);

    rc = 0;

out:
    libxl__xs_transaction_abort(gc, &t);
    for (i = 0; i < num; i++)
        libxl_device_disk_dispose(&disks[i]);
    free(disks);
    libxl_device_disk_dispose(&disk_empty);
    libxl_device_disk_dispose(&disk_saved);
    libxl_domain_config_dispose(&d_config);

    if (lock) libxl__unlock_domain_userdata(lock);

    if (rc) return AO_CREATE_FAIL(rc);
    return AO_INPROGRESS;
}

/* libxl__alloc_vdev only works on the local domain, that is the domain
 * where the toolstack is running */
static char * libxl__alloc_vdev(libxl__gc *gc, void *get_vdev_user,
        xs_transaction_t t)
{
    const char *blkdev_start = (const char *) get_vdev_user;
    int devid = 0, disk = 0, part = 0;
    char *libxl_dom_path = libxl__xs_libxl_path(gc, LIBXL_TOOLSTACK_DOMID);

    libxl__device_disk_dev_number(blkdev_start, &disk, &part);
    if (part != 0) {
        LOG(ERROR, "blkdev_start is invalid");
        return NULL;
    }

    do {
        devid = libxl__device_disk_dev_number(GCSPRINTF("d%dp0", disk),
                NULL, NULL);
        if (devid < 0)
            return NULL;
        if (libxl__xs_read(gc, t,
                    GCSPRINTF("%s/device/vbd/%d/backend",
                        libxl_dom_path, devid)) == NULL) {
            if (errno == ENOENT)
                return libxl__devid_to_vdev(gc, devid);
            else
                return NULL;
        }
        disk++;
    } while (1);
    return NULL;
}

/* Callbacks */

char *libxl__device_disk_find_local_path(libxl__gc *gc, 
                                          libxl_domid guest_domid,
                                          const libxl_device_disk *disk,
                                          bool qdisk_direct)
{
    char *path = NULL;

    /* No local paths for driver domains */
    if (disk->backend_domname != NULL) {
        LOG(DEBUG, "Non-local backend, can't access locally.\n");
        goto out;
    }

    /*
     * If this is in raw format, and we're not using a script or a
     * driver domain, we can access the target path directly.
     */
    if (disk->format == LIBXL_DISK_FORMAT_RAW
        && disk->script == NULL) {
        path = libxl__strdup(gc, disk->pdev_path);
        LOG(DEBUG, "Directly accessing local RAW disk %s", path);
        goto out;
    } 

    /*
     * If we're being called for a qemu path, we can pass the target
     * string directly as well
     */
    if (qdisk_direct && disk->backend == LIBXL_DISK_BACKEND_QDISK) {
        path = libxl__strdup(gc, disk->pdev_path);
        LOG(DEBUG, "Directly accessing local QDISK target %s", path);
        goto out;
    } 

    /* 
     * If the format isn't raw and / or we're using a script, then see
     * if the script has written a path to the "cooked" node
     */
    if (disk->script && guest_domid != INVALID_DOMID) {
        libxl__device device;
        char *be_path, *pdpath;
        int rc;

        LOG(DEBUG,
            "Run from a script; checking for physical-device-path (vdev %s)",
            disk->vdev);

        rc = libxl__device_from_disk(gc, guest_domid, disk, &device);
        if (rc < 0)
            goto out;

        be_path = libxl__device_backend_path(gc, &device);

        pdpath = libxl__sprintf(gc, "%s/physical-device-path", be_path);

        LOG(DEBUG, "Attempting to read node %s", pdpath);
        path = libxl__xs_read(gc, XBT_NULL, pdpath);

        if (path)
            LOG(DEBUG, "Accessing cooked block device %s", path);
        else
            LOG(DEBUG, "No physical-device-path, can't access locally.");

        goto out;
    }

 out:
    return path;
}

static void local_device_attach_cb(libxl__egc *egc, libxl__ao_device *aodev);

void libxl__device_disk_local_initiate_attach(libxl__egc *egc,
                                     libxl__disk_local_state *dls)
{
    STATE_AO_GC(dls->ao);
    int rc;
    const libxl_device_disk *in_disk = dls->in_disk;
    libxl_device_disk *disk = &dls->disk;
    const char *blkdev_start = dls->blkdev_start;

    assert(in_disk->pdev_path);

    disk->vdev = NULL;

    if (dls->diskpath)
        LOG(DEBUG, "Strange, dls->diskpath already set: %s", dls->diskpath);

    LOG(DEBUG, "Trying to find local path");

    dls->diskpath = libxl__device_disk_find_local_path(gc, INVALID_DOMID,
                                                       in_disk, false);
    if (dls->diskpath) {
        LOG(DEBUG, "Local path found, executing callback.");
        dls->callback(egc, dls, 0);
    } else {
        LOG(DEBUG, "Local path not found, initiating attach.");

        memcpy(disk, in_disk, sizeof(libxl_device_disk));
        disk->pdev_path = libxl__strdup(gc, in_disk->pdev_path);
        if (in_disk->script != NULL)
            disk->script = libxl__strdup(gc, in_disk->script);
        disk->vdev = NULL;
        
        rc = libxl__device_disk_setdefault(gc, disk, LIBXL_TOOLSTACK_DOMID);
        if (rc) goto out;

        libxl__prepare_ao_device(ao, &dls->aodev);
        dls->aodev.callback = local_device_attach_cb;
        device_disk_add(egc, LIBXL_TOOLSTACK_DOMID, disk, &dls->aodev,
                        libxl__alloc_vdev, (void *) blkdev_start);
    }

    return;

 out:
    assert(rc);
    dls->rc = rc;
    libxl__device_disk_local_initiate_detach(egc, dls);
    dls->callback(egc, dls, rc);
}

static void local_device_attach_cb(libxl__egc *egc, libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    libxl__disk_local_state *dls = CONTAINER_OF(aodev, *dls, aodev);
    char *be_path = NULL;
    int rc;
    libxl__device device;
    libxl_device_disk *disk = &dls->disk;

    rc = aodev->rc;
    if (rc) {
        LOGE(ERROR, "unable locally attach device: %s", disk->pdev_path);
        goto out;
    }

    rc = libxl__device_from_disk(gc, LIBXL_TOOLSTACK_DOMID, disk, &device);
    if (rc < 0)
        goto out;
    be_path = libxl__device_backend_path(gc, &device);
    rc = libxl__wait_for_backend(gc, be_path, GCSPRINTF("%d", XenbusStateConnected));
    if (rc < 0)
        goto out;

    dls->diskpath = GCSPRINTF("/dev/%s",
                              libxl__devid_to_localdev(gc, device.devid));
    LOG(DEBUG, "locally attached disk %s", dls->diskpath);

    dls->callback(egc, dls, 0);
    return;

 out:
    assert(rc);
    dls->rc = rc;
    libxl__device_disk_local_initiate_detach(egc, dls);
    return;
}

/* Callbacks for local detach */

static void local_device_detach_cb(libxl__egc *egc, libxl__ao_device *aodev);

void libxl__device_disk_local_initiate_detach(libxl__egc *egc,
                                     libxl__disk_local_state *dls)
{
    STATE_AO_GC(dls->ao);
    int rc = 0;
    libxl_device_disk *disk = &dls->disk;
    libxl__device *device;
    libxl__ao_device *aodev = &dls->aodev;
    libxl__prepare_ao_device(ao, aodev);

    if (!dls->diskpath) goto out;

    if (disk->vdev != NULL) {
        GCNEW(device);
        rc = libxl__device_from_disk(gc, LIBXL_TOOLSTACK_DOMID,
                                     disk, device);
        if (rc != 0) goto out;
        
        aodev->action = LIBXL__DEVICE_ACTION_REMOVE;
        aodev->dev = device;
        aodev->callback = local_device_detach_cb;
        aodev->force = 0;
        libxl__initiate_device_generic_remove(egc, aodev);
        return;
    }

out:
    aodev->rc = rc;
    local_device_detach_cb(egc, aodev);
    return;
}

static void local_device_detach_cb(libxl__egc *egc, libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);
    libxl__disk_local_state *dls = CONTAINER_OF(aodev, *dls, aodev);
    int rc;

    if (aodev->rc) {
        LOGE(ERROR, "unable to %s %s with id %u",
                    libxl__device_action_to_string(aodev->action),
                    libxl__device_kind_to_string(aodev->dev->kind),
                    aodev->dev->devid);
        goto out;
    }

out:
    /*
     * If there was an error in dls->rc, it means we have been called from
     * a failed execution of libxl__device_disk_local_initiate_attach,
     * so return the original error.
     */
    rc = dls->rc ? dls->rc : aodev->rc;
    dls->callback(egc, dls, rc);
    return;
}

/******************************************************************************/
int libxl__device_console_add(libxl__gc *gc, uint32_t domid,
                              libxl__device_console *console,
                              libxl__domain_build_state *state,
                              libxl__device *device)
{
    flexarray_t *front, *ro_front;
    flexarray_t *back;
    int rc;

    if (console->devid && state) {
        rc = ERROR_INVAL;
        goto out;
    }
    if (!console->devid && (console->name || console->path)) {
        LOG(ERROR, "Primary console has invalid configuration");
        rc = ERROR_INVAL;
        goto out;
    }

    front = flexarray_make(gc, 16, 1);
    ro_front = flexarray_make(gc, 16, 1);
    back = flexarray_make(gc, 16, 1);

    device->backend_devid = console->devid;
    device->backend_domid = console->backend_domid;
    device->backend_kind = LIBXL__DEVICE_KIND_CONSOLE;
    device->devid = console->devid;
    device->domid = domid;
    device->kind = LIBXL__DEVICE_KIND_CONSOLE;

    flexarray_append(back, "frontend-id");
    flexarray_append(back, GCSPRINTF("%d", domid));
    flexarray_append(back, "online");
    flexarray_append(back, "1");
    flexarray_append(back, "state");
    flexarray_append(back, GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append(back, "protocol");
    flexarray_append(back, LIBXL_XENCONSOLE_PROTOCOL);

    if (console->name) {
        flexarray_append(ro_front, "name");
        flexarray_append(ro_front, console->name);
        flexarray_append(back, "name");
        flexarray_append(back, console->name);
    }
    if (console->connection) {
        flexarray_append(back, "connection");
        flexarray_append(back, console->connection);
    }
    if (console->path) {
        flexarray_append(back, "path");
        flexarray_append(back, console->path);
    }

    flexarray_append(front, "backend-id");
    flexarray_append(front, GCSPRINTF("%d", console->backend_domid));

    flexarray_append(ro_front, "limit");
    flexarray_append(ro_front, GCSPRINTF("%d", LIBXL_XENCONSOLE_LIMIT));
    flexarray_append(ro_front, "type");
    if (console->consback == LIBXL__CONSOLE_BACKEND_XENCONSOLED)
        flexarray_append(ro_front, "xenconsoled");
    else
        flexarray_append(ro_front, "ioemu");
    flexarray_append(ro_front, "output");
    flexarray_append(ro_front, console->output);
    flexarray_append(ro_front, "tty");
    flexarray_append(ro_front, "");

    if (state) {
        flexarray_append(ro_front, "port");
        flexarray_append(ro_front, GCSPRINTF("%"PRIu32, state->console_port));
        flexarray_append(ro_front, "ring-ref");
        flexarray_append(ro_front, GCSPRINTF("%lu", state->console_mfn));
    } else {
        flexarray_append(front, "state");
        flexarray_append(front, GCSPRINTF("%d", XenbusStateInitialising));
        flexarray_append(front, "protocol");
        flexarray_append(front, LIBXL_XENCONSOLE_PROTOCOL);
    }
    libxl__device_generic_add(gc, XBT_NULL, device,
                              libxl__xs_kvs_of_flexarray(gc, back),
                              libxl__xs_kvs_of_flexarray(gc, front),
                              libxl__xs_kvs_of_flexarray(gc, ro_front));
    rc = 0;
out:
    return rc;
}

/******************************************************************************/

int libxl__init_console_from_channel(libxl__gc *gc,
                                     libxl__device_console *console,
                                     int dev_num,
                                     libxl_device_channel *channel)
{
    int rc;

    libxl__device_console_init(console);

    /* Perform validation first, allocate second. */

    if (!channel->name) {
        LOG(ERROR, "channel %d has no name", channel->devid);
        return ERROR_INVAL;
    }

    if (channel->backend_domname) {
        rc = libxl_domain_qualifier_to_domid(CTX, channel->backend_domname,
                                             &channel->backend_domid);
        if (rc < 0) return rc;
    }

    /* The xenstore 'output' node tells the backend what to connect the console
       to. If the channel has "connection = pty" then the "output" node will be
       set to "pty". If the channel has "connection = socket" then the "output"
       node will be set to "chardev:libxl-channel%d". This tells the qemu
       backend to proxy data between the console ring and the character device
       with id "libxl-channel%d". These character devices are currently defined
       on the qemu command-line via "-chardev" options in libxl_dm.c */

    switch (channel->connection) {
        case LIBXL_CHANNEL_CONNECTION_UNKNOWN:
            LOG(ERROR, "channel %d has no defined connection; "
                "to where should it be connected?", channel->devid);
            return ERROR_INVAL;
        case LIBXL_CHANNEL_CONNECTION_PTY:
            console->connection = libxl__strdup(NOGC, "pty");
            console->output = libxl__sprintf(NOGC, "pty");
            break;
        case LIBXL_CHANNEL_CONNECTION_SOCKET:
            if (!channel->u.socket.path) {
                LOG(ERROR, "channel %d has no path", channel->devid);
                return ERROR_INVAL;
            }
            console->connection = libxl__strdup(NOGC, "socket");
            console->path = libxl__strdup(NOGC, channel->u.socket.path);
            console->output = libxl__sprintf(NOGC, "chardev:libxl-channel%d",
                                             channel->devid);
            break;
        default:
            /* We've forgotten to add the clause */
            LOG(ERROR, "%s: missing implementation for channel connection %d",
                __func__, channel->connection);
            abort();
    }

    console->devid = dev_num;
    console->consback = LIBXL__CONSOLE_BACKEND_IOEMU;
    console->backend_domid = channel->backend_domid;
    console->name = libxl__strdup(NOGC, channel->name);

    return 0;
}

static int libxl__device_channel_from_xenstore(libxl__gc *gc,
                                            const char *libxl_path,
                                            libxl_device_channel *channel)
{
    const char *tmp;
    int rc;

    libxl_device_channel_init(channel);

    rc = libxl__xs_read_checked(NOGC, XBT_NULL,
                                GCSPRINTF("%s/name", libxl_path),
                                (const char **)(&channel->name));
    if (rc) goto out;
    rc = libxl__xs_read_checked(gc, XBT_NULL,
                                GCSPRINTF("%s/connection", libxl_path), &tmp);
    if (rc) goto out;
    if (!strcmp(tmp, "pty")) {
        channel->connection = LIBXL_CHANNEL_CONNECTION_PTY;
    } else if (!strcmp(tmp, "socket")) {
        channel->connection = LIBXL_CHANNEL_CONNECTION_SOCKET;
        rc = libxl__xs_read_checked(NOGC, XBT_NULL,
                                    GCSPRINTF("%s/path", libxl_path),
                                    (const char **)(&channel->u.socket.path));
        if (rc) goto out;
    } else {
        rc = ERROR_INVAL;
        goto out;
    }

    rc = 0;
 out:
    return rc;
}

static int libxl__append_channel_list(libxl__gc *gc,
                                              uint32_t domid,
                                              libxl_device_channel **channels,
                                              int *nchannels)
{
    char *libxl_dir_path = NULL;
    char **dir = NULL;
    unsigned int n = 0, devid = 0;
    libxl_device_channel *next = NULL;
    int rc = 0, i;

    libxl_dir_path = GCSPRINTF("%s/device/console",
                               libxl__xs_libxl_path(gc, domid));
    dir = libxl__xs_directory(gc, XBT_NULL, libxl_dir_path, &n);
    if (!dir || !n)
      goto out;

    for (i = 0; i < n; i++) {
        const char *libxl_path, *name;
        libxl_device_channel *tmp;

        libxl_path = GCSPRINTF("%s/%s", libxl_dir_path, dir[i]);
        name = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/name", libxl_path));
        /* 'channels' are consoles with names, so ignore all consoles
           without names */
        if (!name) continue;
        tmp = realloc(*channels,
                      sizeof(libxl_device_channel) * (*nchannels + devid + 1));
        if (!tmp) {
          rc = ERROR_NOMEM;
          goto out;
        }
        *channels = tmp;
        next = *channels + *nchannels + devid;
        rc = libxl__device_channel_from_xenstore(gc, libxl_path, next);
        if (rc) goto out;
        next->devid = devid;
        devid++;
    }
    *nchannels += devid;
    return 0;

 out:
    return rc;
}

libxl_device_channel *libxl_device_channel_list(libxl_ctx *ctx,
                                                uint32_t domid,
                                                int *num)
{
    GC_INIT(ctx);
    libxl_device_channel *channels = NULL;
    int rc;

    *num = 0;

    rc = libxl__append_channel_list(gc, domid, &channels, num);
    if (rc) goto out_err;

    GC_FREE;
    return channels;

out_err:
    LOG(ERROR, "Unable to list channels");
    while (*num) {
        (*num)--;
        libxl_device_channel_dispose(&channels[*num]);
    }
    free(channels);
    return NULL;
}

int libxl_device_channel_getinfo(libxl_ctx *ctx, uint32_t domid,
                                 libxl_device_channel *channel,
                                 libxl_channelinfo *channelinfo)
{
    GC_INIT(ctx);
    char *dompath, *fe_path, *libxl_path;
    char *val;
    int rc;

    dompath = libxl__xs_get_dompath(gc, domid);
    channelinfo->devid = channel->devid;

    fe_path = GCSPRINTF("%s/device/console/%d", dompath,
                        channelinfo->devid + 1);
    libxl_path = GCSPRINTF("%s/device/console/%d",
                           libxl__xs_libxl_path(gc, domid),
                           channelinfo->devid + 1);
    channelinfo->backend = xs_read(ctx->xsh, XBT_NULL,
                                   GCSPRINTF("%s/backend", libxl_path), NULL);
    if (!channelinfo->backend) {
        GC_FREE;
        return ERROR_FAIL;
    }
    rc = libxl__backendpath_parse_domid(gc, channelinfo->backend,
                                        &channelinfo->backend_id);
    if (rc) goto out;

    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/state", fe_path));
    channelinfo->state = val ? strtoul(val, NULL, 10) : -1;
    channelinfo->frontend = libxl__strdup(NOGC, fe_path);
    channelinfo->frontend_id = domid;
    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/ring-ref", fe_path));
    channelinfo->rref = val ? strtoul(val, NULL, 10) : -1;
    val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/port", fe_path));
    channelinfo->evtch = val ? strtoul(val, NULL, 10) : -1;

    channelinfo->connection = channel->connection;
    switch (channel->connection) {
         case LIBXL_CHANNEL_CONNECTION_PTY:
             val = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/tty", fe_path));
             /*
              * It is obviously very wrong for this value to be in the
              * frontend.  But in XSA-175 we don't want to re-engineer
              * this because other xenconsole code elsewhere (some
              * even out of tree, perhaps) expects this node to be
              * here.
              *
              * FE/pty is readonly for the guest.  It always exists if
              * FE does because libxl__device_console_add
              * unconditionally creates it and nothing deletes it.
              *
              * The guest can delete the whole FE (which it has write
              * privilege on) but the containing directories
              * /local/GUEST[/device[/console]] are also RO for the
              * guest.  So if the guest deletes FE it cannot recreate
              * it.
              *
              * Therefore the guest cannot cause FE/pty to contain bad
              * data, although it can cause it to not exist.
              */
             if (!val) val = "/NO-SUCH-PATH";
             channelinfo->u.pty.path = strdup(val);
             break;
         default:
             break;
    }
    rc = 0;
 out:
    GC_FREE;
    return rc;
}

/******************************************************************************/

int libxl__device_vkb_setdefault(libxl__gc *gc, libxl_device_vkb *vkb)
{
    int rc;
    rc = libxl__resolve_domid(gc, vkb->backend_domname, &vkb->backend_domid);
    return rc;
}

static int libxl__device_from_vkb(libxl__gc *gc, uint32_t domid,
                                  libxl_device_vkb *vkb,
                                  libxl__device *device)
{
    device->backend_devid = vkb->devid;
    device->backend_domid = vkb->backend_domid;
    device->backend_kind = LIBXL__DEVICE_KIND_VKBD;
    device->devid = vkb->devid;
    device->domid = domid;
    device->kind = LIBXL__DEVICE_KIND_VKBD;

    return 0;
}

int libxl_device_vkb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vkb *vkb,
                         const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int rc;

    rc = libxl__device_vkb_add(gc, domid, vkb);
    if (rc) {
        LOG(ERROR, "unable to add vkb device");
        goto out;
    }

out:
    libxl__ao_complete(egc, ao, rc);
    return AO_INPROGRESS;
}

int libxl__device_vkb_add(libxl__gc *gc, uint32_t domid,
                          libxl_device_vkb *vkb)
{
    flexarray_t *front;
    flexarray_t *back;
    libxl__device device;
    int rc;

    rc = libxl__device_vkb_setdefault(gc, vkb);
    if (rc) goto out;

    front = flexarray_make(gc, 16, 1);
    back = flexarray_make(gc, 16, 1);

    if (vkb->devid == -1) {
        if ((vkb->devid = libxl__device_nextid(gc, domid, "vkb")) < 0) {
            rc = ERROR_FAIL;
            goto out;
        }
    }

    rc = libxl__device_from_vkb(gc, domid, vkb, &device);
    if (rc != 0) goto out;

    flexarray_append(back, "frontend-id");
    flexarray_append(back, GCSPRINTF("%d", domid));
    flexarray_append(back, "online");
    flexarray_append(back, "1");
    flexarray_append(back, "state");
    flexarray_append(back, GCSPRINTF("%d", XenbusStateInitialising));

    flexarray_append(front, "backend-id");
    flexarray_append(front, GCSPRINTF("%d", vkb->backend_domid));
    flexarray_append(front, "state");
    flexarray_append(front, GCSPRINTF("%d", XenbusStateInitialising));

    libxl__device_generic_add(gc, XBT_NULL, &device,
                              libxl__xs_kvs_of_flexarray(gc, back),
                              libxl__xs_kvs_of_flexarray(gc, front),
                              NULL);
    rc = 0;
out:
    return rc;
}

/******************************************************************************/

int libxl__device_vfb_setdefault(libxl__gc *gc, libxl_device_vfb *vfb)
{
    int rc;

    libxl_defbool_setdefault(&vfb->vnc.enable, true);
    if (libxl_defbool_val(vfb->vnc.enable)) {
        if (!vfb->vnc.listen) {
            vfb->vnc.listen = strdup("127.0.0.1");
            if (!vfb->vnc.listen) return ERROR_NOMEM;
        }

        libxl_defbool_setdefault(&vfb->vnc.findunused, true);
    } else {
        libxl_defbool_setdefault(&vfb->vnc.findunused, false);
    }

    libxl_defbool_setdefault(&vfb->sdl.enable, false);
    libxl_defbool_setdefault(&vfb->sdl.opengl, false);

    rc = libxl__resolve_domid(gc, vfb->backend_domname, &vfb->backend_domid);
    return rc;
}

static int libxl__device_from_vfb(libxl__gc *gc, uint32_t domid,
                                  libxl_device_vfb *vfb,
                                  libxl__device *device)
{
    device->backend_devid = vfb->devid;
    device->backend_domid = vfb->backend_domid;
    device->backend_kind = LIBXL__DEVICE_KIND_VFB;
    device->devid = vfb->devid;
    device->domid = domid;
    device->kind = LIBXL__DEVICE_KIND_VFB;
    return 0;
}

int libxl_device_vfb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vfb *vfb,
                         const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, domid, ao_how);
    int rc;

    rc = libxl__device_vfb_add(gc, domid, vfb);
    if (rc) {
        LOG(ERROR, "unable to add vfb device");
        goto out;
    }

out:
    libxl__ao_complete(egc, ao, rc);
    return AO_INPROGRESS;
}

int libxl__device_vfb_add(libxl__gc *gc, uint32_t domid, libxl_device_vfb *vfb)
{
    flexarray_t *front;
    flexarray_t *back;
    libxl__device device;
    int rc;

    rc = libxl__device_vfb_setdefault(gc, vfb);
    if (rc) goto out;

    front = flexarray_make(gc, 16, 1);
    back = flexarray_make(gc, 16, 1);

    if (vfb->devid == -1) {
        if ((vfb->devid = libxl__device_nextid(gc, domid, "vfb")) < 0) {
            rc = ERROR_FAIL;
            goto out;
        }
    }

    rc = libxl__device_from_vfb(gc, domid, vfb, &device);
    if (rc != 0) goto out;

    flexarray_append_pair(back, "frontend-id", GCSPRINTF("%d", domid));
    flexarray_append_pair(back, "online", "1");
    flexarray_append_pair(back, "state", GCSPRINTF("%d", XenbusStateInitialising));
    flexarray_append_pair(back, "vnc",
                          libxl_defbool_val(vfb->vnc.enable) ? "1" : "0");
    flexarray_append_pair(back, "vnclisten", vfb->vnc.listen);
    flexarray_append_pair(back, "vncpasswd", vfb->vnc.passwd);
    flexarray_append_pair(back, "vncdisplay",
                          GCSPRINTF("%d", vfb->vnc.display));
    flexarray_append_pair(back, "vncunused",
                          libxl_defbool_val(vfb->vnc.findunused) ? "1" : "0");
    flexarray_append_pair(back, "sdl",
                          libxl_defbool_val(vfb->sdl.enable) ? "1" : "0");
    flexarray_append_pair(back, "opengl",
                          libxl_defbool_val(vfb->sdl.opengl) ? "1" : "0");
    if (vfb->sdl.xauthority) {
        flexarray_append_pair(back, "xauthority", vfb->sdl.xauthority);
    }
    if (vfb->sdl.display) {
        flexarray_append_pair(back, "display", vfb->sdl.display);
    }

    flexarray_append_pair(front, "backend-id",
                          GCSPRINTF("%d", vfb->backend_domid));
    flexarray_append_pair(front, "state", GCSPRINTF("%d", XenbusStateInitialising));

    libxl__device_generic_add(gc, XBT_NULL, &device,
                              libxl__xs_kvs_of_flexarray(gc, back),
                              libxl__xs_kvs_of_flexarray(gc, front),
                              NULL);
    rc = 0;
out:
    return rc;
}

/******************************************************************************/

/* The following functions are defined:
 * libxl_device_disk_add
 * libxl__add_disks
 * libxl_device_disk_remove
 * libxl_device_disk_destroy
 * libxl_device_vkb_remove
 * libxl_device_vkb_destroy
 * libxl_device_vfb_remove
 * libxl_device_vfb_destroy
 */

/* channel/console hotunplug is not implemented. There are 2 possibilities:
 * 1. add support for secondary consoles to xenconsoled
 * 2. dynamically add/remove qemu chardevs via qmp messages. */

/* disk */
LIBXL_DEFINE_DEVICE_ADD(disk)
LIBXL_DEFINE_DEVICES_ADD(disk)
LIBXL_DEFINE_DEVICE_REMOVE(disk)

/* vkb */
LIBXL_DEFINE_DEVICE_REMOVE(vkb)

/* vfb */
LIBXL_DEFINE_DEVICE_REMOVE(vfb)

/******************************************************************************/

/*
 * Data structures used to track devices handled by driver domains
 */

/*
 * Structure that describes a device handled by a driver domain
 */
typedef struct libxl__ddomain_device {
    libxl__device *dev;
    LIBXL_SLIST_ENTRY(struct libxl__ddomain_device) next;
} libxl__ddomain_device;

/*
 * Structure that describes a domain and it's associated devices
 */
typedef struct libxl__ddomain_guest {
    uint32_t domid;
    int num_vifs, num_vbds, num_qdisks;
    LIBXL_SLIST_HEAD(, struct libxl__ddomain_device) devices;
    LIBXL_SLIST_ENTRY(struct libxl__ddomain_guest) next;
} libxl__ddomain_guest;

/*
 * Main structure used by a driver domain to keep track of devices
 * currently in use
 */
typedef struct {
    libxl__ao *ao;
    libxl__ev_xswatch watch;
    LIBXL_SLIST_HEAD(, struct libxl__ddomain_guest) guests;
} libxl__ddomain;

static libxl__ddomain_guest *search_for_guest(libxl__ddomain *ddomain,
                                               uint32_t domid)
{
    libxl__ddomain_guest *dguest;

    LIBXL_SLIST_FOREACH(dguest, &ddomain->guests, next) {
        if (dguest->domid == domid)
            return dguest;
    }
    return NULL;
}

static libxl__ddomain_device *search_for_device(libxl__ddomain_guest *dguest,
                                                libxl__device *dev)
{
    libxl__ddomain_device *ddev;

    LIBXL_SLIST_FOREACH(ddev, &dguest->devices, next) {
#define LIBXL_DEVICE_CMP(dev1, dev2, entry) (dev1->entry == dev2->entry)
        if (LIBXL_DEVICE_CMP(ddev->dev, dev, backend_devid) &&
            LIBXL_DEVICE_CMP(ddev->dev, dev, backend_domid) &&
            LIBXL_DEVICE_CMP(ddev->dev, dev, devid) &&
            LIBXL_DEVICE_CMP(ddev->dev, dev, domid) &&
            LIBXL_DEVICE_CMP(ddev->dev, dev, backend_kind) &&
            LIBXL_DEVICE_CMP(ddev->dev, dev, kind))
            return ddev;
#undef LIBXL_DEVICE_CMP
    }

    return NULL;
}

static void device_complete(libxl__egc *egc, libxl__ao_device *aodev)
{
    STATE_AO_GC(aodev->ao);

    LOG(DEBUG, "device %s %s %s",
               libxl__device_backend_path(gc, aodev->dev),
               libxl__device_action_to_string(aodev->action),
               aodev->rc ? "failed" : "succeed");

    if (aodev->action == LIBXL__DEVICE_ACTION_REMOVE)
        free(aodev->dev);

    libxl__nested_ao_free(aodev->ao);
}

static void qdisk_spawn_outcome(libxl__egc *egc, libxl__dm_spawn_state *dmss,
                                int rc)
{
    STATE_AO_GC(dmss->spawn.ao);

    LOG(DEBUG, "qdisk backend spawn for domain %u %s", dmss->guest_domid,
               rc ? "failed" : "succeed");

    libxl__nested_ao_free(dmss->spawn.ao);
}

/*
 * The following comment applies to both add_device and remove_device.
 *
 * If the return value is greater than 0, it means there's no ao dispatched,
 * so the free of the nested ao should be done by the parent when it has
 * finished.
 */
static int add_device(libxl__egc *egc, libxl__ao *ao,
                      libxl__ddomain_guest *dguest,
                      libxl__ddomain_device *ddev)
{
    AO_GC;
    libxl__device *dev = ddev->dev;
    libxl__ao_device *aodev;
    libxl__dm_spawn_state *dmss;
    int rc = 0;

    switch(dev->backend_kind) {
    case LIBXL__DEVICE_KIND_VBD:
    case LIBXL__DEVICE_KIND_VIF:
        if (dev->backend_kind == LIBXL__DEVICE_KIND_VBD) dguest->num_vbds++;
        if (dev->backend_kind == LIBXL__DEVICE_KIND_VIF) dguest->num_vifs++;

        GCNEW(aodev);
        libxl__prepare_ao_device(ao, aodev);
        aodev->dev = dev;
        aodev->action = LIBXL__DEVICE_ACTION_ADD;
        aodev->callback = device_complete;
        libxl__wait_device_connection(egc, aodev);

        break;
    case LIBXL__DEVICE_KIND_QDISK:
        if (dguest->num_qdisks == 0) {
            GCNEW(dmss);
            dmss->guest_domid = dev->domid;
            dmss->spawn.ao = ao;
            dmss->callback = qdisk_spawn_outcome;

            libxl__spawn_qdisk_backend(egc, dmss);
        }
        dguest->num_qdisks++;

        break;
    default:
        rc = 1;
        break;
    }

    return rc;
}

static int remove_device(libxl__egc *egc, libxl__ao *ao,
                         libxl__ddomain_guest *dguest,
                         libxl__ddomain_device *ddev)
{
    AO_GC;
    libxl__device *dev = ddev->dev;
    libxl__ao_device *aodev;
    int rc = 0;

    switch(ddev->dev->backend_kind) {
    case LIBXL__DEVICE_KIND_VBD:
    case LIBXL__DEVICE_KIND_VIF:
        if (dev->backend_kind == LIBXL__DEVICE_KIND_VBD) dguest->num_vbds--;
        if (dev->backend_kind == LIBXL__DEVICE_KIND_VIF) dguest->num_vifs--;

        GCNEW(aodev);
        libxl__prepare_ao_device(ao, aodev);
        aodev->dev = dev;
        aodev->action = LIBXL__DEVICE_ACTION_REMOVE;
        aodev->callback = device_complete;
        libxl__initiate_device_generic_remove(egc, aodev);
        break;
    case LIBXL__DEVICE_KIND_QDISK:
        if (--dguest->num_qdisks == 0) {
            rc = libxl__destroy_qdisk_backend(gc, dev->domid);
            if (rc)
                goto out;
        }
        libxl__device_destroy(gc, dev);
        free(dev);
        /* Fall through to return > 0, no ao has been dispatched */
    default:
        rc = 1;
        break;
    }

out:
    return rc;
}

static void backend_watch_callback(libxl__egc *egc, libxl__ev_xswatch *watch,
                                   const char *watch_path,
                                   const char *event_path)
{
    libxl__ddomain *ddomain = CONTAINER_OF(watch, *ddomain, watch);
    libxl__ao *nested_ao = libxl__nested_ao_create(ddomain->ao);
    STATE_AO_GC(nested_ao);
    char *p, *path;
    const char *sstate, *sonline;
    int state, online, rc, num_devs;
    libxl__device *dev = NULL;
    libxl__ddomain_device *ddev = NULL;
    libxl__ddomain_guest *dguest = NULL;
    bool free_ao = false;

    /* Check if event_path ends with "state" or "online" and truncate it. */
    path = libxl__strdup(gc, event_path);
    p = strrchr(path, '/');
    if (p == NULL)
        goto skip;
    if (strcmp(p, "/state") != 0 && strcmp(p, "/online") != 0)
        goto skip;
    /* Truncate the string so it points to the backend directory. */
    *p = '\0';

    /* Fetch the value of the state and online nodes. */
    rc = libxl__xs_read_checked(gc, XBT_NULL, GCSPRINTF("%s/state", path),
                                &sstate);
    if (rc || !sstate)
        goto skip;
    state = atoi(sstate);

    rc = libxl__xs_read_checked(gc, XBT_NULL, GCSPRINTF("%s/online", path),
                                &sonline);
    if (rc || !sonline)
        goto skip;
    online = atoi(sonline);

    dev = libxl__zalloc(NOGC, sizeof(*dev));
    rc = libxl__parse_backend_path(gc, path, dev);
    if (rc)
        goto skip;

    dguest = search_for_guest(ddomain, dev->domid);
    if (dguest == NULL && state == XenbusStateClosed) {
        /*
         * Spurious state change, device has already been disconnected
         * or never attached.
         */
        goto skip;
    }
    if (dguest == NULL) {
        /* Create a new guest struct and initialize it */
        dguest = libxl__zalloc(NOGC, sizeof(*dguest));
        dguest->domid = dev->domid;
        LIBXL_SLIST_INIT(&dguest->devices);
        LIBXL_SLIST_INSERT_HEAD(&ddomain->guests, dguest, next);
        LOG(DEBUG, "added domain %u to the list of active guests",
                   dguest->domid);
    }
    ddev = search_for_device(dguest, dev);
    if (ddev == NULL && state == XenbusStateClosed) {
        /*
         * Spurious state change, device has already been disconnected
         * or never attached.
         */
        goto skip;
    } else if (ddev == NULL) {
        /*
         * New device addition, allocate a struct to hold it and add it
         * to the list of active devices for a given guest.
         */
        ddev = libxl__zalloc(NOGC, sizeof(*ddev));
        ddev->dev = dev;
        LIBXL_SLIST_INSERT_HEAD(&dguest->devices, ddev, next);
        LOG(DEBUG, "added device %s to the list of active devices", path);
        rc = add_device(egc, nested_ao, dguest, ddev);
        if (rc > 0)
            free_ao = true;
    } else if (state == XenbusStateClosed && online == 0) {
        /*
         * Removal of an active device, remove it from the list and
         * free it's data structures if they are no longer needed.
         *
         * The free of the associated libxl__device is left to the
         * helper remove_device function.
         */
        LIBXL_SLIST_REMOVE(&dguest->devices, ddev, libxl__ddomain_device,
                           next);
        LOG(DEBUG, "removed device %s from the list of active devices", path);
        rc = remove_device(egc, nested_ao, dguest, ddev);
        if (rc > 0)
            free_ao = true;

        free(ddev);
        /* If this was the last device in the domain, remove it from the list */
        num_devs = dguest->num_vifs + dguest->num_vbds + dguest->num_qdisks;
        if (num_devs == 0) {
            LIBXL_SLIST_REMOVE(&ddomain->guests, dguest, libxl__ddomain_guest,
                               next);
            LOG(DEBUG, "removed domain %u from the list of active guests",
                       dguest->domid);
            /* Clear any leftovers in libxl/<domid> */
            libxl__xs_rm_checked(gc, XBT_NULL,
                                 GCSPRINTF("libxl/%u", dguest->domid));
            free(dguest);
        }
    }

    if (free_ao)
        libxl__nested_ao_free(nested_ao);

    return;

skip:
    libxl__nested_ao_free(nested_ao);
    free(dev);
    free(ddev);
    free(dguest);
    return;
}

/* Handler of events for device driver domains */
int libxl_device_events_handler(libxl_ctx *ctx,
                                const libxl_asyncop_how *ao_how)
{
    AO_CREATE(ctx, 0, ao_how);
    int rc;
    uint32_t domid;
    libxl__ddomain ddomain;
    char *be_path;
    char **kinds = NULL, **domains = NULL, **devs = NULL;
    const char *sstate;
    char *state_path;
    int state;
    unsigned int nkinds, ndomains, ndevs;
    int i, j, k;

    ddomain.ao = ao;
    LIBXL_SLIST_INIT(&ddomain.guests);

    rc = libxl__get_domid(gc, &domid);
    if (rc) {
        LOG(ERROR, "unable to get domain id");
        goto out;
    }

    /*
     * We use absolute paths because we want xswatch to also return
     * absolute paths that can be parsed by libxl__parse_backend_path.
     */
    be_path = GCSPRINTF("/local/domain/%u/backend", domid);
    rc = libxl__ev_xswatch_register(gc, &ddomain.watch, backend_watch_callback,
                                    be_path);
    if (rc) goto out;

    kinds = libxl__xs_directory(gc, XBT_NULL, be_path, &nkinds);
    if (kinds) {
        for (i = 0; i < nkinds; i++) {
            domains = libxl__xs_directory(gc, XBT_NULL,
                    GCSPRINTF("%s/%s", be_path, kinds[i]), &ndomains);
            if (!domains)
                continue;
            for (j = 0; j < ndomains; j++) {
                devs = libxl__xs_directory(gc, XBT_NULL,
                        GCSPRINTF("%s/%s/%s", be_path, kinds[i], domains[j]), &ndevs);
                if (!devs)
                    continue;
                for (k = 0; k < ndevs; k++) {
                    state_path = GCSPRINTF("%s/%s/%s/%s/state",
                            be_path, kinds[i], domains[j], devs[k]);
                    rc = libxl__xs_read_checked(gc, XBT_NULL, state_path, &sstate);
                    if (rc || !sstate)
                        continue;
                    state = atoi(sstate);
                    if (state == XenbusStateInitWait)
                        backend_watch_callback(egc, &ddomain.watch,
                                               be_path, state_path);
                }
            }
        }
    }

    return AO_INPROGRESS;

out:
    return AO_CREATE_FAIL(rc);
}

/******************************************************************************/

int libxl_domain_setmaxmem(libxl_ctx *ctx, uint32_t domid, uint64_t max_memkb)
{
    GC_INIT(ctx);
    char *mem, *endptr;
    uint64_t memorykb, size;
    char *dompath = libxl__xs_get_dompath(gc, domid);
    int rc = 1;
    libxl__domain_userdata_lock *lock = NULL;
    libxl_domain_config d_config;

    libxl_domain_config_init(&d_config);

    CTX_LOCK;

    lock = libxl__lock_domain_userdata(gc, domid);
    if (!lock) {
        rc = ERROR_LOCK_FAIL;
        goto out;
    }

    mem = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/memory/target", dompath));
    if (!mem) {
        LOGE(ERROR, "cannot get memory info from %s/memory/target", dompath);
        goto out;
    }
    memorykb = strtoull(mem, &endptr, 10);
    if (*endptr != '\0') {
        LOGE(ERROR, "invalid memory %s from %s/memory/target\n", mem, dompath);
        goto out;
    }

    if (max_memkb < memorykb) {
        LOGE(ERROR,
             "memory_static_max must be greater than or or equal to memory_dynamic_max");
        goto out;
    }

    rc = libxl__get_domain_configuration(gc, domid, &d_config);
    if (rc < 0) {
        LOGE(ERROR, "unable to retrieve domain configuration");
        goto out;
    }

    rc = libxl__arch_extra_memory(gc, &d_config.b_info, &size);
    if (rc < 0) {
        LOGE(ERROR, "Couldn't get arch extra constant memory size");
        goto out;
    }

    rc = xc_domain_setmaxmem(ctx->xch, domid, max_memkb + size);
    if (rc != 0) {
        LOGE(ERROR,
             "xc_domain_setmaxmem domid=%d memkb=%"PRIu64" failed ""rc=%d\n",
             domid, max_memkb + size, rc);
        goto out;
    }

    rc = 0;
out:
    libxl_domain_config_dispose(&d_config);
    if (lock) libxl__unlock_domain_userdata(lock);
    CTX_UNLOCK;
    GC_FREE;
    return rc;
}

static int libxl__fill_dom0_memory_info(libxl__gc *gc, uint64_t *target_memkb,
                                        uint64_t *max_memkb)
{
    int rc;
    libxl_dominfo info;
    libxl_physinfo physinfo;
    char *target = NULL, *staticmax = NULL, *endptr = NULL;
    char *target_path = "/local/domain/0/memory/target";
    char *max_path = "/local/domain/0/memory/static-max";
    xs_transaction_t t;
    libxl_ctx *ctx = libxl__gc_owner(gc);

    libxl_dominfo_init(&info);

retry_transaction:
    t = xs_transaction_start(ctx->xsh);

    target = libxl__xs_read(gc, t, target_path);
    staticmax = libxl__xs_read(gc, t, max_path);
    if (target && staticmax) {
        rc = 0;
        goto out;
    }

    if (target) {
        *target_memkb = strtoull(target, &endptr, 10);
        if (*endptr != '\0') {
            LOGE(ERROR, "invalid memory target %s from %s\n", target,
                 target_path);
            rc = ERROR_FAIL;
            goto out;
        }
    }

    if (staticmax) {
        *max_memkb = strtoull(staticmax, &endptr, 10);
        if (*endptr != '\0') {
            LOGE(ERROR, "invalid memory static-max %s from %s\n", staticmax,
                 max_path);
            rc = ERROR_FAIL;
            goto out;
        }
    }

    libxl_dominfo_dispose(&info);
    libxl_dominfo_init(&info);
    rc = libxl_domain_info(ctx, &info, 0);
    if (rc < 0)
        goto out;

    rc = libxl_get_physinfo(ctx, &physinfo);
    if (rc < 0)
        goto out;

    if (target == NULL) {
        libxl__xs_printf(gc, t, target_path, "%"PRIu64, info.current_memkb);
        *target_memkb = info.current_memkb;
    }
    if (staticmax == NULL) {
        libxl__xs_printf(gc, t, max_path, "%"PRIu64, info.max_memkb);
        *max_memkb = info.max_memkb;
    }

    rc = 0;

out:
    if (!xs_transaction_end(ctx->xsh, t, 0)) {
        if (errno == EAGAIN)
            goto retry_transaction;
        else
            rc = ERROR_FAIL;
    }

    libxl_dominfo_dispose(&info);
    return rc;
}

int libxl_set_memory_target(libxl_ctx *ctx, uint32_t domid,
        int64_t target_memkb, int relative, int enforce)
{
    GC_INIT(ctx);
    int rc, r, lrc, abort_transaction = 0;
    uint64_t memorykb, size;
    uint64_t videoram = 0;
    uint64_t current_target_memkb = 0, new_target_memkb = 0;
    uint64_t current_max_memkb = 0;
    char *memmax, *endptr, *videoram_s = NULL, *target = NULL;
    char *dompath = libxl__xs_get_dompath(gc, domid);
    xc_domaininfo_t info;
    libxl_dominfo ptr;
    char *uuid;
    xs_transaction_t t;
    libxl__domain_userdata_lock *lock;
    libxl_domain_config d_config;

    libxl_domain_config_init(&d_config);

    CTX_LOCK;

    lock = libxl__lock_domain_userdata(gc, domid);
    if (!lock) {
        rc = ERROR_LOCK_FAIL;
        goto out_no_transaction;
    }

    rc = libxl__get_domain_configuration(gc, domid, &d_config);
    if (rc < 0) {
        LOGE(ERROR, "unable to retrieve domain configuration");
        goto out_no_transaction;
    }

    rc = libxl__arch_extra_memory(gc, &d_config.b_info, &size);
    if (rc < 0) {
        LOGE(ERROR, "Couldn't get arch extra constant memory size");
        goto out_no_transaction;
    }

retry_transaction:
    t = xs_transaction_start(ctx->xsh);

    target = libxl__xs_read(gc, t, GCSPRINTF("%s/memory/target", dompath));
    if (!target && !domid) {
        if (!xs_transaction_end(ctx->xsh, t, 1)) {
            rc = ERROR_FAIL;
            goto out_no_transaction;
        }
        lrc = libxl__fill_dom0_memory_info(gc, &current_target_memkb,
                                           &current_max_memkb);
        if (lrc < 0) { rc = ERROR_FAIL; goto out_no_transaction; }
        goto retry_transaction;
    } else if (!target) {
        LOGE(ERROR, "cannot get target memory info from %s/memory/target",
             dompath);
        abort_transaction = 1;
        rc = ERROR_FAIL;
        goto out;
    } else {
        current_target_memkb = strtoull(target, &endptr, 10);
        if (*endptr != '\0') {
            LOGE(ERROR, "invalid memory target %s from %s/memory/target\n",
                 target, dompath);
            abort_transaction = 1;
            rc = ERROR_FAIL;
            goto out;
        }
    }
    memmax = libxl__xs_read(gc, t, GCSPRINTF("%s/memory/static-max", dompath));
    if (!memmax) {
        LOGE(ERROR, "cannot get memory info from %s/memory/static-max",
             dompath);
        abort_transaction = 1;
        rc = ERROR_FAIL;
        goto out;
    }
    memorykb = strtoull(memmax, &endptr, 10);
    if (*endptr != '\0') {
        LOGE(ERROR, "invalid max memory %s from %s/memory/static-max\n",
             memmax, dompath);
        abort_transaction = 1;
        rc = ERROR_FAIL;
        goto out;
    }

    videoram_s = libxl__xs_read(gc, t, GCSPRINTF("%s/memory/videoram",
                                                 dompath));
    videoram = videoram_s ? atoi(videoram_s) : 0;

    if (relative) {
        if (target_memkb < 0 && llabs(target_memkb) > current_target_memkb)
            new_target_memkb = 0;
        else
            new_target_memkb = current_target_memkb + target_memkb;
    } else
        new_target_memkb = target_memkb - videoram;
    if (new_target_memkb > memorykb) {
        LOG(ERROR,
            "memory_dynamic_max must be less than or equal to"
            " memory_static_max\n");
        abort_transaction = 1;
        rc = ERROR_INVAL;
        goto out;
    }

    if (!domid && new_target_memkb < LIBXL_MIN_DOM0_MEM) {
        LOG(ERROR,
            "new target %"PRIu64" for dom0 is below the minimum threshold",
            new_target_memkb);
        abort_transaction = 1;
        rc = ERROR_INVAL;
        goto out;
    }

    if (enforce) {
        memorykb = new_target_memkb + videoram;
        r = xc_domain_setmaxmem(ctx->xch, domid, memorykb + size);
        if (r != 0) {
            LOGE(ERROR,
                 "xc_domain_setmaxmem domid=%u memkb=%"PRIu64" failed ""rc=%d\n",
                 domid,
                 memorykb + size,
                 r);
            abort_transaction = 1;
            rc = ERROR_FAIL;
            goto out;
        }
    }

    r = xc_domain_set_pod_target(ctx->xch, domid,
            (new_target_memkb + size) / 4, NULL, NULL, NULL);
    if (r != 0) {
        LOGE(ERROR,
             "xc_domain_set_pod_target domid=%d, memkb=%"PRIu64" failed rc=%d\n",
             domid,
             (new_target_memkb + size) / 4,
             r);
        abort_transaction = 1;
        rc = ERROR_FAIL;
        goto out;
    }

    libxl__xs_printf(gc, t, GCSPRINTF("%s/memory/target", dompath),
                     "%"PRIu64, new_target_memkb);

    r = xc_domain_getinfolist(ctx->xch, domid, 1, &info);
    if (r != 1 || info.domain != domid) {
        abort_transaction = 1;
        rc = ERROR_FAIL;
        goto out;
    }

    libxl_dominfo_init(&ptr);
    xcinfo2xlinfo(ctx, &info, &ptr);
    uuid = libxl__uuid2string(gc, ptr.uuid);
    libxl__xs_printf(gc, t, GCSPRINTF("/vm/%s/memory", uuid),
                     "%"PRIu64, new_target_memkb / 1024);
    libxl_dominfo_dispose(&ptr);

    rc = 0;
out:
    if (!xs_transaction_end(ctx->xsh, t, abort_transaction)
        && !abort_transaction)
        if (errno == EAGAIN)
            goto retry_transaction;

out_no_transaction:
    libxl_domain_config_dispose(&d_config);
    if (lock) libxl__unlock_domain_userdata(lock);
    CTX_UNLOCK;
    GC_FREE;
    return rc;
}

/* out_target_memkb and out_max_memkb can be NULL */
static int libxl__get_memory_target(libxl__gc *gc, uint32_t domid,
                                    uint64_t *out_target_memkb,
                                    uint64_t *out_max_memkb)
{
    int rc;
    char *target = NULL, *static_max = NULL, *endptr = NULL;
    char *dompath = libxl__xs_get_dompath(gc, domid);
    uint64_t target_memkb, max_memkb;

    target = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/memory/target",
                                                    dompath));
    static_max = libxl__xs_read(gc, XBT_NULL,
                    GCSPRINTF("%s/memory/static-max", dompath));

    rc = ERROR_FAIL;
    if ((!target || !static_max) && !domid) {
        rc = libxl__fill_dom0_memory_info(gc, &target_memkb,
                                          &max_memkb);
        if (rc < 0)
            goto out;
    } else if (!target) {
        LOGE(ERROR, "cannot get target memory info from %s/memory/target",
             dompath);
        goto out;
    } else if (!static_max) {
        LOGE(ERROR,
             "cannot get target memory info from %s/memory/static-max",
             dompath);
        goto out;
    } else {
        target_memkb = strtoull(target, &endptr, 10);
        if (*endptr != '\0') {
            LOGE(ERROR, "invalid memory target %s from %s/memory/target\n",
                 target, dompath);
            goto out;
        }
        max_memkb = strtoull(static_max, &endptr, 10);
        if (*endptr != '\0') {
            LOGE(ERROR,
                 "invalid memory target %s from %s/memory/static-max\n",
                 static_max,
                 dompath);
            goto out;
        }

    }

    if (out_target_memkb)
        *out_target_memkb = target_memkb;

    if (out_max_memkb)
        *out_max_memkb = max_memkb;

    rc = 0;

out:
    return rc;
}

static int libxl__memkb_64to32(libxl_ctx *ctx, int rc,
                               uint64_t val64, uint32_t *ptr32)
{
    GC_INIT(ctx);

    if (rc)
        goto out;

    *ptr32 = val64;
    if (*ptr32 == val64)
        goto out;

    LOGE(ERROR, "memory size %"PRIu64" too large for 32 bit value\n", val64);
    rc = ERROR_FAIL;

out:
    GC_FREE;
    return rc;
}

int libxl_get_memory_target(libxl_ctx *ctx, uint32_t domid,
                            uint64_t *out_target)
{
    GC_INIT(ctx);
    int rc;

    rc = libxl__get_memory_target(gc, domid, out_target, NULL);

    GC_FREE;
    return rc;
}

int libxl_get_memory_target_0x040700(
    libxl_ctx *ctx, uint32_t domid, uint32_t *out_target)
{
    uint64_t my_out_target;
    int rc;

    rc = libxl_get_memory_target(ctx, domid, &my_out_target);
    return libxl__memkb_64to32(ctx, rc, my_out_target, out_target);
}

int libxl_domain_need_memory(libxl_ctx *ctx,
                             const libxl_domain_build_info *b_info_in,
                             uint64_t *need_memkb)
{
    GC_INIT(ctx);
    libxl_domain_build_info b_info[1];
    int rc;

    libxl_domain_build_info_init(b_info);
    libxl_domain_build_info_copy(ctx, b_info, b_info_in);

    rc = libxl__domain_build_info_setdefault(gc, b_info);
    if (rc) goto out;

    *need_memkb = b_info->target_memkb;
    switch (b_info->type) {
    case LIBXL_DOMAIN_TYPE_PVH:
    case LIBXL_DOMAIN_TYPE_HVM:
        *need_memkb += b_info->shadow_memkb + LIBXL_HVM_EXTRA_MEMORY;
        if (libxl_defbool_val(b_info->device_model_stubdomain))
            *need_memkb += 32 * 1024;
        break;
    case LIBXL_DOMAIN_TYPE_PV:
        *need_memkb += b_info->shadow_memkb + LIBXL_PV_EXTRA_MEMORY;
        break;
    default:
        rc = ERROR_INVAL;
        goto out;
    }
    if (*need_memkb % (2 * 1024))
        *need_memkb += (2 * 1024) - (*need_memkb % (2 * 1024));
    rc = 0;
out:
    GC_FREE;
    libxl_domain_build_info_dispose(b_info);
    return rc;

}

int libxl_domain_need_memory_0x040700(libxl_ctx *ctx,
                                      const libxl_domain_build_info *b_info_in,
                                      uint32_t *need_memkb)
{
    uint64_t my_need_memkb;
    int rc;

    rc = libxl_domain_need_memory(ctx, b_info_in, &my_need_memkb);
    return libxl__memkb_64to32(ctx, rc, my_need_memkb, need_memkb);
}

int libxl_get_free_memory(libxl_ctx *ctx, uint64_t *memkb)
{
    int rc = 0;
    libxl_physinfo info;
    GC_INIT(ctx);

    rc = libxl_get_physinfo(ctx, &info);
    if (rc < 0)
        goto out;

    *memkb = (info.free_pages + info.scrub_pages) * 4;

out:
    GC_FREE;
    return rc;
}

int libxl_get_free_memory_0x040700(libxl_ctx *ctx, uint32_t *memkb)
{
    uint64_t my_memkb;
    int rc;

    rc = libxl_get_free_memory(ctx, &my_memkb);
    return libxl__memkb_64to32(ctx, rc, my_memkb, memkb);
}

int libxl_wait_for_free_memory(libxl_ctx *ctx, uint32_t domid,
                               uint64_t memory_kb, int wait_secs)
{
    int rc = 0;
    libxl_physinfo info;
    GC_INIT(ctx);

    while (wait_secs > 0) {
        rc = libxl_get_physinfo(ctx, &info);
        if (rc < 0)
            goto out;
        if (info.free_pages * 4 >= memory_kb) {
            rc = 0;
            goto out;
        }
        wait_secs--;
        sleep(1);
    }
    rc = ERROR_NOMEM;

out:
    GC_FREE;
    return rc;
}

int libxl_wait_for_memory_target(libxl_ctx *ctx, uint32_t domid, int wait_secs)
{
    int rc = 0;
    uint64_t target_memkb = 0;
    uint64_t current_memkb, prev_memkb;
    libxl_dominfo info;

    rc = libxl_get_memory_target(ctx, domid, &target_memkb);
    if (rc < 0)
        return rc;

    libxl_dominfo_init(&info);
    prev_memkb = UINT64_MAX;

    do {
        sleep(2);

        libxl_dominfo_dispose(&info);
        libxl_dominfo_init(&info);
        rc = libxl_domain_info(ctx, &info, domid);
        if (rc < 0)
            goto out;

        current_memkb = info.current_memkb + info.outstanding_memkb;

        if (current_memkb > prev_memkb)
        {
            rc = ERROR_FAIL;
            goto out;
        }
        else if (current_memkb == prev_memkb)
            wait_secs -= 2;
        /* if current_memkb < prev_memkb loop for free as progress has
         * been made */

        prev_memkb = current_memkb;
    } while (wait_secs > 0 && current_memkb > target_memkb);

    if (current_memkb <= target_memkb)
        rc = 0;
    else
        rc = ERROR_FAIL;

out:
    libxl_dominfo_dispose(&info);
    return rc;
}

int libxl_get_physinfo(libxl_ctx *ctx, libxl_physinfo *physinfo)
{
    xc_physinfo_t xcphysinfo = { 0 };
    int rc;
    long l;
    GC_INIT(ctx);

    rc = xc_physinfo(ctx->xch, &xcphysinfo);
    if (rc != 0) {
        LOGE(ERROR, "getting physinfo");
        GC_FREE;
        return ERROR_FAIL;
    }
    physinfo->threads_per_core = xcphysinfo.threads_per_core;
    physinfo->cores_per_socket = xcphysinfo.cores_per_socket;
    physinfo->max_cpu_id = xcphysinfo.max_cpu_id;
    physinfo->nr_cpus = xcphysinfo.nr_cpus;
    physinfo->cpu_khz = xcphysinfo.cpu_khz;
    physinfo->total_pages = xcphysinfo.total_pages;
    physinfo->free_pages = xcphysinfo.free_pages;
    physinfo->scrub_pages = xcphysinfo.scrub_pages;
    physinfo->outstanding_pages = xcphysinfo.outstanding_pages;
    l = xc_sharing_freed_pages(ctx->xch);
    if (l < 0 && errno == ENOSYS) {
        l = 0;
    } else if (l < 0) {
        LOGEV(ERROR, l, "getting sharing freed pages");
        GC_FREE;
        return ERROR_FAIL;
    }
    physinfo->sharing_freed_pages = l;
    l = xc_sharing_used_frames(ctx->xch);
    if (l < 0 && errno == ENOSYS) {
        l = 0;
    } else if (l < 0) {
        LOGEV(ERROR, l, "getting sharing used frames");
        GC_FREE;
        return ERROR_FAIL;
    }
    physinfo->sharing_used_frames = l;
    physinfo->nr_nodes = xcphysinfo.nr_nodes;
    memcpy(physinfo->hw_cap,xcphysinfo.hw_cap, sizeof(physinfo->hw_cap));

    physinfo->cap_hvm = !!(xcphysinfo.capabilities & XEN_SYSCTL_PHYSCAP_hvm);
    physinfo->cap_hvm_directio =
        !!(xcphysinfo.capabilities & XEN_SYSCTL_PHYSCAP_hvm_directio);

    GC_FREE;
    return 0;
}

libxl_cputopology *libxl_get_cpu_topology(libxl_ctx *ctx, int *nb_cpu_out)
{
    GC_INIT(ctx);
    xc_cputopo_t *cputopo;
    libxl_cputopology *ret = NULL;
    int i;
    unsigned num_cpus = 0;

    /* Setting buffer to NULL makes the call return number of CPUs */
    if (xc_cputopoinfo(ctx->xch, &num_cpus, NULL))
    {
        LOGE(ERROR, "Unable to determine number of CPUS");
        goto out;
    }

    cputopo = libxl__zalloc(gc, sizeof(*cputopo) * num_cpus);

    if (xc_cputopoinfo(ctx->xch, &num_cpus, cputopo)) {
        LOGE(ERROR, "CPU topology info hypercall failed");
        goto out;
    }

    ret = libxl__zalloc(NOGC, sizeof(libxl_cputopology) * num_cpus);

    for (i = 0; i < num_cpus; i++) {
#define V(map, i, invalid) ( cputopo[i].map == invalid) ? \
   LIBXL_CPUTOPOLOGY_INVALID_ENTRY : cputopo[i].map
        ret[i].core = V(core, i, XEN_INVALID_CORE_ID);
        ret[i].socket = V(socket, i, XEN_INVALID_SOCKET_ID);
        ret[i].node = V(node, i, XEN_INVALID_NODE_ID);
#undef V
    }

    *nb_cpu_out = num_cpus;

 out:
    GC_FREE;
    return ret;
}

libxl_pcitopology *libxl_get_pci_topology(libxl_ctx *ctx, int *num_devs)
{
    GC_INIT(ctx);
    physdev_pci_device_t *devs;
    uint32_t *nodes;
    libxl_pcitopology *ret = NULL;
    int i, rc;

    *num_devs = libxl__pci_numdevs(gc);
    if (*num_devs < 0) {
        LOG(ERROR, "Unable to determine number of PCI devices, rc %d",
            *num_devs);
        goto out;
    }

    devs = libxl__zalloc(gc, sizeof(*devs) * *num_devs);
    nodes = libxl__zalloc(gc, sizeof(*nodes) * *num_devs);

    rc = libxl__pci_topology_init(gc, devs, *num_devs);
    if (rc) {
        LOG(ERROR, "Cannot initialize PCI hypercall structure, rc %d", rc);
        goto out;
    }

    if (xc_pcitopoinfo(ctx->xch, *num_devs, devs, nodes) != 0) {
        LOGE(ERROR, "PCI topology info hypercall failed");
        goto out;
    }

    ret = libxl__zalloc(NOGC, sizeof(libxl_pcitopology) * *num_devs);

    for (i = 0; i < *num_devs; i++) {
        ret[i].seg = devs[i].seg;
        ret[i].bus = devs[i].bus;
        ret[i].devfn = devs[i].devfn;
        ret[i].node = ((nodes[i] == XEN_INVALID_NODE_ID) ||
                       (nodes[i] == XEN_INVALID_DEV)) ?
            LIBXL_PCITOPOLOGY_INVALID_ENTRY : nodes[i];
    }

 out:
    GC_FREE;
    return ret;
}

libxl_numainfo *libxl_get_numainfo(libxl_ctx *ctx, int *nr)
{
    GC_INIT(ctx);
    xc_meminfo_t *meminfo;
    uint32_t *distance;
    libxl_numainfo *ret = NULL;
    int i, j;
    unsigned num_nodes = 0;

    if (xc_numainfo(ctx->xch, &num_nodes, NULL, NULL)) {
        LOGE(ERROR, "Unable to determine number of nodes");
        goto out;
    }

    meminfo = libxl__zalloc(gc, sizeof(*meminfo) * num_nodes);
    distance = libxl__zalloc(gc, sizeof(*distance) * num_nodes * num_nodes);

    if (xc_numainfo(ctx->xch, &num_nodes, meminfo, distance)) {
        LOGE(ERROR, "getting numainfo");
        goto out;
    }

    *nr = num_nodes;

    ret = libxl__zalloc(NOGC, sizeof(libxl_numainfo) * num_nodes);
    for (i = 0; i < num_nodes; i++)
        ret[i].dists = libxl__calloc(NOGC, num_nodes, sizeof(*distance));

    for (i = 0; i < num_nodes; i++) {
#define V(val, invalid) (val == invalid) ? \
       LIBXL_NUMAINFO_INVALID_ENTRY : val
        ret[i].size = V(meminfo[i].memsize, XEN_INVALID_MEM_SZ);
        ret[i].free = V(meminfo[i].memfree, XEN_INVALID_MEM_SZ);
        ret[i].num_dists = num_nodes;
        for (j = 0; j < ret[i].num_dists; j++) {
            unsigned idx = i * num_nodes + j;
            ret[i].dists[j] = V(distance[idx], XEN_INVALID_NODE_DIST);
        }
#undef V
    }

 out:
    GC_FREE;
    return ret;
}

static int libxl__xc_version_wrap(libxl__gc *gc, libxl_version_info *info,
                                  xen_build_id_t *build)
{
    int r;

    r = xc_version(CTX->xch, XENVER_build_id, build);
    switch (r) {
    case -EPERM:
    case -ENODATA:
    case 0:
        info->build_id = libxl__strdup(NOGC, "");
        break;

    case -ENOBUFS:
        break;

    default:
        if (r > 0) {
            unsigned int i;

            info->build_id = libxl__zalloc(NOGC, (r * 2) + 1);

            for (i = 0; i < r ; i++)
                snprintf(&info->build_id[i * 2], 3, "%02hhx", build->buf[i]);

            r = 0;
        }
        break;
    }
    return r;
}

const libxl_version_info* libxl_get_version_info(libxl_ctx *ctx)
{
    GC_INIT(ctx);
    union {
        xen_extraversion_t xen_extra;
        xen_compile_info_t xen_cc;
        xen_changeset_info_t xen_chgset;
        xen_capabilities_info_t xen_caps;
        xen_platform_parameters_t p_parms;
        xen_commandline_t xen_commandline;
        xen_build_id_t build_id;
    } u;
    long xen_version;
    int r;
    libxl_version_info *info = &ctx->version_info;

    if (info->xen_version_extra != NULL)
        goto out;

    xen_version = xc_version(ctx->xch, XENVER_version, NULL);
    info->xen_version_major = xen_version >> 16;
    info->xen_version_minor = xen_version & 0xFF;

    xc_version(ctx->xch, XENVER_extraversion, &u.xen_extra);
    info->xen_version_extra = libxl__strdup(NOGC, u.xen_extra);

    xc_version(ctx->xch, XENVER_compile_info, &u.xen_cc);
    info->compiler = libxl__strdup(NOGC, u.xen_cc.compiler);
    info->compile_by = libxl__strdup(NOGC, u.xen_cc.compile_by);
    info->compile_domain = libxl__strdup(NOGC, u.xen_cc.compile_domain);
    info->compile_date = libxl__strdup(NOGC, u.xen_cc.compile_date);

    xc_version(ctx->xch, XENVER_capabilities, &u.xen_caps);
    info->capabilities = libxl__strdup(NOGC, u.xen_caps);

    xc_version(ctx->xch, XENVER_changeset, &u.xen_chgset);
    info->changeset = libxl__strdup(NOGC, u.xen_chgset);

    xc_version(ctx->xch, XENVER_platform_parameters, &u.p_parms);
    info->virt_start = u.p_parms.virt_start;

    info->pagesize = xc_version(ctx->xch, XENVER_pagesize, NULL);

    xc_version(ctx->xch, XENVER_commandline, &u.xen_commandline);
    info->commandline = libxl__strdup(NOGC, u.xen_commandline);

    u.build_id.len = sizeof(u) - sizeof(u.build_id);
    r = libxl__xc_version_wrap(gc, info, &u.build_id);
    if (r == -ENOBUFS) {
            xen_build_id_t *build_id;

            build_id = libxl__zalloc(gc, info->pagesize);
            build_id->len = info->pagesize - sizeof(*build_id);
            r = libxl__xc_version_wrap(gc, info, build_id);
            if (r) LOGEV(ERROR, r, "getting build_id");
    }
 out:
    GC_FREE;
    return info;
}

libxl_vcpuinfo *libxl_list_vcpu(libxl_ctx *ctx, uint32_t domid,
                                       int *nr_vcpus_out, int *nr_cpus_out)
{
    GC_INIT(ctx);
    libxl_vcpuinfo *ptr, *ret;
    xc_domaininfo_t domaininfo;
    xc_vcpuinfo_t vcpuinfo;

    if (xc_domain_getinfolist(ctx->xch, domid, 1, &domaininfo) != 1) {
        LOGE(ERROR, "getting infolist");
        GC_FREE;
        return NULL;
    }

    if (domaininfo.max_vcpu_id == XEN_INVALID_MAX_VCPU_ID) {
        GC_FREE;
        return NULL;
    }

    *nr_cpus_out = libxl_get_max_cpus(ctx);
    ret = ptr = libxl__calloc(NOGC, domaininfo.max_vcpu_id + 1,
                              sizeof(libxl_vcpuinfo));

    for (*nr_vcpus_out = 0;
         *nr_vcpus_out <= domaininfo.max_vcpu_id;
         ++*nr_vcpus_out, ++ptr) {
        libxl_bitmap_init(&ptr->cpumap);
        if (libxl_cpu_bitmap_alloc(ctx, &ptr->cpumap, 0))
            goto err;
        libxl_bitmap_init(&ptr->cpumap_soft);
        if (libxl_cpu_bitmap_alloc(ctx, &ptr->cpumap_soft, 0))
            goto err;
        if (xc_vcpu_getinfo(ctx->xch, domid, *nr_vcpus_out, &vcpuinfo) == -1) {
            LOGE(ERROR, "getting vcpu info");
            goto err;
        }

        if (xc_vcpu_getaffinity(ctx->xch, domid, *nr_vcpus_out,
                                ptr->cpumap.map, ptr->cpumap_soft.map,
                                XEN_VCPUAFFINITY_SOFT|XEN_VCPUAFFINITY_HARD) == -1) {
            LOGE(ERROR, "getting vcpu affinity");
            goto err;
        }
        ptr->vcpuid = *nr_vcpus_out;
        ptr->cpu = vcpuinfo.cpu;
        ptr->online = !!vcpuinfo.online;
        ptr->blocked = !!vcpuinfo.blocked;
        ptr->running = !!vcpuinfo.running;
        ptr->vcpu_time = vcpuinfo.cpu_time;
    }
    GC_FREE;
    return ret;

err:
    libxl_bitmap_dispose(&ptr->cpumap);
    libxl_bitmap_dispose(&ptr->cpumap_soft);
    free(ret);
    GC_FREE;
    return NULL;
}

static int libxl__set_vcpuaffinity(libxl_ctx *ctx, uint32_t domid,
                                   uint32_t vcpuid,
                                   const libxl_bitmap *cpumap_hard,
                                   const libxl_bitmap *cpumap_soft,
                                   unsigned flags)
{
    GC_INIT(ctx);
    libxl_bitmap hard, soft;
    int rc;

    libxl_bitmap_init(&hard);
    libxl_bitmap_init(&soft);

    if (!cpumap_hard && !cpumap_soft && !flags) {
        rc = ERROR_INVAL;
        goto out;
    }

    /*
     * Xen wants writable hard and/or soft cpumaps, to put back in them
     * the effective hard and/or soft affinity that will be used.
     */
    if (cpumap_hard) {
        rc = libxl_cpu_bitmap_alloc(ctx, &hard, 0);
        if (rc)
            goto out;

        libxl__bitmap_copy_best_effort(gc, &hard, cpumap_hard);
        flags |= XEN_VCPUAFFINITY_HARD;
    }
    if (cpumap_soft) {
        rc = libxl_cpu_bitmap_alloc(ctx, &soft, 0);
        if (rc)
            goto out;

        libxl__bitmap_copy_best_effort(gc, &soft, cpumap_soft);
        flags |= XEN_VCPUAFFINITY_SOFT;
    }

    if (xc_vcpu_setaffinity(ctx->xch, domid, vcpuid,
                            cpumap_hard ? hard.map : NULL,
                            cpumap_soft ? soft.map : NULL,
                            flags)) {
        LOGE(ERROR, "setting vcpu affinity");
        rc = ERROR_FAIL;
        goto out;
    }

    /*
     * Let's check the results. Hard affinity will never be empty, but it
     * is possible that Xen will use something different from what we asked
     * for various reasons. If that's the case, report it.
     */
    if (cpumap_hard &&
        !libxl_bitmap_equal(cpumap_hard, &hard, 0))
        LOG(DEBUG, "New hard affinity for vcpu %d has unreachable cpus",
        vcpuid);
    /*
     * Soft affinity can both be different from what asked and empty. Check
     * for (and report) both.
     */
    if (cpumap_soft) {
        if (!libxl_bitmap_equal(cpumap_soft, &soft, 0))
            LOG(DEBUG, "New soft affinity for vcpu %d has unreachable cpus",
                vcpuid);
        if (libxl_bitmap_is_empty(&soft))
            LOG(WARN, "all cpus in soft affinity of vcpu %d are unreachable."
                " Only hard affinity will be considered for scheduling",
                vcpuid);
    }

    rc = 0;
 out:
    libxl_bitmap_dispose(&hard);
    libxl_bitmap_dispose(&soft);
    GC_FREE;
    return rc;
}

int libxl_set_vcpuaffinity(libxl_ctx *ctx, uint32_t domid, uint32_t vcpuid,
                           const libxl_bitmap *cpumap_hard,
                           const libxl_bitmap *cpumap_soft)
{
    return libxl__set_vcpuaffinity(ctx, domid, vcpuid, cpumap_hard,
                                   cpumap_soft, 0);
}

int libxl_set_vcpuaffinity_force(libxl_ctx *ctx, uint32_t domid,
                                 uint32_t vcpuid,
                                 const libxl_bitmap *cpumap_hard,
                                 const libxl_bitmap *cpumap_soft)
{
    return libxl__set_vcpuaffinity(ctx, domid, vcpuid, cpumap_hard,
                                   cpumap_soft, XEN_VCPUAFFINITY_FORCE);
}

int libxl_set_vcpuaffinity_all(libxl_ctx *ctx, uint32_t domid,
                               unsigned int max_vcpus,
                               const libxl_bitmap *cpumap_hard,
                               const libxl_bitmap *cpumap_soft)
{
    GC_INIT(ctx);
    int i, rc = 0;

    for (i = 0; i < max_vcpus; i++) {
        if (libxl_set_vcpuaffinity(ctx, domid, i, cpumap_hard, cpumap_soft)) {
            LOG(WARN, "failed to set affinity for %d", i);
            rc = ERROR_FAIL;
        }
    }

    GC_FREE;
    return rc;
}

int libxl_domain_set_nodeaffinity(libxl_ctx *ctx, uint32_t domid,
                                  libxl_bitmap *nodemap)
{
    GC_INIT(ctx);
    if (xc_domain_node_setaffinity(ctx->xch, domid, nodemap->map)) {
        LOGE(ERROR, "setting node affinity");
        GC_FREE;
        return ERROR_FAIL;
    }
    GC_FREE;
    return 0;
}

int libxl_domain_get_nodeaffinity(libxl_ctx *ctx, uint32_t domid,
                                  libxl_bitmap *nodemap)
{
    GC_INIT(ctx);
    if (xc_domain_node_getaffinity(ctx->xch, domid, nodemap->map)) {
        LOGE(ERROR, "getting node affinity");
        GC_FREE;
        return ERROR_FAIL;
    }
    GC_FREE;
    return 0;
}

static int libxl__set_vcpuonline_xenstore(libxl__gc *gc, uint32_t domid,
                                         libxl_bitmap *cpumap,
                                         const libxl_dominfo *info)
{
    char *dompath;
    xs_transaction_t t;
    int i, rc = ERROR_FAIL;

    if (!(dompath = libxl__xs_get_dompath(gc, domid)))
        goto out;

retry_transaction:
    t = xs_transaction_start(CTX->xsh);
    for (i = 0; i <= info->vcpu_max_id; i++)
        libxl__xs_printf(gc, t,
                         GCSPRINTF("%s/cpu/%u/availability", dompath, i),
                         "%s", libxl_bitmap_test(cpumap, i) ? "online" : "offline");
    if (!xs_transaction_end(CTX->xsh, t, 0)) {
        if (errno == EAGAIN)
            goto retry_transaction;
    } else
        rc = 0;
out:
    return rc;
}

static int libxl__set_vcpuonline_qmp(libxl__gc *gc, uint32_t domid,
                                     libxl_bitmap *cpumap,
                                     const libxl_dominfo *info)
{
    int i, rc;
    libxl_bitmap current_map, final_map;

    libxl_bitmap_init(&current_map);
    libxl_bitmap_init(&final_map);

    libxl_bitmap_alloc(CTX, &current_map, info->vcpu_max_id + 1);
    libxl_bitmap_set_none(&current_map);
    rc = libxl__qmp_query_cpus(gc, domid, &current_map);
    if (rc) {
        LOG(ERROR, "failed to query cpus for domain %d", domid);
        goto out;
    }

    libxl_bitmap_copy_alloc(CTX, &final_map, cpumap);

    libxl_for_each_set_bit(i, current_map)
        libxl_bitmap_reset(&final_map, i);

    libxl_for_each_set_bit(i, final_map) {
        rc = libxl__qmp_cpu_add(gc, domid, i);
        if (rc) {
            LOG(ERROR, "failed to add cpu %d to domain %d", i, domid);
            goto out;
        }
    }

    rc = 0;
out:
    libxl_bitmap_dispose(&current_map);
    libxl_bitmap_dispose(&final_map);
    return rc;
}

int libxl_set_vcpuonline(libxl_ctx *ctx, uint32_t domid, libxl_bitmap *cpumap)
{
    GC_INIT(ctx);
    int rc, maxcpus;
    libxl_dominfo info;

    libxl_dominfo_init(&info);

    rc = libxl_domain_info(CTX, &info, domid);
    if (rc < 0) {
        LOGE(ERROR, "getting domain info list");
        goto out;
    }

    maxcpus = libxl_bitmap_count_set(cpumap);
    if (maxcpus > info.vcpu_max_id + 1)
    {
        LOGE(ERROR, "Requested %d VCPUs, however maxcpus is %d!",
             maxcpus, info.vcpu_max_id + 1);
        rc = ERROR_FAIL;
        goto out;
    }

    switch (libxl__domain_type(gc, domid)) {
    case LIBXL_DOMAIN_TYPE_HVM:
        switch (libxl__device_model_version_running(gc, domid)) {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
            break;
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
            rc = libxl__set_vcpuonline_qmp(gc, domid, cpumap, &info);
            break;
        default:
            rc = ERROR_INVAL;
        }
        break;
    case LIBXL_DOMAIN_TYPE_PVH:
    case LIBXL_DOMAIN_TYPE_PV:
        break;
    default:
        rc = ERROR_INVAL;
    }

    if (!rc)
        rc = libxl__set_vcpuonline_xenstore(gc, domid, cpumap, &info);

out:
    libxl_dominfo_dispose(&info);
    GC_FREE;
    return rc;
}

int libxl_get_scheduler(libxl_ctx *ctx)
{
    int r, sched;

    GC_INIT(ctx);
    r = xc_sched_id(ctx->xch, &sched);
    if (r != 0) {
        LOGE(ERROR, "getting current scheduler id");
        sched = ERROR_FAIL;
    }
    GC_FREE;
    return sched;
}

static int sched_arinc653_domain_set(libxl__gc *gc, uint32_t domid,
                                     const libxl_domain_sched_params *scinfo)
{
    /* Currently, the ARINC 653 scheduler does not take any domain-specific
         configuration, so we simply return success. */
    return 0;
}

static int sched_credit_domain_get(libxl__gc *gc, uint32_t domid,
                                   libxl_domain_sched_params *scinfo)
{
    struct xen_domctl_sched_credit sdom;
    int rc;

    rc = xc_sched_credit_domain_get(CTX->xch, domid, &sdom);
    if (rc != 0) {
        LOGE(ERROR, "getting domain sched credit");
        return ERROR_FAIL;
    }

    libxl_domain_sched_params_init(scinfo);
    scinfo->sched = LIBXL_SCHEDULER_CREDIT;
    scinfo->weight = sdom.weight;
    scinfo->cap = sdom.cap;

    return 0;
}

static int sched_credit_domain_set(libxl__gc *gc, uint32_t domid,
                                   const libxl_domain_sched_params *scinfo)
{
    struct xen_domctl_sched_credit sdom;
    xc_domaininfo_t domaininfo;
    int rc;

    rc = xc_domain_getinfolist(CTX->xch, domid, 1, &domaininfo);
    if (rc < 0) {
        LOGE(ERROR, "getting domain info list");
        return ERROR_FAIL;
    }
    if (rc != 1 || domaininfo.domain != domid)
        return ERROR_INVAL;

    rc = xc_sched_credit_domain_get(CTX->xch, domid, &sdom);
    if (rc != 0) {
        LOGE(ERROR, "getting domain sched credit");
        return ERROR_FAIL;
    }

    if (scinfo->weight != LIBXL_DOMAIN_SCHED_PARAM_WEIGHT_DEFAULT) {
        if (scinfo->weight < 1 || scinfo->weight > 65535) {
            LOG(ERROR, "Cpu weight out of range, "
                "valid values are within range from 1 to 65535");
            return ERROR_INVAL;
        }
        sdom.weight = scinfo->weight;
    }

    if (scinfo->cap != LIBXL_DOMAIN_SCHED_PARAM_CAP_DEFAULT) {
        if (scinfo->cap < 0
            || scinfo->cap > (domaininfo.max_vcpu_id + 1) * 100) {
            LOG(ERROR, "Cpu cap out of range, "
                "valid range is from 0 to %d for specified number of vcpus",
                ((domaininfo.max_vcpu_id + 1) * 100));
            return ERROR_INVAL;
        }
        sdom.cap = scinfo->cap;
    }

    rc = xc_sched_credit_domain_set(CTX->xch, domid, &sdom);
    if ( rc < 0 ) {
        LOGE(ERROR, "setting domain sched credit");
        return ERROR_FAIL;
    }

    return 0;
}

static int sched_ratelimit_check(libxl__gc *gc, int ratelimit)
{
    if (ratelimit != 0 &&
        (ratelimit <  XEN_SYSCTL_SCHED_RATELIMIT_MIN ||
         ratelimit > XEN_SYSCTL_SCHED_RATELIMIT_MAX)) {
        LOG(ERROR, "Ratelimit out of range, valid range is from %d to %d",
            XEN_SYSCTL_SCHED_RATELIMIT_MIN, XEN_SYSCTL_SCHED_RATELIMIT_MAX);
        return ERROR_INVAL;
    }

    return 0;
}

int libxl_sched_credit_params_get(libxl_ctx *ctx, uint32_t poolid,
                                  libxl_sched_credit_params *scinfo)
{
    struct xen_sysctl_credit_schedule sparam;
    int r, rc;
    GC_INIT(ctx);

    r = xc_sched_credit_params_get(ctx->xch, poolid, &sparam);
    if (r < 0) {
        LOGE(ERROR, "getting Credit scheduler parameters");
        rc = ERROR_FAIL;
        goto out;
    }

    scinfo->tslice_ms = sparam.tslice_ms;
    scinfo->ratelimit_us = sparam.ratelimit_us;

    rc = 0;
 out:
    GC_FREE;
    return rc;
}

int libxl_sched_credit_params_set(libxl_ctx *ctx, uint32_t poolid,
                                  libxl_sched_credit_params *scinfo)
{
    struct xen_sysctl_credit_schedule sparam;
    int r, rc;
    GC_INIT(ctx);

    if (scinfo->tslice_ms <  XEN_SYSCTL_CSCHED_TSLICE_MIN
        || scinfo->tslice_ms > XEN_SYSCTL_CSCHED_TSLICE_MAX) {
        LOG(ERROR, "Time slice out of range, valid range is from %d to %d",
            XEN_SYSCTL_CSCHED_TSLICE_MIN, XEN_SYSCTL_CSCHED_TSLICE_MAX);
        rc = ERROR_INVAL;
        goto out;
    }
    rc = sched_ratelimit_check(gc, scinfo->ratelimit_us);
    if (rc) {
        goto out;
    }
    if (scinfo->ratelimit_us > scinfo->tslice_ms*1000) {
        LOG(ERROR, "Ratelimit cannot be greater than timeslice");
        rc = ERROR_INVAL;
        goto out;
    }

    sparam.tslice_ms = scinfo->tslice_ms;
    sparam.ratelimit_us = scinfo->ratelimit_us;

    r = xc_sched_credit_params_set(ctx->xch, poolid, &sparam);
    if ( r < 0 ) {
        LOGE(ERROR, "Setting Credit scheduler parameters");
        rc = ERROR_FAIL;
        goto out;
    }

    scinfo->tslice_ms = sparam.tslice_ms;
    scinfo->ratelimit_us = sparam.ratelimit_us;

    rc = 0;
 out:
    GC_FREE;
    return rc;
}

int libxl_sched_credit2_params_get(libxl_ctx *ctx, uint32_t poolid,
                                   libxl_sched_credit2_params *scinfo)
{
    struct xen_sysctl_credit2_schedule sparam;
    int r, rc;
    GC_INIT(ctx);

    r = xc_sched_credit2_params_get(ctx->xch, poolid, &sparam);
    if (r < 0) {
        LOGE(ERROR, "getting Credit2 scheduler parameters");
        rc = ERROR_FAIL;
        goto out;
    }

    scinfo->ratelimit_us = sparam.ratelimit_us;

    rc = 0;
 out:
    GC_FREE;
    return rc;
}


int libxl_sched_credit2_params_set(libxl_ctx *ctx, uint32_t poolid,
                                   libxl_sched_credit2_params *scinfo)
{
    struct xen_sysctl_credit2_schedule sparam;
    int r, rc;
    GC_INIT(ctx);

    rc = sched_ratelimit_check(gc, scinfo->ratelimit_us);
    if (rc) goto out;

    sparam.ratelimit_us = scinfo->ratelimit_us;

    r = xc_sched_credit2_params_set(ctx->xch, poolid, &sparam);
    if (r < 0) {
        LOGE(ERROR, "Setting Credit2 scheduler parameters");
        rc = ERROR_FAIL;
        goto out;
    }

    scinfo->ratelimit_us = sparam.ratelimit_us;

    rc = 0;
 out:
    GC_FREE;
    return rc;
}

static int sched_credit2_domain_get(libxl__gc *gc, uint32_t domid,
                                    libxl_domain_sched_params *scinfo)
{
    struct xen_domctl_sched_credit2 sdom;
    int rc;

    rc = xc_sched_credit2_domain_get(CTX->xch, domid, &sdom);
    if (rc != 0) {
        LOGE(ERROR, "getting domain sched credit2");
        return ERROR_FAIL;
    }

    libxl_domain_sched_params_init(scinfo);
    scinfo->sched = LIBXL_SCHEDULER_CREDIT2;
    scinfo->weight = sdom.weight;

    return 0;
}

static int sched_credit2_domain_set(libxl__gc *gc, uint32_t domid,
                                    const libxl_domain_sched_params *scinfo)
{
    struct xen_domctl_sched_credit2 sdom;
    int rc;

    rc = xc_sched_credit2_domain_get(CTX->xch, domid, &sdom);
    if (rc != 0) {
        LOGE(ERROR, "getting domain sched credit2");
        return ERROR_FAIL;
    }

    if (scinfo->weight != LIBXL_DOMAIN_SCHED_PARAM_WEIGHT_DEFAULT) {
        if (scinfo->weight < 1 || scinfo->weight > 65535) {
            LOG(ERROR, "Cpu weight out of range, "
                       "valid values are within range from 1 to 65535");
            return ERROR_INVAL;
        }
        sdom.weight = scinfo->weight;
    }

    rc = xc_sched_credit2_domain_set(CTX->xch, domid, &sdom);
    if ( rc < 0 ) {
        LOGE(ERROR, "setting domain sched credit2");
        return ERROR_FAIL;
    }

    return 0;
}

static int sched_rtds_validate_params(libxl__gc *gc, int period, int budget)
{
    int rc;

    if (period < 1) {
        LOG(ERROR, "Invalid VCPU period of %d (it should be >= 1)", period);
        rc = ERROR_INVAL;
        goto out;
    }

    if (budget < 1) {
        LOG(ERROR, "Invalid VCPU budget of %d (it should be >= 1)", budget);
        rc = ERROR_INVAL;
        goto out;
    }

    if (budget > period) {
        LOG(ERROR, "VCPU budget must be smaller than or equal to period, "
                   "but %d > %d", budget, period);
        rc = ERROR_INVAL;
        goto out;
    }
    rc = 0;
out:
    return rc;
}

/* Get the RTDS scheduling parameters of vcpu(s) */
static int sched_rtds_vcpu_get(libxl__gc *gc, uint32_t domid,
                               libxl_vcpu_sched_params *scinfo)
{
    uint32_t num_vcpus;
    int i, r, rc;
    xc_dominfo_t info;
    struct xen_domctl_schedparam_vcpu *vcpus;

    r = xc_domain_getinfo(CTX->xch, domid, 1, &info);
    if (r < 0) {
        LOGE(ERROR, "getting domain info");
        rc = ERROR_FAIL;
        goto out;
    }

    if (scinfo->num_vcpus <= 0) {
        rc = ERROR_INVAL;
        goto out;
    } else {
        num_vcpus = scinfo->num_vcpus;
        GCNEW_ARRAY(vcpus, num_vcpus);
        for (i = 0; i < num_vcpus; i++) {
            if (scinfo->vcpus[i].vcpuid < 0 ||
                scinfo->vcpus[i].vcpuid > info.max_vcpu_id) {
                LOG(ERROR, "VCPU index is out of range, "
                           "valid values are within range from 0 to %d",
                           info.max_vcpu_id);
                rc = ERROR_INVAL;
                goto out;
            }
            vcpus[i].vcpuid = scinfo->vcpus[i].vcpuid;
        }
    }

    r = xc_sched_rtds_vcpu_get(CTX->xch, domid, vcpus, num_vcpus);
    if (r != 0) {
        LOGE(ERROR, "getting vcpu sched rtds");
        rc = ERROR_FAIL;
        goto out;
    }
    scinfo->sched = LIBXL_SCHEDULER_RTDS;
    for (i = 0; i < num_vcpus; i++) {
        scinfo->vcpus[i].period = vcpus[i].u.rtds.period;
        scinfo->vcpus[i].budget = vcpus[i].u.rtds.budget;
        scinfo->vcpus[i].vcpuid = vcpus[i].vcpuid;
    }
    rc = 0;
out:
    return rc;
}

/* Get the RTDS scheduling parameters of all vcpus of a domain */
static int sched_rtds_vcpu_get_all(libxl__gc *gc, uint32_t domid,
                                   libxl_vcpu_sched_params *scinfo)
{
    uint32_t num_vcpus;
    int i, r, rc;
    xc_dominfo_t info;
    struct xen_domctl_schedparam_vcpu *vcpus;

    r = xc_domain_getinfo(CTX->xch, domid, 1, &info);
    if (r < 0) {
        LOGE(ERROR, "getting domain info");
        rc = ERROR_FAIL;
        goto out;
    }

    if (scinfo->num_vcpus > 0) {
        rc = ERROR_INVAL;
        goto out;
    } else {
        num_vcpus = info.max_vcpu_id + 1;
        GCNEW_ARRAY(vcpus, num_vcpus);
        for (i = 0; i < num_vcpus; i++)
            vcpus[i].vcpuid = i;
    }

    r = xc_sched_rtds_vcpu_get(CTX->xch, domid, vcpus, num_vcpus);
    if (r != 0) {
        LOGE(ERROR, "getting vcpu sched rtds");
        rc = ERROR_FAIL;
        goto out;
    }
    scinfo->sched = LIBXL_SCHEDULER_RTDS;
    scinfo->num_vcpus = num_vcpus;
    scinfo->vcpus = libxl__calloc(NOGC, num_vcpus,
                                  sizeof(libxl_sched_params));

    for (i = 0; i < num_vcpus; i++) {
        scinfo->vcpus[i].period = vcpus[i].u.rtds.period;
        scinfo->vcpus[i].budget = vcpus[i].u.rtds.budget;
        scinfo->vcpus[i].vcpuid = vcpus[i].vcpuid;
    }
    rc = 0;
out:
    return rc;
}

/* Set the RTDS scheduling parameters of vcpu(s) */
static int sched_rtds_vcpu_set(libxl__gc *gc, uint32_t domid,
                               const libxl_vcpu_sched_params *scinfo)
{
    int r, rc;
    int i;
    uint16_t max_vcpuid;
    xc_dominfo_t info;
    struct xen_domctl_schedparam_vcpu *vcpus;

    r = xc_domain_getinfo(CTX->xch, domid, 1, &info);
    if (r < 0) {
        LOGE(ERROR, "getting domain info");
        rc = ERROR_FAIL;
        goto out;
    }
    max_vcpuid = info.max_vcpu_id;

    if (scinfo->num_vcpus <= 0) {
        rc = ERROR_INVAL;
        goto out;
    }
    for (i = 0; i < scinfo->num_vcpus; i++) {
        if (scinfo->vcpus[i].vcpuid < 0 ||
            scinfo->vcpus[i].vcpuid > max_vcpuid) {
            LOG(ERROR, "Invalid VCPU %d: valid range is [0, %d]",
                       scinfo->vcpus[i].vcpuid, max_vcpuid);
            rc = ERROR_INVAL;
            goto out;
        }
        rc = sched_rtds_validate_params(gc, scinfo->vcpus[i].period,
                                        scinfo->vcpus[i].budget);
        if (rc) {
            rc = ERROR_INVAL;
            goto out;
        }
    }
    GCNEW_ARRAY(vcpus, scinfo->num_vcpus);
    for (i = 0; i < scinfo->num_vcpus; i++) {
        vcpus[i].vcpuid = scinfo->vcpus[i].vcpuid;
        vcpus[i].u.rtds.period = scinfo->vcpus[i].period;
        vcpus[i].u.rtds.budget = scinfo->vcpus[i].budget;
    }

    r = xc_sched_rtds_vcpu_set(CTX->xch, domid,
                               vcpus, scinfo->num_vcpus);
    if (r != 0) {
        LOGE(ERROR, "setting vcpu sched rtds");
        rc = ERROR_FAIL;
        goto out;
    }
    rc = 0;
out:
    return rc;
}

/* Set the RTDS scheduling parameters of all vcpus of a domain */
static int sched_rtds_vcpu_set_all(libxl__gc *gc, uint32_t domid,
                                   const libxl_vcpu_sched_params *scinfo)
{
    int r, rc;
    int i;
    uint16_t max_vcpuid;
    xc_dominfo_t info;
    struct xen_domctl_schedparam_vcpu *vcpus;
    uint32_t num_vcpus;

    r = xc_domain_getinfo(CTX->xch, domid, 1, &info);
    if (r < 0) {
        LOGE(ERROR, "getting domain info");
        rc = ERROR_FAIL;
        goto out;
    }
    max_vcpuid = info.max_vcpu_id;

    if (scinfo->num_vcpus != 1) {
        rc = ERROR_INVAL;
        goto out;
    }
    if (sched_rtds_validate_params(gc, scinfo->vcpus[0].period,
                                   scinfo->vcpus[0].budget)) {
        rc = ERROR_INVAL;
        goto out;
    }
    num_vcpus = max_vcpuid + 1;
    GCNEW_ARRAY(vcpus, num_vcpus);
    for (i = 0; i < num_vcpus; i++) {
        vcpus[i].vcpuid = i;
        vcpus[i].u.rtds.period = scinfo->vcpus[0].period;
        vcpus[i].u.rtds.budget = scinfo->vcpus[0].budget;
    }

    r = xc_sched_rtds_vcpu_set(CTX->xch, domid,
                               vcpus, num_vcpus);
    if (r != 0) {
        LOGE(ERROR, "setting vcpu sched rtds");
        rc = ERROR_FAIL;
        goto out;
    }
    rc = 0;
out:
    return rc;
}

static int sched_rtds_domain_get(libxl__gc *gc, uint32_t domid,
                               libxl_domain_sched_params *scinfo)
{
    struct xen_domctl_sched_rtds sdom;
    int rc;

    rc = xc_sched_rtds_domain_get(CTX->xch, domid, &sdom);
    if (rc != 0) {
        LOGE(ERROR, "getting domain sched rtds");
        return ERROR_FAIL;
    }

    libxl_domain_sched_params_init(scinfo);

    scinfo->sched = LIBXL_SCHEDULER_RTDS;
    scinfo->period = sdom.period;
    scinfo->budget = sdom.budget;

    return 0;
}

static int sched_rtds_domain_set(libxl__gc *gc, uint32_t domid,
                               const libxl_domain_sched_params *scinfo)
{
    struct xen_domctl_sched_rtds sdom;
    int rc;

    rc = xc_sched_rtds_domain_get(CTX->xch, domid, &sdom);
    if (rc != 0) {
        LOGE(ERROR, "getting domain sched rtds");
        return ERROR_FAIL;
    }
    if (scinfo->period != LIBXL_DOMAIN_SCHED_PARAM_PERIOD_DEFAULT)
        sdom.period = scinfo->period;
    if (scinfo->budget != LIBXL_DOMAIN_SCHED_PARAM_BUDGET_DEFAULT)
        sdom.budget = scinfo->budget;
    if (sched_rtds_validate_params(gc, sdom.period, sdom.budget))
        return ERROR_INVAL;

    rc = xc_sched_rtds_domain_set(CTX->xch, domid, &sdom);
    if (rc < 0) {
        LOGE(ERROR, "setting domain sched rtds");
        return ERROR_FAIL;
    }

    return 0;
}

int libxl_domain_sched_params_set(libxl_ctx *ctx, uint32_t domid,
                                  const libxl_domain_sched_params *scinfo)
{
    GC_INIT(ctx);
    libxl_scheduler sched = scinfo->sched;
    int ret;

    if (sched == LIBXL_SCHEDULER_UNKNOWN)
        sched = libxl__domain_scheduler(gc, domid);

    switch (sched) {
    case LIBXL_SCHEDULER_SEDF:
        LOG(ERROR, "SEDF scheduler no longer available");
        ret=ERROR_FEATURE_REMOVED;
        break;
    case LIBXL_SCHEDULER_CREDIT:
        ret=sched_credit_domain_set(gc, domid, scinfo);
        break;
    case LIBXL_SCHEDULER_CREDIT2:
        ret=sched_credit2_domain_set(gc, domid, scinfo);
        break;
    case LIBXL_SCHEDULER_ARINC653:
        ret=sched_arinc653_domain_set(gc, domid, scinfo);
        break;
    case LIBXL_SCHEDULER_RTDS:
        ret=sched_rtds_domain_set(gc, domid, scinfo);
        break;
    default:
        LOG(ERROR, "Unknown scheduler");
        ret=ERROR_INVAL;
        break;
    }

    GC_FREE;
    return ret;
}

int libxl_vcpu_sched_params_set(libxl_ctx *ctx, uint32_t domid,
                                const libxl_vcpu_sched_params *scinfo)
{
    GC_INIT(ctx);
    libxl_scheduler sched = scinfo->sched;
    int rc;

    if (sched == LIBXL_SCHEDULER_UNKNOWN)
        sched = libxl__domain_scheduler(gc, domid);

    switch (sched) {
    case LIBXL_SCHEDULER_SEDF:
        LOG(ERROR, "SEDF scheduler no longer available");
        rc = ERROR_FEATURE_REMOVED;
        break;
    case LIBXL_SCHEDULER_CREDIT:
    case LIBXL_SCHEDULER_CREDIT2:
    case LIBXL_SCHEDULER_ARINC653:
        LOG(ERROR, "per-VCPU parameter setting not supported for this scheduler");
        rc = ERROR_INVAL;
        break;
    case LIBXL_SCHEDULER_RTDS:
        rc = sched_rtds_vcpu_set(gc, domid, scinfo);
        break;
    default:
        LOG(ERROR, "Unknown scheduler");
        rc = ERROR_INVAL;
        break;
    }

    GC_FREE;
    return rc;
}

int libxl_vcpu_sched_params_set_all(libxl_ctx *ctx, uint32_t domid,
                                    const libxl_vcpu_sched_params *scinfo)
{
    GC_INIT(ctx);
    libxl_scheduler sched = scinfo->sched;
    int rc;

    if (sched == LIBXL_SCHEDULER_UNKNOWN)
        sched = libxl__domain_scheduler(gc, domid);

    switch (sched) {
    case LIBXL_SCHEDULER_SEDF:
        LOG(ERROR, "SEDF scheduler no longer available");
        rc = ERROR_FEATURE_REMOVED;
        break;
    case LIBXL_SCHEDULER_CREDIT:
    case LIBXL_SCHEDULER_CREDIT2:
    case LIBXL_SCHEDULER_ARINC653:
        LOG(ERROR, "per-VCPU parameter setting not supported for this scheduler");
        rc = ERROR_INVAL;
        break;
    case LIBXL_SCHEDULER_RTDS:
        rc = sched_rtds_vcpu_set_all(gc, domid, scinfo);
        break;
    default:
        LOG(ERROR, "Unknown scheduler");
        rc = ERROR_INVAL;
        break;
    }

    GC_FREE;
    return rc;
}

int libxl_domain_sched_params_get(libxl_ctx *ctx, uint32_t domid,
                                  libxl_domain_sched_params *scinfo)
{
    GC_INIT(ctx);
    int ret;

    libxl_domain_sched_params_init(scinfo);

    scinfo->sched = libxl__domain_scheduler(gc, domid);

    switch (scinfo->sched) {
    case LIBXL_SCHEDULER_SEDF:
        LOG(ERROR, "SEDF scheduler no longer available");
        ret=ERROR_FEATURE_REMOVED;
        break;
    case LIBXL_SCHEDULER_CREDIT:
        ret=sched_credit_domain_get(gc, domid, scinfo);
        break;
    case LIBXL_SCHEDULER_CREDIT2:
        ret=sched_credit2_domain_get(gc, domid, scinfo);
        break;
    case LIBXL_SCHEDULER_RTDS:
        ret=sched_rtds_domain_get(gc, domid, scinfo);
        break;
    default:
        LOG(ERROR, "Unknown scheduler");
        ret=ERROR_INVAL;
        break;
    }

    GC_FREE;
    return ret;
}

int libxl_vcpu_sched_params_get(libxl_ctx *ctx, uint32_t domid,
                                libxl_vcpu_sched_params *scinfo)
{
    GC_INIT(ctx);
    int rc;

    scinfo->sched = libxl__domain_scheduler(gc, domid);

    switch (scinfo->sched) {
    case LIBXL_SCHEDULER_SEDF:
        LOG(ERROR, "SEDF scheduler is no longer available");
        rc = ERROR_FEATURE_REMOVED;
        break;
    case LIBXL_SCHEDULER_CREDIT:
    case LIBXL_SCHEDULER_CREDIT2:
    case LIBXL_SCHEDULER_ARINC653:
        LOG(ERROR, "per-VCPU parameter getting not supported for this scheduler");
        rc = ERROR_INVAL;
        break;
    case LIBXL_SCHEDULER_RTDS:
        rc = sched_rtds_vcpu_get(gc, domid, scinfo);
        break;
    default:
        LOG(ERROR, "Unknown scheduler");
        rc = ERROR_INVAL;
        break;
    }

    GC_FREE;
    return rc;
}

int libxl_vcpu_sched_params_get_all(libxl_ctx *ctx, uint32_t domid,
                                    libxl_vcpu_sched_params *scinfo)
{
    GC_INIT(ctx);
    int rc;

    scinfo->sched = libxl__domain_scheduler(gc, domid);

    switch (scinfo->sched) {
    case LIBXL_SCHEDULER_SEDF:
        LOG(ERROR, "SEDF scheduler is no longer available");
        rc = ERROR_FEATURE_REMOVED;
        break;
    case LIBXL_SCHEDULER_CREDIT:
    case LIBXL_SCHEDULER_CREDIT2:
    case LIBXL_SCHEDULER_ARINC653:
        LOG(ERROR, "per-VCPU parameter getting not supported for this scheduler");
        rc = ERROR_INVAL;
        break;
    case LIBXL_SCHEDULER_RTDS:
        rc = sched_rtds_vcpu_get_all(gc, domid, scinfo);
        break;
    default:
        LOG(ERROR, "Unknown scheduler");
        rc = ERROR_INVAL;
        break;
    }

    GC_FREE;
    return rc;
}

static int libxl__domain_s3_resume(libxl__gc *gc, int domid)
{
    int rc = 0;

    switch (libxl__domain_type(gc, domid)) {
    case LIBXL_DOMAIN_TYPE_HVM:
        switch (libxl__device_model_version_running(gc, domid)) {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
            rc = xc_hvm_param_set(CTX->xch, domid, HVM_PARAM_ACPI_S_STATE, 0);
            break;
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
            rc = libxl__qmp_system_wakeup(gc, domid);
            break;
        default:
            rc = ERROR_INVAL;
            break;
        }
        break;
    default:
        rc = ERROR_INVAL;
        break;
    }

    return rc;
}

int libxl_send_trigger(libxl_ctx *ctx, uint32_t domid,
                       libxl_trigger trigger, uint32_t vcpuid)
{
    int rc;
    GC_INIT(ctx);

    switch (trigger) {
    case LIBXL_TRIGGER_POWER:
        rc = xc_domain_send_trigger(ctx->xch, domid,
                                    XEN_DOMCTL_SENDTRIGGER_POWER, vcpuid);
        break;
    case LIBXL_TRIGGER_SLEEP:
        rc = xc_domain_send_trigger(ctx->xch, domid,
                                    XEN_DOMCTL_SENDTRIGGER_SLEEP, vcpuid);
        break;
    case LIBXL_TRIGGER_NMI:
        rc = xc_domain_send_trigger(ctx->xch, domid,
                                    XEN_DOMCTL_SENDTRIGGER_NMI, vcpuid);
        break;
    case LIBXL_TRIGGER_INIT:
        rc = xc_domain_send_trigger(ctx->xch, domid,
                                    XEN_DOMCTL_SENDTRIGGER_INIT, vcpuid);
        break;
    case LIBXL_TRIGGER_RESET:
        rc = xc_domain_send_trigger(ctx->xch, domid,
                                    XEN_DOMCTL_SENDTRIGGER_RESET, vcpuid);
        break;
    case LIBXL_TRIGGER_S3RESUME:
        rc = libxl__domain_s3_resume(gc, domid);
        break;
    default:
        rc = -1;
        errno = EINVAL;
        break;
    }

    if (rc != 0) {
        LOGE(ERROR, "Send trigger '%s' failed",
             libxl_trigger_to_string(trigger));
        rc = ERROR_FAIL;
    }

    GC_FREE;
    return rc;
}

int libxl_send_sysrq(libxl_ctx *ctx, uint32_t domid, char sysrq)
{
    GC_INIT(ctx);
    char *dompath = libxl__xs_get_dompath(gc, domid);

    libxl__xs_printf(gc, XBT_NULL, GCSPRINTF("%s/control/sysrq", dompath),
                     "%c", sysrq);

    GC_FREE;
    return 0;
}

int libxl_send_debug_keys(libxl_ctx *ctx, char *keys)
{
    int ret;
    GC_INIT(ctx);
    ret = xc_send_debug_keys(ctx->xch, keys);
    if ( ret < 0 ) {
        LOGE(ERROR, "sending debug keys");
        GC_FREE;
        return ERROR_FAIL;
    }
    GC_FREE;
    return 0;
}

libxl_xen_console_reader *
    libxl_xen_console_read_start(libxl_ctx *ctx, int clear)
{
    GC_INIT(ctx);
    libxl_xen_console_reader *cr;
    unsigned int size = 16384;

    cr = libxl__zalloc(NOGC, sizeof(libxl_xen_console_reader));
    cr->buffer = libxl__zalloc(NOGC, size);
    cr->size = size;
    cr->count = size;
    cr->clear = clear;
    cr->incremental = 1;

    GC_FREE;
    return cr;
}

/* return values:                                          *line_r
 *   1          success, whole line obtained from buffer    non-0
 *   0          no more lines available right now           0
 *   negative   error code ERROR_*                          0
 * On success *line_r is updated to point to a nul-terminated
 * string which is valid until the next call on the same console
 * reader.  The libxl caller may overwrite parts of the string
 * if it wishes. */
int libxl_xen_console_read_line(libxl_ctx *ctx,
                                libxl_xen_console_reader *cr,
                                char **line_r)
{
    int ret;
    GC_INIT(ctx);

    memset(cr->buffer, 0, cr->size);
    ret = xc_readconsolering(ctx->xch, cr->buffer, &cr->count,
                             cr->clear, cr->incremental, &cr->index);
    if (ret < 0) {
        LOGE(ERROR, "reading console ring buffer");
        GC_FREE;
        return ERROR_FAIL;
    }
    if (!ret) {
        if (cr->count) {
            *line_r = cr->buffer;
            ret = 1;
        } else {
            *line_r = NULL;
            ret = 0;
        }
    }

    GC_FREE;
    return ret;
}

void libxl_xen_console_read_finish(libxl_ctx *ctx,
                                   libxl_xen_console_reader *cr)
{
    free(cr->buffer);
    free(cr);
}

uint32_t libxl_vm_get_start_time(libxl_ctx *ctx, uint32_t domid)
{
    GC_INIT(ctx);
    char *dompath = libxl__xs_get_dompath(gc, domid);
    char *vm_path, *start_time;
    uint32_t ret;

    vm_path = libxl__xs_read(
        gc, XBT_NULL, GCSPRINTF("%s/vm", dompath));
    start_time = libxl__xs_read(
        gc, XBT_NULL, GCSPRINTF("%s/start_time", vm_path));
    if (start_time == NULL) {
        LOGEV(ERROR, -1, "Can't get start time of domain '%d'", domid);
        ret = -1;
    }else{
        ret = strtoul(start_time, NULL, 10);
    }
    GC_FREE;
    return ret;
}

char *libxl_tmem_list(libxl_ctx *ctx, uint32_t domid, int use_long)
{
    int r;
    char _buf[32768];
    GC_INIT(ctx);

    r = xc_tmem_control(ctx->xch, -1, XEN_SYSCTL_TMEM_OP_LIST, domid, 32768,
                        use_long, _buf);
    if (r < 0) {
        LOGE(ERROR, "Can not get tmem list");
        GC_FREE;
        return NULL;
    }

    GC_FREE;
    return strdup(_buf);
}

int libxl_tmem_freeze(libxl_ctx *ctx, uint32_t domid)
{
    int r, rc;
    GC_INIT(ctx);

    r = xc_tmem_control(ctx->xch, -1, XEN_SYSCTL_TMEM_OP_FREEZE, domid, 0, 0,
                        NULL);
    if (r < 0) {
        LOGE(ERROR, "Can not freeze tmem pools");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;
out:
    GC_FREE;
    return rc;
}

int libxl_tmem_thaw(libxl_ctx *ctx, uint32_t domid)
{
    int r, rc;
    GC_INIT(ctx);

    r = xc_tmem_control(ctx->xch, -1, XEN_SYSCTL_TMEM_OP_THAW, domid, 0, 0,
                        NULL);
    if (r < 0) {
        LOGE(ERROR, "Can not thaw tmem pools");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;
out:
    GC_FREE;
    return rc;
}

static int32_t tmem_setop_from_string(char *set_name, uint32_t val,
                                      xen_tmem_client_t *info)
{
    if (!strcmp(set_name, "weight"))
        info->weight = val;
    else if (!strcmp(set_name, "compress"))
        info->flags.u.compress = val;
    else
        return -1;

    return 0;
}

int libxl_tmem_set(libxl_ctx *ctx, uint32_t domid, char* name, uint32_t set)
{
    int r, rc;
    xen_tmem_client_t info;
    GC_INIT(ctx);

    r = xc_tmem_control(ctx->xch, -1 /* pool_id */,
                        XEN_SYSCTL_TMEM_OP_GET_CLIENT_INFO,
                        domid, sizeof(info), 0 /* arg */, &info);
    if (r < 0) {
        LOGE(ERROR, "Can not get tmem data!");
        rc = ERROR_FAIL;
        goto out;
    }
    rc = tmem_setop_from_string(name, set, &info);
    if (rc == -1) {
        LOGEV(ERROR, -1, "Invalid set, valid sets are <weight|compress>");
        rc = ERROR_INVAL;
        goto out;
    }
    r = xc_tmem_control(ctx->xch, -1 /* pool_id */,
                        XEN_SYSCTL_TMEM_OP_SET_CLIENT_INFO,
                        domid, sizeof(info), 0 /* arg */, &info);
    if (r < 0) {
        LOGE(ERROR, "Can not set tmem %s", name);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;
out:
    GC_FREE;
    return rc;
}

int libxl_tmem_shared_auth(libxl_ctx *ctx, uint32_t domid,
                           char* uuid, int auth)
{
    int r, rc;
    GC_INIT(ctx);

    r = xc_tmem_auth(ctx->xch, domid, uuid, auth);
    if (r < 0) {
        LOGE(ERROR, "Can not set tmem shared auth");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;
out:
    GC_FREE;
    return rc;
}

int libxl_tmem_freeable(libxl_ctx *ctx)
{
    int r, rc;
    GC_INIT(ctx);

    r = xc_tmem_control(ctx->xch, -1, XEN_SYSCTL_TMEM_OP_QUERY_FREEABLE_MB,
                        -1, 0, 0, 0);
    if (r < 0) {
        LOGE(ERROR, "Can not get tmem freeable memory");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;
out:
    GC_FREE;
    return rc;
}

int libxl_get_freecpus(libxl_ctx *ctx, libxl_bitmap *cpumap)
{
    int ncpus;

    ncpus = libxl_get_max_cpus(ctx);
    if (ncpus < 0)
        return ncpus;

    cpumap->map = xc_cpupool_freeinfo(ctx->xch);
    if (cpumap->map == NULL)
        return ERROR_FAIL;

    cpumap->size = (ncpus + 7) / 8;

    return 0;
}

int libxl_cpupool_create(libxl_ctx *ctx, const char *name,
                         libxl_scheduler sched,
                         libxl_bitmap cpumap, libxl_uuid *uuid,
                         uint32_t *poolid)
{
    GC_INIT(ctx);
    int rc;
    int i;
    xs_transaction_t t;
    char *uuid_string;

    uuid_string = libxl__uuid2string(gc, *uuid);
    if (!uuid_string) {
        GC_FREE;
        return ERROR_NOMEM;
    }

    rc = xc_cpupool_create(ctx->xch, poolid, sched);
    if (rc) {
        LOGEV(ERROR, rc, "Could not create cpupool");
        GC_FREE;
        return ERROR_FAIL;
    }

    libxl_for_each_bit(i, cpumap)
        if (libxl_bitmap_test(&cpumap, i)) {
            rc = xc_cpupool_addcpu(ctx->xch, *poolid, i);
            if (rc) {
                LOGEV(ERROR, rc, "Error moving cpu to cpupool");
                libxl_cpupool_destroy(ctx, *poolid);
                GC_FREE;
                return ERROR_FAIL;
            }
        }

    for (;;) {
        t = xs_transaction_start(ctx->xsh);

        xs_mkdir(ctx->xsh, t, GCSPRINTF("/local/pool/%d", *poolid));
        libxl__xs_printf(gc, t,
                         GCSPRINTF("/local/pool/%d/uuid", *poolid),
                         "%s", uuid_string);
        libxl__xs_printf(gc, t,
                         GCSPRINTF("/local/pool/%d/name", *poolid),
                         "%s", name);

        if (xs_transaction_end(ctx->xsh, t, 0) || (errno != EAGAIN)) {
            GC_FREE;
            return 0;
        }
    }
}

int libxl_cpupool_destroy(libxl_ctx *ctx, uint32_t poolid)
{
    GC_INIT(ctx);
    int rc, i;
    xc_cpupoolinfo_t *info;
    xs_transaction_t t;
    libxl_bitmap cpumap;

    info = xc_cpupool_getinfo(ctx->xch, poolid);
    if (info == NULL) {
        GC_FREE;
        return ERROR_NOMEM;
    }

    rc = ERROR_INVAL;
    if ((info->cpupool_id != poolid) || (info->n_dom))
        goto out;

    rc = libxl_cpu_bitmap_alloc(ctx, &cpumap, 0);
    if (rc)
        goto out;

    memcpy(cpumap.map, info->cpumap, cpumap.size);
    libxl_for_each_bit(i, cpumap)
        if (libxl_bitmap_test(&cpumap, i)) {
            rc = xc_cpupool_removecpu(ctx->xch, poolid, i);
            if (rc) {
                LOGEV(ERROR, rc, "Error removing cpu from cpupool");
                rc = ERROR_FAIL;
                goto out1;
            }
        }

    rc = xc_cpupool_destroy(ctx->xch, poolid);
    if (rc) {
        LOGEV(ERROR, rc, "Could not destroy cpupool");
        rc = ERROR_FAIL;
        goto out1;
    }

    for (;;) {
        t = xs_transaction_start(ctx->xsh);

        xs_rm(ctx->xsh, XBT_NULL, GCSPRINTF("/local/pool/%d", poolid));

        if (xs_transaction_end(ctx->xsh, t, 0) || (errno != EAGAIN))
            break;
    }

    rc = 0;

out1:
    libxl_bitmap_dispose(&cpumap);
out:
    xc_cpupool_infofree(ctx->xch, info);
    GC_FREE;

    return rc;
}

int libxl_cpupool_rename(libxl_ctx *ctx, const char *name, uint32_t poolid)
{
    GC_INIT(ctx);
    xs_transaction_t t;
    xc_cpupoolinfo_t *info;
    int rc;

    info = xc_cpupool_getinfo(ctx->xch, poolid);
    if (info == NULL) {
        GC_FREE;
        return ERROR_NOMEM;
    }

    rc = ERROR_INVAL;
    if (info->cpupool_id != poolid)
        goto out;

    rc = 0;

    for (;;) {
        t = xs_transaction_start(ctx->xsh);

        libxl__xs_printf(gc, t,
                         GCSPRINTF("/local/pool/%d/name", poolid),
                         "%s", name);

        if (xs_transaction_end(ctx->xsh, t, 0))
            break;

        if (errno == EAGAIN)
            continue;

        rc = ERROR_FAIL;
        break;
    }

out:
    xc_cpupool_infofree(ctx->xch, info);
    GC_FREE;

    return rc;
}

int libxl_cpupool_cpuadd(libxl_ctx *ctx, uint32_t poolid, int cpu)
{
    GC_INIT(ctx);
    int rc = 0;

    rc = xc_cpupool_addcpu(ctx->xch, poolid, cpu);
    if (rc) {
        LOGE(ERROR, "Error moving cpu %d to cpupool", cpu);
        rc = ERROR_FAIL;
    }

    GC_FREE;
    return rc;
}

int libxl_cpupool_cpuadd_cpumap(libxl_ctx *ctx, uint32_t poolid,
                                const libxl_bitmap *cpumap)
{
    int c, ncpus = 0, rc = 0;

    libxl_for_each_set_bit(c, *cpumap) {
        if (!libxl_cpupool_cpuadd(ctx, poolid, c))
            ncpus++;
    }

    if (ncpus != libxl_bitmap_count_set(cpumap))
        rc = ERROR_FAIL;

    return rc;
}

int libxl_cpupool_cpuadd_node(libxl_ctx *ctx, uint32_t poolid, int node, int *cpus)
{
    int rc = 0;
    int cpu, nr;
    libxl_bitmap freemap;
    libxl_cputopology *topology;

    if (libxl_get_freecpus(ctx, &freemap)) {
        return ERROR_FAIL;
    }

    topology = libxl_get_cpu_topology(ctx, &nr);
    if (!topology) {
        rc = ERROR_FAIL;
        goto out;
    }

    *cpus = 0;
    for (cpu = 0; cpu < nr; cpu++) {
        if (libxl_bitmap_test(&freemap, cpu) && (topology[cpu].node == node) &&
            !libxl_cpupool_cpuadd(ctx, poolid, cpu)) {
                (*cpus)++;
        }
        libxl_cputopology_dispose(&topology[cpu]);
    }

    free(topology);
out:
    libxl_bitmap_dispose(&freemap);
    return rc;
}

int libxl_cpupool_cpuremove(libxl_ctx *ctx, uint32_t poolid, int cpu)
{
    GC_INIT(ctx);
    int rc = 0;

    rc = xc_cpupool_removecpu(ctx->xch, poolid, cpu);
    if (rc) {
        LOGE(ERROR, "Error removing cpu %d from cpupool", cpu);
        rc = ERROR_FAIL;
    }

    GC_FREE;
    return rc;
}

int libxl_cpupool_cpuremove_cpumap(libxl_ctx *ctx, uint32_t poolid,
                                   const libxl_bitmap *cpumap)
{
    int c, ncpus = 0, rc = 0;

    libxl_for_each_set_bit(c, *cpumap) {
        if (!libxl_cpupool_cpuremove(ctx, poolid, c))
            ncpus++;
    }

    if (ncpus != libxl_bitmap_count_set(cpumap))
        rc = ERROR_FAIL;

    return rc;
}

int libxl_cpupool_cpuremove_node(libxl_ctx *ctx, uint32_t poolid, int node, int *cpus)
{
    int ret = 0;
    int n_pools;
    int p;
    int cpu, nr_cpus;
    libxl_cputopology *topology;
    libxl_cpupoolinfo *poolinfo;

    poolinfo = libxl_list_cpupool(ctx, &n_pools);
    if (!poolinfo) {
        return ERROR_NOMEM;
    }

    topology = libxl_get_cpu_topology(ctx, &nr_cpus);
    if (!topology) {
        ret = ERROR_FAIL;
        goto out;
    }

    *cpus = 0;
    for (p = 0; p < n_pools; p++) {
        if (poolinfo[p].poolid == poolid) {
            for (cpu = 0; cpu < nr_cpus; cpu++) {
                if ((topology[cpu].node == node) &&
                    libxl_bitmap_test(&poolinfo[p].cpumap, cpu) &&
                    !libxl_cpupool_cpuremove(ctx, poolid, cpu)) {
                        (*cpus)++;
                }
            }
        }
    }

    libxl_cputopology_list_free(topology, nr_cpus);

out:
    libxl_cpupoolinfo_list_free(poolinfo, n_pools);

    return ret;
}

int libxl_cpupool_movedomain(libxl_ctx *ctx, uint32_t poolid, uint32_t domid)
{
    GC_INIT(ctx);
    int rc;

    rc = xc_cpupool_movedomain(ctx->xch, poolid, domid);
    if (rc) {
        LOGEV(ERROR, rc, "Error moving domain to cpupool");
        GC_FREE;
        return ERROR_FAIL;
    }

    GC_FREE;
    return 0;
}

static int fd_set_flags(libxl_ctx *ctx, int fd,
                        int fcntlgetop, int fcntlsetop, const char *fl,
                        int flagmask, int set_p)
{
    int flags, r;
    GC_INIT(ctx);

    flags = fcntl(fd, fcntlgetop);
    if (flags == -1) {
        LOGE(ERROR, "fcntl(,F_GET%s) failed", fl);
        GC_FREE;
        return ERROR_FAIL;
    }

    if (set_p)
        flags |= flagmask;
    else
        flags &= ~flagmask;

    r = fcntl(fd, fcntlsetop, flags);
    if (r == -1) {
        LOGE(ERROR, "fcntl(,F_SET%s) failed", fl);
        GC_FREE;
        return ERROR_FAIL;
    }

    GC_FREE;
    return 0;
}

int libxl_fd_set_cloexec(libxl_ctx *ctx, int fd, int cloexec)
  { return fd_set_flags(ctx,fd, F_GETFD,F_SETFD,"FD", FD_CLOEXEC, cloexec); }

int libxl_fd_set_nonblock(libxl_ctx *ctx, int fd, int nonblock)
  { return fd_set_flags(ctx,fd, F_GETFL,F_SETFL,"FL", O_NONBLOCK, nonblock); }

int libxl__fd_flags_modify_save(libxl__gc *gc, int fd,
                                int mask, int val, int *r_oldflags)
{
    int rc, ret, fdfl;

    fdfl = fcntl(fd, F_GETFL);
    if (fdfl < 0) {
        LOGE(ERROR, "failed to fcntl.F_GETFL for fd %d", fd);
        rc = ERROR_FAIL;
        goto out_err;
    }

    LOG(DEBUG, "fnctl F_GETFL flags for fd %d are 0x%x", fd, fdfl);

    if (r_oldflags)
        *r_oldflags = fdfl;

    fdfl &= mask;
    fdfl |= val;

    LOG(DEBUG, "fnctl F_SETFL of fd %d to 0x%x", fd, fdfl);

    ret = fcntl(fd, F_SETFL, fdfl);
    if (ret < 0) {
        LOGE(ERROR, "failed to fcntl.F_SETFL for fd %d", fd);
        rc = ERROR_FAIL;
        goto out_err;
    }

    rc = 0;

out_err:
    return rc;
}

int libxl__fd_flags_restore(libxl__gc *gc, int fd, int fdfl)
{
    int ret, rc;

    LOG(DEBUG, "fnctl F_SETFL of fd %d to 0x%x", fd, fdfl);

    ret = fcntl(fd, F_SETFL, fdfl);
    if (ret < 0) {
        LOGE(ERROR, "failed to fcntl.F_SETFL for fd %d", fd);
        rc = ERROR_FAIL;
        goto out_err;
    }

    rc = 0;

out_err:
    return rc;

}

void libxl_hwcap_copy(libxl_ctx *ctx,libxl_hwcap *dst, const libxl_hwcap *src)
{
    int i;

    for (i = 0; i < 8; i++)
        (*dst)[i] = (*src)[i];
}

void libxl_mac_copy(libxl_ctx *ctx, libxl_mac *dst, const libxl_mac *src)
{
    int i;

    for (i = 0; i < 6; i++)
        (*dst)[i] = (*src)[i];
}

/* For QEMU upstream we always need to provide the number of cpus present to
 * QEMU whether they are online or not; otherwise QEMU won't accept the saved
 * state. See implementation of libxl__qmp_query_cpus.
 */
static int libxl__update_avail_vcpus_qmp(libxl__gc *gc, uint32_t domid,
                                         unsigned int max_vcpus,
                                         libxl_bitmap *map)
{
    int rc;

    rc = libxl__qmp_query_cpus(gc, domid, map);
    if (rc) {
        LOG(ERROR, "fail to get number of cpus for domain %d", domid);
        goto out;
    }

    rc = 0;
out:
    return rc;
}

static int libxl__update_avail_vcpus_xenstore(libxl__gc *gc, uint32_t domid,
                                              unsigned int max_vcpus,
                                              libxl_bitmap *map)
{
    int rc;
    unsigned int i;
    const char *dompath;

    dompath = libxl__xs_get_dompath(gc, domid);
    if (!dompath) {
        rc = ERROR_FAIL;
        goto out;
    }

    for (i = 0; i < max_vcpus; i++) {
        const char *path = GCSPRINTF("%s/cpu/%u/availability", dompath, i);
        const char *content;
        rc = libxl__xs_read_checked(gc, XBT_NULL, path, &content);
        if (rc) goto out;
        if (content && !strcmp(content, "online"))
            libxl_bitmap_set(map, i);
    }

    rc = 0;
out:
    return rc;
}

int libxl_retrieve_domain_configuration(libxl_ctx *ctx, uint32_t domid,
                                        libxl_domain_config *d_config)
{
    GC_INIT(ctx);
    int rc;
    libxl__domain_userdata_lock *lock = NULL;

    CTX_LOCK;

    lock = libxl__lock_domain_userdata(gc, domid);
    if (!lock) {
        rc = ERROR_LOCK_FAIL;
        goto out;
    }

    rc = libxl__get_domain_configuration(gc, domid, d_config);
    if (rc) {
        LOG(ERROR, "fail to get domain configuration for domain %d", domid);
        rc = ERROR_FAIL;
        goto out;
    }

    /* Domain name */
    {
        char *domname;
        domname = libxl_domid_to_name(ctx, domid);
        if (!domname) {
            LOG(ERROR, "fail to get domain name for domain %d", domid);
            goto out;
        }
        free(d_config->c_info.name);
        d_config->c_info.name = domname; /* steals allocation */
    }

    /* Domain UUID */
    {
        libxl_dominfo info;
        libxl_dominfo_init(&info);
        rc = libxl_domain_info(ctx, &info, domid);
        if (rc) {
            LOG(ERROR, "fail to get domain info for domain %d", domid);
            libxl_dominfo_dispose(&info);
            goto out;
        }
        libxl_uuid_copy(ctx, &d_config->c_info.uuid, &info.uuid);
        libxl_dominfo_dispose(&info);
    }

    /* VCPUs */
    {
        libxl_bitmap *map = &d_config->b_info.avail_vcpus;
        unsigned int max_vcpus = d_config->b_info.max_vcpus;
        libxl_device_model_version version;

        libxl_bitmap_dispose(map);
        libxl_bitmap_init(map);
        libxl_bitmap_alloc(CTX, map, max_vcpus);
        libxl_bitmap_set_none(map);

        switch (d_config->b_info.type) {
        case LIBXL_DOMAIN_TYPE_HVM:
            version = libxl__device_model_version_running(gc, domid);
            assert(version != LIBXL_DEVICE_MODEL_VERSION_UNKNOWN);
            switch (version) {
            case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
                rc = libxl__update_avail_vcpus_qmp(gc, domid,
                                                   max_vcpus, map);
                break;
            case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
                rc = libxl__update_avail_vcpus_xenstore(gc, domid,
                                                        max_vcpus, map);
                break;
            default:
                abort();
            }
            break;
        case LIBXL_DOMAIN_TYPE_PVH:
        case LIBXL_DOMAIN_TYPE_PV:
            rc = libxl__update_avail_vcpus_xenstore(gc, domid,
                                                    max_vcpus, map);
            break;
        default:
            abort();
        }

        if (rc) {
            LOG(ERROR, "fail to update available cpu map for domain %d", domid);
            goto out;
        }
    }

    /* Memory limits:
     *
     * Currently there are three memory limits:
     *  1. "target" in xenstore (originally memory= in config file)
     *  2. "static-max" in xenstore (originally maxmem= in config file)
     *  3. "max_memkb" in hypervisor
     *
     * The third one is not visible and currently managed by
     * toolstack. In order to rebuild a domain we only need to have
     * "target" and "static-max".
     */
    {
        uint64_t target_memkb = 0, max_memkb = 0;

        /* "target" */
        rc = libxl__get_memory_target(gc, domid, &target_memkb, &max_memkb);
        if (rc) {
            LOG(ERROR, "fail to get memory target for domain %d", domid);
            goto out;
        }

        /* libxl__get_targetmem_fudge() calculates the difference from
         * what is in xenstore to what we have in the domain build info.
         */
        d_config->b_info.target_memkb = target_memkb +
            libxl__get_targetmem_fudge(gc, &d_config->b_info);

        d_config->b_info.max_memkb = max_memkb;
    }

    /* Devices: disk, nic, vtpm, pcidev etc. */

    /* The MERGE macro implements following logic:
     * 0. retrieve JSON (done by now)
     * 1. retrieve list of device from xenstore
     * 2. use xenstore entries as primary reference and compare JSON
     *    entries with them.
     *    a. if a device is present in xenstore and in JSON, merge the
     *       two views.
     *    b. if a device is not present in xenstore but in JSON, delete
     *       it from the result.
     *    c. it's impossible to have an entry present in xenstore but
     *       not in JSON, because we maintain an invariant that every
     *       entry in xenstore must have a corresponding entry in JSON.
     * 3. "merge" operates on "src" and "dst". "src" points to the
     *    entry retrieved from xenstore while "dst" points to the entry
     *    retrieve from JSON.
     */
    {
        const struct libxl_device_type *dt;
        int idx;

        for (idx = 0;; idx++) {
            void *p = NULL;
            void **devs;
            int i, j, num;
            int *num_dev;

            dt = device_type_tbl[idx];
            if (!dt)
                break;

            if (!dt->list || !dt->compare)
                continue;

            num_dev = libxl__device_type_get_num(dt, d_config);
            p = dt->list(CTX, domid, &num);
            if (p == NULL) {
                LOG(DEBUG, "no %s from xenstore for domain %d",
                    dt->type, domid);
            }
            devs = libxl__device_type_get_ptr(dt, d_config);

            for (i = 0; i < *num_dev; i++) {
                void *q;

                q = libxl__device_type_get_elem(dt, d_config, i);
                for (j = 0; j < num; j++) {
                    if (dt->compare(p + dt->dev_elem_size * j, q))
                        break;
                }

                if (j < num) {         /* found in xenstore */
                    if (dt->merge)
                        dt->merge(ctx, p + dt->dev_elem_size * j, q);
                } else {                /* not found in xenstore */
                    LOG(WARN,
                        "Device present in JSON but not in xenstore, ignored");

                    dt->dispose(q);

                    for (j = i; j < *num_dev - 1; j++)
                        memcpy(libxl__device_type_get_elem(dt, d_config, j),
                               libxl__device_type_get_elem(dt, d_config, j+1),
                               dt->dev_elem_size);

                    /* rewind counters */
                    (*num_dev)--;
                    i--;

                    *devs = libxl__realloc(NOGC, *devs,
                                           dt->dev_elem_size * *num_dev);
                }
            }

            for (i = 0; i < num; i++)
                dt->dispose(p + dt->dev_elem_size * i);
            free(p);
        }
    }

out:
    if (lock) libxl__unlock_domain_userdata(lock);
    CTX_UNLOCK;
    GC_FREE;
    return rc;
}

static int libxl_device_disk_compare(libxl_device_disk *d1,
                                     libxl_device_disk *d2)
{
    return COMPARE_DISK(d1, d2);
}

/* Take care of removable device. We maintain invariant in the
 * insert / remove operation so that:
 * 1. if xenstore is "empty" while JSON is not, the result
 *    is "empty"
 * 2. if xenstore has a different media than JSON, use the
 *    one in JSON
 * 3. if xenstore and JSON have the same media, well, you
 *    know the answer :-)
 *
 * Currently there is only one removable device -- CDROM.
 * Look for libxl_cdrom_insert for reference.
 */
static void libxl_device_disk_merge(libxl_ctx *ctx, void *d1, void *d2)
{
    GC_INIT(ctx);
    libxl_device_disk *src = d1;
    libxl_device_disk *dst = d2;

    if (src->removable) {
        if (!src->pdev_path || *src->pdev_path == '\0') {
            /* 1, no media in drive */
            free(dst->pdev_path);
            dst->pdev_path = libxl__strdup(NOGC, "");
            dst->format = LIBXL_DISK_FORMAT_EMPTY;
        } else {
            /* 2 and 3, use JSON, no need to touch anything */
            ;
        }
    }
}

static int libxl_device_disk_dm_needed(void *e, unsigned domid)
{
    libxl_device_disk *elem = e;

    return elem->backend == LIBXL_DISK_BACKEND_QDISK &&
           elem->backend_domid == domid;
}

DEFINE_DEVICE_TYPE_STRUCT(disk,
    .merge       = libxl_device_disk_merge,
    .dm_needed   = libxl_device_disk_dm_needed,
    .skip_attach = 1
);

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
