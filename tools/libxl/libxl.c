/*
 * Copyright 2009-2017 Citrix Ltd and other contributors
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

#define PAGE_TO_MEMKB(pages) ((pages) * 4)

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
            LOGEVD(ERROR, errno, domid, "Create xs transaction for domain (re)name");
            goto x_fail;
        }
    }

    if (!new_name) {
        LOGD(ERROR, domid, "New domain name not specified");
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
            LOGD(ERROR, domid, "Unexpected error checking for existing domain");
            goto x_rc;
        } else if (domid_e == domid) {
            /* domain already has this name, ok (but we do still
             * need the rest of the code as we may need to check
             * old_name, for example). */
        } else {
            LOGD(ERROR, domid, "Domain with name \"%s\" already exists.", new_name);
            rc = ERROR_INVAL;
            goto x_rc;
        }
    }

    if (old_name) {
        got_old_name = xs_read(ctx->xsh, trans, name_path, &got_old_len);
        if (!got_old_name) {
            LOGEVD(ERROR, errno, domid,
                   "Check old name for domain allegedly named `%s'",
                   old_name);
            goto x_fail;
        }
        if (strcmp(old_name, got_old_name)) {
            LOGD(ERROR, domid,
                 "Allegedly named `%s' is actually named `%s' - racing ?",
                 old_name,
                 got_old_name);
            free(got_old_name);
            goto x_fail;
        }
        free(got_old_name);
    }
    if (!xs_write(ctx->xsh, trans, name_path,
                  new_name, strlen(new_name))) {
        LOGD(ERROR, domid,
             "Failed to write new name `%s'"
             " for domain previously named `%s'",
             new_name,
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
            LOGED(ERROR, domid, "Unable to rename stub-domain");
            goto x_rc;
        }
    }

    if (our_trans) {
        if (!xs_transaction_end(ctx->xsh, our_trans, 0)) {
            trans = our_trans = 0;
            if (errno != EAGAIN) {
                LOGD(ERROR, domid,
                     "Failed to commit new name `%s'"
                     " for domain previously named `%s'",
                     new_name,
                     old_name);
                goto x_fail;
            }
            LOGD(DEBUG, domid,
                 "Need to retry rename transaction"
                 " for domain (name_path=\"%s\", new_name=\"%s\")",
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

void libxl__xcinfo2xlinfo(libxl_ctx *ctx,
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
            libxl__xcinfo2xlinfo(ctx, &info[i], &ptr[size + i]);
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
        LOGED(ERROR, domid, "Getting domain info list");
        GC_FREE;
        return ERROR_FAIL;
    }
    if (ret==0 || xcinfo.domain != domid) {
        GC_FREE;
        return ERROR_DOMAIN_NOTFOUND;
    }

    if (info_r)
        libxl__xcinfo2xlinfo(ctx, &xcinfo, info_r);
    GC_FREE;
    return 0;
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
        LOGD(ERROR, domid, "Colo mode must be enabled/disabled");
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
            LOGD(ERROR, domid, "Cannot use memory checkpoint "
                        "compression in COLO mode");
            rc = ERROR_FAIL;
            goto out;
    }

    if (!libxl_defbool_val(info->allow_unsafe) &&
        (libxl_defbool_val(info->blackhole) ||
         !libxl_defbool_val(info->netbuf) ||
         !libxl_defbool_val(info->diskbuf))) {
        LOGD(ERROR, domid, "Unsafe mode must be enabled to replicate to /dev/null,"
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
        LOGED(ERROR, domid, "Pausing domain");
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
        LOGED(ERROR, domid, "Core dumping domain to %s", filename);
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
        if (libxl__device_model_version_running(gc, domid) !=
            LIBXL_DEVICE_MODEL_VERSION_NONE) {
            rc = libxl__domain_resume_device_model(gc, domid);
            if (rc < 0) {
                LOGD(ERROR, domid, "Failed to unpause device model for domain:%d",
                     rc);
                goto out;
            }
        }
    }
    ret = xc_domain_unpause(ctx->xch, domid);
    if (ret<0) {
        LOGED(ERROR, domid, "Unpausing domain");
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
        LOGED(ERROR, domid, "Getting HVM callback IRQ");
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

    LOGD(DEBUG, evg->domid, "%s", why);

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

        LOGD(DEBUG, evg->domid, "[evg=%p] nentries=%d rc=%d %ld..%ld",
             evg, nentries, rc,
             rc>0 ? (long)domaininfos[0].domain : 0,
             rc>0 ? (long)domaininfos[rc-1].domain : 0);

        for (;;) {
            if (!evg) {
                LOG(DEBUG, "[evg=0] all reported");
                goto all_reported;
            }

            LOGD(DEBUG, evg->domid, "[evg=%p]"
                 "   got=domaininfos[%d] got->domain=%ld",
                 evg, (int)(got - domaininfos),
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
            LOGD(DEBUG, evg->domid, "Exists shutdown_reported=%d"" dominf.flags=%x",
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
        LOGD(ERROR, dds->domid, "Destruction of domain failed");

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
        LOGD(ERROR, dds->domain.domid, "Unable to destroy stubdom with domid %u",
             dis->domid);
        dds->rc = rc;
    }

    dds->stubdom_finished = 1;
    savefile = libxl__device_model_savefile(gc, dis->domid);
    rc = libxl__remove_file(gc, savefile);
    if (rc) {
        LOGD(ERROR, dds->domain.domid, "Failed to remove device-model savefile %s",
             savefile);
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
        LOGD(ERROR, dis->domid, "Unable to destroy guest");
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
        LOGD(ERROR, domid, "Non-existant domain");
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
        LOGD(ERROR, domid, "Pci shutdown failed");
    rc = xc_domain_pause(ctx->xch, domid);
    if (rc < 0) {
        LOGEVD(ERROR, rc, domid, "xc_domain_pause failed");
    }
    if (dm_present) {
        if (libxl__destroy_device_model(gc, domid) < 0)
            LOGD(ERROR, domid, "libxl__destroy_device_model failed");

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
        LOGD(ERROR, domid, "libxl__devices_destroy failed");

    vm_path = libxl__xs_read(gc, XBT_NULL, GCSPRINTF("%s/vm", dom_path));
    if (vm_path)
        if (!xs_rm(ctx->xsh, XBT_NULL, vm_path))
            LOGED(ERROR, domid, "xs_rm failed for %s", vm_path);

    if (!xs_rm(ctx->xsh, XBT_NULL, dom_path))
        LOGED(ERROR, domid, "xs_rm failed for %s", dom_path);

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
            LOGED(ERROR, domid,
 "xc_domain_destroy failed (with difficult errno value %d)",
                  errno);
            _exit(-1);
        }
    }
    LOGD(DEBUG, domid, "Forked pid %ld for destroy of domain", (long)rc);

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
            LOGEVD(ERROR, WEXITSTATUS(status), dis->domid,
                   "xc_domain_destroy failed");
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

int libxl__resolve_domid(libxl__gc *gc, const char *name, uint32_t *domid)
{
    if (!name)
        return 0;
    return libxl_domain_qualifier_to_domid(CTX, name, domid);
}

/******************************************************************************/
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
        LOGED(ERROR, domid, "Getting infolist");
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
            LOGED(ERROR, domid, "Getting vcpu info");
            goto err;
        }

        if (xc_vcpu_getaffinity(ctx->xch, domid, *nr_vcpus_out,
                                ptr->cpumap.map, ptr->cpumap_soft.map,
                                XEN_VCPUAFFINITY_SOFT|XEN_VCPUAFFINITY_HARD) == -1) {
            LOGED(ERROR, domid, "Getting vcpu affinity");
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
        LOGD(ERROR, domid, "Failed to query cpus");
        goto out;
    }

    libxl_bitmap_copy_alloc(CTX, &final_map, cpumap);

    libxl_for_each_set_bit(i, current_map)
        libxl_bitmap_reset(&final_map, i);

    libxl_for_each_set_bit(i, final_map) {
        rc = libxl__qmp_cpu_add(gc, domid, i);
        if (rc) {
            LOGD(ERROR, domid, "Failed to add cpu %d", i);
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
        LOGED(ERROR, domid, "Getting domain info list");
        goto out;
    }

    maxcpus = libxl_bitmap_count_set(cpumap);
    if (maxcpus > info.vcpu_max_id + 1)
    {
        LOGED(ERROR, domid, "Requested %d VCPUs, however maxcpus is %d!",
              maxcpus, info.vcpu_max_id + 1);
        rc = ERROR_FAIL;
        goto out;
    }

    switch (libxl__domain_type(gc, domid)) {
    case LIBXL_DOMAIN_TYPE_HVM:
        switch (libxl__device_model_version_running(gc, domid)) {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
        case LIBXL_DEVICE_MODEL_VERSION_NONE:
            break;
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
            rc = libxl__set_vcpuonline_qmp(gc, domid, cpumap, &info);
            break;
        default:
            rc = ERROR_INVAL;
        }
        break;
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
        LOGED(ERROR, domid, "Send trigger '%s' failed",
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
        LOGEVD(ERROR, -1, domid, "Can't get start time of domain");
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
        LOGED(ERROR, domid, "Can not get tmem list");
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
        LOGED(ERROR, domid, "Can not freeze tmem pools");
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
        LOGED(ERROR, domid, "Can not thaw tmem pools");
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
        LOGED(ERROR, domid, "Can not get tmem data!");
        rc = ERROR_FAIL;
        goto out;
    }
    rc = tmem_setop_from_string(name, set, &info);
    if (rc == -1) {
        LOGEVD(ERROR, -1, domid, "Invalid set, valid sets are <weight|compress>");
        rc = ERROR_INVAL;
        goto out;
    }
    r = xc_tmem_control(ctx->xch, -1 /* pool_id */,
                        XEN_SYSCTL_TMEM_OP_SET_CLIENT_INFO,
                        domid, sizeof(info), 0 /* arg */, &info);
    if (r < 0) {
        LOGED(ERROR, domid, "Can not set tmem %s", name);
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
        LOGED(ERROR, domid, "Can not set tmem shared auth");
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
        LOGD(ERROR, domid, "Fail to get number of cpus");
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
        LOGD(ERROR, domid, "Fail to get domain configuration");
        rc = ERROR_FAIL;
        goto out;
    }

    /* Domain name */
    {
        char *domname;
        domname = libxl_domid_to_name(ctx, domid);
        if (!domname) {
            LOGD(ERROR, domid, "Fail to get domain name");
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
            LOGD(ERROR, domid, "Fail to get domain info");
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
            case LIBXL_DEVICE_MODEL_VERSION_NONE:
                rc = libxl__update_avail_vcpus_xenstore(gc, domid,
                                                        max_vcpus, map);
                break;
            default:
                abort();
            }
            break;
        case LIBXL_DOMAIN_TYPE_PV:
            rc = libxl__update_avail_vcpus_xenstore(gc, domid,
                                                    max_vcpus, map);
            break;
        default:
            abort();
        }

        if (rc) {
            LOGD(ERROR, domid, "Fail to update available cpu map");
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
            LOGD(ERROR, domid, "Fail to get memory target");
            goto out;
        }

        /* libxl__get_targetmem_fudge() calculates the difference from
         * what is in xenstore to what we have in the domain build info.
         */
        d_config->b_info.target_memkb = target_memkb +
            libxl__get_targetmem_fudge(gc, &d_config->b_info);

        d_config->b_info.max_memkb = max_memkb;
    }

    /* Scheduler params */
    {
        libxl_domain_sched_params_dispose(&d_config->b_info.sched_params);
        rc = libxl_domain_sched_params_get(ctx, domid,
                                           &d_config->b_info.sched_params);
        if (rc) {
            LOGD(ERROR, domid, "Fail to get scheduler parameters");
            goto out;
        }
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
                LOGD(DEBUG, domid, "No %s from xenstore",
                     dt->type);
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
                    LOGD(WARN, domid,
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

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
