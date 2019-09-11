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
    physinfo->max_possible_mfn = xcphysinfo.max_mfn;
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
    physinfo->cap_pv = !!(xcphysinfo.capabilities & XEN_SYSCTL_PHYSCAP_pv);
    physinfo->cap_hvm_directio =
        !!(xcphysinfo.capabilities & XEN_SYSCTL_PHYSCAP_directio);
    physinfo->cap_hap = !!(xcphysinfo.capabilities & XEN_SYSCTL_PHYSCAP_hap);

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

int libxl_set_parameters(libxl_ctx *ctx, char *params)
{
    int ret;
    GC_INIT(ctx);

    ret = xc_set_parameters(ctx->xch, params);
    if (ret < 0) {
        LOGEV(ERROR, ret, "setting parameters");
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

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
