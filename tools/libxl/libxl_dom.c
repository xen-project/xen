/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
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

#include <stdio.h>
#include <assert.h>
#include <glob.h>
#include <inttypes.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h> /* for struct timeval */
#include <sys/stat.h> /* for stat */
#include <unistd.h> /* for sleep(2) */

#include <xenctrl.h>
#include <xc_dom.h>
#include <xenguest.h>
#include <fcntl.h>

#include <xen/hvm/hvm_info_table.h>

#include "libxl.h"
#include "libxl_internal.h"

int libxl__domain_is_hvm(libxl_ctx *ctx, uint32_t domid)
{
    xc_domaininfo_t info;
    int ret;

    ret = xc_domain_getinfolist(ctx->xch, domid, 1, &info);
    if (ret != 1)
        return -1;
    if (info.domain != domid)
        return -1;
    return !!(info.flags & XEN_DOMINF_hvm_guest);
}

int libxl__domain_shutdown_reason(libxl_ctx *ctx, uint32_t domid)
{
    xc_domaininfo_t info;
    int ret;

    ret = xc_domain_getinfolist(ctx->xch, domid, 1, &info);
    if (ret != 1)
        return -1;
    if (info.domain != domid)
        return -1;
    if (!(info.flags & XEN_DOMINF_shutdown))
        return -1;

    return (info.flags >> XEN_DOMINF_shutdownshift) & XEN_DOMINF_shutdownmask;
}

int libxl__build_pre(libxl_ctx *ctx, uint32_t domid,
              libxl_domain_build_info *info, libxl_domain_build_state *state)
{
    xc_domain_max_vcpus(ctx->xch, domid, info->max_vcpus);
    xc_domain_setmaxmem(ctx->xch, domid, info->target_memkb + LIBXL_MAXMEM_CONSTANT);
    xc_domain_set_memmap_limit(ctx->xch, domid, 
            (info->hvm) ? info->max_memkb : 
            (info->max_memkb + info->u.pv.slack_memkb));
    xc_domain_set_tsc_info(ctx->xch, domid, info->tsc_mode, 0, 0, 0);
    if ( info->disable_migrate )
        xc_domain_disable_migrate(ctx->xch, domid);

    if (info->hvm) {
        unsigned long shadow;
        shadow = (info->shadow_memkb + 1023) / 1024;
        xc_shadow_control(ctx->xch, domid, XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION, NULL, 0, &shadow, 0, NULL);
    }

    state->store_port = xc_evtchn_alloc_unbound(ctx->xch, domid, 0);
    state->console_port = xc_evtchn_alloc_unbound(ctx->xch, domid, 0);
    return 0;
}

int libxl__build_post(libxl_ctx *ctx, uint32_t domid,
               libxl_domain_build_info *info, libxl_domain_build_state *state,
               char **vms_ents, char **local_ents)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    char *dom_path, *vm_path;
    xs_transaction_t t;
    char **ents;
    int i;
    char *cpuid_res[4];

#if defined(__i386__) || defined(__x86_64__)
    xc_cpuid_apply_policy(ctx->xch, domid);
    if (info->cpuid != NULL) {
        for (i = 0; info->cpuid[i].input[0] != XEN_CPUID_INPUT_UNUSED; i++)
            xc_cpuid_set(ctx->xch, domid, info->cpuid[i].input,
                         (const char**)(info->cpuid[i].policy), cpuid_res);
    }
#endif

    ents = libxl__calloc(&gc, 12 + (info->max_vcpus * 2) + 2, sizeof(char *));
    ents[0] = "memory/static-max";
    ents[1] = libxl__sprintf(&gc, "%d", info->max_memkb);
    ents[2] = "memory/target";
    ents[3] = libxl__sprintf(&gc, "%d", info->target_memkb - info->video_memkb);
    ents[4] = "memory/videoram";
    ents[5] = libxl__sprintf(&gc, "%d", info->video_memkb);
    ents[6] = "domid";
    ents[7] = libxl__sprintf(&gc, "%d", domid);
    ents[8] = "store/port";
    ents[9] = libxl__sprintf(&gc, "%"PRIu32, state->store_port);
    ents[10] = "store/ring-ref";
    ents[11] = libxl__sprintf(&gc, "%lu", state->store_mfn);
    for (i = 0; i < info->max_vcpus; i++) {
        ents[12+(i*2)]   = libxl__sprintf(&gc, "cpu/%d/availability", i);
        ents[12+(i*2)+1] = (i && info->cur_vcpus && !(info->cur_vcpus & (1 << i)))
                            ? "offline" : "online";
    }

    dom_path = libxl__xs_get_dompath(&gc, domid);
    if (!dom_path)
        return ERROR_FAIL;

    vm_path = xs_read(ctx->xsh, XBT_NULL, libxl__sprintf(&gc, "%s/vm", dom_path), NULL);
retry_transaction:
    t = xs_transaction_start(ctx->xsh);

    libxl__xs_writev(&gc, t, dom_path, ents);
    libxl__xs_writev(&gc, t, dom_path, local_ents);
    libxl__xs_writev(&gc, t, vm_path, vms_ents);

    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;
    xs_introduce_domain(ctx->xsh, domid, state->store_mfn, state->store_port);
    free(vm_path);
    libxl__free_all(&gc);
    return 0;
}

int libxl__build_pv(libxl_ctx *ctx, uint32_t domid,
             libxl_domain_build_info *info, libxl_domain_build_state *state)
{
    struct xc_dom_image *dom;
    int ret;
    int flags = 0;

    xc_dom_loginit(ctx->xch);

    dom = xc_dom_allocate(ctx->xch, info->u.pv.cmdline, info->u.pv.features);
    if (!dom) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_allocate failed");
        return ERROR_FAIL;
    }

    if (info->kernel.mapped) {
        if ( (ret = xc_dom_kernel_mem(dom, info->kernel.data, info->kernel.size)) != 0) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_kernel_mem failed");
            goto out;
        }
    } else {
        if ( (ret = xc_dom_kernel_file(dom, info->kernel.path)) != 0) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_kernel_file failed");
            goto out;
        }
    }

    if ( info->u.pv.ramdisk.path && strlen(info->u.pv.ramdisk.path) ) {
        if (info->u.pv.ramdisk.mapped) {
            if ( (ret = xc_dom_ramdisk_mem(dom, info->u.pv.ramdisk.data, info->u.pv.ramdisk.size)) != 0 ) {
                LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_ramdisk_mem failed");
                goto out;
            }
        } else {
            if ( (ret = xc_dom_ramdisk_file(dom, info->u.pv.ramdisk.path)) != 0 ) {
                LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_ramdisk_file failed");
                goto out;
            }
        }
    }

    dom->flags = flags;
    dom->console_evtchn = state->console_port;
    dom->xenstore_evtchn = state->store_port;

    if ( (ret = xc_dom_boot_xen_init(dom, ctx->xch, domid)) != 0 ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_boot_xen_init failed");
        goto out;
    }
    if ( (ret = xc_dom_parse_image(dom)) != 0 ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_parse_image failed");
        goto out;
    }
    if ( (ret = xc_dom_mem_init(dom, info->target_memkb / 1024)) != 0 ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_mem_init failed");
        goto out;
    }
    if ( (ret = xc_dom_boot_mem_init(dom)) != 0 ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_boot_mem_init failed");
        goto out;
    }
    if ( (ret = xc_dom_build_image(dom)) != 0 ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_build_image failed");
        goto out;
    }
    if ( (ret = xc_dom_boot_image(dom)) != 0 ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xc_dom_boot_image failed");
        goto out;
    }

    state->console_mfn = xc_dom_p2m_host(dom, dom->console_pfn);
    state->store_mfn = xc_dom_p2m_host(dom, dom->xenstore_pfn);

    ret = 0;
out:
    xc_dom_release(dom);
    return ret == 0 ? 0 : ERROR_FAIL;
}

static int hvm_build_set_params(xc_interface *handle, uint32_t domid,
                                libxl_domain_build_info *info,
                                int store_evtchn, unsigned long *store_mfn,
                                int console_evtchn, unsigned long *console_mfn)
{
    struct hvm_info_table *va_hvm;
    uint8_t *va_map, sum;
    int i;

    va_map = xc_map_foreign_range(handle, domid,
                                  XC_PAGE_SIZE, PROT_READ | PROT_WRITE,
                                  HVM_INFO_PFN);
    if (va_map == NULL)
        return -1;

    va_hvm = (struct hvm_info_table *)(va_map + HVM_INFO_OFFSET);
    va_hvm->acpi_enabled = info->u.hvm.acpi;
    va_hvm->apic_mode = info->u.hvm.apic;
    va_hvm->nr_vcpus = info->max_vcpus;
    memcpy(va_hvm->vcpu_online, &info->cur_vcpus, sizeof(info->cur_vcpus));
    for (i = 0, sum = 0; i < va_hvm->length; i++)
        sum += ((uint8_t *) va_hvm)[i];
    va_hvm->checksum -= sum;
    munmap(va_map, XC_PAGE_SIZE);

    xc_get_hvm_param(handle, domid, HVM_PARAM_STORE_PFN, store_mfn);
    xc_get_hvm_param(handle, domid, HVM_PARAM_CONSOLE_PFN, console_mfn);
    xc_set_hvm_param(handle, domid, HVM_PARAM_PAE_ENABLED, info->u.hvm.pae);
#if defined(__i386__) || defined(__x86_64__)
    xc_set_hvm_param(handle, domid, HVM_PARAM_VIRIDIAN, info->u.hvm.viridian);
    xc_set_hvm_param(handle, domid, HVM_PARAM_HPET_ENABLED, (unsigned long) info->u.hvm.hpet);
#endif
    xc_set_hvm_param(handle, domid, HVM_PARAM_TIMER_MODE, (unsigned long) info->u.hvm.timer_mode);
    xc_set_hvm_param(handle, domid, HVM_PARAM_VPT_ALIGN, (unsigned long) info->u.hvm.vpt_align);
    xc_set_hvm_param(handle, domid, HVM_PARAM_STORE_EVTCHN, store_evtchn);
    xc_set_hvm_param(handle, domid, HVM_PARAM_CONSOLE_EVTCHN, console_evtchn);
    return 0;
}

int libxl__build_hvm(libxl_ctx *ctx, uint32_t domid,
              libxl_domain_build_info *info, libxl_domain_build_state *state)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    int ret, rc = ERROR_INVAL;

    if (info->kernel.mapped) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "libxl__build_hvm kernel cannot be mmapped");
        goto out;
    }

    rc = ERROR_FAIL;
    ret = xc_hvm_build_target_mem(
        ctx->xch,
        domid,
        (info->max_memkb - info->video_memkb) / 1024,
        (info->target_memkb - info->video_memkb) / 1024,
        libxl__abs_path(&gc, (char *)info->kernel.path,
                       libxl_xenfirmwaredir_path()));
    if (ret) {
        LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, ret, "hvm building failed");
        goto out;
    }
    ret = hvm_build_set_params(ctx->xch, domid, info, state->store_port,
                               &state->store_mfn, state->console_port, &state->console_mfn);
    if (ret) {
        LIBXL__LOG_ERRNOVAL(ctx, LIBXL__LOG_ERROR, ret, "hvm build set params failed");
        goto out;
    }
    rc = 0;
out:
    libxl__free_all(&gc);
    return 0;
}

int libxl__domain_restore_common(libxl_ctx *ctx, uint32_t domid,
                   libxl_domain_build_info *info, libxl_domain_build_state *state,
                   int fd)
{
    /* read signature */
    int rc;
    rc = xc_domain_restore(ctx->xch, fd, domid,
                             state->store_port, &state->store_mfn,
                             state->console_port, &state->console_mfn,
                             info->hvm, info->u.hvm.pae, 0);
    if ( rc ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "restoring domain");
        return ERROR_FAIL;
    }
    return 0;
}

struct suspendinfo {
    libxl__gc *gc;
    int xce; /* event channel handle */
    int suspend_eventchn;
    int domid;
    int hvm;
    unsigned int flags;
};

static int libxl__domain_suspend_common_switch_qemu_logdirty(int domid, unsigned int enable, void *data)
{
    struct suspendinfo *si = data;
    libxl_ctx *ctx = libxl__gc_owner(si->gc);
    char *path;
    bool rc;

    path = libxl__sprintf(si->gc, "/local/domain/0/device-model/%u/logdirty/cmd", domid);
    if (!path)
        return 1;

    if (enable)
        rc = xs_write(ctx->xsh, XBT_NULL, path, "enable", strlen("enable"));
    else
        rc = xs_write(ctx->xsh, XBT_NULL, path, "disable", strlen("disable"));

    return rc ? 0 : 1;
}

static int libxl__domain_suspend_common_callback(void *data)
{
    struct suspendinfo *si = data;
    unsigned long s_state = 0;
    int ret;
    char *path, *state = "suspend";
    int watchdog = 60;
    libxl_ctx *ctx = libxl__gc_owner(si->gc);

    if (si->hvm)
        xc_get_hvm_param(ctx->xch, si->domid, HVM_PARAM_ACPI_S_STATE, &s_state);
    if ((s_state == 0) && (si->suspend_eventchn >= 0)) {
        ret = xc_evtchn_notify(si->xce, si->suspend_eventchn);
        if (ret < 0) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "xc_evtchn_notify failed ret=%d", ret);
            return 0;
        }
        ret = xc_await_suspend(ctx->xch, si->xce, si->suspend_eventchn);
        if (ret < 0) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "xc_await_suspend failed ret=%d", ret);
            return 0;
        }
        return 1;
    }
    path = libxl__sprintf(si->gc, "%s/control/shutdown", libxl__xs_get_dompath(si->gc, si->domid));
    libxl__xs_write(si->gc, XBT_NULL, path, "suspend");
    if (si->hvm) {
        unsigned long hvm_pvdrv, hvm_s_state;
        xc_get_hvm_param(ctx->xch, si->domid, HVM_PARAM_CALLBACK_IRQ, &hvm_pvdrv);
        xc_get_hvm_param(ctx->xch, si->domid, HVM_PARAM_ACPI_S_STATE, &hvm_s_state);
        if (!hvm_pvdrv || hvm_s_state) {
            LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Calling xc_domain_shutdown on the domain");
            xc_domain_shutdown(ctx->xch, si->domid, SHUTDOWN_suspend);
        }
    }
    LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "wait for the guest to suspend");
    while (!strcmp(state, "suspend") && watchdog > 0) {
        xc_domaininfo_t info;

        usleep(100000);
        ret = xc_domain_getinfolist(ctx->xch, si->domid, 1, &info);
        if (ret == 1 && info.domain == si->domid && info.flags & XEN_DOMINF_shutdown) {
            int shutdown_reason;

            shutdown_reason = (info.flags >> XEN_DOMINF_shutdownshift) & XEN_DOMINF_shutdownmask;
            if (shutdown_reason == SHUTDOWN_suspend)
                return 1;
        }
        state = libxl__xs_read(si->gc, XBT_NULL, path);
        watchdog--;
    }
    if (!strcmp(state, "suspend")) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "guest didn't suspend in time");
        libxl__xs_write(si->gc, XBT_NULL, path, "");
    }
    return 1;
}

int libxl__domain_suspend_common(libxl_ctx *ctx, uint32_t domid, int fd,
		int hvm, int live, int debug)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    int flags;
    int port;
    struct save_callbacks callbacks;
    struct suspendinfo si;
    int rc = ERROR_FAIL;

    flags = (live) ? XCFLAGS_LIVE : 0
          | (debug) ? XCFLAGS_DEBUG : 0
          | (hvm) ? XCFLAGS_HVM : 0;

    si.domid = domid;
    si.flags = flags;
    si.hvm = hvm;
    si.gc = &gc;
    si.suspend_eventchn = -1;

    si.xce = xc_evtchn_open();
    if (si.xce < 0)
        goto out;

    if (si.xce > 0) {
        port = xs_suspend_evtchn_port(si.domid);

        if (port >= 0) {
            si.suspend_eventchn = xc_suspend_evtchn_init(ctx->xch, si.xce, si.domid, port);

            if (si.suspend_eventchn < 0)
                LIBXL__LOG(ctx, LIBXL__LOG_WARNING, "Suspend event channel initialization failed");
        }
    }

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.suspend = libxl__domain_suspend_common_callback;
    callbacks.switch_qemu_logdirty = libxl__domain_suspend_common_switch_qemu_logdirty;
    callbacks.data = &si;

    rc = xc_domain_save(ctx->xch, fd, domid, 0, 0, flags, &callbacks, hvm);
    if ( rc ) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "saving domain");
        rc = ERROR_FAIL;
    }

    if (si.suspend_eventchn > 0)
        xc_suspend_evtchn_release(ctx->xch, si.xce, domid, si.suspend_eventchn);
    if (si.xce > 0)
        xc_evtchn_close(si.xce);

out:
    libxl__free_all(&gc);
    return rc;
}

int libxl__domain_save_device_model(libxl_ctx *ctx, uint32_t domid, int fd)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    int fd2, c;
    char buf[1024];
    char *filename = libxl__sprintf(&gc, "/var/lib/xen/qemu-save.%d", domid);
    struct stat st;
    uint32_t qemu_state_len;

    LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Saving device model state to %s", filename);
    libxl__xs_write(&gc, XBT_NULL, libxl__sprintf(&gc, "/local/domain/0/device-model/%d/command", domid), "save");
    libxl__wait_for_device_model(ctx, domid, "paused", NULL, NULL);

    if (stat(filename, &st) < 0)
    {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Unable to stat qemu save file\n");
        return ERROR_FAIL;
    }

    qemu_state_len = st.st_size;
    LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Qemu state is %d bytes\n", qemu_state_len);

    c = libxl_write_exactly(ctx, fd, QEMU_SIGNATURE, strlen(QEMU_SIGNATURE),
                            "saved-state file", "qemu signature");
    if (c)
        return c;

    c = libxl_write_exactly(ctx, fd, &qemu_state_len, sizeof(qemu_state_len),
                            "saved-state file", "saved-state length");
    if (c)
        return c;

    fd2 = open(filename, O_RDONLY);
    while ((c = read(fd2, buf, sizeof(buf))) != 0) {
        if (c < 0) {
            if (errno == EINTR)
                continue;
            libxl__free_all(&gc);
            return errno;
        }
        c = libxl_write_exactly(
            ctx, fd, buf, c, "saved-state file", "qemu state");
        if (c) {
            libxl__free_all(&gc);
            return c;
        }
    }
    close(fd2);
    unlink(filename);
    libxl__free_all(&gc);
    return 0;
}

char *libxl__uuid2string(libxl__gc *gc, const libxl_uuid uuid)
{
    char *s = libxl__sprintf(gc, LIBXL_UUID_FMT, LIBXL_UUID_BYTES(uuid));
    if (!s)
        LIBXL__LOG(libxl__gc_owner(gc), LIBXL__LOG_ERROR, "cannot allocate for uuid");
    return s;
}

static const char *userdata_path(libxl__gc *gc, uint32_t domid,
                                      const char *userdata_userid,
                                      const char *wh)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *path, *uuid_string;
    libxl_dominfo info;
    int rc;

    rc = libxl_domain_info(ctx, &info, domid);
    if (rc) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "unable to find domain info"
                     " for domain %"PRIu32, domid);
        return NULL;
    }
    uuid_string = libxl__sprintf(gc, LIBXL_UUID_FMT, LIBXL_UUID_BYTES(info.uuid));

    path = libxl__sprintf(gc, "/var/lib/xen/"
                         "userdata-%s.%u.%s.%s",
                         wh, domid, uuid_string, userdata_userid);
    if (!path)
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "unable to allocate for"
                     " userdata path");
    return path;
}

static int userdata_delete(libxl_ctx *ctx, const char *path) {
    int r;
    r = unlink(path);
    if (r) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "remove failed for %s", path);
        return errno;
    }
    return 0;
}

void libxl__userdata_destroyall(libxl_ctx *ctx, uint32_t domid)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    const char *pattern;
    glob_t gl;
    int r, i;

    pattern = userdata_path(&gc, domid, "*", "?");
    if (!pattern)
        goto out;

    gl.gl_pathc = 0;
    gl.gl_pathv = 0;
    gl.gl_offs = 0;
    r = glob(pattern, GLOB_ERR|GLOB_NOSORT|GLOB_MARK, 0, &gl);
    if (r == GLOB_NOMATCH)
        goto out;
    if (r)
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "glob failed for %s", pattern);

    for (i=0; i<gl.gl_pathc; i++) {
        userdata_delete(ctx, gl.gl_pathv[i]);
    }
    globfree(&gl);
out:
    libxl__free_all(&gc);
}

int libxl_userdata_store(libxl_ctx *ctx, uint32_t domid,
                              const char *userdata_userid,
                              const uint8_t *data, int datalen)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    const char *filename;
    const char *newfilename;
    int e, rc;
    int fd = -1;
    FILE *f = NULL;
    size_t rs;

    filename = userdata_path(&gc, domid, userdata_userid, "d");
    if (!filename) {
        rc = ERROR_NOMEM;
        goto out;
    }

    if (!datalen) {
        rc = userdata_delete(ctx, filename);
        goto out;
    }

    newfilename = userdata_path(&gc, domid, userdata_userid, "n");
    if (!newfilename) {
        rc = ERROR_NOMEM;
        goto out;
    }

    rc = ERROR_FAIL;

    fd= open(newfilename, O_RDWR|O_CREAT|O_TRUNC, 0600);
    if (fd<0)
        goto err;

    f= fdopen(fd, "wb");
    if (!f)
        goto err;
    fd = -1;

    rs = fwrite(data, 1, datalen, f);
    if (rs != datalen) {
        assert(ferror(f));
        goto err;
    }

    if (fclose(f))
        goto err;
    f = 0;

    if (rename(newfilename,filename))
        goto err;

    rc = 0;

err:
    e = errno;
    if (f) fclose(f);
    if (fd>=0) close(fd);

    errno = e;
    if ( rc )
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "cannot write %s for %s",
                 newfilename, filename);
out:
    libxl__free_all(&gc);
    return rc;
}

int libxl_userdata_retrieve(libxl_ctx *ctx, uint32_t domid,
                                 const char *userdata_userid,
                                 uint8_t **data_r, int *datalen_r)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    const char *filename;
    int e, rc;
    int datalen = 0;
    void *data = 0;

    filename = userdata_path(&gc, domid, userdata_userid, "d");
    if (!filename) {
        rc = ERROR_NOMEM;
        goto out;
    }

    e = libxl_read_file_contents(ctx, filename, data_r ? &data : 0, &datalen);

    if (!e && !datalen) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "userdata file %s is empty", filename);
        if (data_r) assert(!*data_r);
        rc = ERROR_FAIL;
        goto out;
    }

    if (data_r) *data_r = data;
    if (datalen_r) *datalen_r = datalen;
    rc = 0;
out:
    libxl__free_all(&gc);
    return rc;
}
