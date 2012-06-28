/*
 * Copyright (C) 2012      Citrix Ltd.
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

void libxl__xc_domain_restore(libxl__egc *egc, libxl__domain_create_state *dcs,
                              int hvm, int pae, int superpages,
                              int no_incr_generationid)
{
    STATE_AO_GC(dcs->ao);

    /* Convenience aliases */
    const uint32_t domid = dcs->guest_domid;
    const int restore_fd = dcs->restore_fd;
    libxl__domain_build_state *const state = &dcs->build_state;

    int r = xc_domain_restore(CTX->xch, restore_fd, domid,
                              state->store_port, &state->store_mfn,
                              state->store_domid, state->console_port,
                              &state->console_mfn, state->console_domid,
                              hvm, pae, superpages, no_incr_generationid,
                              &state->vm_generationid_addr, &dcs->callbacks);
    libxl__xc_domain_restore_done(egc, dcs, 0, r, errno);
}

void libxl__xc_domain_save(libxl__egc *egc, libxl__domain_suspend_state *dss,
                           unsigned long vm_generationid_addr)
{
    STATE_AO_GC(dss->ao);
    int r;

    r = xc_domain_save(CTX->xch, dss->fd, dss->domid, 0, 0, dss->xcflags,
                       &dss->callbacks, dss->hvm, vm_generationid_addr);
    libxl__xc_domain_save_done(egc, dss, 0, r, errno);
}
