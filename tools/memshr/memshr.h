/******************************************************************************
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Grzegorz Milos)
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef __MEMSHR_H__
#define __MEMSHR_H__

#include <stdint.h>
#include <xen/xen.h>
#include <xen/grant_table.h>

typedef uint64_t xen_mfn_t;

typedef struct share_tuple 
{
    uint32_t domain;
    uint64_t frame;
    uint64_t handle;
} share_tuple_t;

extern void memshr_set_domid(int domid);
extern void memshr_daemon_initialize(void);
extern void memshr_vbd_initialize(void);
extern uint16_t memshr_vbd_image_get(const char* file);
extern void memshr_vbd_image_put(uint16_t memshr_id);
extern int memshr_vbd_issue_ro_request(char *buf,
                                       grant_ref_t gref,
                                       uint16_t file_id, 
                                       uint64_t sec, 
                                       int secs,
                                       share_tuple_t *hnd);
extern void memshr_vbd_complete_ro_request(
                                       share_tuple_t hnd,
                                       uint16_t file_id, 
                                       uint64_t sec, 
                                       int secs);

#endif /* __MEMSHR_H__ */
