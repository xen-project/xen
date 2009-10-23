/*
 *
 *  Authors:  Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *            George Coker, <gscoker@alpha.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#ifndef __FLASK_H__
#define __FLASK_H__

#include <stdint.h>
#include <xen/xen.h>
#include <xen/xsm/flask_op.h>

int flask_load(int xc_handle, char *buf, uint32_t size);
int flask_context_to_sid(int xc_handle, char *buf, uint32_t size, uint32_t *sid);
int flask_sid_to_context(int xc_handle, int sid, char *buf, uint32_t size);
int flask_getenforce(int xc_handle);
int flask_setenforce(int xc_handle, int mode);

#endif /* __FLASK_H__ */
