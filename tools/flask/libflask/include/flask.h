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
int flask_add_pirq(int xc_handle, unsigned int pirq, char *scontext);
int flask_add_ioport(int xc_handle, unsigned long low, unsigned long high,
                      char *scontext);
int flask_add_iomem(int xc_handle, unsigned long low, unsigned long high,
                     char *scontext);
int flask_add_device(int xc_handle, unsigned long device, char *scontext);
int flask_del_pirq(int xc_handle, unsigned int pirq);
int flask_del_ioport(int xc_handle, unsigned long low, unsigned long high);
int flask_del_iomem(int xc_handle, unsigned long low, unsigned long high);
int flask_del_device(int xc_handle, unsigned long device);
#define flask_add_single_ioport(x, l, s) flask_add_ioport(x, l, l, s)
#define flask_add_single_iomem(x, l, s) flask_add_iomem(x, l, l, s)
#define flask_del_single_ioport(x, l) flask_del_ioport(x, l, l)
#define flask_del_single_iomem(x, l) flask_del_iomem(x, l, l);

#define OCON_PIRQ_STR   "pirq"
#define OCON_IOPORT_STR "ioport"
#define OCON_IOMEM_STR  "iomem"
#define OCON_DEVICE_STR "pcidevice"
#define INITCONTEXTLEN  256
#endif /* __FLASK_H__ */
