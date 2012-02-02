/*
 *
 *  Authors:  Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *            George Coker, <gscoker@alpha.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#ifndef __LIBFLASK_H__
#define __LIBFLASK_H__

#include <stdint.h>
#include <xen/xen.h>
#include <xen/xsm/flask_op.h>
#include <xenctrl.h>

int flask_load(xc_interface *xc_handle, char *buf, uint32_t size);
int flask_context_to_sid(xc_interface *xc_handle, char *buf, uint32_t size, uint32_t *sid);
int flask_sid_to_context(xc_interface *xc_handle, int sid, char *buf, uint32_t size);
int flask_getenforce(xc_interface *xc_handle);
int flask_setenforce(xc_interface *xc_handle, int mode);
int flask_getbool_byid(xc_interface *xc_handle, int id, char *name, int *curr, int *pend);
int flask_getbool_byname(xc_interface *xc_handle, char *name, int *curr, int *pend);
int flask_setbool(xc_interface *xc_handle, char *name, int value, int commit);
int flask_add_pirq(xc_interface *xc_handle, unsigned int pirq, char *scontext);
int flask_add_ioport(xc_interface *xc_handle, unsigned long low, unsigned long high,
                      char *scontext);
int flask_add_iomem(xc_interface *xc_handle, unsigned long low, unsigned long high,
                     char *scontext);
int flask_add_device(xc_interface *xc_handle, unsigned long device, char *scontext);
int flask_del_pirq(xc_interface *xc_handle, unsigned int pirq);
int flask_del_ioport(xc_interface *xc_handle, unsigned long low, unsigned long high);
int flask_del_iomem(xc_interface *xc_handle, unsigned long low, unsigned long high);
int flask_del_device(xc_interface *xc_handle, unsigned long device);
int flask_access(xc_interface *xc_handle, const char *scon, const char *tcon,
                  u_int16_t tclass, u_int32_t req,
                  u_int32_t *allowed, u_int32_t *decided,
                  u_int32_t *auditallow, u_int32_t *auditdeny,
                  u_int32_t *seqno);
int flask_avc_cachestats(xc_interface *xc_handle, char *buf, int size);
int flask_policyvers(xc_interface *xc_handle, char *buf, int size);
int flask_avc_hashstats(xc_interface *xc_handle, char *buf, int size);
int flask_getavc_threshold(xc_interface *xc_handle);
int flask_setavc_threshold(xc_interface *xc_handle, int threshold);
#define flask_add_single_ioport(x, l, s) flask_add_ioport(x, l, l, s)
#define flask_add_single_iomem(x, l, s) flask_add_iomem(x, l, l, s)
#define flask_del_single_ioport(x, l) flask_del_ioport(x, l, l)
#define flask_del_single_iomem(x, l) flask_del_iomem(x, l, l);

#define OCON_PIRQ_STR   "pirq"
#define OCON_IOPORT_STR "ioport"
#define OCON_IOMEM_STR  "iomem"
#define OCON_DEVICE_STR "pcidevice"
#define INITCONTEXTLEN  256
#endif /* __LIBFLASK_H__ */
