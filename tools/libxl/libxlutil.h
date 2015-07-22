/*
 * Copyright (C) 2010      Citrix Ltd.
 * Author Ian Jackson <ian.jackson@eu.citrix.com>
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

#ifndef LIBXLUTIL_H
#define LIBXLUTIL_H

#include <stdio.h>

#include "libxl.h"

enum XLU_ConfigValueType {
    XLU_STRING,
    XLU_LIST,
};

/* Unless otherwise stated, all functions return an errno value. */
typedef struct XLU_Config XLU_Config;
typedef struct XLU_ConfigList XLU_ConfigList;
typedef struct XLU_ConfigValue XLU_ConfigValue;

XLU_Config *xlu_cfg_init(FILE *report, const char *report_filename);
  /* 0 means we got ENOMEM. */
  /* report_filename is copied; report is saved and must remain valid
   *  until the Config is destroyed. */

int xlu_cfg_readfile(XLU_Config*, const char *real_filename);
int xlu_cfg_readdata(XLU_Config*, const char *data, int length);
  /* If these fail, then it is undefined behaviour to call xlu_cfg_get_...
   * functions.  You have to just xlu_cfg_destroy. */

void xlu_cfg_destroy(XLU_Config*);


/* All of the following print warnings to "report" if there is a problem.
 * Return values are:
 *   0        OK
 *   ESRCH    not defined
 *   EINVAL   value found but wrong format for request (prints warning unless dont_warn=true)
 *   ERANGE   value out of range (from strtol)
 */

int xlu_cfg_get_string(const XLU_Config*, const char *n, const char **value_r,
                       int dont_warn);
/* free/strdup version */
int xlu_cfg_replace_string(const XLU_Config *cfg, const char *n,
                           char **value_r, int dont_warn);
int xlu_cfg_get_long(const XLU_Config*, const char *n, long *value_r,
                     int dont_warn);
int xlu_cfg_get_defbool(const XLU_Config*, const char *n, libxl_defbool *b,
                     int dont_warn);

int xlu_cfg_get_list(const XLU_Config*, const char *n,
                     XLU_ConfigList **list_r /* may be 0 */,
                     int *entries_r /* may be 0 */,
                     int dont_warn);
  /* there is no need to free *list_r; lifetime is that of the XLU_Config */
int xlu_cfg_get_list_as_string_list(const XLU_Config *cfg, const char *n,
                                    libxl_string_list *sl, int dont_warn);
const char *xlu_cfg_get_listitem(const XLU_ConfigList*, int entry);
  /* xlu_cfg_get_listitem cannot fail, except that if entry is
   * out of range it returns 0 (not setting errno) */

enum XLU_ConfigValueType xlu_cfg_value_type(const XLU_ConfigValue *value);
int xlu_cfg_value_get_string(const XLU_Config *cfg,  XLU_ConfigValue *value,
                             char **value_r, int dont_warn);
int xlu_cfg_value_get_list(const XLU_Config *cfg, XLU_ConfigValue *value,
                           XLU_ConfigList **value_r, int dont_warn);
XLU_ConfigValue *xlu_cfg_get_listitem2(const XLU_ConfigList *list,
                                       int entry);

/*
 * Disk specification parsing.
 */

int xlu_disk_parse(XLU_Config *cfg, int nspecs, const char *const *specs,
                   libxl_device_disk *disk);
  /* disk must have been initialised.
   *
   * On error, returns errno value.  Bad strings cause EINVAL and
   * print a message to cfg's report (that's all cfg is used for).
   *
   * Normally one would pass nspecs==1 and only specs[0].  But it is
   * permitted to pass more strings in which case each is parsed as a
   * string containing a collection of parameters (but they all refer
   * to of the configuration for a single disk).
   *
   * nspecs==0 is permitted but since it does not specify some mandatory
   * properties, it produces a run-time configuration error if the
   * resulting disk struct is used with libxl.
   */

/*
 * PCI specification parsing
 */
int xlu_pci_parse_bdf(XLU_Config *cfg, libxl_device_pci *pcidev, const char *str);

/*
 * RDM parsing
 */
int xlu_rdm_parse(XLU_Config *cfg, libxl_rdm_reserve *rdm, const char *str);

/*
 * Vif rate parsing.
 */

int xlu_vif_parse_rate(XLU_Config *cfg, const char *rate,
                       libxl_device_nic *nic);

#endif /* LIBXLUTIL_H */

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
