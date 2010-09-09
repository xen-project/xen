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

/* Unless otherwise stated, all functions return an errno value. */
typedef struct XLU_Config XLU_Config;
typedef struct XLU_ConfigList XLU_ConfigList;

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
 *   EINVAL   value found but wrong format for request (prints warning)
 *   ERANGE   value out of range (from strtol)
 */

int xlu_cfg_get_string(const XLU_Config*, const char *n, const char **value_r);
int xlu_cfg_replace_string(const XLU_Config *cfg, const char *n, char **value_r); /* free/strdup version */
int xlu_cfg_get_long(const XLU_Config*, const char *n, long *value_r);

int xlu_cfg_get_list(const XLU_Config*, const char *n,
                     XLU_ConfigList **list_r /* may be 0 */,
                     int *entries_r /* may be 0 */);
  /* there is no need to free *list_r; lifetime is that of the XLU_Config */
const char *xlu_cfg_get_listitem(const XLU_ConfigList*, int entry);
  /* xlu_cfg_get_listitem cannot fail, except that if entry is
   * out of range it returns 0 (not setting errno) */

#endif /* LIBXLUTIL_H */
