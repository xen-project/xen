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

#ifndef LIBXLU_INTERNAL_H
#define LIBXLU_INTERNAL_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <regex.h>

#define XLU_ConfigList XLU_ConfigSetting

#include "libxlutil.h"

struct XLU_ConfigSetting { /* transparent */
    struct XLU_ConfigSetting *next;
    char *name;
    int nvalues, avalues; /* lists have avalues>1 */
    char **values;
    int lineno;
};

struct XLU_Config {
    XLU_ConfigSetting *settings;
    FILE *report;
    char *config_source;
};

typedef struct {
    XLU_Config *cfg;
    int err, lexerrlineno, likely_python;
    void *scanner;
} CfgParseContext;


#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#endif /*LIBXLU_INTERNAL_H*/

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
