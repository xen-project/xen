/*
 * Interface to booleans in the security server. This is exported
 * for the selinuxfs.
 *
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 *
 * Copyright (C) 2003 - 2004 Tresys Technology, LLC
 *    This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, version 2.
 */

#ifndef _FLASK_CONDITIONAL_H_
#define _FLASK_CONDITIONAL_H_

#include <xen/types.h>

int security_get_bools(int *len, char ***names, int **values, size_t *maxstr);

int security_set_bools(int len, int *values);

int security_find_bool(const char *name);

char *security_get_bool_name(unsigned int b);
int security_get_bool_value(unsigned int b);

#endif
