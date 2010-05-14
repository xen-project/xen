/*
 * Author Yang Hongyang <yanghy@cn.fujitsu.com>
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

#ifndef XL_CMDTABLE_H
#define XL_CMDTABLE_H

#include "xl_cmdimpl.h"

struct cmd_spec {
    char *cmd_name;
    int (*cmd_impl)(int argc, char **argv);
    char *cmd_desc;
    char *cmd_usage;
    char *cmd_option;
};

extern struct cmd_spec cmd_table[];
extern int cmdtable_len;

#endif /* XL_CMDTABLE_H */
