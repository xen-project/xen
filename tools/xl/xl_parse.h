/*
 * Copyright 2009-2017 Citrix Ltd and other contributors
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

#ifndef XL_PARSE_H
#define XL_PARSE_H

#include <libxl.h>

void parse_config_data(const char *config_source,
                       const char *config_data,
                       int config_len,
                       libxl_domain_config *d_config);
int parse_range(const char *str, unsigned long *a, unsigned long *b);
int64_t parse_mem_size_kb(const char *mem);
void parse_disk_config(XLU_Config **config, const char *spec,
                       libxl_device_disk *disk);

void parse_disk_config_multistring(XLU_Config **config,
                                   int nspecs, const char *const *specs,
                                   libxl_device_disk *disk);
int parse_usbctrl_config(libxl_device_usbctrl *usbctrl, char *token);
int parse_usbdev_config(libxl_device_usbdev *usbdev, char *token);
int parse_cpurange(const char *cpu, libxl_bitmap *cpumap);
int parse_nic_config(libxl_device_nic *nic, XLU_Config **config, char *token);
int parse_vdispl_config(libxl_device_vdispl *vdispl, char *token);

int match_option_size(const char *prefix, size_t len,
                      char *arg, char **argopt);
#define MATCH_OPTION(prefix, arg, oparg) \
    match_option_size((prefix "="), sizeof((prefix)), (arg), &(oparg))


void split_string_into_string_list(const char *str, const char *delim,
                                   libxl_string_list *psl);
int split_string_into_pair(const char *str, const char *delim,
                           char **a, char **b);
void replace_string(char **str, const char *val);

/* NB: this follows the interface used by <ctype.h>. See 'man 3 ctype'
   and look for CTYPE in libxl_internal.h */
typedef int (*char_predicate_t)(const int c);
void trim(char_predicate_t predicate, const char *input, char **output);

const char *get_action_on_shutdown_name(libxl_action_on_shutdown a);

#endif	/* XL_PARSE_H */

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
