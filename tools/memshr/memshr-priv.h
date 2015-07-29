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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __MEMSHR_PRIV_H__
#define __MEMSHR_PRIV_H__

#include <syslog.h>
#include <xenctrl.h>
#include "memshr.h"

#if 1
#define DPRINTF(_f, _a...) syslog(LOG_INFO, _f, ##_a)
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

#define EPRINTF(_f, _a...) syslog(LOG_ERR, "memshr:%s: " _f, __func__, ##_a)

#endif /* __MEMSHR_PRIV_H__ */
