/******************************************************************************
 * xc_cpu_hotplug.c - Libxc API for Xen Physical CPU hotplug Management
 *
 * Copyright (c) 2008, Shan Haitao <haitao.shan@intel.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "xc_private.h"

int xc_cpu_online(xc_interface *xch, int cpu)
{
    DECLARE_SYSCTL;
    int ret;

    sysctl.cmd = XEN_SYSCTL_cpu_hotplug;
    sysctl.u.cpu_hotplug.cpu = cpu;
    sysctl.u.cpu_hotplug.op = XEN_SYSCTL_CPU_HOTPLUG_ONLINE;
    ret = xc_sysctl(xch, &sysctl);

    return ret;
}

int xc_cpu_offline(xc_interface *xch, int cpu)
{
    DECLARE_SYSCTL;
    int ret;

    sysctl.cmd = XEN_SYSCTL_cpu_hotplug;
    sysctl.u.cpu_hotplug.cpu = cpu;
    sysctl.u.cpu_hotplug.op = XEN_SYSCTL_CPU_HOTPLUG_OFFLINE;
    ret = xc_sysctl(xch, &sysctl);

    return ret;
}

