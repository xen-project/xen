#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2006-2007 XenSource Ltd.
#============================================================================

#
# Xen API Enums
#

XEN_API_VM_POWER_STATE = [
    'Halted',
    'Paused',
    'Running',
    'Suspended',
    'Halted',
    'Unknown'
]

XEN_API_VM_POWER_STATE_HALTED = 0
XEN_API_VM_POWER_STATE_PAUSED = 1
XEN_API_VM_POWER_STATE_RUNNING = 2
XEN_API_VM_POWER_STATE_SUSPENDED = 3
XEN_API_VM_POWER_STATE_SHUTTINGDOWN = 4
XEN_API_VM_POWER_STATE_UNKNOWN = 5

XEN_API_ON_NORMAL_EXIT = [
    'destroy',
    'restart',
]

XEN_API_ON_CRASH_BEHAVIOUR = [
    'destroy',
    'coredump_and_destroy',
    'restart',
    'coredump_and_restart',
    'preserve',
    'rename_restart'
]

XEN_API_VBD_MODE = ['RO', 'RW']
XEN_API_VDI_TYPE = ['system', 'user', 'ephemeral']
XEN_API_VBD_TYPE = ['CD', 'Disk']
XEN_API_TASK_STATUS_TYPE = ['pending', 'success', 'failure']
XEN_API_CONSOLE_PROTOCOL = ['vt100', 'rfb', 'rdp']
