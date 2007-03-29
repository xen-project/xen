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
# Copyright (C) 2006 XenSource Ltd.
#============================================================================

from xen.xend.XendAPIConstants import *

#
# Shutdown codes and reasons.
#

DOMAIN_POWEROFF = 0 
DOMAIN_REBOOT   = 1
DOMAIN_SUSPEND  = 2
DOMAIN_CRASH    = 3
DOMAIN_HALT     = 4

DOMAIN_SHUTDOWN_REASONS = {
    DOMAIN_POWEROFF: "poweroff",
    DOMAIN_REBOOT  : "reboot",
    DOMAIN_SUSPEND : "suspend",
    DOMAIN_CRASH   : "crash",
    DOMAIN_HALT    : "halt"
}
REVERSE_DOMAIN_SHUTDOWN_REASONS = \
    dict([(y, x) for x, y in DOMAIN_SHUTDOWN_REASONS.items()])

HVM_PARAM_CALLBACK_IRQ = 0
HVM_PARAM_STORE_PFN    = 1
HVM_PARAM_STORE_EVTCHN = 2
HVM_PARAM_PAE_ENABLED  = 4
HVM_PARAM_IOREQ_PFN    = 5
HVM_PARAM_BUFIOREQ_PFN = 6

restart_modes = [
    "restart",
    "destroy",
    "preserve",
    "rename-restart"
    ]

DOM_STATES = [
    'halted',
    'paused',
    'running',
    'suspended',
    'shutdown',
    'unknown',
]

DOM_STATE_HALTED = XEN_API_VM_POWER_STATE_HALTED
DOM_STATE_PAUSED = XEN_API_VM_POWER_STATE_PAUSED
DOM_STATE_RUNNING = XEN_API_VM_POWER_STATE_RUNNING
DOM_STATE_SUSPENDED = XEN_API_VM_POWER_STATE_SUSPENDED
DOM_STATE_SHUTDOWN = XEN_API_VM_POWER_STATE_SHUTTINGDOWN
DOM_STATE_UNKNOWN = XEN_API_VM_POWER_STATE_UNKNOWN

DOM_STATES_OLD = [
    'running',
    'blocked',
    'paused',
    'shutdown',
    'crashed',
    'dying'
    ]

STATE_DOM_OK       = 1
STATE_DOM_SHUTDOWN = 2

SHUTDOWN_TIMEOUT = 30.0

ZOMBIE_PREFIX = 'Zombie-'

"""Minimum time between domain restarts in seconds."""
MINIMUM_RESTART_TIME = 20

RESTART_IN_PROGRESS = 'xend/restart_in_progress'
LAST_SHUTDOWN_REASON = 'xend/last_shutdown_reason'

TRIGGER_NMI   = 0
TRIGGER_RESET = 1
TRIGGER_INIT  = 2

TRIGGER_TYPE = {
    "nmi"   : TRIGGER_NMI,
    "reset" : TRIGGER_RESET,
    "init"  : TRIGGER_INIT
}

#
# Device migration stages (eg. XendDomainInfo, XendCheckpoint, server.tpmif)
#

DEV_MIGRATE_TEST  = 0
DEV_MIGRATE_STEP1 = 1
DEV_MIGRATE_STEP2 = 2
DEV_MIGRATE_STEP3 = 3

#
# VTPM-related constants
#

VTPM_DELETE_SCRIPT = '/etc/xen/scripts/vtpm-delete'

#
# Xenstore Constants
#

XS_VMROOT = "/vm/"

