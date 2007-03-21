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
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (c) 2006, 2007 XenSource Inc.
#============================================================================

from xmlrpclib import Fault

import XendClient

class XendInvalidDomain(Fault):
    def __init__(self, value):
        Fault.__init__(self, XendClient.ERROR_INVALID_DOMAIN, value)

class XendError(Fault):
    
    def __init__(self, value):
        Fault.__init__(self, XendClient.ERROR_GENERIC, value)
        self.value = value

    def __str__(self):
        return self.value

class VMBadState(XendError):
    def __init__(self, value, expected, actual):
        XendError.__init__(self, value)
        self.expected = expected
        self.actual = actual

class NetworkAlreadyConnected(XendError):
    def __init__(self, pif_uuid):
        XendError.__init__(self, 'Network already connected')
        self.pif_uuid = pif_uuid

class PIFIsPhysical(XendError):
    def __init__(self):
        XendError.__init__(self, 'PIF is physical')

class VLANTagInvalid(XendError):
    def __init__(self):
        XendError.__init__(self, 'VLAN tag invalid')

class VmError(XendError):
    """Vm construction error."""
    pass

class HVMRequired(VmError):
    def __init__(self):
        XendError.__init__(self,
                           'HVM guest support is unavailable: is VT/AMD-V '
                           'supported by your CPU and enabled in your BIOS?')


XEND_ERROR_AUTHENTICATION_FAILED = ('ELUSER', 'Authentication Failed')
XEND_ERROR_SESSION_INVALID       = ('EPERMDENIED', 'Session Invalid')
XEND_ERROR_DOMAIN_INVALID        = ('EINVALIDDOMAIN', 'Domain Invalid')
XEND_ERROR_HOST_INVALID          = ('EINVALIDHOST', 'Host Invalid')
XEND_ERROR_HOST_RUNNING          = ('EHOSTRUNNING', 'Host is still Running')
XEND_ERROR_HOST_CPU_INVALID      = ('EHOSTCPUINVALID', 'Host CPU Invalid')
XEND_ERROR_UNSUPPORTED           = ('EUNSUPPORTED', 'Method Unsupported')
XEND_ERROR_VM_INVALID            = ('EVMINVALID', 'VM Invalid')
XEND_ERROR_VBD_INVALID           = ('EVBDINVALID', 'VBD Invalid')
XEND_ERROR_VIF_INVALID           = ('EVIFINVALID', 'VIF Invalid')
XEND_ERROR_VTPM_INVALID          = ('EVTPMINVALID', 'VTPM Invalid')
XEND_ERROR_VDI_INVALID           = ('EVDIINVALID', 'VDI Invalid')
XEND_ERROR_SR_INVALID           = ('ESRINVALID', 'SR Invalid')
XEND_ERROR_TODO                  = ('ETODO', 'Lazy Programmer Error')
