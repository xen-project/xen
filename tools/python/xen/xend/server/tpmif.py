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
# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 IBM Corporation
#   Author: Stefan Berger, stefanb@us.ibm.com
# Copyright (C) 2005 XenSource Ltd
#============================================================================

"""Support for virtual TPM interfaces.
"""

from xen.xend import sxp
from xen.xend.XendLogging import log

from xen.xend.server.DevController import DevController


class TPMifController(DevController):
    """TPM interface controller. Handles all TPM devices for a domain.
    """

    def __init__(self, vm):
        DevController.__init__(self, vm)


    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""

        devid = int(sxp.child_value(config, 'instance', '0'))
        log.info("The domain has a TPM with instance %d." % devid)

        back  = { 'instance' : "%i" % devid }
        front = { 'handle' : "%i" % devid }

        return (devid, back, front)

    def configuration(self, devid):

        result = DevController.configuration(self, devid)

        (instance,) = self.readBackend(devid, 'instance')

        if instance:
            result.append(['instance', instance])
            log.info("configuration: instance=%d." % instance)

        return result
