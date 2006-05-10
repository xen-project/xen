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
from xen.xend.XendError import XendError
from xen.xend import XendRoot
from xen.xend.XendDomainInfo import DEV_MIGRATE_TEST

from xen.xend.server.DevController import DevController

import os
import re


xroot = XendRoot.instance()


class TPMifController(DevController):
    """TPM interface controller. Handles all TPM devices for a domain.
    """

    def __init__(self, vm):
        DevController.__init__(self, vm)


    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""

        devid = self.allocateDeviceID()
        inst = int(sxp.child_value(config, 'pref_instance', '-1'))
        if inst == -1:
            inst = int(sxp.child_value(config, 'instance' , '0'))

        log.info("The domain has a TPM with instance %d and devid %d.",
                 inst, devid)
        back  = { 'pref_instance' : "%i" % inst,
                  'resume'        : "%s" % (self.vm.getResume()) }
        front = { 'handle' : "%i" % devid }

        return (devid, back, front)

    def configuration(self, devid):

        result = DevController.configuration(self, devid)

        instance = self.readBackend(devid, 'instance')

        if instance:
            result.append(['instance', instance])

        return result

    def migrate(self, deviceConfig, network, dst, step, domName):
        """@see DevContoller.migrate"""
        if network:
            tool = xroot.get_external_migration_tool()
            if tool != '':
                log.info("Request to network-migrate device to %s. step=%d.",
                         dst, step)

                if step == DEV_MIGRATE_TEST:
                    """Assuming for now that everything is ok and migration
                       with the given tool can proceed.
                    """
                    return 0
                else:
                    fd = os.popen("%s -type vtpm -step %d -host %s -domname %s" %
                                  (tool, step, dst, domName),
                                  'r')
                    for line in fd.readlines():
                        mo = re.search('Error', line)
                        if mo:
                            raise XendError("vtpm: Fatal error in migration step %d: %s" %
                                            (step, line))
                    return 0
            else:
                log.debug("External migration tool not in configuration.")
                return -1
        return 0

    def recover_migrate(self, deviceConfig, network, dst, step, domName):
        """@see DevContoller.recover_migrate"""
        if network:
            tool = xroot.get_external_migration_tool()
            if tool != '':
                log.info("Request to recover network-migrated device. last good step=%d.",
                         step)
                fd = os.popen("%s -type vtpm -step %d -host %s -domname %s -recover" %
                              (tool, step, dst, domName),
                              'r')
        return 0
