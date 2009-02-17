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
# Copyright (C) 2007 FUJITSU Limited
#                     Based on the blkif.py
#============================================================================


"""Support for VSCSI Devices.
"""
import re
import string

import types

from xen.xend import sxp
from xen.xend.XendError import VmError
from xen.xend.XendLogging import log

from xen.xend.server.DevController import DevController
from xen.xend.server.DevConstants import xenbusState
from xen.xend.xenstore.xstransact import xstransact

class VSCSIController(DevController):
    """VSCSI Devices.
    """
    def __init__(self, vm):
        """Create a VSCSI Devices.
        """
        DevController.__init__(self, vm)


    def sxprs(self):
        """@see DevController.sxprs"""
        devslist = []
        for devid in self.deviceIDs():
            vscsi_devs = self.readBackendList(devid, "vscsi-devs")
            vscsipath = "vscsi-devs/"
            devs = []
            vscsi_config = []
            for dev in vscsi_devs:
                devpath = vscsipath + dev
                backstate = self.readBackend(devid, devpath + '/state')
                pdev = self.readBackend(devid, devpath + '/p-dev')
                pdevname = self.readBackend(devid, devpath + '/p-devname')
                vdev = self.readBackend(devid, devpath + '/v-dev')
                localdevid = self.readBackend(devid, devpath + '/devid')
                frontstate = self.readFrontend(devid, devpath + '/state')
                devs.append(['dev', \
                                    ['state', backstate], \
                                    ['devid', localdevid], \
                                    ['p-dev', pdev], \
                                    ['p-devname', pdevname], \
                                    ['v-dev', vdev], \
                                    ['frontstate', frontstate] ])

            vscsi_config.append(['devs', devs])
            state = self.readFrontend(devid, 'state')
            vscsi_config.append(['state', state])
            hostmode = self.readBackend(devid, 'feature-host')
            vscsi_config.append(['feature-host', hostmode])
            backid = self.readFrontend(devid, 'backend-id')
            vscsi_config.append(['backend-id', backid])
            backpath = self.readFrontend(devid, 'backend')
            vscsi_config.append(['backend', backpath])

            devslist.append([devid, vscsi_config])

        return devslist


    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""
        back = {}
        vscsipath = "vscsi-devs/"
        for vscsi_config in config.get('devs', []):
            localdevid = self.allocateDeviceID()
            # vscsi-devs/dev-0
            devpath = vscsipath + 'dev-%i' % localdevid
            back[devpath] = ""
            pdev = vscsi_config.get('p-dev', '')
            back[devpath + '/p-dev'] = pdev
            pdevname = vscsi_config.get('p-devname', '')
            back[devpath + '/p-devname'] = pdevname
            vdev = vscsi_config.get('v-dev', '')
            back[devpath + '/v-dev'] = vdev
            state = vscsi_config.get('state', xenbusState['Unknown'])
            back[devpath + '/state'] = str(state)
            devid = vscsi_config.get('devid', '')
            back[devpath + '/devid'] = str(devid)

        host_mode = config.get('feature-host','')
        back['feature-host'] = str(host_mode)
        back['uuid'] = config.get('uuid','')
        devid = int(devid)
        return (devid, back, {})


    def readBackendList(self, devid, *args):
        frontpath = self.frontendPath(devid)
        backpath = xstransact.Read(frontpath + "/backend")
        if backpath:
            paths = map(lambda x: backpath + "/" + x, args)
            return xstransact.List(*paths)


    def getDeviceConfiguration(self, devid, transaction = None):
        config = DevController.getDeviceConfiguration(self, devid, transaction)

        vscsi_devs = []

        devs = self.readBackendList(devid, "vscsi-devs")
        vscsipath = "vscsi-devs/"
        for dev in devs:
            devpath = vscsipath + dev
            pdev = self.readBackend(devid, devpath + '/p-dev')
            pdevname = self.readBackend(devid, devpath + '/p-devname')
            vdev = self.readBackend(devid, devpath + '/v-dev')
            state = self.readBackend(devid, devpath + '/state')
            localdevid = self.readBackend(devid, devpath + '/devid')
            dev_dict = {'p-dev': pdev,
                        'p-devname': pdevname,
                        'v-dev': vdev,
                        'state': state,
                        'devid': localdevid }
            vscsi_devs.append(dev_dict)

        config['devs'] = vscsi_devs
        config['feature-host'] = self.readBackend(devid, 'feature-host')
        config['uuid'] = self.readBackend(devid, 'uuid')
        return config


    def configuration(self, devid, transaction = None):
        """Returns SXPR for devices on domain.
        @note: we treat this dict especially to convert to
        SXP because it is not a straight dict of strings."""
        
        configDict = self.getDeviceConfiguration(devid, transaction)
        sxpr = [self.deviceClass]

        # remove devs
        devs = configDict.pop('devs', [])
        
        for dev in devs:
            dev_sxpr = ['dev']
            for dev_item in dev.items():
                dev_sxpr.append(list(dev_item))
            sxpr.append(dev_sxpr)
        
        for key, val in configDict.items():
            if type(val) == type(list()):
                for v in val:
                    sxpr.append([key, v])
            else:
                sxpr.append([key, val])

        return sxpr


    def reconfigureDevice(self, _, config):
        """@see DevController.reconfigureDevice"""
        (devid, back, front) = self.getDeviceDetails(config)
        devid = int(devid)
        vscsi_config = config['devs'][0]
        state = vscsi_config.get('state', xenbusState['Unknown'])
        driver_state = self.readBackend(devid, 'state')

        if str(xenbusState['Connected']) != driver_state:
            raise VmError("Driver status is not connected")

        uuid = self.readBackend(devid, 'uuid')
        if state == xenbusState['Initialising']:
            back['uuid'] = uuid
            self.writeBackend(devid, back)

        elif state == xenbusState['Closing']:
            found = False
            devs = self.readBackendList(devid, "vscsi-devs")
            hostmode = int(self.readBackend(devid, 'feature-host'))
            vscsipath = "vscsi-devs/"
            vdev = vscsi_config.get('v-dev', '')

            for dev in devs:
                devpath = vscsipath + dev
                old_vdev = self.readBackend(devid, devpath + '/v-dev')

                if hostmode == 1:
                    #At hostmode, all v-dev that belongs to devid is deleted.
                    found = True
                    self.writeBackend(devid, devpath + '/state', \
                                    str(xenbusState['Closing']))
                elif vdev == old_vdev:
                    found = True
                    self.writeBackend(devid, devpath + '/state', \
                                    str(xenbusState['Closing']))
                    break

            if not found:
                raise VmError("Device %s not connected" % vdev)

        else:
            raise XendError("Error configuring device invalid "
                            "state '%s'" % xenbusState[state])

        self.writeBackend(devid, 'state', str(xenbusState['Reconfiguring']))
        return self.readBackend(devid, 'uuid')


    def cleanupDevice(self, devid):
        devs = self.readBackendList(devid, "vscsi-devs")
        vscsipath = "vscsi-devs/"
        new_num_devs = 0
        
        for dev in devs:
            new_num_devs = new_num_devs + 1
            devpath = vscsipath + dev
            devstate = self.readBackend(devid, devpath + '/state')

            if str(xenbusState['Closed']) == devstate:
                self.removeBackend(devid, devpath)
                frontpath = self.frontendPath(devid)
                xstransact.Remove(frontpath + '/' + devpath)
                new_num_devs = new_num_devs - 1

            frontpath = self.frontendPath(devid)
            front_devstate = xstransact.Read(frontpath + '/' + devpath)
            if front_devstate is not None:
                if str(xenbusState['Closed']) == front_devstate:
                    self.removeBackend(devid, devpath)
                    xstransact.Remove(frontpath + '/' + devpath)
                    new_num_devs = new_num_devs - 1

        return new_num_devs

