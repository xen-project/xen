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
# Copyright (C) 2005 XenSource Ltd
#============================================================================


from xen.xend import sxp
from xen.xend.XendError import VmError
from xen.xend.XendLogging import log
from xen.xend.xenstore.xstransact import xstransact


class DevController:
    """Abstract base class for a device controller.  Device controllers create
    appropriate entries in the store to trigger the creation, reconfiguration,
    and destruction of devices in guest domains.  Each subclass of
    DevController is responsible for a particular device-class, and
    understands the details of configuration specific to that device-class.

    DevController itself provides the functionality common to all device
    creation tasks, as well as providing an interface to XendDomainInfo for
    triggering those events themselves.
    """

    # Set when registered.
    deviceClass = None


    ## public:

    def __init__(self, vm):
        self.vm = vm


    def createDevice(self, config):
        """Trigger the creation of a device with the given configuration.

        @return The ID for the newly created device.
        """
        (devid, back, front) = self.getDeviceDetails(config)

        self.writeDetails(config, devid, back, front)

        return devid


    def reconfigureDevice(self, devid, config):
        """Reconfigure the specified device.

        The implementation here just raises VmError.  This may be overridden
        by those subclasses that can reconfigure their devices.
        """
        raise VmError('%s devices may not be reconfigured' % self.deviceClass)


    def destroyDevice(self, devid):
        """Destroy the specified device.

        The implementation here simply deletes the appropriate paths from
        the store.  This may be overridden by subclasses who need to perform
        other tasks on destruction.
        """

        frontpath = self.frontendPath(devid)
        backpath = xstransact.Read("%s/backend" % frontpath)

        xstransact.Remove(frontpath)
        xstransact.Remove(backpath)


    def sxpr(self, devid):
        """@return an s-expression describing the specified device.
        """
        return [self.deviceClass, ['dom', self.vm.getDomain(),
                                   'id', devid]]


    ## protected:

    def getDeviceDetails(self, config):
        """Compute the details for creation of a device corresponding to the
        given configuration.  These details consist of a tuple of (devID,
        backDetails, frontDetails), where devID is the ID for the new device,
        and backDetails and frontDetails are the device configuration
        specifics for the backend and frontend respectively.

        backDetails and frontDetails should be dictionaries, the keys and
        values of which will be used as paths in the store.  There is no need
        for these dictionaries to include the references from frontend to
        backend, nor vice versa, as these will be handled by DevController.

        Abstract; must be implemented by every subclass.

        @return (devID, backDetails, frontDetails), as specified above.
        """

        raise NotImplementedError()


    def getDomain(self):
        """Stub to {@link XendDomainInfo.getDomain}, for use by our
        subclasses.
        """
        return self.vm.getDomain()


    ## private:

    def writeDetails(self, config, devid, backDetails, frontDetails):
        """Write the details in the store to trigger creation of a device.
        The backend domain ID is taken from the given config, paths for
        frontend and backend are computed, and these are written to the store
        appropriately, including references from frontend to backend and vice
        versa.

        @param config The configuration of the device, as given to
        {@link #createDevice}.
        @param devid        As returned by {@link #getDeviceDetails}.
        @param backDetails  As returned by {@link #getDeviceDetails}.
        @param frontDetails As returned by {@link #getDeviceDetails}.
        """

        import xen.xend.XendDomain
        backdom = xen.xend.XendDomain.instance().domain_lookup_by_name(
            sxp.child_value(config, 'backend', '0'))

        frontpath = self.frontendPath(devid)
        backpath  = self.backendPath(backdom, devid)
        
        frontDetails.update({
            'backend' : backpath,
            'backend-id' : "%i" % backdom.getDomain()
            })


        backDetails.update({
            'domain' : self.vm.getName(),
            'frontend' : frontpath,
            'frontend-id' : "%i" % self.vm.getDomain()
            })

        log.debug('DevController: writing %s to %s.', str(frontDetails),
                  frontpath)
        log.debug('DevController: writing %s to %s.', str(backDetails),
                  backpath)

        xstransact.Write(frontpath, frontDetails)
        xstransact.Write(backpath, backDetails)


    def backendPath(self, backdom, devid):
        """@param backdom [XendDomainInfo] The backend domain info."""

        return "%s/backend/%s/%s/%d" % (backdom.getPath(),
                                        self.deviceClass,
                                        self.vm.getUuid(), devid)


    def frontendPath(self, devid):
        return "%s/device/%s/%d" % (self.vm.getPath(),
                                    self.deviceClass,
                                    devid)
