# Copyright (c) 2005, XenSource Ltd.


from xen.xend.server.blkif import BlkifController
from xen.xend.XendLogging import log

phantomDev = 0;
phantomId = 0;

class BlktapController(BlkifController):
    def __init__(self, vm):
        BlkifController.__init__(self, vm)
        
    def frontendRoot(self):
        """@see DevController#frontendRoot"""
        
        return "%s/device/vbd" % self.vm.getDomainPath()

    def getDeviceDetails(self, config):
        (devid, back, front) = BlkifController.getDeviceDetails(self, config)

        phantomDevid = 0
        wrapped = False

        try:
            imagetype = self.vm.info['image']['type']
        except:
            imagetype = ""

        if imagetype == 'hvm':
            tdevname = back['dev']
            index = ['c', 'd', 'e', 'f', 'g', 'h', 'i', \
                     'j', 'l', 'm', 'n', 'o', 'p']
            while True:
                global phantomDev
                global phantomId
                import os, stat

                phantomId = phantomId + 1
                if phantomId == 16:
                    if index[phantomDev] == index[-1]:
                        if wrapped:
                            raise VmError(" No loopback block \
                                       devices are available. ")
                        wrapped = True
                        phantomDev = 0
                    else:
                        phantomDev = phantomDev + 1
                    phantomId = 1
                devname = 'xvd%s%d' % (index[phantomDev], phantomId)
                try:
                    info = os.stat('/dev/%s' % devname)
                except:
                    break

            vbd = { 'mode': 'w', 'device': devname }
            fn = 'tap:%s' % back['params']

            # recurse ... by creating the vbd, then fallthrough
            # and finish creating the original device

            from xen.xend import XendDomain
            dom0 = XendDomain.instance().privilegedDomain()
            phantomDevid = dom0.create_phantom_vbd_with_vdi(vbd, fn)
            # we need to wait for this device at a higher level
            # the vbd that gets created will have a link to us
            # and will let them do it there

        # add a hook to point to the phantom device,
        # root path is always the same (dom0 tap)
        if phantomDevid != 0:
            front['phantom_vbd'] = '/local/domain/0/backend/tap/0/%s' \
                                   % str(phantomDevid)

        return (devid, back, front)

