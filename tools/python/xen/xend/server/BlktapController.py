# Copyright (c) 2005, XenSource Ltd.


from xen.xend.server.blkif import BlkifController


class BlktapController(BlkifController):
    def __init__(self, vm):
        BlkifController.__init__(self, vm)
        
    def frontendRoot(self):
        """@see DevController#frontendRoot"""
        
        return "%s/device/vbd" % self.vm.getDomainPath()
