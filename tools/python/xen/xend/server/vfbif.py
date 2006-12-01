from xen.xend.server.DevController import DevController

class VfbifController(DevController):
    """Virtual frame buffer controller. Handles all vfb devices for a domain.
    """

    def __init__(self, vm):
        DevController.__init__(self, vm)

    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""
        devid = 0
        back = {}
        front = {}
        return (devid, back, front)

class VkbdifController(DevController):
    """Virtual keyboard controller. Handles all vkbd devices for a domain.
    """

    def __init__(self, vm):
        DevController.__init__(self, vm)

    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""
        devid = 0
        back = {}
        front = {}
        return (devid, back, front)
