import channel
import controller
from messages import *

class DomainControllerFactory(controller.ControllerFactory):
    """Factory for creating domain controllers.
    """

    def createInstance(self, dom):
        d = DomainController(self, dom)
        self.addInstance(d)
        return d
    
    def getInstanceByDom(self, dom):
        for inst in self.instances.values():
            if inst.dom == dom:
                return inst
        inst = self.createInstance(dom)
        return inst


class DomainController(controller.Controller):
    """Generic controller for a domain.
    """

    reasons = {'poweroff' : 'shutdown_poweroff_t',
               'reboot'   : 'shutdown_reboot_t',
               'suspend'  : 'shutdown_suspend_t' }

    def __init__(self, factory, dom):
        controller.Controller.__init__(self, factory, dom)
        self.majorTypes = [ CMSG_SHUTDOWN ]
        self.registerChannel()
        print 'DomainController>', self, self.channel, self.idx

    def shutdown(self, reason):
        msgtype = self.reasons.get(reason)
        if not msgtype:
            raise ValueError('invalid reason:' + reason)
        msg = packMsg(msgtype, {})
        self.writeRequest(msg)
