# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import channel
import controller
from messages import *

class DomainControllerFactory(controller.ControllerFactory):
    """Factory for creating domain controllers.
    """

    def createInstance(self, dom):
        """Create a domain controller.

        dom domain

        returns domain controller
        """
        d = DomainController(self, dom)
        self.addInstance(d)
        return d
    
    def getInstanceByDom(self, dom):
        """Get a domain controller for a domain, creating if necessary.

        dom domain

        returns domain controller
        """
        for inst in self.instances.values():
            if inst.dom == dom:
                return inst
        inst = self.createInstance(dom)
        return inst


class DomainController(controller.Controller):
    """Generic controller for a domain.
    Used for domain shutdown.
    """

    """Map shutdown reasons to the message type to use.
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
        """Shutdown a domain.

        reason shutdown reason
        """
        msgtype = self.reasons.get(reason)
        if not msgtype:
            raise ValueError('invalid reason:' + reason)
        msg = packMsg(msgtype, {})
        self.writeRequest(msg)
