# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from xen.xend.XendError import XendError

import channel
import controller
from messages import *

class DomainControllerFactory(controller.ControllerFactory):
    """Factory for creating domain controllers.
    """

    def createController(self, dom):
        """Create a domain controller.

        dom domain

        returns domain controller
        """
        return DomainController(self, dom)

class DomainController(controller.Controller):
    """Generic controller for a domain.
    Used for domain shutdown.
    """

    """Map shutdown reasons to the message type to use.
    """
    reasons = {'poweroff' : 'shutdown_poweroff_t',
               'reboot'   : 'shutdown_reboot_t',
               'suspend'  : 'shutdown_suspend_t',
               'sysrq'    : 'shutdown_sysrq_t' }

    def __init__(self, factory, dom):
        controller.Controller.__init__(self, factory, dom)
        self.addMethod(CMSG_SHUTDOWN, 0, None)
        self.addMethod(CMSG_MEM_REQUEST, 0, None)
        self.registerChannel()

    def shutdown(self, reason, key=None):
        """Shutdown a domain.

        reason shutdown reason
        key    sysrq key (only if reason is 'sysrq')
        """
        msgtype = self.reasons.get(reason)
        if not msgtype:
            raise XendError('invalid reason:' + reason)
        extra = {}
        if reason == 'sysrq': extra['key'] = key
        print extra
        self.writeRequest(packMsg(msgtype, extra))

    def mem_target_set(self, target):
        """Set domain memory target in pages.
        """
        msg = packMsg('mem_request_t', { 'target' : target * (1 << 8)} )
        self.writeRequest(msg)
