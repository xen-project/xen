# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import socket
import xen.lowlevel.xc
xc = xen.lowlevel.xc.new()

import sxp
import XendRoot
xroot = XendRoot.instance()
import XendDB
from XendError import XendError

import EventServer
eserver = EventServer.instance()

from xen.xend.server import SrvDaemon
daemon = SrvDaemon.instance()

class XendConsole:

    def  __init__(self):
        pass
        eserver.subscribe('xend.domain.died', self.onDomainDied)
        eserver.subscribe('xend.domain.destroy', self.onDomainDied)

    def onDomainDied(self, event, val):
        pass

    def console_ls(self):
        return [ c.console_port for c in self.consoles() ]

    def consoles(self):
        return daemon.get_consoles()
    
    def console_create(self, dom, console_port=None, remote_port=0):
        consinfo = daemon.console_create(dom, console_port=console_port,
                                         remote_port=remote_port)
        return consinfo
    
    def console_get(self, id):
        id = int(id)
        for c in self.consoles():
            if c.console_port == id:
                return c
        return None

    def console_disconnect(self, id):
        console = self.console_get(id)
        if not console:
            raise XendError('Invalid console id')
        console.disconnect()

def instance():
    global inst
    try:
        inst
    except:
        inst = XendConsole()
    return inst
