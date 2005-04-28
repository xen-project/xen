# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import xen.lowlevel.xc
xc = xen.lowlevel.xc.new()

import XendRoot; xroot = XendRoot.instance()
from XendError import XendError

class XendConsole:

    def  __init__(self):
        pass

    def console_ls(self):
        return [ c.console_port for c in self.consoles() ]

    def consoles(self):
        l = []
        xd = XendRoot.get_component('xen.xend.XendDomain')
        for vm in xd.domains():
            ctrl = vm.getDeviceController("console", error=False)
            if (not ctrl): continue
            console = ctrl.getDevice(0)
            if (not console): continue
            l.append(console)
        return l
    
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
