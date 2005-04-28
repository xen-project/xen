# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from xen.xend import XendRoot
xroot = XendRoot.instance()
from xen.web.SrvDir import SrvDir

class SrvRoot(SrvDir):
    """The root of the xend server.
    """

    """Server sub-components. Each entry is (name, class), where
    'name' is the entry name and  'class' is the name of its class.
    """
    #todo Get this list from the XendRoot config.
    subdirs = [
        ('node',    'SrvNode'       ),
        ('domain',  'SrvDomainDir'  ),
        ('console', 'SrvConsoleDir' ),
        ('vnet',    'SrvVnetDir'    ),
        ]

    def __init__(self):
        SrvDir.__init__(self)
        for (name, klass) in self.subdirs:
            self.add(name, klass)
        for (name, klass) in self.subdirs:
            self.get(name)
        xroot.start()
        
    def __repr__(self):
        return "<SrvRoot %x %s>" %(id(self), self.table.keys())

